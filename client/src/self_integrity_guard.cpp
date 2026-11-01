#include "pch.h"
#include "self_integrity_guard.h"
#include "win_path_utils.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <limits>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    constexpr auto kVerificationInterval = std::chrono::seconds(5);
    constexpr size_t kMaxSelfImageBytes = 64ULL * 1024ULL * 1024ULL;

    bool IsCodeSection(const IMAGE_SECTION_HEADER& section) {
        const auto characteristics = section.Characteristics;
        return (characteristics & IMAGE_SCN_CNT_CODE) != 0 &&
               (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    bool HasRange(size_t totalSize, size_t offset, size_t length) {
        return offset <= totalSize && length <= totalSize - offset;
    }

    // Validate every pointer range before exposing typed PE-header pointers.
    bool GetValidatedDiskHeaders(
        const std::vector<uint8_t>& image,
        const IMAGE_DOS_HEADER*& dosHeader,
        const IMAGE_NT_HEADERS*& ntHeaders,
        const IMAGE_SECTION_HEADER*& sections) {
        dosHeader = nullptr;
        ntHeaders = nullptr;
        sections = nullptr;

        if (!HasRange(image.size(), 0, sizeof(IMAGE_DOS_HEADER))) {
            return false;
        }

        dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < 0) {
            return false;
        }

        const size_t ntOffset = static_cast<size_t>(dosHeader->e_lfanew);
        if ((ntOffset % alignof(IMAGE_NT_HEADERS)) != 0 ||
            !HasRange(image.size(), ntOffset, sizeof(IMAGE_NT_HEADERS))) {
            return false;
        }

        ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + ntOffset);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER) ||
            ntHeaders->FileHeader.NumberOfSections == 0 ||
            ntHeaders->OptionalHeader.SizeOfImage == 0 ||
            ntHeaders->OptionalHeader.SizeOfHeaders == 0 ||
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
            return false;
        }

        const size_t sectionTableOffset = ntOffset + sizeof(IMAGE_NT_HEADERS);
        const size_t sectionCount = ntHeaders->FileHeader.NumberOfSections;
        const size_t sectionBytes = sectionCount * sizeof(IMAGE_SECTION_HEADER);
        if (!HasRange(image.size(), sectionTableOffset, sectionBytes) ||
            ntHeaders->OptionalHeader.SizeOfHeaders < sectionTableOffset + sectionBytes ||
            ntHeaders->OptionalHeader.SizeOfHeaders > image.size()) {
            return false;
        }

        sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            image.data() + sectionTableOffset);
        const uint64_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        for (size_t i = 0; i < sectionCount; ++i) {
            const IMAGE_SECTION_HEADER& section = sections[i];
            const uint64_t sectionExtent =
                (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
            if (section.VirtualAddress > imageSize ||
                sectionExtent > imageSize - section.VirtualAddress) {
                return false;
            }
            if (section.SizeOfRawData != 0 &&
                !HasRange(image.size(), section.PointerToRawData, section.SizeOfRawData)) {
                return false;
            }
        }
        return true;
    }

    bool IsReadableModuleRange(
        const uint8_t* moduleBase,
        size_t offset,
        size_t length,
        const void* expectedAllocationBase) {
        if (!moduleBase || length == 0) {
            return length == 0 && moduleBase != nullptr;
        }

        const uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleBase);
        if (offset > (std::numeric_limits<uintptr_t>::max)() - baseAddress) {
            return false;
        }
        const uintptr_t start = baseAddress + offset;
        if (length > (std::numeric_limits<uintptr_t>::max)() - start) {
            return false;
        }
        const uintptr_t end = start + length;
        uintptr_t current = start;

        while (current < end) {
            MEMORY_BASIC_INFORMATION memoryInfo{};
            if (VirtualQuery(reinterpret_cast<const void*>(current),
                             &memoryInfo, sizeof(memoryInfo)) != sizeof(memoryInfo)) {
                return false;
            }
            if (memoryInfo.AllocationBase != expectedAllocationBase ||
                memoryInfo.State != MEM_COMMIT ||
                (memoryInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
                return false;
            }

            const DWORD protection = memoryInfo.Protect & 0xFF;
            const bool readable =
                protection == PAGE_READONLY ||
                protection == PAGE_READWRITE ||
                protection == PAGE_WRITECOPY ||
                protection == PAGE_EXECUTE_READ ||
                protection == PAGE_EXECUTE_READWRITE ||
                protection == PAGE_EXECUTE_WRITECOPY;
            if (!readable) {
                return false;
            }

            const uintptr_t regionBase = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
            if (memoryInfo.RegionSize >
                    (std::numeric_limits<uintptr_t>::max)() - regionBase) {
                return false;
            }
            const uintptr_t regionEnd = regionBase + memoryInfo.RegionSize;
            if (regionEnd <= current) {
                return false;
            }
            current = (std::min)(end, regionEnd);
        }

        return true;
    }
}

namespace Oblivion {
    SelfIntegrityGuard::SelfIntegrityGuard(HMODULE moduleHandle)
        : m_module(moduleHandle),
          m_running(false) {
        if (m_module) {
            m_modulePath = Oblivion::WinPath::GetModulePath(m_module);
        }
    }

    SelfIntegrityGuard::~SelfIntegrityGuard() {
        Stop();
    }

    bool SelfIntegrityGuard::Start() {
        if (m_running.load() || !m_module || m_modulePath.empty()) {
            return false;
        }

        if (!LoadDiskImage()) {
            return false;
        }

        if (!ParseRelocations()) {
            ReportTamper("INVALID_SELF_IMAGE_RELOCATIONS");
            return false;
        }

        if (!VerifySectionsOnce()) {
            return false;
        }

        m_running = true;
        try {
            m_worker = std::thread(&SelfIntegrityGuard::MonitoringLoop, this);
        } catch (...) {
            m_running = false;
            throw;
        }
        return true;
    }

    void SelfIntegrityGuard::Stop() {
        // KRITIS: jangan early-return berdasar m_running. Loop pemantauan mematok
        // flag itu `false` sendiri saat melaporkan pelanggaran, sehingga early-return
        // akan melewati join() dan std::thread yang masih joinable dihancurkan ->
        // std::terminate. Idempotent: join() hanya jalan bila thread masih joinable.
        m_running = false;
        if (m_worker.joinable()) {
            m_worker.join();
        }
    }

    bool SelfIntegrityGuard::IsRunning() const {
        return m_running.load();
    }

    bool SelfIntegrityGuard::LoadDiskImage() {
        if (!m_diskImage.empty()) {
            return true;
        }

        std::ifstream file(m_modulePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }

        const std::streampos endPosition = file.tellg();
        if (endPosition <= std::streampos(0)) {
            return false;
        }

        const std::streamoff fileSize = static_cast<std::streamoff>(endPosition);
        if (fileSize <= 0 ||
            static_cast<uint64_t>(fileSize) > static_cast<uint64_t>(kMaxSelfImageBytes)) {
            return false;
        }

        const size_t sizeValue = static_cast<size_t>(fileSize);
        m_diskImage.resize(sizeValue);
        file.seekg(0, std::ios::beg);
        if (!file) {
            m_diskImage.clear();
            return false;
        }

        file.read(reinterpret_cast<char*>(m_diskImage.data()),
                  static_cast<std::streamsize>(sizeValue));
        if (file.gcount() != static_cast<std::streamsize>(sizeValue)) {
            m_diskImage.clear();
            return false;
        }
        return true;
    }

    void SelfIntegrityGuard::MonitoringLoop() {
        while (m_running.load()) {
            if (!VerifySectionsOnce()) {
                // ReportViolationAndExit already called inside VerifySectionsOnce.
                return;
            }

            auto slept = std::chrono::milliseconds(0);
            while (slept < kVerificationInterval && m_running.load()) {
                Sleep(100);
                slept += std::chrono::milliseconds(100);
            }
        }
    }

    bool SelfIntegrityGuard::VerifySectionsOnce() const {
        const IMAGE_DOS_HEADER* fileDosHeader = nullptr;
        const IMAGE_NT_HEADERS* fileNtHeaders = nullptr;
        const IMAGE_SECTION_HEADER* fileSections = nullptr;
        if (!GetValidatedDiskHeaders(m_diskImage, fileDosHeader, fileNtHeaders, fileSections)) {
            ReportTamper("INVALID_DISK_PE_HEADERS");
            return false;
        }

        const auto* moduleBase = reinterpret_cast<const uint8_t*>(m_module);
        if (!IsReadableModuleRange(moduleBase, 0, sizeof(IMAGE_DOS_HEADER), m_module)) {
            ReportTamper("INVALID_MEMORY_DOS_HEADER");
            return false;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
            dosHeader->e_lfanew < 0 ||
            dosHeader->e_lfanew != fileDosHeader->e_lfanew) {
            ReportTamper("PE_DOS_HEADER");
            return false;
        }

        const size_t ntOffset = static_cast<size_t>(fileDosHeader->e_lfanew);
        if (!IsReadableModuleRange(moduleBase, ntOffset, sizeof(IMAGE_NT_HEADERS), m_module)) {
            ReportTamper("INVALID_MEMORY_NT_HEADERS");
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + ntOffset);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->FileHeader.NumberOfSections != fileNtHeaders->FileHeader.NumberOfSections ||
            ntHeaders->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER) ||
            ntHeaders->OptionalHeader.SizeOfImage != fileNtHeaders->OptionalHeader.SizeOfImage ||
            ntHeaders->OptionalHeader.SizeOfHeaders != fileNtHeaders->OptionalHeader.SizeOfHeaders) {
            ReportTamper("PE_NT_HEADERS");
            return false;
        }

        const size_t sectionCount = fileNtHeaders->FileHeader.NumberOfSections;
        const size_t sectionTableOffset = ntOffset + sizeof(IMAGE_NT_HEADERS);
        const size_t sectionBytes = sectionCount * sizeof(IMAGE_SECTION_HEADER);
        if (!IsReadableModuleRange(moduleBase, sectionTableOffset, sectionBytes, m_module)) {
            ReportTamper("INVALID_MEMORY_SECTION_TABLE");
            return false;
        }

        const auto* memorySections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            moduleBase + sectionTableOffset);
        for (size_t i = 0; i < sectionCount; ++i) {
            const IMAGE_SECTION_HEADER& currentSection = memorySections[i];
            if (std::memcmp(&currentSection, &fileSections[i], sizeof(IMAGE_SECTION_HEADER)) != 0) {
                ReportTamper("PE_SECTION_HEADERS");
                return false;
            }

            if (!IsCodeSection(currentSection)) {
                continue;
            }

            if (!CompareSection(currentSection)) {
                size_t length = 0;
                while (length < IMAGE_SIZEOF_SHORT_NAME && currentSection.Name[length] != '\0') {
                    ++length;
                }
                const std::string sectionName(
                    reinterpret_cast<const char*>(currentSection.Name), length);
                ReportTamper(sectionName);
                return false;
            }
        }

        return true;
    }

    bool SelfIntegrityGuard::CompareSection(const IMAGE_SECTION_HEADER& section) const {
        const IMAGE_DOS_HEADER* fileDosHeader = nullptr;
        const IMAGE_NT_HEADERS* fileNtHeaders = nullptr;
        const IMAGE_SECTION_HEADER* fileSections = nullptr;
        if (!GetValidatedDiskHeaders(m_diskImage, fileDosHeader, fileNtHeaders, fileSections)) {
            return false;
        }

        size_t sectionSize = static_cast<size_t>(section.SizeOfRawData);
        const size_t virtualSize = static_cast<size_t>(section.Misc.VirtualSize);
        if (virtualSize > 0 && virtualSize < sectionSize) {
            sectionSize = virtualSize;
        }

        if (sectionSize == 0) {
            return true;
        }

        const uint64_t imageSize = fileNtHeaders->OptionalHeader.SizeOfImage;
        if (section.VirtualAddress > imageSize ||
            sectionSize > imageSize - section.VirtualAddress ||
            !HasRange(m_diskImage.size(), section.PointerToRawData, sectionSize)) {
            return false;
        }

        const auto* moduleBase = reinterpret_cast<const uint8_t*>(m_module);
        if (!IsReadableModuleRange(moduleBase, section.VirtualAddress, sectionSize, m_module)) {
            return false;
        }

        const auto* sectionMemory = moduleBase + section.VirtualAddress;
        const auto* sectionOnDisk = m_diskImage.data() + section.PointerToRawData;

        std::vector<std::pair<size_t, size_t>> skipIntervals;
        const DWORD sectionStartRva = section.VirtualAddress;
        const DWORD sectionEndRva = sectionStartRva + static_cast<DWORD>(sectionSize);
        BuildSkipIntervals(sectionStartRva, sectionEndRva, skipIntervals);

        if (skipIntervals.empty()) {
            return std::memcmp(sectionMemory, sectionOnDisk, sectionSize) == 0;
        }

        size_t currentOffset = 0;
        for (const auto& interval : skipIntervals) {
            const size_t start = interval.first;
            const size_t end = interval.second;
            if (currentOffset < start) {
                const size_t length = start - currentOffset;
                if (std::memcmp(sectionMemory + currentOffset,
                                sectionOnDisk + currentOffset, length) != 0) {
                    return false;
                }
            }
            currentOffset = (std::max)(currentOffset, end);
        }

        if (currentOffset < sectionSize) {
            const size_t length = sectionSize - currentOffset;
            if (std::memcmp(sectionMemory + currentOffset,
                            sectionOnDisk + currentOffset, length) != 0) {
                return false;
            }
        }

        return true;
    }

    void SelfIntegrityGuard::ReportTamper(const std::string& sectionName) const {
        std::string details = "Self integrity mismatch detected";
        if (!sectionName.empty()) {
            details += " in section ";
            details += sectionName;
        }
        ReportViolationAndExit(L"", "SELF_TAMPER_DETECTED", details);
    }

    bool SelfIntegrityGuard::ParseRelocations() {
        m_relocationSpans.clear();

        const IMAGE_DOS_HEADER* dosHeader = nullptr;
        const IMAGE_NT_HEADERS* ntHeaders = nullptr;
        const IMAGE_SECTION_HEADER* sections = nullptr;
        if (!GetValidatedDiskHeaders(m_diskImage, dosHeader, ntHeaders, sections)) {
            return false;
        }

        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            return true;
        }

        const auto& relocDirectory =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDirectory.VirtualAddress == 0 && relocDirectory.Size == 0) {
            return true;
        }
        if (relocDirectory.VirtualAddress == 0 || relocDirectory.Size == 0) {
            return false;
        }

        DWORD relocFileOffset = 0;
        if (!RvaToFileRange(relocDirectory.VirtualAddress, relocDirectory.Size, relocFileOffset)) {
            return false;
        }

        size_t remaining = relocDirectory.Size;
        const uint8_t* cursor = m_diskImage.data() + relocFileOffset;
        const uint64_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;

        while (remaining > 0) {
            if (remaining < sizeof(IMAGE_BASE_RELOCATION)) {
                return false;
            }

            IMAGE_BASE_RELOCATION block{};
            std::memcpy(&block, cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > remaining ||
                ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0) {
                return false;
            }

            const size_t entryCount =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const uint8_t* entryBytes = cursor + sizeof(IMAGE_BASE_RELOCATION);

            for (size_t i = 0; i < entryCount; ++i) {
                WORD typeOffset = 0;
                std::memcpy(&typeOffset, entryBytes + i * sizeof(WORD), sizeof(typeOffset));
                const WORD type = typeOffset >> 12;
                const WORD offset = typeOffset & 0x0FFF;

                size_t spanSize = 0;
                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    continue;
                case IMAGE_REL_BASED_HIGHLOW:
                    spanSize = sizeof(DWORD);
                    break;
                case IMAGE_REL_BASED_DIR64:
                    spanSize = sizeof(ULONGLONG);
                    break;
                default:
                    continue;
                }

                const uint64_t rva64 = static_cast<uint64_t>(block.VirtualAddress) + offset;
                if (rva64 > (std::numeric_limits<DWORD>::max)() ||
                    rva64 > imageSize || spanSize > imageSize - rva64) {
                    return false;
                }
                m_relocationSpans.push_back({ static_cast<DWORD>(rva64), spanSize });
            }

            cursor += block.SizeOfBlock;
            remaining -= block.SizeOfBlock;
        }

        std::sort(m_relocationSpans.begin(), m_relocationSpans.end(),
            [](const RelocationSpan& lhs, const RelocationSpan& rhs) {
                return lhs.rva < rhs.rva;
            });
        return true;
    }

    bool SelfIntegrityGuard::RvaToFileRange(DWORD rva, DWORD size, DWORD& fileOffset) const {
        if (size == 0) {
            return false;
        }

        const IMAGE_DOS_HEADER* dosHeader = nullptr;
        const IMAGE_NT_HEADERS* ntHeaders = nullptr;
        const IMAGE_SECTION_HEADER* sections = nullptr;
        if (!GetValidatedDiskHeaders(m_diskImage, dosHeader, ntHeaders, sections)) {
            return false;
        }

        const uint64_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        if (rva >= imageSize || static_cast<uint64_t>(size) > imageSize - rva) {
            return false;
        }

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER& section = sections[i];
            const uint64_t sectionStart = section.VirtualAddress;
            const uint64_t sectionExtent =
                (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
            const uint64_t sectionEnd = sectionStart + sectionExtent;
            if (static_cast<uint64_t>(rva) < sectionStart ||
                static_cast<uint64_t>(rva) >= sectionEnd) {
                continue;
            }

            const uint64_t offsetWithinSection = static_cast<uint64_t>(rva) - sectionStart;
            if (offsetWithinSection > section.SizeOfRawData ||
                static_cast<uint64_t>(size) > section.SizeOfRawData - offsetWithinSection) {
                return false;
            }

            const uint64_t offset = static_cast<uint64_t>(section.PointerToRawData) +
                                    offsetWithinSection;
            if (offset > (std::numeric_limits<DWORD>::max)() ||
                !HasRange(m_diskImage.size(), static_cast<size_t>(offset), size)) {
                return false;
            }
            fileOffset = static_cast<DWORD>(offset);
            return true;
        }

        if (rva < ntHeaders->OptionalHeader.SizeOfHeaders &&
            size <= ntHeaders->OptionalHeader.SizeOfHeaders - rva &&
            HasRange(m_diskImage.size(), rva, size)) {
            fileOffset = rva;
            return true;
        }
        return false;
    }

    void SelfIntegrityGuard::BuildSkipIntervals(
        DWORD sectionStart,
        DWORD sectionEnd,
        std::vector<std::pair<size_t, size_t>>& skips) const {
        skips.clear();
        if (m_relocationSpans.empty() || sectionStart >= sectionEnd) {
            return;
        }

        for (const auto& span : m_relocationSpans) {
            const uint64_t spanStart = span.rva;
            const uint64_t spanEnd = spanStart + span.size;
            if (spanEnd <= sectionStart || spanStart >= sectionEnd) {
                continue;
            }

            const auto relativeStart = static_cast<size_t>(
                (std::max<uint64_t>)(spanStart, sectionStart) - sectionStart);
            const auto relativeEnd = static_cast<size_t>(
                (std::min<uint64_t>)(spanEnd, sectionEnd) - sectionStart);
            if (relativeStart < relativeEnd) {
                skips.emplace_back(relativeStart, relativeEnd);
            }
        }

        if (skips.empty()) {
            return;
        }

        std::sort(skips.begin(), skips.end());
        std::vector<std::pair<size_t, size_t>> merged;
        merged.reserve(skips.size());

        auto current = skips.front();
        for (size_t i = 1; i < skips.size(); ++i) {
            const auto& interval = skips[i];
            if (interval.first <= current.second) {
                current.second = (std::max)(current.second, interval.second);
            } else {
                merged.push_back(current);
                current = interval;
            }
        }
        merged.push_back(current);
        skips.swap(merged);
    }

}

