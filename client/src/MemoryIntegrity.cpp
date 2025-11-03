#include "../pch.h"
#include "MemoryIntegrity.h"
#include "Logger.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

// ===== CRC32 Implementation =====
namespace CRC32 {
    static DWORD s_table[256];
    static bool s_initialized = false;

    void InitializeTable() {
        if (s_initialized) return;
        
        const DWORD polynomial = 0xEDB88320;
        for (DWORD i = 0; i < 256; i++) {
            DWORD crc = i;
            for (DWORD j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ polynomial;
                } else {
                    crc >>= 1;
                }
            }
            s_table[i] = crc;
        }
        s_initialized = true;
    }

    DWORD Calculate(const void* data, size_t size) {
        if (!s_initialized) InitializeTable();
        
        DWORD crc = 0xFFFFFFFF;
        const BYTE* bytes = static_cast<const BYTE*>(data);
        
        for (size_t i = 0; i < size; i++) {
            BYTE index = (crc ^ bytes[i]) & 0xFF;
            crc = (crc >> 8) ^ s_table[index];
        }
        
        return ~crc;
    }
}

// ===== SHA256 Implementation (Simple) =====
// NOTE: For production, use CryptoAPI or BCrypt for proper SHA256
namespace SHA256 {
    // Simplified SHA256 (using CRC32 cascaded for demonstration)
    // In production, replace with proper SHA256 using BCrypt/CryptoAPI
    Hash Calculate(const void* data, size_t size) {
        Hash result = {};
        
        // Split data into 8 chunks and calculate CRC32 for each
        const BYTE* bytes = static_cast<const BYTE*>(data);
        size_t chunkSize = size / 8;
        
        for (int i = 0; i < 8; i++) {
            size_t offset = i * chunkSize;
            size_t len = (i == 7) ? (size - offset) : chunkSize;
            
            if (len > 0) {
                DWORD crc = CRC32::Calculate(bytes + offset, len);
                memcpy(result.data + (i * 4), &crc, 4);
            }
        }
        
        return result;
    }

    bool Hash::operator==(const Hash& other) const {
        return memcmp(data, other.data, 32) == 0;
    }

    bool Hash::operator!=(const Hash& other) const {
        return !(*this == other);
    }

    std::string Hash::ToString() const {
        char buffer[65];
        for (int i = 0; i < 32; i++) {
            sprintf_s(buffer + (i * 2), 3, "%02X", data[i]);
        }
        buffer[64] = '\0';
        return std::string(buffer);
    }
}

// ===== MemoryIntegrity Implementation =====

MemoryIntegrity::MemoryIntegrity()
    : m_monitorThread(nullptr)
    , m_isMonitoring(false)
    , m_shouldStop(false)
    , m_checkIntervalMs(2000)  // Default: check every 2 seconds
    , m_violationThreshold(3)  // Trigger after 3 violations
    , m_useSHA256(false)       // Default: use faster CRC32
    , m_enableApiHookDetection(true)
    , m_originalVirtualProtect(nullptr)
    , m_originalVirtualProtectEx(nullptr)
    , m_originalVirtualAlloc(nullptr)
    , m_originalVirtualAllocEx(nullptr)
{
    CRC32::InitializeTable();
    
    // Store original API addresses for hook detection
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        m_originalVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");
        m_originalVirtualProtectEx = GetProcAddress(hKernel32, "VirtualProtectEx");
        m_originalVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
        m_originalVirtualAllocEx = GetProcAddress(hKernel32, "VirtualAllocEx");
    }
    
    LOG_INFO("MemoryIntegrity initialized");
}

MemoryIntegrity::~MemoryIntegrity() {
    StopMonitoring();
    LOG_INFO("MemoryIntegrity destroyed");
}

void MemoryIntegrity::RegisterCriticalRegion(void* address, size_t size, const std::string& name, bool useSHA256) {
    if (!address || size == 0) {
        LOG_WARNING("MemoryIntegrity: Invalid address or size");
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    
    CriticalRegion region = {};
    region.baseAddress = address;
    region.size = size;
    region.name = name.empty() ? "Unknown" : name;
    region.usesSHA256 = useSHA256;
    region.violationCount = 0;
    region.lastCheckTime = GetTickCount64();
    
    // Get current protection
    if (!GetMemoryProtection(address, region.originalProtection)) {
        LOG_ERROR_FMT("MemoryIntegrity: Failed to get protection for region %s at 0x%p, fallback to PAGE_EXECUTE_READ. Possible cause: region not committed, invalid address, or OS interference.", name.c_str(), address);
        region.originalProtection = PAGE_EXECUTE_READ;  // Assume default
    }
    region.currentProtection = region.originalProtection;
    
    // Calculate initial hash
    UpdateRegionHash(region);
    
    m_regions[address] = region;
    
    LOG_INFO_FMT("MemoryIntegrity: Registered region '%s' at 0x%p, size=%zu, hash=%s",
                 name.c_str(), address, size, 
                 useSHA256 ? region.expectedSHA256.ToString().c_str() : std::to_string(region.expectedCRC32).c_str());
}

void MemoryIntegrity::UnregisterCriticalRegion(void* address) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_regions.find(address);
    if (it != m_regions.end()) {
        LOG_INFO_FMT("MemoryIntegrity: Unregistered region '%s' at 0x%p", 
                     it->second.name.c_str(), address);
        m_regions.erase(it);
    }
}

bool MemoryIntegrity::VerifyIntegrity() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    bool allValid = true;
    ULONGLONG now = GetTickCount64();
    
    for (auto& pair : m_regions) {
        CriticalRegion& region = pair.second;
        
        // Calculate current hash
        bool hashValid = true;
        if (region.usesSHA256) {
            SHA256::Hash currentHash = CalculateSHA256(region.baseAddress, region.size);
            hashValid = (currentHash == region.expectedSHA256);
            
            if (!hashValid) {
                MemoryModification mod = {};
                mod.address = region.baseAddress;
                mod.size = region.size;
                mod.regionName = region.name;
                mod.modificationType = "HASH_MISMATCH_SHA256";
                mod.timestamp = now;
                m_modifications.push_back(mod);
                
                region.violationCount++;
                allValid = false;
                
                LOG_WARNING_FMT("MemoryIntegrity: SHA256 mismatch in region '%s' at 0x%p (violations: %d)",
                               region.name.c_str(), region.baseAddress, region.violationCount);
            }
        } else {
            DWORD currentCRC = CalculateCRC32(region.baseAddress, region.size);
            hashValid = (currentCRC == region.expectedCRC32);
            
            if (!hashValid) {
                MemoryModification mod = {};
                mod.address = region.baseAddress;
                mod.size = region.size;
                mod.regionName = region.name;
                mod.modificationType = "HASH_MISMATCH_CRC32";
                mod.expectedHash = region.expectedCRC32;
                mod.actualHash = currentCRC;
                mod.timestamp = now;
                m_modifications.push_back(mod);
                
                region.violationCount++;
                allValid = false;
                
                LOG_WARNING_FMT("MemoryIntegrity: CRC32 mismatch in region '%s' at 0x%p (expected: 0x%X, actual: 0x%X, violations: %d)",
                               region.name.c_str(), region.baseAddress, region.expectedCRC32, currentCRC, region.violationCount);
            }
        }
        
        region.lastCheckTime = now;
    }
    
    return allValid;
}

bool MemoryIntegrity::VerifyRegion(void* address) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_regions.find(address);
    if (it == m_regions.end()) {
        LOG_WARNING_FMT("MemoryIntegrity: Region 0x%p not registered", address);
        return false;
    }
    
    CriticalRegion& region = it->second;
    ULONGLONG now = GetTickCount64();
    
    bool valid = true;
    if (region.usesSHA256) {
        SHA256::Hash currentHash = CalculateSHA256(region.baseAddress, region.size);
        valid = (currentHash == region.expectedSHA256);
    } else {
        DWORD currentCRC = CalculateCRC32(region.baseAddress, region.size);
        valid = (currentCRC == region.expectedCRC32);
    }
    
    if (!valid) {
        region.violationCount++;
    }
    
    region.lastCheckTime = now;
    return valid;
}

DWORD MemoryIntegrity::CalculateCRC32(void* address, size_t size) {
    std::vector<BYTE> buffer(size);
    
    if (!ReadMemorySafe(address, buffer.data(), size)) {
        LOG_ERROR_FMT("MemoryIntegrity: Failed to read memory at 0x%p", address);
        return 0;
    }
    
    return CRC32::Calculate(buffer.data(), size);
}

SHA256::Hash MemoryIntegrity::CalculateSHA256(void* address, size_t size) {
    std::vector<BYTE> buffer(size);
    
    if (!ReadMemorySafe(address, buffer.data(), size)) {
        LOG_ERROR_FMT("MemoryIntegrity: Failed to read memory at 0x%p", address);
        return SHA256::Hash{};
    }
    
    return SHA256::Calculate(buffer.data(), size);
}

bool MemoryIntegrity::DetectMemoryModifications() {
    return !VerifyIntegrity();
}

bool MemoryIntegrity::CheckPageProtection() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    bool protectionChanged = false;
    ULONGLONG now = GetTickCount64();
    
    // Cek apakah debugger aktif
    if (IsDebuggerPresent()) {
        LOG_INFO("MemoryIntegrity: Debugger detected, protection change warnings are suppressed.");
        return false;
    }
    auto normalizeProt = [](DWORD p) -> DWORD {
        // Mask out PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE noise flags
        return p & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    };

    auto isTextRegion = [](const std::string& name) -> bool {
        return name.find("::text") != std::string::npos;
    };

    for (auto& pair : m_regions) {
        CriticalRegion& region = pair.second;
        DWORD currentProtection = 0;
        if (GetMemoryProtection(region.baseAddress, currentProtection)) {
            // Normalize to ignore auxiliary flags
            currentProtection = normalizeProt(currentProtection);
            DWORD lastProtection = normalizeProt(region.currentProtection);

            // Only react if protection actually changed since last check
            if (currentProtection != lastProtection) {
                bool textRegion = isTextRegion(region.name);
                bool allowedTextProt = textRegion &&
                    (currentProtection == PAGE_EXECUTE_READ || currentProtection == PAGE_EXECUTE_WRITECOPY);

                if (allowedTextProt) {
                    // Benign transition for .text: READ/WRITECOPY/EXECUTE_READ toggles
                    LOG_INFO_FMT("MemoryIntegrity: Protection updated for text region '%s' at 0x%p (prev: 0x%X, now: 0x%X)",
                                 region.name.c_str(), region.baseAddress, lastProtection, currentProtection);
                } else {
                    // If region is .text and becomes EXECUTE_READWRITE, this can be legitimate during patching.
                    // If content hash hasn't changed, lower severity (no violation count increment).
                    bool loweredSeverity = false;
                    if (textRegion && currentProtection == PAGE_EXECUTE_READWRITE) {
                        bool hashSame = false;
                        if (region.usesSHA256) {
                            hashSame = (CalculateSHA256(region.baseAddress, region.size) == region.expectedSHA256);
                        } else {
                            hashSame = (CalculateCRC32(region.baseAddress, region.size) == region.expectedCRC32);
                        }
                        if (hashSame) {
                            LOG_INFO_FMT("MemoryIntegrity: Text region temporarily writeable but hash unchanged '%s' at 0x%p (prev: 0x%X, now: 0x%X)",
                                         region.name.c_str(), region.baseAddress, lastProtection, currentProtection);
                            loweredSeverity = true;
                        }
                    }

                    if (!loweredSeverity) {
                        MemoryModification mod = {};
                        mod.address = region.baseAddress;
                        mod.size = region.size;
                        mod.regionName = region.name;
                        mod.modificationType = "PROTECTION_CHANGED";
                        mod.expectedProtection = region.currentProtection; // previous observed protection
                        mod.actualProtection = currentProtection;
                        mod.timestamp = now;
                        m_modifications.push_back(mod);
                        protectionChanged = true;
                        region.violationCount++;
                        LOG_WARNING_FMT("MemoryIntegrity: Protection changed in region '%s' at 0x%p (prev: 0x%X, now: 0x%X)",
                                        region.name.c_str(), region.baseAddress, lastProtection, currentProtection);
                    }
                }

                // Update current protection to suppress repeated logs while state is stable
                region.currentProtection = currentProtection;
            }
        }
    }
    
    return protectionChanged;
}

bool MemoryIntegrity::DetectApiHooks() {
    if (!m_enableApiHookDetection) return false;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    DetectApiHooksInternal();
    
    return !m_apiHooks.empty();
}

void MemoryIntegrity::RegisterAllTextSections(bool useSHA256) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG_ERROR("MemoryIntegrity: Failed to create module snapshot");
        return;
    }
    
    MODULEENTRY32W me = {};
    me.dwSize = sizeof(MODULEENTRY32W);
    
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            RegisterModuleTextSection(me.hModule, "", useSHA256);
        } while (Module32NextW(hSnapshot, &me));
    }
    
    CloseHandle(hSnapshot);
    LOG_INFO_FMT("MemoryIntegrity: Registered %d .text sections", GetRegisteredRegionCount());
}

void MemoryIntegrity::RegisterModuleTextSection(HMODULE hModule, const std::string& moduleName, bool useSHA256) {
    if (!hModule) return;

    // Get DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }
    
    // Get NT headers
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    
    // Find .text section
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        // Check if this is .text section
        if (memcmp(section->Name, ".text", 5) == 0) {
            void* textBase = (BYTE*)hModule + section->VirtualAddress;
            size_t textSize = section->Misc.VirtualSize;
            
            // Get module name
            char moduleNameBuf[MAX_PATH] = {};
            GetModuleFileNameA(hModule, moduleNameBuf, MAX_PATH);
            std::string name = moduleName.empty() ? std::string(moduleNameBuf) : moduleName;
            name += "::text";
            
            RegisterCriticalRegion(textBase, textSize, name, useSHA256);
            break;
        }
    }
}

std::vector<std::string> MemoryIntegrity::GetRegisteredRegionNames() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::string> names;
    names.reserve(m_regions.size());
    
    for (const auto& pair : m_regions) {
        names.push_back(pair.second.name);
    }
    
    return names;
}

void MemoryIntegrity::StartMonitoring() {
    if (m_isMonitoring) {
        LOG_WARNING("MemoryIntegrity: Already monitoring");
        return;
    }
    
    m_shouldStop = false;
    m_monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
    
    if (m_monitorThread) {
        m_isMonitoring = true;
        LOG_INFO("MemoryIntegrity: Background monitoring started");
    } else {
        LOG_ERROR("MemoryIntegrity: Failed to start monitoring thread");
    }
}

void MemoryIntegrity::StopMonitoring() {
    if (!m_isMonitoring) return;
    
    m_shouldStop = true;
    
    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = nullptr;
    }
    
    m_isMonitoring = false;
    LOG_INFO("MemoryIntegrity: Background monitoring stopped");
}

bool MemoryIntegrity::ReadMemorySafe(void* address, void* buffer, size_t size) {
    __try {
        memcpy(buffer, address, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool MemoryIntegrity::GetMemoryProtection(void* address, DWORD& protection) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        protection = mbi.Protect;
        return true;
    }
    return false;
}

void MemoryIntegrity::UpdateRegionHash(CriticalRegion& region) {
    if (region.usesSHA256) {
        region.expectedSHA256 = CalculateSHA256(region.baseAddress, region.size);
    } else {
        region.expectedCRC32 = CalculateCRC32(region.baseAddress, region.size);
    }
}

void MemoryIntegrity::DetectApiHooksInternal() {
    m_apiHooks.clear();
    ULONGLONG now = GetTickCount64();
    
    // Check VirtualProtect
    void* currentVP = GetApiAddress("kernel32.dll", "VirtualProtect");
    if (currentVP && m_originalVirtualProtect && currentVP != m_originalVirtualProtect) {
        ApiHookInfo hook = {};
        hook.apiName = "VirtualProtect";
        hook.expectedAddress = m_originalVirtualProtect;
        hook.actualAddress = currentVP;
        hook.isHooked = true;
        hook.detectionTime = now;
        m_apiHooks.push_back(hook);
        
        LOG_WARNING_FMT("MemoryIntegrity: VirtualProtect hooked! (expected: 0x%p, actual: 0x%p)",
                       m_originalVirtualProtect, currentVP);
    }
    
    // Check VirtualProtectEx
    void* currentVPEx = GetApiAddress("kernel32.dll", "VirtualProtectEx");
    if (currentVPEx && m_originalVirtualProtectEx && currentVPEx != m_originalVirtualProtectEx) {
        ApiHookInfo hook = {};
        hook.apiName = "VirtualProtectEx";
        hook.expectedAddress = m_originalVirtualProtectEx;
        hook.actualAddress = currentVPEx;
        hook.isHooked = true;
        hook.detectionTime = now;
        m_apiHooks.push_back(hook);
        
        LOG_WARNING_FMT("MemoryIntegrity: VirtualProtectEx hooked! (expected: 0x%p, actual: 0x%p)",
                       m_originalVirtualProtectEx, currentVPEx);
    }
    
    // Check VirtualAlloc
    void* currentVA = GetApiAddress("kernel32.dll", "VirtualAlloc");
    if (currentVA && m_originalVirtualAlloc && currentVA != m_originalVirtualAlloc) {
        ApiHookInfo hook = {};
        hook.apiName = "VirtualAlloc";
        hook.expectedAddress = m_originalVirtualAlloc;
        hook.actualAddress = currentVA;
        hook.isHooked = true;
        hook.detectionTime = now;
        m_apiHooks.push_back(hook);
        
        LOG_WARNING_FMT("MemoryIntegrity: VirtualAlloc hooked! (expected: 0x%p, actual: 0x%p)",
                       m_originalVirtualAlloc, currentVA);
    }
    
    // Check VirtualAllocEx
    void* currentVAEx = GetApiAddress("kernel32.dll", "VirtualAllocEx");
    if (currentVAEx && m_originalVirtualAllocEx && currentVAEx != m_originalVirtualAllocEx) {
        ApiHookInfo hook = {};
        hook.apiName = "VirtualAllocEx";
        hook.expectedAddress = m_originalVirtualAllocEx;
        hook.actualAddress = currentVAEx;
        hook.isHooked = true;
        hook.detectionTime = now;
        m_apiHooks.push_back(hook);
        
        LOG_WARNING_FMT("MemoryIntegrity: VirtualAllocEx hooked! (expected: 0x%p, actual: 0x%p)",
                       m_originalVirtualAllocEx, currentVAEx);
    }
}

void* MemoryIntegrity::GetApiAddress(const char* moduleName, const char* functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) return nullptr;
    
    return GetProcAddress(hModule, functionName);
}

DWORD WINAPI MemoryIntegrity::MonitorThreadProc(LPVOID param) {
    MemoryIntegrity* pThis = static_cast<MemoryIntegrity*>(param);
    
    LOG_INFO("MemoryIntegrity: Monitor thread started");
    
    while (!pThis->m_shouldStop) {
        // Verify integrity
        pThis->VerifyIntegrity();
        
        // Check page protection
        pThis->CheckPageProtection();
        
        // Detect API hooks
        if (pThis->m_enableApiHookDetection) {
            pThis->DetectApiHooks();
        }
        
        // Sleep for configured interval
        DWORD sleepTime = pThis->m_checkIntervalMs;
        DWORD elapsed = 0;
        while (elapsed < sleepTime && !pThis->m_shouldStop) {
            Sleep(100);
            elapsed += 100;
        }
    }
    
    LOG_INFO("MemoryIntegrity: Monitor thread stopped");
    return 0;
}
