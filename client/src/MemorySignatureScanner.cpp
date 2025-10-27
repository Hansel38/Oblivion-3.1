#include "../pch.h"
#include "MemorySignatureScanner.h"
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

static bool IsReadable(const MEMORY_BASIC_INFORMATION& mbi)
{
    if (!(mbi.State & MEM_COMMIT)) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

static inline bool MatchByte(unsigned char v, unsigned char pat, unsigned char mask)
{
    if (mask == 0x00) return true;        // wildcard
    if (mask == 0xFF) return v == pat;    // exact
    if (mask == 0xF0) return (v & 0xF0) == (pat & 0xF0); // high nibble match
    if (mask == 0x0F) return (v & 0x0F) == (pat & 0x0F); // low nibble match
    // default: masked equality
    return (v & mask) == (pat & mask);
}

bool MemorySignatureScanner::MatchAt(BYTE* p, SIZE_T size, const MemSigPattern& pat) const
{
    if (size < pat.bytes.size()) return false;
    for (size_t i=0;i<pat.bytes.size();++i) {
        if (!MatchByte(p[i], pat.bytes[i], pat.mask[i])) return false;
    }
    return true;
}

bool MemorySignatureScanner::ScanRegion(BYTE* base, SIZE_T size, const std::wstring* regionModule, MemorySignatureFinding& outFinding, int& score)
{
    for (SIZE_T i=0;i<size; ++i) {
        for (const auto& pat : m_patterns) {
            if (MatchAt(base + i, size - i, pat)) {
                score += pat.weight;
                outFinding.address = base + i;
                outFinding.patternName = std::wstring(pat.name.begin(), pat.name.end());
                if (regionModule) outFinding.moduleName = *regionModule;
                if (score >= m_threshold) return true;
            }
        }
    }
    return false;
}

bool MemorySignatureScanner::RunOnceScan(MemorySignatureFinding& outFinding)
{
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* end  = (BYTE*)si.lpMaximumApplicationAddress;
    int score = 0;

    HMODULE hMods[1024]; DWORD cbNeeded=0;
    std::vector<std::pair<void*, std::wstring>> modules;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        size_t cnt = cbNeeded/sizeof(HMODULE);
        wchar_t path[MAX_PATH];
        for (size_t i=0;i<cnt;++i) {
            if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], path, MAX_PATH)) {
                modules.emplace_back((void*)hMods[i], std::wstring(path));
            }
        }
    }

    auto moduleOf = [&](void* p)->const std::wstring*{
        for (auto& m : modules) {
            auto base = (BYTE*)m.first;
            // naive: check within first module range using headers; fallback to nullptr
            __try {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
                SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
                if ((BYTE*)p >= base && (BYTE*)p < base + imageSize) return &m.second;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
        return nullptr;
    };

    auto allowedModule = [&](const std::wstring* mod)->bool{
        if (!mod) return m_modulePrefixes.empty();
        if (m_modulePrefixes.empty()) return true;
        for (auto& pre : m_modulePrefixes) {
            if (mod->size() >= pre.size() && _wcsnicmp(mod->c_str(), pre.c_str(), pre.size()) == 0) return true;
        }
        return false;
    };

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (IsReadable(mbi)) {
            bool isImage = (mbi.Type & MEM_IMAGE) != 0;
            const std::wstring* modName = nullptr;
            if (isImage) modName = moduleOf(mbi.BaseAddress);
            if (m_imagesOnly && !isImage) {
                // skip non-image regions
            } else {
                if (allowedModule(modName)) {
                    if (ScanRegion((BYTE*)mbi.BaseAddress, mbi.RegionSize, modName, outFinding, score)) {
                        outFinding.indicators = score;
                        return true;
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }
    return false;
}
