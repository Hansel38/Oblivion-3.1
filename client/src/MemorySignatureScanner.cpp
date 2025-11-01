#include "../pch.h"
#include "MemorySignatureScanner.h"
#include <psapi.h>
#include <cmath>

#pragma comment(lib, "psapi.lib")

// Calculate Shannon entropy for shellcode detection
static float CalculateEntropy(const BYTE* data, SIZE_T len)
{
    if (!data || len == 0) return 0.0f;
    
    int freq[256] = {0};
    for (SIZE_T i = 0; i < len; ++i) {
        freq[data[i]]++;
    }
    
    float H = 0.0f;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / (float)len;
            H -= p * log2f(p);
        }
    }
    
    return H; // Returns 0-8, shellcode typically > 5.5
}

// Detect ROP chain by counting gadgets
static bool DetectRopChain(const BYTE* region, SIZE_T size, int& gadgetCount)
{
    gadgetCount = 0;
    const SIZE_T maxScan = (size > 0x10000) ? 0x10000 : size; // Limit to 64KB
    
    __try {
        for (SIZE_T i = 0; i < maxScan - 1; ++i) {
            // RET instructions (C3, C2 xx xx)
            if (region[i] == 0xC3) {
                gadgetCount++;
            } else if (region[i] == 0xC2 && i + 2 < maxScan) {
                gadgetCount++;
                i += 2;
            }
            // POP reg (58-5F)
            else if (region[i] >= 0x58 && region[i] <= 0x5F) {
                gadgetCount++;
            }
            // Short conditional jumps (common in ROP)
            else if (region[i] >= 0x70 && region[i] <= 0x7F) {
                gadgetCount++;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    
    // High density of gadgets (>150 per 64KB) is very suspicious
    float density = (float)gadgetCount / (float)maxScan;
    return density > 0.0023f; // ~150/64K
}

// Detect polymorphic/metamorphic patterns
static bool DetectPolymorphicCode(const BYTE* data, SIZE_T len)
{
    if (len < 100) return false;
    
    __try {
        // Count instruction prefixes and NOPs (common in polymorphic engines)
        int nopCount = 0;
        int prefixCount = 0;
        int xorCount = 0;
        
        for (SIZE_T i = 0; i < len - 2; ++i) {
            // NOP variations
            if (data[i] == 0x90) nopCount++;
            
            // Instruction prefixes (66, 67, F2, F3, etc.)
            if (data[i] == 0x66 || data[i] == 0x67 || 
                data[i] == 0xF2 || data[i] == 0xF3) {
                prefixCount++;
            }
            
            // XOR patterns (common in decoders)
            if (data[i] == 0x31 || data[i] == 0x33) { // XOR r/m32, r32
                xorCount++;
            }
        }
        
        // High ratio of NOPs/prefixes/XORs indicates polymorphic code
        float nopRatio = (float)nopCount / (float)len;
        float prefixRatio = (float)prefixCount / (float)len;
        float xorRatio = (float)xorCount / (float)len;
        
        return (nopRatio > 0.1f) || (prefixRatio > 0.05f) || (xorRatio > 0.05f);
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

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
    // Perform signature matching
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
    
    // Advanced heuristics for pattern-less detection
    SIZE_T sampleSize = (size > 4096) ? 4096 : size;
    
    // Entropy analysis
    float entropy = CalculateEntropy(base, sampleSize);
    if (entropy > 6.5f) { // High entropy shellcode
        score += 2;
        outFinding.address = base;
        outFinding.patternName = L"High-entropy shellcode";
        if (regionModule) outFinding.moduleName = *regionModule;
        if (score >= m_threshold) return true;
    }
    
    // ROP chain detection
    int gadgetCount = 0;
    if (DetectRopChain(base, size, gadgetCount)) {
        score += 3;
        outFinding.address = base;
        wchar_t buf[128];
        swprintf_s(buf, L"ROP chain (%d gadgets)", gadgetCount);
        outFinding.patternName = buf;
        if (regionModule) outFinding.moduleName = *regionModule;
        if (score >= m_threshold) return true;
    }
    
    // Polymorphic code detection
    if (DetectPolymorphicCode(base, sampleSize)) {
        score += 2;
        outFinding.address = base;
        outFinding.patternName = L"Polymorphic code patterns";
        if (regionModule) outFinding.moduleName = *regionModule;
        if (score >= m_threshold) return true;
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
