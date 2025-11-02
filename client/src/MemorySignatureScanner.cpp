#include "../pch.h"
#include "MemorySignatureScanner.h"
#include <psapi.h>
#include <cmath>
#include <vector>
#include <map>
#include "../include/SimdUtils.h"

#pragma comment(lib, "psapi.lib")

// Entropy calculation moved to SimdUtils::ComputeEntropyShannon

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

// ===== PRIORITY 2.1.1: CODE CAVE PATTERN DETECTION =====
// Detect code cave patterns commonly used by CE auto-assembler
static bool DetectCodeCavePattern(const BYTE* data, SIZE_T len, int& outScore)
{
    if (len < 32) return false;
    outScore = 0;
    
    __try {
        // Check for NOP sled pattern (common in code caves)
        int nopSledCount = 0;
        int maxConsecNops = 0;
        int consecNops = 0;
        
        for (SIZE_T i = 0; i < len && i < 512; ++i) {
            if (data[i] == 0x90) { // NOP
                consecNops++;
                nopSledCount++;
                if (consecNops > maxConsecNops) maxConsecNops = consecNops;
            } else {
                consecNops = 0;
            }
        }
        
        // NOP sled of 8+ consecutive NOPs is highly suspicious
        if (maxConsecNops >= 8) outScore += 3;
        else if (maxConsecNops >= 4) outScore += 1;
        
        // Check for common CE auto-assembler patterns
        // Pattern 1: PUSHAD (60) + code + POPAD (61) + JMP/RET
        for (SIZE_T i = 0; i < len - 16; ++i) {
            if (data[i] == 0x60) { // PUSHAD
                for (SIZE_T j = i + 1; j < i + 256 && j < len - 1; ++j) {
                    if (data[j] == 0x61) { // POPAD
                        // Check if followed by JMP or RET
                        if (j + 1 < len && (data[j+1] == 0xC3 || data[j+1] == 0xE9 || data[j+1] == 0xEB)) {
                            outScore += 4; // Very characteristic of CE injection
                            break;
                        }
                    }
                }
            }
        }
        
        // Pattern 2: MOV [address], immediate followed by JMP back
        // Common in CE value-write scripts: MOV DWORD PTR [xxxxxxxx], value
        int movMemImmCount = 0;
        for (SIZE_T i = 0; i < len - 10; ++i) {
            // C7 05 [addr32] [imm32] - MOV DWORD PTR [addr], imm
            if (data[i] == 0xC7 && data[i+1] == 0x05) {
                movMemImmCount++;
            }
            // C6 05 [addr32] [imm8] - MOV BYTE PTR [addr], imm
            else if (data[i] == 0xC6 && data[i+1] == 0x05) {
                movMemImmCount++;
            }
        }
        if (movMemImmCount >= 3) outScore += 2;
        
        // Pattern 3: CALL + POP (GetEIP technique used in position-independent code)
        for (SIZE_T i = 0; i < len - 6; ++i) {
            // E8 00 00 00 00 (CALL $+5) followed by POP reg
            if (data[i] == 0xE8 && data[i+1] == 0x00 && data[i+2] == 0x00 && 
                data[i+3] == 0x00 && data[i+4] == 0x00 && 
                data[i+5] >= 0x58 && data[i+5] <= 0x5F) {
                outScore += 3; // GetEIP technique
            }
        }
        
        // Pattern 4: High density of direct memory operations
        int directMemOps = 0;
        for (SIZE_T i = 0; i < len - 8; ++i) {
            // A1 [addr32] - MOV EAX, [addr]
            // A3 [addr32] - MOV [addr], EAX
            if (data[i] == 0xA1 || data[i] == 0xA3) directMemOps++;
        }
        if (directMemOps >= 5) outScore += 2;
        
        return outScore > 0;
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ===== PRIORITY 2.1.2: AOB (ARRAY OF BYTES) INJECTION DETECTION =====
// Detect AOB injection patterns from CE scripts
static bool DetectAOBInjectionPattern(const BYTE* data, SIZE_T len, int& outScore)
{
    if (len < 16) return false;
    outScore = 0;
    
    __try {
        // AOB injections often have specific characteristics:
        // 1. High instruction density without proper PE structure
        // 2. Unusual instruction sequences
        // 3. Lack of typical function prologue/epilogue patterns
        
        // Check for executable code without PE header
        bool hasPEHeader = false;
        if (len >= 2 && data[0] == 0x4D && data[1] == 0x5A) { // MZ header
            hasPEHeader = true;
        }
        
        if (!hasPEHeader && len >= 64) {
            // Count valid x86/x64 instruction opcodes
            int validInstructions = 0;
            int totalBytes = 0;
            
            for (SIZE_T i = 0; i < len && i < 256; ++i) {
                // Common instruction opcodes
                BYTE op = data[i];
                
                // MOV instructions (88-8C, A0-A3, B0-BF, C6-C7)
                if ((op >= 0x88 && op <= 0x8C) || (op >= 0xA0 && op <= 0xA3) ||
                    (op >= 0xB0 && op <= 0xBF) || op == 0xC6 || op == 0xC7) {
                    validInstructions++;
                }
                // PUSH/POP (50-5F)
                else if (op >= 0x50 && op <= 0x5F) {
                    validInstructions++;
                }
                // JMP/CALL (E8-E9, EB)
                else if (op == 0xE8 || op == 0xE9 || op == 0xEB) {
                    validInstructions++;
                }
                // ADD/SUB/XOR/CMP (00-05, 28-2D, 30-35, 38-3D)
                else if ((op >= 0x00 && op <= 0x05) || (op >= 0x28 && op <= 0x2D) ||
                         (op >= 0x30 && op <= 0x35) || (op >= 0x38 && op <= 0x3D)) {
                    validInstructions++;
                }
                // TEST/LEA (84-85, 8D)
                else if (op == 0x84 || op == 0x85 || op == 0x8D) {
                    validInstructions++;
                }
                
                totalBytes++;
            }
            
            // High instruction density (>40%) without PE header suggests AOB injection
            float instructionDensity = (float)validInstructions / (float)totalBytes;
            if (instructionDensity > 0.4f) outScore += 3;
            else if (instructionDensity > 0.25f) outScore += 1;
        }
        
        // CE-specific pattern: alternating code and data sections
        // Look for patterns like: code bytes + data bytes + code bytes
        int codeDataTransitions = 0;
        bool inCodeSection = false;
        int consecCodeBytes = 0;
        int consecDataBytes = 0;
        
        for (SIZE_T i = 0; i < len && i < 512; ++i) {
            BYTE b = data[i];
            bool isLikelyCode = (b >= 0x50 && b <= 0x5F) || // PUSH/POP
                                (b == 0xE8 || b == 0xE9) || // CALL/JMP
                                (b >= 0x88 && b <= 0x8C);   // MOV variations
            
            if (isLikelyCode) {
                consecCodeBytes++;
                if (consecDataBytes >= 8 && !inCodeSection) {
                    codeDataTransitions++;
                    inCodeSection = true;
                }
                consecDataBytes = 0;
            } else {
                consecDataBytes++;
                if (consecCodeBytes >= 8 && inCodeSection) {
                    codeDataTransitions++;
                    inCodeSection = false;
                }
                consecCodeBytes = 0;
            }
        }
        
        if (codeDataTransitions >= 4) outScore += 2;
        
        // Pattern: Repeated identical instruction sequences (copy-paste injection)
        for (SIZE_T i = 0; i < len - 32; ++i) {
            for (SIZE_T j = i + 16; j < len - 16; ++j) {
                if (memcmp(data + i, data + j, 16) == 0) {
                    outScore += 1;
                    break; // Found one match is enough
                }
            }
        }
        
        return outScore > 0;
        
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
    const size_t len = pat.bytes.size();
    if (size < len) return false;
    if (m_enableSIMD && len >= 16) {
        // Fast path using SIMD masked compare
        return SimdMaskedCompare(p, pat.bytes.data(), pat.mask.data(), len);
    }
    // Fallback scalar compare
    for (size_t i=0;i<len;++i) {
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
    float entropy = ComputeEntropyShannon(base, sampleSize, m_enableSIMD);
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
    
    // ===== PRIORITY 2.1.1: Code Cave Detection =====
    int codeCaveScore = 0;
    if (DetectCodeCavePattern(base, size, codeCaveScore)) {
        score += codeCaveScore;
        outFinding.address = base;
        outFinding.patternName = L"CE Auto-Assembler Code Cave";
        if (regionModule) outFinding.moduleName = *regionModule;
        if (score >= m_threshold) return true;
    }
    
    // ===== PRIORITY 2.1.2: AOB Injection Detection =====
    int aobScore = 0;
    if (DetectAOBInjectionPattern(base, size, aobScore)) {
        score += aobScore;
        outFinding.address = base;
        outFinding.patternName = L"AOB (Array of Bytes) Injection";
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
            
            // ===== PRIORITY 2.1.1: Focus on potential code caves =====
            // Code caves: small executable regions without backing file
            bool isPotentialCodeCave = false;
            if (!isImage && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                // Executable non-image region
                SIZE_T regionSize = mbi.RegionSize;
                // Typical code caves are 4KB-64KB
                if (regionSize >= 0x1000 && regionSize <= 0x10000) {
                    isPotentialCodeCave = true;
                    // Boost score for suspicious protection
                    if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                        score += 2; // RWX is highly suspicious
                    }
                }
            }
            
            if (m_imagesOnly && !isImage && !isPotentialCodeCave) {
                // skip non-image regions unless they're potential code caves
            } else {
                if (allowedModule(modName) || isPotentialCodeCave) {
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

// Simple sequential memory scan pattern detection
static bool DetectSequentialMemoryScan(const std::vector<ULONGLONG>& accessAddresses, size_t minSequence = 10, size_t step = 4) {
    if (accessAddresses.size() < minSequence) return false;
    size_t count = 0;
    for (size_t i = 1; i < accessAddresses.size(); ++i) {
        if (accessAddresses[i] - accessAddresses[i-1] == step) {
            count++;
            if (count >= minSequence - 1) return true;
        } else {
            count = 0;
        }
    }
    return false;
}
// Untuk integrasi nyata, perlu hook pada ReadProcessMemory dan log alamat yang diakses, lalu panggil DetectSequentialMemoryScan.
