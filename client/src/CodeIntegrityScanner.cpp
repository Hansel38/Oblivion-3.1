#include "../pch.h"
#include "../include/CodeIntegrityScanner.h"
#include "../include/JsonBuilder.h"
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <cmath>

#pragma comment(lib, "psapi.lib")

// Extended structures for VAD walking
typedef struct _MEMORY_REGION_INFORMATION {
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG RegionType;
    SIZE_T RegionSize;
} MEMORY_REGION_INFORMATION, *PMEMORY_REGION_INFORMATION;

CodeIntegrityScanner::CodeIntegrityScanner() {}

// Minimal helpers we can use without private APIs. This is not true VAD-walk, but covers practical checks:
// - Enumerate loaded modules and hash .text sections; flag drift.
// - QueryVirtualMemory to find RX/RWX private regions and scan for suspicious bytes (e.g., low entropy shellcode stub).
// - EAT/inline hook: compare first bytes of exported functions to on-disk image mapping and check trampolines/foreign targets.
// SSDT check requires kernel; we will skip or use KernelBridge in future.

static DWORD RvaToOffset(PBYTE base, DWORD rva)
{
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i=0; i<nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD va = sec->VirtualAddress; DWORD sz = sec->Misc.VirtualSize;
        if (rva >= va && rva < va + sz) return (rva - va) + sec->PointerToRawData;
    }
    return 0;
}

static bool HashBuffer(const BYTE* data, size_t len, DWORD& out)
{
    // Very light FNV-1a to avoid CryptoAPI overhead
    const DWORD FNV_PRIME = 16777619u; DWORD h = 2166136261u;
    for (size_t i=0;i<len;++i) { h ^= data[i]; h *= FNV_PRIME; }
    out = h; return true;
}

static std::wstring GetModulePath(HMODULE m)
{
    wchar_t path[MAX_PATH] = {0}; GetModuleFileNameW(m, path, MAX_PATH);
    return path;
}

static bool IsSystemPath(const std::wstring& path)
{
    std::wstring low = path; std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    return low.find(L"\\windows\\system32\\") != std::wstring::npos || low.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

bool CodeIntegrityScanner::IsWhitelistedPath(const std::wstring& path) const
{
    std::wstring low = path; std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    if (IsSystemPath(low)) return true;
    for (auto& p : m_whitelist) {
        std::wstring pl = p; std::transform(pl.begin(), pl.end(), pl.begin(), ::towlower);
        if (!pl.empty() && (low == pl || low.rfind(pl, 0) == 0)) return true;
    }
    return false;
}

static bool MapFileImage(const std::wstring& path, std::unique_ptr<BYTE[]>& outBuf, size_t& outSize)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    HANDLE mm = CreateFileMappingW(h, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(h);
    if (!mm) return false;
    PBYTE view = (PBYTE)MapViewOfFile(mm, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(mm);
    if (!view) return false;
    // Copy to private buffer so we can unmap
    auto dos = (PIMAGE_DOS_HEADER)view;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) { UnmapViewOfFile(view); return false; }
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)view + dos->e_lfanew);
    size_t sz = nt->OptionalHeader.SizeOfImage;
    std::unique_ptr<BYTE[]> buf(new BYTE[sz]);
    memcpy(buf.get(), view, sz);
    UnmapViewOfFile(view);
    outBuf = std::move(buf); outSize = sz; return true;
}

static bool HashModuleText(HMODULE mod, DWORD& outHash)
{
    PBYTE base = (PBYTE)mod;
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i=0;i<nt->FileHeader.NumberOfSections;++i,++sec) {
        char name[9] = {0}; memcpy(name, sec->Name, 8);
        if (strcmp(name, ".text") == 0) {
            PBYTE ptr = base + sec->VirtualAddress; DWORD sz = sec->Misc.VirtualSize;
            return HashBuffer(ptr, sz, outHash);
        }
    }
    return false;
}

static bool GetModuleRange(HMODULE mod, PBYTE& start, PBYTE& end)
{
    if (!mod) return false;
    PBYTE base = (PBYTE)mod;
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    start = base; end = base + nt->OptionalHeader.SizeOfImage; return true;
}

static HMODULE FindOwnerModule(void* addr)
{
    HMODULE mods[1024]; DWORD needed=0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        size_t count = needed/sizeof(HMODULE); PBYTE p = (PBYTE)addr;
        for (size_t i=0;i<count;++i) {
            PBYTE s=nullptr,e=nullptr; if (GetModuleRange(mods[i], s, e)) { if (p>=s && p<e) return mods[i]; }
        }
    }
    return nullptr;
}

static bool IsTrampolineOpcode(const BYTE* p)
{
    if (!p) return false;
    // jmp rel32 (E9), call rel32 (E8), jmp [rip+imm] (FF 25), push imm; ret (68 xx xx xx xx C3)
    if (p[0] == 0xE9 || p[0] == 0xE8) return true;
    if (p[0] == 0xFF && p[1] == 0x25) return true;
    if (p[0] == 0x68 && p[5] == 0xC3) return true;
    return false;
}

static bool CompareExportEntry(HMODULE mod, const std::wstring& path, const char* name, bool& drift, bool& foreignTarget)
{
    drift = false; foreignTarget = false;
    PBYTE mem = (PBYTE)mod;
    std::unique_ptr<BYTE[]> imgBuf; size_t imgSz=0;
    if (!MapFileImage(path, imgBuf, imgSz)) return false;
    PBYTE img = imgBuf.get();

    auto dosM = (PIMAGE_DOS_HEADER)mem; auto ntM = (PIMAGE_NT_HEADERS)(mem + dosM->e_lfanew);
    auto expM = (PIMAGE_EXPORT_DIRECTORY)(mem + ntM->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto dosF = (PIMAGE_DOS_HEADER)img; auto ntF = (PIMAGE_NT_HEADERS)(img + dosF->e_lfanew);
    auto expF = (PIMAGE_EXPORT_DIRECTORY)(img + ntF->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!expM || !expF) return false;

    DWORD* namesM = (DWORD*)(mem + expM->AddressOfNames);
    WORD* ordsM = (WORD*)(mem + expM->AddressOfNameOrdinals);
    DWORD* funcsM = (DWORD*)(mem + expM->AddressOfFunctions);

    DWORD* namesF = (DWORD*)(img + expF->AddressOfNames);
    WORD* ordsF = (WORD*)(img + expF->AddressOfNameOrdinals);
    DWORD* funcsF = (DWORD*)(img + expF->AddressOfFunctions);

    // Locate export by name in file image
    for (DWORD i=0;i<expF->NumberOfNames;++i) {
        const char* nmF = (const char*)(img + namesF[i]);
        if (nmF && _stricmp(nmF, name) == 0) {
            WORD ordF = ordsF[i]; DWORD rvaF = funcsF[ordF]; PBYTE fnFile = img + rvaF;
            // Now find matching in memory exports
            for (DWORD j=0;j<expM->NumberOfNames;++j) {
                const char* nmM = (const char*)(mem + namesM[j]);
                if (nmM && _stricmp(nmM, name) == 0) {
                    WORD ordM = ordsM[j]; DWORD rvaM = funcsM[ordM]; PBYTE fnMem = mem + rvaM;
                    // Compare first 16 bytes for inline hook drift
                    if (memcmp(fnMem, fnFile, 16) != 0) drift = true;
                    // Foreign target check: first bytes a hard trampoline and target belongs to another module
                    if (IsTrampolineOpcode(fnMem)) {
                        HMODULE owner = FindOwnerModule(fnMem);
                        if (owner && owner != mod) foreignTarget = true;
                    }
                    return true;
                }
            }
            return false;
        }
    }
    return false;
}

static double EstimateEntropySample(const BYTE* data, size_t len)
{
    if (!data || len == 0) return 0.0;
    unsigned counts[256] = {0};
    for (size_t i=0;i<len;++i) counts[data[i]]++;
    double H = 0.0; double inv = 1.0 / (double)len;
    for (int i=0;i<256;++i) if (counts[i]) { double p = counts[i] * inv; H -= p * log2(p); }
    return H; // max 8
}

static bool DetectProcessHollowing(HMODULE mainModule, std::wstring& reason)
{
    // Process hollowing detection: Compare PEB ImageBaseAddress with actual module base
    // Get PEB via NtQueryInformationProcess
    typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1[2];
        PVOID PebBaseAddress;
        PVOID Reserved2[4];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;
    
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return false;
    
    auto NtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNt, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return false;
    
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG retLen = 0;
    if (NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen) != 0) 
        return false;
    
    if (!pbi.PebBaseAddress) return false;
    
    __try {
        // Read ImageBaseAddress from PEB (offset 0x10 on x64, 0x8 on x86)
#ifdef _M_X64
        PVOID* pImageBase = (PVOID*)((BYTE*)pbi.PebBaseAddress + 0x10);
#else
        PVOID* pImageBase = (PVOID*)((BYTE*)pbi.PebBaseAddress + 0x8);
#endif
        PVOID pebImageBase = *pImageBase;
        
        // Compare with actual main module base
        if (pebImageBase != (PVOID)mainModule) {
            reason = L"PEB ImageBase mismatch (process hollowing)";
            return true;
        }
        
        // Additional check: Verify PE header integrity
        auto dos = (IMAGE_DOS_HEADER*)mainModule;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            reason = L"Invalid DOS signature (hollowed)";
            return true;
        }
        
        auto nt = (IMAGE_NT_HEADERS*)((BYTE*)mainModule + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            reason = L"Invalid NT signature (hollowed)";
            return true;
        }
        
        // Check if entry point is within image
        DWORD entryRva = nt->OptionalHeader.AddressOfEntryPoint;
        DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        if (entryRva >= imageSize) {
            reason = L"Entry point outside image (hollowed)";
            return true;
        }
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        reason = L"Exception accessing PEB (hollowing)";
        return true;
    }
    
    return false;
}

static bool ScanForROPChain(BYTE* region, SIZE_T size, int& gadgetCount)
{
    // Simple ROP chain detection: count RET/POP gadgets
    gadgetCount = 0;
    const SIZE_T maxScan = std::min<SIZE_T>(size, 0x10000); // Limit scan to 64KB
    
    __try {
        for (SIZE_T i = 0; i < maxScan; ++i) {
            // RET (C3, C2 xx xx)
            if (region[i] == 0xC3) {
                gadgetCount++;
            } else if (region[i] == 0xC2 && i + 2 < maxScan) {
                gadgetCount++;
                i += 2;
            }
            // POP reg (58-5F for x86/x64)
            else if (region[i] >= 0x58 && region[i] <= 0x5F) {
                gadgetCount++;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    
    // High density of gadgets is suspicious (>100 in 64KB)
    return gadgetCount > 100;
}

static bool EnumerateVADs(std::vector<MEMORY_REGION_INFORMATION>& regions)
{
    // True VAD walk using VirtualQuery
    SYSTEM_INFO si = {0};
    GetSystemInfo(&si);
    
    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* maxAddr = (BYTE*)si.lpMaximumApplicationAddress;
    
    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) 
            break;
        
        if (mbi.State == MEM_COMMIT) {
            MEMORY_REGION_INFORMATION mri = {0};
            mri.AllocationBase = mbi.AllocationBase;
            mri.AllocationProtect = mbi.AllocationProtect;
            mri.RegionType = mbi.Type;
            mri.RegionSize = mbi.RegionSize;
            regions.push_back(mri);
        }
        
        addr += mbi.RegionSize;
    }
    
    return !regions.empty();
}

static bool WcsEndsWithInsensitive(const std::wstring& s, const std::wstring& suf)
{
    if (s.size() < suf.size()) return false;
    for (size_t i=0;i<suf.size();++i) {
        wchar_t a = towlower(s[s.size()-suf.size()+i]); wchar_t b = towlower(suf[i]); if (a != b) return false;
    }
    return true;
}

bool CodeIntegrityScanner::RunOnceScan(DetectionResult& out)
{
    out.detected = false; out.pid = GetCurrentProcessId(); out.processName = L""; out.reason = L""; out.indicatorCount = 0;

    // 0) Check for process hollowing
    HMODULE mainModule = GetModuleHandleW(nullptr);
    if (mainModule) {
        std::wstring hollowReason;
        if (DetectProcessHollowing(mainModule, hollowReason)) {
            out.detected = true;
            out.processName = L"<main>";
            out.reason = hollowReason;
            out.indicatorCount += 5; // Very high score for hollowing
        }
    }

    // 1) Enumerate modules and hash .text; compare with on-disk image mapping
    HMODULE mods[1024]; DWORD needed=0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i=0;i<count;++i) {
            HMODULE m = mods[i];
            wchar_t path[MAX_PATH]; if (!GetModuleFileNameExW(GetCurrentProcess(), m, path, MAX_PATH)) continue;
            if (IsWhitelistedPath(path)) continue;

            DWORD memHash=0; if (HashModuleText(m, memHash)) {
                std::unique_ptr<BYTE[]> img; size_t imgSz=0;
                if (MapFileImage(path, img, imgSz)) {
                    // Hash .text from file image
                    PBYTE base = img.get(); auto dos = (PIMAGE_DOS_HEADER)base; auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
                    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt); DWORD fileHash=0; bool gotFile=false;
                    for (UINT s=0;s<nt->FileHeader.NumberOfSections;++s,++sec) {
                        char name[9] = {0}; memcpy(name, sec->Name, 8);
                        if (strcmp(name, ".text") == 0) { HashBuffer(base + sec->VirtualAddress, sec->Misc.VirtualSize, fileHash); gotFile=true; break; }
                    }
                    if (gotFile && fileHash != memHash) {
                        out.detected = true; out.processName = path; if(!out.reason.empty()) out.reason += L"; "; out.reason += L".text drift from on-disk image"; out.indicatorCount++;
                    }
                }
            }

            // Inline hook quick check for selected sensitive APIs in this module
            static const char* kNames[] = {
                "NtOpenProcess","NtReadVirtualMemory","NtWriteVirtualMemory","NtCreateThreadEx","CreateRemoteThread","VirtualProtect","VirtualProtectEx"};
            for (const char* nm : kNames) {
                bool drift=false, foreign=false; if (CompareExportEntry(m, path, nm, drift, foreign)) {
                    if (drift || foreign) {
                        out.detected = true; if (!out.processName.size()) out.processName = path;
                        if (!out.reason.empty()) out.reason += L"; ";
                        out.reason += L"Export hook: "; out.reason += std::wstring(nm, nm + strlen(nm));
                        if (foreign) out.reason += L" -> trampoline/foreign"; else out.reason += L" prologue mismatch";
                        out.indicatorCount++;
                    }
                }
            }
        }

        // ntdll syscall stub verification (userland)
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            std::wstring ntdllPath = GetModulePath(hNtdll);
            static const char* kNtStubs[] = {"NtOpenProcess","NtReadVirtualMemory","NtWriteVirtualMemory","NtCreateThreadEx","NtProtectVirtualMemory"};
            for (const char* nm : kNtStubs) {
                bool drift=false, foreign=false; if (CompareExportEntry(hNtdll, ntdllPath, nm, drift, foreign)) {
                    // Only flag if drift and target is not within ntdll itself
                    if (drift || foreign || IsTrampolineOpcode((BYTE*)GetProcAddress(hNtdll, nm))) {
                        out.detected = true; if (!out.processName.size()) out.processName = L"ntdll.dll";
                        if (!out.reason.empty()) out.reason += L"; "; out.reason += L"NTDLL stub drift: "; out.reason += std::wstring(nm, nm + strlen(nm)); out.indicatorCount++;
                    }
                }
            }
        }
    }

    // 2) True VAD walk - enumerate all committed memory regions
    std::vector<MEMORY_REGION_INFORMATION> vads;
    if (EnumerateVADs(vads)) {
        for (const auto& vad : vads) {
            // Check for suspicious RWX private regions
            bool isPrivate = (vad.RegionType == MEM_PRIVATE);
            bool isRWX = (vad.AllocationProtect & PAGE_EXECUTE_READWRITE) != 0;
            
            if (isPrivate && isRWX && vad.RegionSize >= 0x1000) {
                // Scan for ROP chain patterns
                int gadgetCount = 0;
                if (ScanForROPChain((BYTE*)vad.AllocationBase, vad.RegionSize, gadgetCount)) {
                    out.detected = true;
                    wchar_t buf[128];
                    swprintf_s(buf, L"ROP chain detected at 0x%p (%d gadgets)", vad.AllocationBase, gadgetCount);
                    if (!out.reason.empty()) out.reason += L"; ";
                    out.reason += buf;
                    out.indicatorCount += 2;
                }
                
                // High entropy check for shellcode
                if (vad.RegionSize >= 512) {
                    double H = EstimateEntropySample((BYTE*)vad.AllocationBase, 
                                                     std::min<SIZE_T>(vad.RegionSize, 4096));
                    if (H > 6.5) { // High entropy shellcode
                        out.detected = true;
                        wchar_t buf[128];
                        swprintf_s(buf, L"High-entropy RWX region at 0x%p (H=%.2f)", vad.AllocationBase, H);
                        if (!out.reason.empty()) out.reason += L"; ";
                        out.reason += buf;
                        out.indicatorCount += 2;
                    }
                }
            }
            
            // Check for execute-only private regions (very suspicious)
            bool isExecuteOnly = (vad.AllocationProtect & PAGE_EXECUTE) && 
                               !(vad.AllocationProtect & (PAGE_READWRITE | PAGE_READONLY));
            if (isPrivate && isExecuteOnly && vad.RegionSize >= 0x1000) {
                out.detected = true;
                wchar_t buf[128];
                swprintf_s(buf, L"Execute-only private region at 0x%p", vad.AllocationBase);
                if (!out.reason.empty()) out.reason += L"; ";
                out.reason += buf;
                out.indicatorCount += 3;
            }
        }
    }

    // 3) Legacy walk for additional coverage (kept for compatibility)
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    BYTE* p = (BYTE*)si.lpMinimumApplicationAddress; BYTE* maxp = (BYTE*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi{};
    int rxCount = 0, rwxCount = 0;
    while (p < maxp) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        bool isPrivate = (mbi.Type == MEM_PRIVATE);
        bool rx = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool rwx = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
        if (isPrivate && rx && mbi.State == MEM_COMMIT && mbi.RegionSize >= 0x2000) { // require >=8KB
            ++rxCount; if (rwx) ++rwxCount;
            // sample first 512 bytes if readable
            if (mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY)) {
                size_t sample = (size_t)std::min<ULONG_PTR>(mbi.RegionSize, 512);
                double H = EstimateEntropySample(p, sample);
                if (H < 2.5) { // lower sensitivity
                    out.detected = true; wchar_t buf[64]; swprintf_s(buf, L"0x%p", p);
                    if (!out.reason.empty()) out.reason += L"; "; out.reason += L"Low-entropy RX private region at "; out.reason += buf; out.indicatorCount++;
                }
            } else {
                out.detected = true; wchar_t buf[64]; swprintf_s(buf, L"0x%p", p);
                if (!out.reason.empty()) out.reason += L"; "; out.reason += L"Execute-only private region at "; out.reason += buf; out.indicatorCount++;
            }
        }
        p += mbi.RegionSize;
    }

    if (!out.reason.empty() && out.processName.empty()) out.processName = L"<current>";
    return out.detected && out.indicatorCount >= m_threshold;
}
