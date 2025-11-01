#include "../pch.h"
#include "HijackedThreadScanner.h"
#include <Psapi.h>
#include <algorithm>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

static std::wstring tolower_ws(const std::wstring& s) { std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

static bool IsSystemPathLower(const std::wstring& p)
{
    return p.find(L"\\windows\\system32\\") != std::wstring::npos || p.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

static bool IsReadableExecutable(const MEMORY_BASIC_INFORMATION& mbi)
{
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

HijackedThreadScanner::PFN_NtQueryInformationThread HijackedThreadScanner::ResolveNtQueryInformationThread()
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return nullptr;
    return (PFN_NtQueryInformationThread)GetProcAddress(hNt, "NtQueryInformationThread");
}

std::wstring HijackedThreadScanner::ModuleFromAddress(PVOID addr)
{
    HMODULE hMods[1024]; DWORD needed=0;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &needed)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i=0;i<count;++i) {
            MODULEINFO mi{}; if (!GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi))) continue;
            BYTE* base = (BYTE*)mi.lpBaseOfDll; SIZE_T size = mi.SizeOfImage;
            if ((BYTE*)addr >= base && (BYTE*)addr < base + size) {
                wchar_t path[MAX_PATH]{}; if (GetModuleFileNameW(hMods[i], path, MAX_PATH)) {
                    return tolower_ws(path);
                }
            }
        }
    }
    return L"";
}

bool HijackedThreadScanner::IsWhitelistedModule(const std::wstring& modulePathLower)
{
    if (m_whitelist.empty()) return false;
    for (const auto& p : m_whitelist) {
        std::wstring pl = tolower_ws(p);
        if (!pl.empty() && modulePathLower.rfind(pl, 0) == 0) return true;
    }
    return false;
}

bool HijackedThreadScanner::RunOnceScan(HijackedThreadFinding& out)
{
    out = HijackedThreadFinding{};

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    DWORD selfPid = GetCurrentProcessId();

    auto NtQueryInformationThread = ResolveNtQueryInformationThread();
    if (!NtQueryInformationThread) { CloseHandle(snap); return false; }

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            PVOID startAddr = nullptr; ULONG retLen = 0;
            // ThreadQuerySetWin32StartAddress = 9
            if (NtQueryInformationThread(hThread, 9, &startAddr, sizeof(startAddr), &retLen) == 0 /*STATUS_SUCCESS*/) {
                int score = 0;
                std::wstring mod = ModuleFromAddress(startAddr);
                if (mod.empty()) { score += 2; }
                else if (!IsWhitelistedModule(mod)) { score += 1; }
                // suspicious names boost
                if (mod.find(L"temp\\") != std::wstring::npos || mod.find(L"appdata\\") != std::wstring::npos) score += 1;

                // Analyze current RIP/EIP to detect APC/thread start hijack
                CONTEXT ctx{};
#ifdef _M_X64
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#else
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#endif
                DWORD prev = SuspendThread(hThread);
                if (prev != (DWORD)-1) {
                    if (GetThreadContext(hThread, &ctx)) {
#ifdef _M_X64
                        void* ip = (void*)ctx.Rip;
                        void* sp = (void*)ctx.Rsp;
#else
                        void* ip = (void*)ctx.Eip;
                        void* sp = (void*)ctx.Esp;
#endif
                        std::wstring ipMod = ModuleFromAddress(ip);
                        if (ipMod.empty()) {
                            // instruction pointer not within any module -> private shellcode or unmapped
                            score += 3;
                        } else {
                            // if IP module is not the same as thread start module, add suspicion
                            if (!mod.empty() && ipMod != tolower_ws(mod)) score += 1;
                            // non-system, non-whitelisted modules raise score
                            if (!IsWhitelistedModule(ipMod) && !IsSystemPathLower(ipMod)) score += 1;
                        }

                        // Check if IP points to RX private memory
                        MEMORY_BASIC_INFORMATION mbi{};
                        if (VirtualQuery(ip, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                            if ((mbi.Type == MEM_PRIVATE) && IsReadableExecutable(mbi)) {
                                score += 2; // likely injected code / APC shellcode
                            }
                        }

                        // Lightweight stack scan: walk a few frames and look for suspicious owners
                        // Initialize symbols once per process (best-effort)
                        static bool s_symInit = false;
                        if (!s_symInit) { SymInitialize(GetCurrentProcess(), NULL, TRUE); s_symInit = true; }

#ifdef _M_X64
                        DWORD machine = IMAGE_FILE_MACHINE_AMD64;
                        STACKFRAME64 sf{};
                        sf.AddrPC.Mode = AddrModeFlat;   sf.AddrPC.Offset = (DWORD64)ctx.Rip;
                        sf.AddrStack.Mode = AddrModeFlat; sf.AddrStack.Offset = (DWORD64)ctx.Rsp;
                        sf.AddrFrame.Mode = AddrModeFlat; sf.AddrFrame.Offset = (DWORD64)ctx.Rbp;
#else
                        DWORD machine = IMAGE_FILE_MACHINE_I386;
                        STACKFRAME64 sf{};
                        sf.AddrPC.Mode = AddrModeFlat;   sf.AddrPC.Offset = (DWORD64)ctx.Eip;
                        sf.AddrStack.Mode = AddrModeFlat; sf.AddrStack.Offset = (DWORD64)ctx.Esp;
                        sf.AddrFrame.Mode = AddrModeFlat; sf.AddrFrame.Offset = (DWORD64)ctx.Ebp;
#endif
                        int suspiciousFrames = 0; int frames = 0;
                        while (frames < 32 && StackWalk64(machine, GetCurrentProcess(), hThread, &sf, &ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
                            ++frames;
                            PVOID faddr = (PVOID)(ULONG_PTR)sf.AddrPC.Offset;
                            if (!faddr) break;
                            std::wstring fmod = ModuleFromAddress(faddr);
                            if (fmod.empty()) {
                                // frame in unknown memory
                                ++suspiciousFrames; continue;
                            }
                            if (!IsWhitelistedModule(fmod) && !IsSystemPathLower(fmod)) {
                                ++suspiciousFrames;
                            }
                        }
                        if (suspiciousFrames >= 2) {
                            score += 2; // multiple suspicious frames in stack
                        }
                    }
                    ResumeThread(hThread);
                }

                if (score >= m_threshold) {
                    out.tid = te.th32ThreadID;
                    out.startAddress = startAddr;
                    out.moduleName = mod;
                    out.indicators = score;
                    CloseHandle(hThread);
                    CloseHandle(snap);
                    return true;
                }
            }
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return false;
}
