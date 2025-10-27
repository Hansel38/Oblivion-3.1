#include "../pch.h"
#include "HijackedThreadScanner.h"
#include <Psapi.h>
#include <algorithm>

static std::wstring tolower_ws(const std::wstring& s) { std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

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
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
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
