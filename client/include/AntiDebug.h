#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>

// Simple Anti-Debug scanner (header-only to avoid project file edits)
// Uses multiple indicators and requires threshold to trigger.
class AntiDebug {
public:
    void SetThreshold(int t) { m_threshold = t; }

    bool RunScan(struct DetectionResult& out) {
        int score = 0;
        std::wstring reason;

        // 1) IsDebuggerPresent (current process)
        if (IsDebuggerPresent()) {
            score++; appendreason(reason, L"IsDebuggerPresent");
        }

        // 2) CheckRemoteDebuggerPresent
        BOOL b = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &b) && b) {
            score++; appendreason(reason, L"CheckRemoteDebuggerPresent");
        }

        // 3) NtQueryInformationProcess: DebugPort, DebugFlags, DebugObjectHandle
        QueryNtIndicators(score, reason);

        // 4) Known debugger processes running (lightweight heuristic)
        if (DebuggerProcessRunning()) { score++; appendreason(reason, L"Debugger process present"); }

        // 5) Hardware breakpoints on any thread (DR0-DR3)
        if (CheckHWBPAllThreads()) { score += 2; appendreason(reason, L"HWBP (DRx) present"); }

        // 6) PEB anti-debug spoof (BeingDebugged vs DebugFlags consistency)
        if (CheckPebSpoof()) { score++; appendreason(reason, L"PEB/DebugFlags inconsistency"); }

        // 7) VEH/Speedhack artifacts via loaded module heuristics
        if (CheckSpeedhackModules()) { score++; appendreason(reason, L"Speedhack/VEH module present"); }

        // 8) ThreadHideFromDebugger anomalies (NtSetInformationThread/NtQueryInformationThread)
        if (CheckThreadHideFromDebuggerAnomaly()) { score++; appendreason(reason, L"ThreadHideFromDebugger anomaly"); }

        // 9) Time-warp drift (QPC vs GetTickCount64 ratio)
        if (CheckTimewarpDrift()) { score++; appendreason(reason, L"Timewarp/QPC drift"); }

        // 10) DBK/CE driver artifacts (renamed/custom CE)
        if (CheckDbkDriverArtifacts()) { score += 2; appendreason(reason, L"DBK/CE driver artifact"); }

        if (score >= m_threshold) {
            out.detected = true;
            out.pid = GetCurrentProcessId();
            out.processName = L"RRO.exe"; // displaying game name context; can be resolved if needed
            out.reason = reason.empty() ? L"Anti-Debug indicators" : reason;
            out.indicatorCount = score;
            return true;
        }
        return false;
    }

private:
    int m_threshold = 2;

    static DWORD WINAPI DummyThreadProc(LPVOID) {
        return 0; // no work, exits immediately when resumed
    }

    static void appendreason(std::wstring& r, const std::wstring& add) {
        if (!r.empty()) r += L"; ";
        r += add;
    }

    typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    typedef LONG (NTAPI *PFN_NtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
    typedef LONG (NTAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    void QueryNtIndicators(int& score, std::wstring& reason) {
        HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
        if (!hNt) return;
        auto NtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNt, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return;

        // ProcessDebugPort = 7
        ULONG_PTR dbgPort = 0; ULONG retLen = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), 7, &dbgPort, sizeof(dbgPort), &retLen) == 0 /*STATUS_SUCCESS*/) {
            if (dbgPort != 0) { score += 2; appendreason(reason, L"DebugPort!=0"); }
        }

        // ProcessDebugObjectHandle = 30 (0x1E)
        HANDLE dbgObj = nullptr; retLen = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), 30, &dbgObj, sizeof(dbgObj), &retLen) == 0) {
            if (dbgObj != nullptr && dbgObj != (HANDLE)-1) { score += 2; appendreason(reason, L"DebugObjectHandle"); }
        }

        // ProcessDebugFlags = 31 (0x1F) -> nonzero means no debugger, zero means being debugged
        ULONG dbgFlags = 0; retLen = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), 31, &dbgFlags, sizeof(dbgFlags), &retLen) == 0) {
            if (dbgFlags == 0) { score++; appendreason(reason, L"DebugFlags==0"); }
        }
    }

    bool DebuggerProcessRunning() {
        static const wchar_t* kDbgNames[] = { L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"windbg.exe", L"ida.exe", L"ida64.exe" };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        bool found = false;
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring name = pe.szExeFile; for (auto& c : name) c = towlower(c);
                for (auto n : kDbgNames) {
                    std::wstring nn = n; for (auto& c : nn) c = towlower(c);
                    if (name == nn) { found = true; break; }
                }
                if (found) break;
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

    bool CheckHWBPAllThreads() {
        DWORD pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        bool hit = false;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hThread) continue;
                // Suspend to reliably query context of other threads
                DWORD suspendCount = SuspendThread(hThread);
                CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(hThread, &ctx)) {
#ifdef _M_X64
                    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) hit = true;
#else
                    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) hit = true;
#endif
                }
                if (suspendCount != (DWORD)-1) ResumeThread(hThread);
                CloseHandle(hThread);
                if (hit) break;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return hit;
    }

    // Minimal PROCESS_BASIC_INFORMATION just for PebBaseAddress
    typedef struct _PBI_MIN {
        PVOID Reserved1[2];
        PVOID PebBaseAddress; // offset 2
        PVOID Reserved2[4];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PBI_MIN;

    bool CheckPebSpoof() {
        // Read PEB->BeingDebugged and compare with DebugFlags
        HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
        if (!hNt) return false;
        auto NtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNt, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return false;
        PBI_MIN pbi{}; ULONG retLen = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &retLen) != 0) return false;
        if (pbi.PebBaseAddress == nullptr) return false; // avoid null-deref
        BYTE being = 0;
        __try {
            // BeingDebugged is a BYTE at offset 0x2 in PEB on both x86/x64 (documented behavior)
            BYTE* peb = reinterpret_cast<BYTE*>(pbi.PebBaseAddress);
            being = *(peb + 2);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        // DebugFlags via NtQueryInformationProcess(31)
        ULONG dbgFlags = 1; // default not debugged
        if (NtQueryInformationProcess(GetCurrentProcess(), 31, &dbgFlags, sizeof(dbgFlags), &retLen) != 0) dbgFlags = 1;
        // If BeingDebugged==0 but DebugFlags==0 -> inconsistent (spoof)
        if (being == 0 && dbgFlags == 0) return true;
        return false;
    }

    bool CheckSpeedhackModules() {
        // Heuristics: look for known CE speedhack/VEH modules loaded in this process
        static const wchar_t* kNames[] = {
            L"speedhack64.dll", L"speedhack-i386.dll", L"speedhack.dll",
            L"vehdebug.dll", L"vehdebug64.dll", L"vehlib.dll",
            L"cheatengine-x86_64.exe", L"cheatengine-i386.exe", L"cheatengine.exe",
            L"dbk64.sys", L"dbk32.sys", L"cedebugger.dll", L"iceext.dll"
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32W me{}; me.dwSize = sizeof(me);
        bool found = false;
        if (Module32FirstW(snap, &me)) {
            do {
                std::wstring base = me.szModule; for (auto& c : base) c = towlower(c);
                for (auto n : kNames) {
                    std::wstring nn = n; for (auto& c : nn) c = towlower(c);
                    if (base == nn) { found = true; break; }
                    // substring match on path
                    std::wstring path = me.szExePath; for (auto& c : path) c = towlower(c);
                    if (path.find(nn) != std::wstring::npos) { found = true; break; }
                }
                if (found) break;
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return found;
    }

    bool CheckThreadHideFromDebuggerAnomaly() {
        HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
        if (!hNt) return false;
        auto NtSetInformationThread = (PFN_NtSetInformationThread)GetProcAddress(hNt, "NtSetInformationThread");
        auto NtQueryInformationThread = (PFN_NtQueryInformationThread)GetProcAddress(hNt, "NtQueryInformationThread");
        if (!NtSetInformationThread || !NtQueryInformationThread) return false;

        // Create a suspended dummy thread to avoid changing the current thread semantics
        HANDLE hThread = CreateThread(nullptr, 0, &DummyThreadProc, nullptr, CREATE_SUSPENDED, nullptr);
        if (!hThread) return false;

        bool suspicious = false;
        ULONG retLen = 0;
        // 0x11 = ThreadHideFromDebugger; querying should not succeed normally
        LONG stQ1 = NtQueryInformationThread(hThread, 0x11, nullptr, 0, &retLen);
        if (stQ1 == 0 /*STATUS_SUCCESS*/) {
            suspicious = true; // unexpected success
        }

        // Try to set hide flag (usually returns STATUS_SUCCESS regardless of debugger)
        LONG stSet = NtSetInformationThread(hThread, 0x11, nullptr, 0);
        (void)stSet; // do not rely on this as a signal to reduce false positives

        // Query again; success remains suspicious
        retLen = 0;
        LONG stQ2 = NtQueryInformationThread(hThread, 0x11, nullptr, 0, &retLen);
        if (stQ2 == 0) {
            suspicious = true;
        }

        // Proper cleanup: resume the suspended thread so it can exit normally, then wait
        ResumeThread(hThread);
        WaitForSingleObject(hThread, 2000); // wait up to 2s for clean exit
        CloseHandle(hThread);
        return suspicious;
    }

    bool CheckTimewarpDrift() {
        LARGE_INTEGER fq{}; if (!QueryPerformanceFrequency(&fq) || fq.QuadPart == 0) return false;
        const double freq = (double)fq.QuadPart;
        ULONGLONG gtc0 = GetTickCount64();
        LARGE_INTEGER q0{}; QueryPerformanceCounter(&q0);
        Sleep(200); // short window
        ULONGLONG gtc1 = GetTickCount64();
        LARGE_INTEGER q1{}; QueryPerformanceCounter(&q1);
        double dqpc_ms = ((double)(q1.QuadPart - q0.QuadPart)) * 1000.0 / freq;
        double dgtc_ms = (double)(gtc1 - gtc0);
        if (dgtc_ms <= 0.0) return false;
        double ratio = dqpc_ms / dgtc_ms; // expect ~1.0
        // Allow generous tolerance (+/-15%) for system variance
        return (ratio < 0.85 || ratio > 1.15);
    }

    bool CheckDbkDriverArtifacts() {
        // 1) Enumerate loaded drivers for names containing 'dbk' or 'cedriver'
        LPVOID drivers[512]; DWORD cbNeeded = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
            int count = (int)(cbNeeded / sizeof(drivers[0]));
            wchar_t nameBuf[260];
            for (int i = 0; i < count; ++i) {
                if (GetDeviceDriverBaseNameW(drivers[i], nameBuf, 260)) {
                    std::wstring base = nameBuf; for (auto& c : base) c = towlower(c);
                    if (base.find(L"dbk") != std::wstring::npos || base.find(L"cedriver") != std::wstring::npos) {
                        return true;
                    }
                }
            }
        }
        // 2) Probe common DBK device names (lightweight)
        const wchar_t* devs[] = { L"\\\\.\\dbk64", L"\\\\.\\dbk32", L"\\\\.\\dbk", L"\\\\.\\cedriver" };
        for (auto d : devs) {
            HANDLE h = CreateFileW(d, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
        }
        // 3) Probe cedriver with common numeric suffixes (limited range to avoid overhead)
        for (int v = 60; v <= 80; ++v) {
            wchar_t path[64]; swprintf_s(path, L"\\\\.\\cedriver%d", v);
            HANDLE h = CreateFileW(path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
        }
        return false;
    }
};
