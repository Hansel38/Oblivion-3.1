#include "../pch.h"
#include "CEBehaviorMonitor.h"
#include <TlHelp32.h>
#include <vector>
#include <algorithm>

// Local NT declarations (avoid sdk deps)
namespace {
    using pfnNtQuerySystemInformation = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
    typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

    static bool DuplicateAndCheckTarget(HANDLE srcProc, HANDLE srcHandle, DWORD& outTargetPid, ULONG& outAccess)
    {
        outTargetPid = 0; outAccess = 0;
        HANDLE hDup = nullptr;
        if (!DuplicateHandle(srcProc, srcHandle, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        HANDLE hLocal = hDup;
        outTargetPid = GetProcessId(hLocal);
        // Can't query GrantedAccess from duplicated handle portably here; use caller-provided access
        CloseHandle(hLocal);
        return true;
    }
}

CEBehaviorMonitor::CEBehaviorMonitor() {}
CEBehaviorMonitor::~CEBehaviorMonitor() { Stop(); }

bool CEBehaviorMonitor::Start()
{
    Stop();
    m_stop = false;
    m_thread = CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
    return m_thread != nullptr;
}

void CEBehaviorMonitor::Stop()
{
    if (m_thread) {
        m_stop = true;
        WaitForSingleObject(m_thread, 2000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
}

DWORD WINAPI CEBehaviorMonitor::ThreadProc(LPVOID p)
{
    reinterpret_cast<CEBehaviorMonitor*>(p)->Loop();
    return 0;
}

void CEBehaviorMonitor::Loop()
{
    while (!m_stop) {
        SampleOnce();
        DWORD poll;
        {
            std::lock_guard<std::mutex> _g(m_lock);
            poll = m_pollMs;
        }
        Sleep(poll);
    }
}

bool CEBehaviorMonitor::CheckSuspiciousBehavior(BehaviorFinding& outFinding)
{
    std::lock_guard<std::mutex> _g(m_lock);
    outFinding = {};

    // Find offender with highest burst within window
    DWORD bestPid = 0; unsigned bestBurst = 0; ULONGLONG now = GetTickCount64();
    for (auto& kv : m_counts) {
        const DWORD pid = kv.first; const Counter& c = kv.second;
        if (c.burst > bestBurst && (now - c.last) <= m_windowMs) { bestPid = pid; bestBurst = c.burst; }
    }
    if (bestPid && bestBurst >= (unsigned)m_threshold) {
        const Counter& c = m_counts[bestPid];
        ULONGLONG windowDur = (c.last > c.first) ? (c.last - c.first) : m_windowMs;
        double ratePerSec = windowDur ? (1000.0 * (double)c.burst / (double)windowDur) : (double)c.burst;

        outFinding.detected = true;
        outFinding.pid = bestPid;
        outFinding.processName = GetProcessName(bestPid);
        wchar_t buf[320];
        // Heuristic tag if the rate is steady and high -> likely sequential scan pattern
        const bool likelySequential = (ratePerSec >= 50.0) && (bestBurst >= (unsigned)(m_threshold + 2));
        outFinding.likelySequential = likelySequential;
        if (likelySequential) {
            swprintf_s(buf, L"Likely memory scanning pattern (steady remote VM access rate ~%.1f/sec) in %u ms window (burst=%u)", ratePerSec, (unsigned)m_windowMs, bestBurst);
            outFinding.indicators = 4; // stronger weight when looks like scanning
            // Lightweight debug logging to aid field tuning
            wchar_t dbg[256];
            swprintf_s(dbg, L"[Oblivion] memory_scanning: pid=%u burst=%u windowMs=%u rate=%.1f/sec\n", bestPid, bestBurst, (unsigned)m_windowMs, ratePerSec);
            OutputDebugStringW(dbg);
        } else {
            swprintf_s(buf, L"Excessive remote VM access to our process in %u ms window (burst=%u, rate=~%.1f/sec)", (unsigned)m_windowMs, bestBurst, ratePerSec);
            // Weight indicators by how big the burst is above threshold
            outFinding.indicators = 3 + (int)std::min<unsigned>(2, bestBurst - (unsigned)m_threshold);
        }
        outFinding.reason = buf;
        return true;
    }
    return false;
}

void CEBehaviorMonitor::SampleOnce()
{
    std::vector<std::pair<DWORD, ULONG>> offenders; // pid, access
    if (!EnumRemoteHandlesToSelf(offenders)) return;

    ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> _g(m_lock);

    // Decay old entries and update bursts
    for (const auto& pr : offenders) {
        DWORD pid = pr.first; ULONG access = pr.second; (void)access;
        Counter& c = m_counts[pid];
        if (c.first == 0 || (now - c.first) > m_windowMs) { c.first = now; c.burst = 0; }
        c.last = now; c.burst++;
        ULONGLONG span = (c.last > c.first) ? (c.last - c.first) : 0ULL;
        if (span >= 200) { // avoid division noise on very small spans
            c.avgRatePerSec = 1000.0 * (double)c.burst / (double)span;
        }
        if (m_names.find(pid) == m_names.end()) m_names[pid] = GetProcessName(pid);
    }

    // Prune stale
    for (auto it = m_counts.begin(); it != m_counts.end(); ) {
        if ((now - it->second.last) > (m_windowMs * 2ULL)) it = m_counts.erase(it); else ++it;
    }
}

bool CEBehaviorMonitor::EnumRemoteHandlesToSelf(std::vector<std::pair<DWORD, ULONG>>& outPidAndAccess)
{
    outPidAndAccess.clear();
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto NtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) return false;

    ULONG len = 1u << 20; // 1MB
    std::vector<BYTE> buf; LONG st;
    for (;;) {
        buf.resize(len);
        st = NtQuerySystemInformation(0x40 /*SystemExtendedHandleInformation*/, buf.data(), len, &len);
        if (st == 0) break; // STATUS_SUCCESS
        if (st == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) { if (len > (1u<<26)) return false; continue; }
        return false;
    }
    auto shi = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buf.data());
    DWORD self = GetCurrentProcessId();

    const ULONG READ = 0x0010, WRITE = 0x0020, OP = 0x0008, CREATE_THREAD = 0x0002;
    const ULONG suspiciousMask = READ | WRITE | OP | CREATE_THREAD;

    for (ULONG_PTR i = 0; i < shi->NumberOfHandles; ++i) {
        const auto& e = shi->Handles[i];
        if ((DWORD)e.UniqueProcessId == self) continue;
        HANDLE srcHandle = (HANDLE)(ULONG_PTR)e.HandleValue;
        HANDLE hSource = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)e.UniqueProcessId);
        if (!hSource) continue;
        DWORD targetPid = 0; ULONG access = e.GrantedAccess;
        if (DuplicateAndCheckTarget(hSource, srcHandle, targetPid, access)) {
            if (targetPid == self && (e.GrantedAccess & suspiciousMask)) {
                outPidAndAccess.emplace_back((DWORD)e.UniqueProcessId, e.GrantedAccess);
            }
        }
        CloseHandle(hSource);
    }

    return !outPidAndAccess.empty();
}

std::wstring CEBehaviorMonitor::GetProcessName(DWORD pid)
{
    auto it = m_names.find(pid);
    if (it != m_names.end()) return it->second;
    std::wstring name;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap && snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do { if (pe.th32ProcessID == pid) { name = pe.szExeFile; break; } } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (name.empty()) name = L"<unknown>";
    m_names[pid] = name;
    return name;
}
