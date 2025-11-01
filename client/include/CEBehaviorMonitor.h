#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>
#include <mutex>

// Lightweight behavior monitor focused on CE-like memory access patterns
// This module observes remote handles to our process with VM_READ/VM_WRITE access
// and aggregates bursts over a sliding time window.
class CEBehaviorMonitor {
public:
    struct BehaviorFinding {
        bool detected = false;
        DWORD pid = 0;
        std::wstring processName;
        std::wstring reason;
        int indicators = 0; // weight 1..5
    };

    CEBehaviorMonitor();
    ~CEBehaviorMonitor();

    // Start/Stop background sampler
    bool Start();
    void Stop();

    // Configure sensitivity/thresholds
    // Number of observations within window to trigger detection
    void SetThreshold(int t) { std::lock_guard<std::mutex> _g(m_lock); m_threshold = (t < 1 ? 1 : (t > 10 ? 10 : t)); }
    void SetMonitorWindowMs(DWORD ms) { std::lock_guard<std::mutex> _g(m_lock); m_windowMs = (ms < 500 ? 500 : (ms > 60000 ? 60000 : ms)); }
    void SetPollingIntervalMs(DWORD ms) { std::lock_guard<std::mutex> _g(m_lock); m_pollMs = (ms < 200 ? 200 : (ms > 5000 ? 5000 : ms)); }

    // One-shot check from aggregated state; returns top suspicious finding (if any)
    bool CheckSuspiciousBehavior(BehaviorFinding& outFinding);

private:
    struct Counter { ULONGLONG first=0, last=0; unsigned burst=0; };
    std::unordered_map<DWORD, Counter> m_counts; // per offender pid
    std::unordered_map<DWORD, std::wstring> m_names;
    std::mutex m_lock;

    int m_threshold = 4;       // default sensitivity
    DWORD m_windowMs = 5000;   // sliding window
    DWORD m_pollMs = 500;      // sampling period

    HANDLE m_thread = nullptr;
    bool m_stop = false;

    static DWORD WINAPI ThreadProc(LPVOID p);
    void Loop();

    // Helpers
    void SampleOnce();
    bool EnumRemoteHandlesToSelf(std::vector<std::pair<DWORD, ULONG>>& outPidAndAccess);
    std::wstring GetProcessName(DWORD pid);
};
