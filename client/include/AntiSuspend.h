#pragma once
#include <windows.h>
#include <string>
#include <atomic>
#include "ProcessThreadWatcher.h" // for DetectionResult

// Callback prototype to report detection back to host
typedef void (*AntiSuspendReportFn)(const DetectionResult& result, const char* subtype);

class AntiSuspend
{
public:
    AntiSuspend();
    ~AntiSuspend();

    // Configure and start heartbeat/watchdog threads
    bool Start(DWORD heartbeatIntervalMs,
               DWORD stallWindowMs,
               int missesThreshold,
               AntiSuspendReportFn reportFn);

    // Stop threads and cleanup
    void Stop();

private:
    static DWORD WINAPI HeartbeatThreadProc(LPVOID lpParam);
    static DWORD WINAPI WatchdogThreadProc(LPVOID lpParam);

    void HeartbeatLoop();
    void WatchdogLoop();

    std::atomic<bool> m_stop{false};
    std::atomic<ULONGLONG> m_lastBeatTick{0};
    std::atomic<bool> m_reported{false};

    DWORD m_heartbeatIntervalMs = 200;    // how often to update heartbeat
    DWORD m_stallWindowMs = 3000;         // consider stalled if no beat for this long
    int   m_missesThreshold = 2;          // consecutive stall samples required

    HANDLE m_hHeartbeatThread = nullptr;
    HANDLE m_hWatchdogThread = nullptr;

    AntiSuspendReportFn m_reportFn = nullptr;

    std::wstring GetExeName() const;
};
