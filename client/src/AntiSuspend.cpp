#include "../pch.h"
#include "AntiSuspend.h"
#include <tlhelp32.h>
#include <algorithm>

AntiSuspend::AntiSuspend() {}
AntiSuspend::~AntiSuspend() { Stop(); }

bool AntiSuspend::Start(DWORD heartbeatIntervalMs,
                        DWORD stallWindowMs,
                        int missesThreshold,
                        AntiSuspendReportFn reportFn)
{
    if (m_hHeartbeatThread || m_hWatchdogThread) return true; // already running

    m_heartbeatIntervalMs = heartbeatIntervalMs ? heartbeatIntervalMs : 200;
    m_stallWindowMs = stallWindowMs ? stallWindowMs : 3000;
    m_missesThreshold = missesThreshold > 0 ? missesThreshold : 2;
    m_reportFn = reportFn;

    m_stop = false;
    m_reported = false;
    m_lastBeatTick = GetTickCount64();

    m_hHeartbeatThread = CreateThread(nullptr, 0, HeartbeatThreadProc, this, 0, nullptr);
    m_hWatchdogThread = CreateThread(nullptr, 0, WatchdogThreadProc, this, 0, nullptr);

    return m_hHeartbeatThread && m_hWatchdogThread;
}

void AntiSuspend::Stop()
{
    m_stop = true;
    if (m_hHeartbeatThread) { WaitForSingleObject(m_hHeartbeatThread, 2000); CloseHandle(m_hHeartbeatThread); m_hHeartbeatThread = nullptr; }
    if (m_hWatchdogThread) { WaitForSingleObject(m_hWatchdogThread, 2000); CloseHandle(m_hWatchdogThread); m_hWatchdogThread = nullptr; }
}

DWORD WINAPI AntiSuspend::HeartbeatThreadProc(LPVOID lpParam)
{
    reinterpret_cast<AntiSuspend*>(lpParam)->HeartbeatLoop();
    return 0;
}

DWORD WINAPI AntiSuspend::WatchdogThreadProc(LPVOID lpParam)
{
    reinterpret_cast<AntiSuspend*>(lpParam)->WatchdogLoop();
    return 0;
}

void AntiSuspend::HeartbeatLoop()
{
    while (!m_stop) {
        m_lastBeatTick = GetTickCount64();
        Sleep(m_heartbeatIntervalMs);
    }
}

std::wstring AntiSuspend::GetExeName() const
{
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p(path);
    size_t pos = p.find_last_of(L"\\/");
    if (pos != std::wstring::npos) p = p.substr(pos + 1);
    return p;
}

void AntiSuspend::WatchdogLoop()
{
    int missCount = 0;
    const DWORD sampleInterval = 500; // 0.5s

    while (!m_stop) {
        ULONGLONG now = GetTickCount64();
        ULONGLONG last = m_lastBeatTick.load();
        if (now - last > m_stallWindowMs) {
            missCount++;
        } else {
            if (missCount > 0) missCount--;
        }

        if (!m_reported && missCount >= m_missesThreshold && m_reportFn) {
            m_reported = true;
            DetectionResult dr{};
            dr.detected = true;
            dr.pid = GetCurrentProcessId();
            dr.processName = GetExeName();
            dr.reason = L"Heartbeat stalled (possible thread/process suspension)";
            dr.indicatorCount = missCount;
            m_reportFn(dr, "antisuspend");
        }

        Sleep(sampleInterval);
    }
}
