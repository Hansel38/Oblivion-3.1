#include "../pch.h"
#include "PeriodicScanner.h"

void PeriodicScanner::Start(DWORD intervalMs)
{
    Stop();
    m_intervalMs = intervalMs ? intervalMs : 15000;
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_thread = CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
}

void PeriodicScanner::Stop()
{
    if (m_thread) {
        if (m_stopEvent) SetEvent(m_stopEvent);
        WaitForSingleObject(m_thread, 3000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
    if (m_stopEvent) { CloseHandle(m_stopEvent); m_stopEvent = nullptr; }
}

DWORD WINAPI PeriodicScanner::ThreadProc(LPVOID ctx)
{
    static_cast<PeriodicScanner*>(ctx)->RunLoop();
    return 0;
}

void PeriodicScanner::RunLoop()
{
    while (WaitForSingleObject(m_stopEvent, m_intervalMs) == WAIT_TIMEOUT) {
        if (Tick) Tick();
    }
}
