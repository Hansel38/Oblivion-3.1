#include "../pch.h"
#include "Heartbeat.h"
#include "JsonBuilder.h"
#include "HWID.h"
#include "NetworkClient.h"
#include "ClientVersion.h"
#include <string>

void Heartbeat::Start(DWORD intervalMs)
{
    Stop();
    m_intervalMs = intervalMs ? intervalMs : 30000;
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_thread = CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
}

void Heartbeat::Stop()
{
    if (m_thread) {
        if (m_stopEvent) SetEvent(m_stopEvent);
        WaitForSingleObject(m_thread, 3000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
    if (m_stopEvent) { CloseHandle(m_stopEvent); m_stopEvent = nullptr; }
}

DWORD WINAPI Heartbeat::ThreadProc(LPVOID ctx)
{
    static_cast<Heartbeat*>(ctx)->RunLoop();
    return 0;
}

void Heartbeat::RunLoop()
{
    const std::string hwid = GetHWID();
    while (WaitForSingleObject(m_stopEvent, m_intervalMs) == WAIT_TIMEOUT) {
        if (!m_net) continue;
        std::wstring pname = L"RRO.exe";
        std::wstring reason = L"heartbeat";
        std::string json = JsonBuilder::BuildDetectionReport(GetCurrentProcessId(), pname, reason, "heartbeat", 1, hwid, OBLIVION_CLIENT_VERSION);
        m_net->SendMessage(json);
    }
}
