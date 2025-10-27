#pragma once
#include <windows.h>
#include <string>

class NetworkClient;

class Heartbeat
{
public:
    explicit Heartbeat(NetworkClient* net) : m_net(net) {}
    void Start(DWORD intervalMs);
    void Stop();

private:
    static DWORD WINAPI ThreadProc(LPVOID ctx);
    void RunLoop();

    NetworkClient* m_net = nullptr;
    HANDLE m_thread = nullptr;
    HANDLE m_stopEvent = nullptr;
    DWORD m_intervalMs = 30000;
};
