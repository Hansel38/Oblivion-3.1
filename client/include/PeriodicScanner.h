#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

struct DetectionResult;
class NetworkClient;

class PeriodicScanner
{
public:
    explicit PeriodicScanner(NetworkClient* net) : m_net(net) {}
    void Start(DWORD intervalMs);
    void Stop();
    void SetIntervalMs(DWORD intervalMs) { m_intervalMs = intervalMs ? intervalMs : 15000; }

    // Callbacks to perform each scan step provided by dllmain
    std::function<bool()> Tick;

private:
    static DWORD WINAPI ThreadProc(LPVOID ctx);
    void RunLoop();

    NetworkClient* m_net = nullptr;
    HANDLE m_thread = nullptr;
    HANDLE m_stopEvent = nullptr;
    DWORD m_intervalMs = 15000;
};
