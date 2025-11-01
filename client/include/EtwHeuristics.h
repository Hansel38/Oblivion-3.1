#pragma once
#include <windows.h>
#include <string>
#include <atomic>
#include <thread>

class NetworkClient;

class EtwHeuristics {
public:
    EtwHeuristics(NetworkClient* net, int threshold, DWORD windowMs);
    ~EtwHeuristics();

    bool Start();
    void Stop();

    void UpdateParameters(int threshold, DWORD windowMs);
    void SetMemscanMinStreak(int v) { m_memscanMinStreak.store(v); }

private:
    static void ThreadMain(EtwHeuristics* self);
    void Run();

    // ETW state
    std::atomic<bool> m_run{false};
    std::thread m_thread;
    NetworkClient* m_net;
    std::atomic<int> m_threshold;
    std::atomic<DWORD> m_windowMs;
    std::atomic<int> m_memscanMinStreak{4};
};
