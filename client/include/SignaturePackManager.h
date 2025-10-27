#pragma once
#include <windows.h>
#include <string>
#include "ConfigLoader.h"

// Simple server-pushed (polled) signature pack manager.
// Periodically asks the server for the latest signature pack and updates
// ClientConfig.memorySignatures and related knobs at runtime for rapid rollout.
class SignaturePackManager {
public:
    SignaturePackManager(const std::string& serverIp, int serverPort, ClientConfig* cfg);
    ~SignaturePackManager();

    void Start(DWORD intervalMs = 60000); // default 60s
    void Stop();

private:
    static DWORD WINAPI ThreadProc(LPVOID ctx);
    void RunLoop();
    bool PollOnce();

    std::string m_serverIp;
    int m_serverPort = 0;
    ClientConfig* m_cfg = nullptr; // not owned

    HANDLE m_thread = nullptr;
    HANDLE m_stopEvent = nullptr;
    DWORD m_intervalMs = 60000;

    int m_currentVersion = 0;
};
