#pragma once
#include <windows.h>
#include <string>

// Network client for sending reports to server
class NetworkClient {
public:
    NetworkClient();
    ~NetworkClient();

    // Initialize with server IP and port
    bool Initialize(const std::string& serverIp, int serverPort);

    // Send JSON message to server
    bool SendMessage(const std::string& jsonMessage);

    // Close connection
    void Close();

    // Optional: set HMAC secret (ASCII/UTF-8). If set, client will append header line 'Auth: HMAC-SHA256 <hex>' before JSON.
    void SetHmacSecret(const std::string& secret) { m_hmacSecret = secret; }

private:
    std::string m_serverIp;
    int m_serverPort;
    bool m_initialized;
    std::string m_hmacSecret;
};

// ===== Hook for packet timing analysis (used by SpeedHackDetector) =====
// Consumer can set a callback to be notified on send/recv events.
// timestamp: GetTickCount64() at event time; size: bytes; isOutgoing: true for send, false for recv
using NetworkPacketHook = void(*)(unsigned long long timestamp, size_t size, bool isOutgoing);

// Set or clear the global packet hook. Thread-safe for simple usage.
void NetworkClient_SetPacketHook(NetworkPacketHook cb);
