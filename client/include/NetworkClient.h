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
