#pragma once

#include <string>
#include <atomic>
#include <winsock2.h>

namespace Oblivion {
    class NetworkReporter {
    public:
        NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey);
        ~NetworkReporter();

        // Fungsi untuk check-in ke server (cek apakah di-ban)
        // Mengembalikan true jika diizinkan, false jika di-ban
        bool CheckBanStatus();

        // Fungsi utama untuk melaporkan pelanggaran
        void ReportViolation(const std::string& type, const std::string& details);

        // Heartbeat: start and stop (future use)
        void StartHeartbeat();
        void StopHeartbeat();

    private:
        std::string m_serverIP;
        int m_serverPort;
        std::string m_hwid;  // Hardware ID yang di-generate saat konstruktor
        // Hanya dipakai untuk membuat proof HMAC; nilainya tidak pernah dikirim
        // sebagai plaintext melalui wire protocol.
        std::string m_secretKey;

        bool OpenAuthenticatedConnection(const std::string& purpose,
                                         SOCKET& socket,
                                         uint64_t& sessionNonce,
                                         std::string& sessionKey);

        // Internal heartbeat state
        std::atomic<bool> m_hbRunning{ false };
        SOCKET m_hbSocket = INVALID_SOCKET; // Socket untuk heartbeat
        uint64_t m_sessionNonce = 0; // Session nonce dari server
        std::string m_sessionKey;
    };
}
