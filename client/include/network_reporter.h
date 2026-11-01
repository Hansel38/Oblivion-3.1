#pragma once

#include <cstddef>
#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <atomic>
#include <thread>
#include <winsock2.h>
#include <openssl/ssl.h>
#include "heartbeat_protocol.h"

namespace Oblivion {
    class NetworkReporter {
    public:
        // defaultHost/defaultPort dipakai HANYA sebagai fallback bila tidak ada
        // konfigurasi lain (file oblivion.cfg / environment variable).
        NetworkReporter(const std::string& defaultHost, int defaultPort, const std::string& secretKey);
        ~NetworkReporter();

        // Fungsi untuk check-in ke server (cek apakah di-ban).
        // Mengembalikan true jika client diizinkan bermain.
        //
        // Kebijakan produksi selalu fail-closed. Fail-open hanya tersedia pada
        // build development yang secara eksplisit mengaktifkan macro kompilasi.
        bool CheckBanStatus();

        // Fungsi utama untuk melaporkan pelanggaran
        void ReportViolation(const std::string& type, const std::string& details);

        // Heartbeat: start and stop
        void StartHeartbeat();
        void StopHeartbeat();

        // Status runtime yang dikirim pada setiap PONG (diisi oleh dllmain dari
        // komponen anti-suspend & self-integrity yang sebenarnya).
        void SetStatusProvider(std::function<ClientStatus()> provider);

    private:
        struct Endpoint {
            std::string host;
            int port = 0;
        };

        // Konfigurasi jaringan hasil resolusi (file oblivion.cfg -> env -> default)
        std::vector<Endpoint> m_endpoints;
        std::atomic<size_t> m_activeEndpoint{ 0 };      // endpoint yang terakhir berhasil
        bool m_failClosed = false;        // true = fail-closed (tutup client bila server tak terjangkau)
        int m_connectTimeoutMs = 3000;    // timeout connect per endpoint
        int m_retryCount = 3;             // jumlah percobaan untuk seluruh endpoint
        int m_handshakeTimeoutMs = 4000;  // timeout menunggu respons server

        std::function<ClientStatus()> m_statusProvider;

        std::string m_serverIP;   // fallback host (parameter konstruktor)
        int m_serverPort;         // fallback port
        std::string m_hwid;       // Hardware ID yang di-generate saat konstruktor
        bool m_hwidValid = false; // true bila m_hwid berformat sah (hex + dash) dan layak dikirim
        std::string m_secretKey;  // Shared key loaded from environment/config
        bool m_secretValid = false; // Production requires at least 32 bytes
        std::vector<std::string> m_tlsPins; // Required leaf-certificate SHA-256 pin set
        std::string m_tlsPinError;
        SSL_CTX* m_tlsContext = nullptr;

        void LoadConfiguration();
        SOCKET ConnectToAnyEndpoint(std::string& outHost, int& outPort);
        SOCKET ConnectWithTimeout(const std::string& host, int port) const;
        bool PerformCheckin(SOCKET s, SSL* tls, bool& isBanned, std::string& errorOut);
        void LogClientIssue(const std::string& type, const std::string& details) const;
        void QueuePendingViolation(const std::string& type, const std::string& details) const;

        // Internal heartbeat state.
        //
        // Thread heartbeat DIMILIKI objek ini (tidak detach) supaya bisa di-join
        // saat shutdown. Versi sebelumnya memakai thread detached + recv blocking
        // tanpa timeout: bila server berhenti mengirim, thread tetap hidup setelah
        // destruktor selesai dan mengakses m_secretKey/m_hwid/m_statusProvider yang
        // sudah dihancurkan (use-after-free) serta menutup socket milik pihak lain.
        std::atomic<bool> m_hbRunning{ false };
        std::thread m_hbThread;
        SOCKET m_hbSocket = INVALID_SOCKET; // Socket untuk heartbeat
        SSL* m_hbTls = nullptr; // TLS session bound to the heartbeat socket
        uint64_t m_sessionNonce = 0; // Session nonce dari server
        std::string m_pendingHeartbeatData; // TCP bytes received after the check-in response

        // Antrian laporan pelanggaran yang gagal terkirim: disimpan di memori
        // (best-effort, dibatasi jumlahnya) sebagai jejak audit lokal di samping
        // file oblivion_client_errors.log.
        // mutable karena QueuePendingViolation() sengaja const (tidak mengubah state publik).
        mutable std::vector<std::pair<std::string, std::string>> m_pendingViolations;
        mutable CRITICAL_SECTION m_pendingLock;
        bool m_pendingLockInitialized = false;
        bool m_winsockInitialized = false;
    };
}