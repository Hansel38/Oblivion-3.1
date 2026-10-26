#include "pch.h"
#include "network_reporter.h"
#include "heartbeat_protocol.h"
#include "hwid_generator.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <random>
#include <fstream>
#include <utility>
#include <iostream>
#include <bcrypt.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

#ifndef BCRYPT_ALG_HANDLE_HMAC
#define BCRYPT_ALG_HANDLE_HMAC 0x00000008
#endif

// ============================================================================
//  KONFIGURASI ENDPOINT SERVER
//
//  Client harus bisa tersambung ke server Oblivion di VPS tanpa perlu recompile,
//  apa pun konfigurasi server game-nya (lokal / rAthena). Prioritas (atas menang):
//
//   1. Environment variable
//        OBLIVION_SERVER / OBLIVION_SERVERS = "host:port,host2:port2"
//        OBLIVION_PORT                      = port default bila spec tanpa port
//        OBLIVION_FAIL_MODE                 = open | closed
//        OBLIVION_CONNECT_TIMEOUT_MS, OBLIVION_RETRY_COUNT, OBLIVION_HANDSHAKE_TIMEOUT_MS
//
//   2. File "oblivion.cfg" di folder executable (key=value, '#' = komentar), contoh:
//        server=oblivion.example.com:54321
//        server=103.150.1.10:54321
//        port=54321
//        fail_mode=open
//
//   3. Default di kode (parameter konstruktor), saat ini 127.0.0.1:54321 (dev)
// ============================================================================
namespace {
    struct EndpointSpec {
        std::string host;
        int port = 0;
    };

    struct NetworkConfiguration {
        std::vector<EndpointSpec> endpoints;
        int defaultPort = 54321;
        bool failClosed = false;
        // true bila endpoint berasal dari konfigurasi yang bisa diubah pemain
        // (oblivion.cfg / environment variable), bukan dari build yang di-pin admin.
        bool endpointsFromLocalConfig = false;
        int connectTimeoutMs = 3000;
        int retryCount = 3;
        int handshakeTimeoutMs = 4000;
    };

    // Bila 0 (default/produksi): endpoint yang berasal dari konfigurasi lokal TIDAK
    // boleh fail-open, sebab pemain yang sudah di-ban cukup mengarahkan endpoint ke
    // alamat mati supaya check-in dianggap "gangguan jaringan" dan proteksi dilewati.
    // Set 1 hanya untuk deployment development yang toleran terhadap downtime server.
#ifndef OBLIVION_ALLOW_LOCAL_ENDPOINT_FAIL_OPEN
#define OBLIVION_ALLOW_LOCAL_ENDPOINT_FAIL_OPEN 0
#endif

    std::string TrimCopy(const std::string& input) {
        const size_t first = input.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            return "";
        }
        const size_t last = input.find_last_not_of(" \t\r\n");
        return input.substr(first, last - first + 1);
    }

    std::string ToLowerAscii(const std::string& input) {
        std::string out = input;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
            return static_cast<char>(::tolower(c));
        });
        return out;
    }

    // Aturan format HWID harus SAMA dengan validasi di server (ParseProtocol):
    // tidak kosong, maksimal 128 karakter, hanya karakter hex + tanda '-'.
    bool IsValidHwidFormat(const std::string& hwid) {
        if (hwid.empty() || hwid.size() > 128) {
            return false;
        }
        for (char c : hwid) {
            if (!std::isxdigit(static_cast<unsigned char>(c)) && c != '-') {
                return false;
            }
        }
        return true;
    }

    // Folder tempat executable (client game) berada; config & log diletakkan di sini.
    std::wstring GetExecutableDirectory() {
        wchar_t pathBuf[MAX_PATH] = {0};
        const DWORD len = GetModuleFileNameW(NULL, pathBuf, MAX_PATH);
        if (len == 0) {
            return L"";
        }
        std::wstring path(pathBuf, len);
        const size_t lastSlash = path.find_last_of(L"\\/");
        return (lastSlash == std::wstring::npos) ? L"" : path.substr(0, lastSlash + 1);
    }

    // Pisahkan "host:port" (port opsional). Mendukung IPv6 dalam kurung: [::1]:54321
    bool SplitHostPort(const std::string& spec, int defaultPort, std::string& outHost, int& outPort) {
        outHost.clear();
        outPort = defaultPort;

        const std::string value = TrimCopy(spec);
        if (value.empty()) {
            return false;
        }

        if (value.front() == '[') {
            const size_t close = value.find(']');
            if (close == std::string::npos) {
                return false;
            }
            outHost = value.substr(1, close - 1);
            if (close + 1 < value.size() && value[close + 1] == ':') {
                try {
                    outPort = std::stoi(value.substr(close + 2));
                } catch (...) {
                    return false;
                }
            }
        } else {
            const size_t colon = value.rfind(':');
            if (colon != std::string::npos && value.find(':') == colon) {
                outHost = value.substr(0, colon);
                try {
                    outPort = std::stoi(value.substr(colon + 1));
                } catch (...) {
                    return false;
                }
            } else {
                outHost = value;
            }
        }

        if (outPort <= 0 || outPort > 65535) {
            return false;
        }
        return !outHost.empty();
    }

    // Daftar endpoint dipisah koma / titik-koma / spasi.
    void AppendEndpointList(NetworkConfiguration& cfg, const std::string& list) {
        std::string token;
        for (size_t i = 0; i <= list.size(); ++i) {
            const bool isSeparator = (i == list.size()) || list[i] == ',' || list[i] == ';' ||
                                     list[i] == ' ' || list[i] == '\t' || list[i] == '\r' || list[i] == '\n';
            if (!isSeparator) {
                token.push_back(list[i]);
                continue;
            }

            if (!token.empty()) {
                std::string host;
                int port = cfg.defaultPort;
                if (SplitHostPort(token, cfg.defaultPort, host, port)) {
                    cfg.endpoints.push_back({host, port});
                }
                token.clear();
            }
        }
    }

    int ReadEnvInt(const char* name, int currentValue) {
        char buf[64] = {0};
        const DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
        if (n == 0 || n >= sizeof(buf)) {
            return currentValue;
        }
        try {
            return std::stoi(TrimCopy(std::string(buf, n)));
        } catch (...) {
            return currentValue;
        }
    }

    NetworkConfiguration LoadNetworkConfiguration(const std::string& fallbackHost, int fallbackPort) {
        NetworkConfiguration cfg;
        cfg.defaultPort = fallbackPort;

        // ---- 1) File oblivion.cfg (dua pass supaya urutan baris tidak penting) ----
        std::vector<std::pair<std::string, std::string>> fileEntries;
        std::ifstream configFile(GetExecutableDirectory() + L"oblivion.cfg");
        if (configFile.is_open()) {
            std::string line;
            while (std::getline(configFile, line)) {
                const std::string trimmed = TrimCopy(line);
                if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
                    continue;
                }
                const size_t eq = trimmed.find('=');
                if (eq == std::string::npos) {
                    continue;
                }
                fileEntries.emplace_back(ToLowerAscii(TrimCopy(trimmed.substr(0, eq))),
                                         TrimCopy(trimmed.substr(eq + 1)));
            }
        }

        for (const auto& entry : fileEntries) {
            if (entry.first != "port") {
                continue;
            }
            try {
                const int port = std::stoi(entry.second);
                if (port > 0 && port <= 65535) {
                    cfg.defaultPort = port;
                }
            } catch (...) {
            }
        }

        for (const auto& entry : fileEntries) {
            if (entry.first == "server" || entry.first == "servers" || entry.first == "host") {
                const size_t endpointsBefore = cfg.endpoints.size();
                AppendEndpointList(cfg, entry.second);
                if (cfg.endpoints.size() > endpointsBefore) {
                    cfg.endpointsFromLocalConfig = true;
                }
            } else if (entry.first == "fail_mode" || entry.first == "strict_net") {
                const std::string v = ToLowerAscii(entry.second);
                cfg.failClosed = (v == "closed" || v == "strict" || v == "1" || v == "true" || v == "on");
            } else if (entry.first == "connect_timeout_ms") {
                try { cfg.connectTimeoutMs = std::stoi(entry.second); } catch (...) {}
            } else if (entry.first == "retry_count") {
                try { cfg.retryCount = std::stoi(entry.second); } catch (...) {}
            } else if (entry.first == "handshake_timeout_ms" || entry.first == "report_timeout_ms") {
                try { cfg.handshakeTimeoutMs = std::stoi(entry.second); } catch (...) {}
            }
        }

        // ---- 2) Environment variable (menimpa file config) ----
        cfg.defaultPort = ReadEnvInt("OBLIVION_PORT", cfg.defaultPort);

        char envSpec[2048] = {0};
        DWORD specLen = GetEnvironmentVariableA("OBLIVION_SERVERS", envSpec, sizeof(envSpec));
        if (specLen == 0 || specLen >= sizeof(envSpec)) {
            specLen = GetEnvironmentVariableA("OBLIVION_SERVER", envSpec, sizeof(envSpec));
        }
        if (specLen > 0 && specLen < sizeof(envSpec)) {
            cfg.endpoints.clear();
            AppendEndpointList(cfg, std::string(envSpec, specLen));
            if (!cfg.endpoints.empty()) {
                cfg.endpointsFromLocalConfig = true;
            }
        }

        char envMode[32] = {0};
        const DWORD modeLen = GetEnvironmentVariableA("OBLIVION_FAIL_MODE", envMode, sizeof(envMode));
        if (modeLen > 0 && modeLen < sizeof(envMode)) {
            const std::string v = ToLowerAscii(TrimCopy(std::string(envMode, modeLen)));
            cfg.failClosed = (v == "closed" || v == "strict" || v == "1" || v == "true" || v == "on");
        }

        cfg.connectTimeoutMs = ReadEnvInt("OBLIVION_CONNECT_TIMEOUT_MS", cfg.connectTimeoutMs);
        cfg.retryCount = ReadEnvInt("OBLIVION_RETRY_COUNT", cfg.retryCount);
        cfg.handshakeTimeoutMs = ReadEnvInt("OBLIVION_HANDSHAKE_TIMEOUT_MS", cfg.handshakeTimeoutMs);

        // Batas aman supaya nilai config yang salah tidak membuat client "hang"
        if (cfg.connectTimeoutMs < 500) cfg.connectTimeoutMs = 500;
        if (cfg.connectTimeoutMs > 30000) cfg.connectTimeoutMs = 30000;
        if (cfg.retryCount < 1) cfg.retryCount = 1;
        if (cfg.retryCount > 10) cfg.retryCount = 10;
        if (cfg.handshakeTimeoutMs < 500) cfg.handshakeTimeoutMs = 500;
        if (cfg.handshakeTimeoutMs > 30000) cfg.handshakeTimeoutMs = 30000;

        // ---- 3) Default dari kode (fallback terakhir) ----
        if (cfg.endpoints.empty()) {
            AppendEndpointList(cfg, fallbackHost + ":" + std::to_string(cfg.defaultPort));
        }

        return cfg;
    }
}

namespace Oblivion {
    NetworkReporter::NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey)
        : m_serverIP(serverIP), m_serverPort(serverPort), m_secretKey(secretKey), m_hbSocket(INVALID_SOCKET) {
        // Lock untuk antrian laporan yang gagal terkirim (dipakai lintas thread pelaporan).
        InitializeCriticalSection(&m_pendingLock);

        // Resolusi konfigurasi jaringan (oblivion.cfg -> environment -> default kode)
        // dilakukan lebih dulu supaya daftar endpoint & fail_mode siap sebelum koneksi pertama.
        LoadConfiguration();

        // Inisialisasi Winsock sekali saja untuk seluruh aplikasi
        // Catatan: WSAStartup bisa dipanggil beberapa kali, setiap panggilan harus diikuti WSACleanup
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        // Jika WSAStartup gagal, gunakan fallback (jangan tutup aplikasi di constructor)
        if (iResult != 0) {
            m_hwid = "UNKNOWN";
            return;
        }
        
        // --- GENERATE HWID SAAT PEMBUATAN OBJEK ---
        // Gunakan try-catch untuk menangani error dari WMI atau hashing
        try {
            m_hwid = HWIDGenerator::Generate();
            // Jika Generate() mengembalikan string kosong, gunakan fallback
            if (m_hwid.empty()) {
                m_hwid = "UNKNOWN";
            }
        } catch (...) {
            // Jika ada exception (misalnya dari WMI), gunakan fallback
            m_hwid = "UNKNOWN";
        }

        // Validasi format: HWID yang tidak sah ("UNKNOWN") akan DITOLAK server
        // dengan ERROR:INVALID_FORMAT. Tandai supaya check-in tidak dikirim dan
        // kegagalannya diperlakukan sebagai masalah infrastruktur (bukan cheat).
        m_hwidValid = IsValidHwidFormat(m_hwid);
        if (!m_hwidValid) {
            std::cerr << "[WARN] HWID tidak valid/tidak dapat digenerate: '" << m_hwid << "'" << std::endl;
        }
    }

    NetworkReporter::~NetworkReporter() {
        // Stop heartbeat dan cleanup socket
        StopHeartbeat();
        if (m_hbSocket != INVALID_SOCKET) {
            closesocket(m_hbSocket);
            m_hbSocket = INVALID_SOCKET;
        }
        // Cleanup antrian laporan & Winsock saat DLL dibongkar
        DeleteCriticalSection(&m_pendingLock);
        WSACleanup();
    }

    void NetworkReporter::SetStatusProvider(std::function<ClientStatus()> provider) {
        // Dipasang oleh dllmain; dipakai thread heartbeat untuk mengisi status pada PONG.
        m_statusProvider = std::move(provider);
    }

    void NetworkReporter::LoadConfiguration() {
        const NetworkConfiguration cfg = LoadNetworkConfiguration(m_serverIP, m_serverPort);

        m_endpoints.clear();
        m_endpoints.reserve(cfg.endpoints.size());
        for (const auto& ep : cfg.endpoints) {
            m_endpoints.push_back(Endpoint{ep.host, ep.port});
        }
        if (m_endpoints.empty()) {
            // Minimal satu endpoint supaya check-in tidak pernah "mati total".
            m_endpoints.push_back(Endpoint{m_serverIP, m_serverPort});
        }

        m_activeEndpoint = 0;
        m_failClosed = cfg.failClosed;

#if !OBLIVION_ALLOW_LOCAL_ENDPOINT_FAIL_OPEN
        // KEBIJAKAN KEAMANAN: endpoint yang berasal dari konfigurasi pemain
        // (oblivion.cfg / env) tidak boleh fail-open, karena pemain yang sudah
        // di-ban cukup mengarahkannya ke alamat mati sehingga client berjalan
        // tanpa sesi, tanpa ban-check, dan tanpa heartbeat.
        if (cfg.endpointsFromLocalConfig) {
            m_failClosed = true;
            std::cout << "[NET] Endpoint berasal dari konfigurasi lokal -> fail_mode dipaksa 'closed'" << std::endl;
        }
#endif
        m_connectTimeoutMs = cfg.connectTimeoutMs;
        m_retryCount = cfg.retryCount;
        m_handshakeTimeoutMs = cfg.handshakeTimeoutMs;

        std::cout << "[NET] Config: " << m_endpoints.size() << " endpoint, fail_mode="
                  << (m_failClosed ? "closed" : "open")
                  << ", connectTimeout=" << m_connectTimeoutMs << "ms"
                  << ", handshakeTimeout=" << m_handshakeTimeoutMs << "ms"
                  << ", retry=" << m_retryCount << std::endl;
        for (const auto& ep : m_endpoints) {
            std::cout << "[NET]   endpoint " << ep.host << ":" << ep.port << std::endl;
        }
    }

    SOCKET NetworkReporter::ConnectWithTimeout(const std::string& host, int port) const {
        struct addrinfo hints;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo* result = NULL;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
            return INVALID_SOCKET;
        }

        SOCKET connected = INVALID_SOCKET;
        for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            SOCKET candidate = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (candidate == INVALID_SOCKET) {
                continue;
            }

            // Connect non-blocking + select supaya client tidak ikut menunggu TCP timeout
            // default Windows (bisa > 20 detik) ketika server/VPS tidak merespons.
            u_long nonBlocking = 1;
            if (ioctlsocket(candidate, FIONBIO, &nonBlocking) != 0) {
                closesocket(candidate);
                continue;
            }

            bool ok = (connect(candidate, ptr->ai_addr, (int)ptr->ai_addrlen) == 0);
            if (!ok) {
                const int lastError = WSAGetLastError();
                if (lastError == WSAEWOULDBLOCK || lastError == WSAEINPROGRESS) {
                    fd_set writeSet;
                    FD_ZERO(&writeSet);
                    FD_SET(candidate, &writeSet);
                    struct timeval tv;
                    tv.tv_sec = m_connectTimeoutMs / 1000;
                    tv.tv_usec = (m_connectTimeoutMs % 1000) * 1000;
                    if (select(0, NULL, &writeSet, NULL, &tv) > 0 && FD_ISSET(candidate, &writeSet)) {
                        int soError = 0;
                        int soErrorLen = (int)sizeof(soError);
                        if (getsockopt(candidate, SOL_SOCKET, SO_ERROR, (char*)&soError, &soErrorLen) == 0 && soError == 0) {
                            ok = true;
                        }
                    }
                }
            }

            if (!ok) {
                closesocket(candidate);
                continue;
            }

            // Kembalikan ke blocking mode: check-in & heartbeat memakai recv/send sederhana.
            u_long blocking = 0;
            ioctlsocket(candidate, FIONBIO, &blocking);
            connected = candidate;
            break;
        }

        freeaddrinfo(result);
        return connected;
    }

    SOCKET NetworkReporter::ConnectToAnyEndpoint(std::string& outHost, int& outPort) {
        outHost.clear();
        outPort = 0;
        if (m_endpoints.empty()) {
            return INVALID_SOCKET;
        }

        const size_t endpointCount = m_endpoints.size();
        const int attempts = (m_retryCount < 1) ? 1 : m_retryCount;

        for (int attempt = 0; attempt < attempts; ++attempt) {
            for (size_t i = 0; i < endpointCount; ++i) {
                // Mulai dari endpoint yang terakhir berhasil supaya server utama tetap dipakai.
                const size_t index = (m_activeEndpoint + i) % endpointCount;
                const Endpoint& ep = m_endpoints[index];
                SOCKET s = ConnectWithTimeout(ep.host, ep.port);
                if (s == INVALID_SOCKET) {
                    continue;
                }
                m_activeEndpoint = index;
                outHost = ep.host;
                outPort = ep.port;
                return s;
            }

            // Jeda singkat sebelum putaran percobaan berikutnya.
            if (attempt + 1 < attempts) {
                Sleep(300);
            }
        }

        return INVALID_SOCKET;
    }

    bool NetworkReporter::PerformCheckin(SOCKET s, bool& isBanned, std::string& errorOut) {
        isBanned = false;
        errorOut.clear();

        // Format check-in yang dipakai server: "CHECKIN::HWID:SECRET;"
        const std::string checkin = "CHECKIN::" + m_hwid + ":" + m_secretKey + ";";
        if (send(s, checkin.c_str(), (int)checkin.length(), 0) <= 0) {
            errorOut = "send() gagal saat check-in";
            return false;
        }

        // Tunggu keputusan server dengan timeout yang bisa dikonfigurasi.
        char recvbuf[512] = { 0 };
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(s, &fdset);
        struct timeval tv;
        tv.tv_sec = m_handshakeTimeoutMs / 1000;
        tv.tv_usec = (m_handshakeTimeoutMs % 1000) * 1000;

        if (select(0, &fdset, NULL, NULL, &tv) <= 0) {
            errorOut = "timeout menunggu respons check-in";
            return false;
        }

        const int bytesReceived = recv(s, recvbuf, (int)sizeof(recvbuf) - 1, 0);
        if (bytesReceived <= 0) {
            errorOut = "koneksi ditutup server saat check-in";
            return false;
        }

        // Parse respons: buang null terminator lalu trim whitespace.
        std::string response(recvbuf, bytesReceived);
        response.erase(std::remove(response.begin(), response.end(), '\0'), response.end());
        const size_t start = response.find_first_not_of(" \t\n\r");
        if (start != std::string::npos) {
            response = response.substr(start);
        }
        const size_t end = response.find_last_not_of(" \t\n\r");
        if (end != std::string::npos) {
            response = response.substr(0, end + 1);
        }

        std::string responseUpper = response;
        std::transform(responseUpper.begin(), responseUpper.end(), responseUpper.begin(), ::toupper);

        // Ambil token pertama (sebelum ';') saja. Sebelumnya kode memakai
        // responseUpper.find("KICK") di SELURUH respons, sehingga teks apa pun yang
        // mengandung "KICK" dianggap ban dan client langsung menampilkan
        // "HWID Anda telah di-ban" lalu menutup diri.
        const size_t firstSemi = responseUpper.find(';');
        const std::string firstToken =
            responseUpper.substr(0, firstSemi == std::string::npos ? responseUpper.size() : firstSemi);

        const bool startsWithKick = (firstToken.rfind("KICK", 0) == 0);
        const bool startsWithOk = (firstToken.rfind("OK", 0) == 0);
        const bool isAuthError = (firstToken.rfind("ERROR:AUTH", 0) == 0);

        if (startsWithKick) {
            // Server hanya mengirim KICK untuk HWID yang memang ada di bans.txt.
            isBanned = true;
            return true;
        }

        if (isAuthError) {
            // PENTING: ini BUKAN ban. Server mengirim ERROR:AUTH saat secret client
            // dan server tidak cocok (secret.dat berbeda / OBLIVION_SECRET salah),
            // sehingga pesan "di-ban" ke seluruh pemain tidak boleh muncul.
            errorOut = "autentikasi ditolak server (secret/config tidak cocok): " + response;
            return false;
        }

        if (!startsWithOk) {
            errorOut = "respons server tidak dikenali: " + response;
            return false;
        }

        // OK: ambil SESSION_NONCE yang dipakai untuk menurunkan session key heartbeat.
        const std::string nonceField = "SESSION_NONCE:";
        m_sessionNonce = 0;
        const size_t posSN = response.find(nonceField);
        if (posSN != std::string::npos) {
            const size_t snStart = posSN + nonceField.size();
            const size_t snEnd = response.find(';', posSN);
            const std::string sn = response.substr(snStart,
                snEnd == std::string::npos ? std::string::npos : snEnd - snStart);
            try { m_sessionNonce = std::stoull(sn); } catch (...) { m_sessionNonce = 0; }
        }

        return true;
    }

    bool NetworkReporter::CheckBanStatus() {
        // HWID harus sah lebih dulu: HWID "UNKNOWN" (WMI gagal) pasti ditolak server
        // dengan ERROR:INVALID_FORMAT, sehingga check-in tidak ada gunanya dan
        // kegagalannya BUKAN bukti kecurangan.
        if (!m_hwidValid) {
            const std::string reason = "HWID tidak valid / gagal digenerate - check-in dilewati";
            LogClientIssue("HWID_INVALID", reason);
            if (m_failClosed) {
                MessageBoxW(NULL, L"Gagal mengidentifikasi perangkat (HWID).\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }
            std::cerr << "[WARN] " << reason << " (fail-open)" << std::endl;
            return true;
        }

        // Check-in ke server: memastikan sesi sah dan HWID tidak sedang diban.
        std::string activeHost;
        int activePort = 0;
        SOCKET connectSocket = ConnectToAnyEndpoint(activeHost, activePort);

        if (connectSocket == INVALID_SOCKET) {
            // Seluruh endpoint gagal. Ini kegagalan infrastruktur, bukan bukti cheat,
            // sehingga kebijakannya ditentukan oleh fail_mode (default: fail-open).
            const std::string reason = "Semua endpoint keamanan tidak dapat dihubungi";
            LogClientIssue("SERVER_UNREACHABLE", reason);
            if (m_failClosed) {
                MessageBoxW(NULL, L"Tidak dapat terhubung ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }
            std::cerr << "[WARN] " << reason << " - check-in dilewati (fail-open)" << std::endl;
            return true;
        }

        std::cout << "[NET] Check-in ke " << activeHost << ":" << activePort << std::endl;

        // Handshake: kirim check-in lalu baca keputusan server (OK / KICK).
        bool isBanned = false;
        std::string handshakeError;
        const bool handshakeOk = PerformCheckin(connectSocket, isBanned, handshakeError);

        if (!handshakeOk) {
            // Handshake gagal = kegagalan infrastruktur, bukan bukti cheat.
            closesocket(connectSocket);
            LogClientIssue("CHECKIN_FAILED", handshakeError);
            if (m_failClosed) {
                MessageBoxW(NULL, L"Gagal melakukan check-in ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }
            std::cerr << "[WARN] Check-in gagal (" << handshakeError << ") - dilanjutkan (fail-open)" << std::endl;
            return true;
        }

        if (isBanned) {
            // HWID di-ban: tutup socket lalu akhiri sesi pemain.
            closesocket(connectSocket);
            MessageBoxW(NULL, L"HWID Anda telah di-ban dari server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Banned", MB_OK | MB_ICONERROR | MB_TOPMOST);

            Sleep(100); // Beri waktu singkat untuk MessageBox ditutup

            ExitProcess(0); // Paksa tutup proses

            // Fallback jika ExitProcess tidak bekerja
            TerminateProcess(GetCurrentProcess(), 0);

            // Tidak akan sampai di sini
            return false;
        }

        // Sesi sah (server menjawab OK): pakai socket yang sama untuk heartbeat.
        m_hbSocket = connectSocket;
        StartHeartbeat();
        return true; // Jangan close socket, akan digunakan untuk heartbeat
    }

    // --- HEARTBEAT IMPLEMENTATION (basic ping/pong) ---
    // Secure HMAC-SHA256 via Windows CNG (bcrypt)
    static std::string HmacSha256(const std::string& key, const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
        if (status != 0) return std::string();
        DWORD objLen = 0, dataLen = 0;
        (void)BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dataLen, 0);
        std::vector<UCHAR> obj(objLen);
        status = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
        status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
        UCHAR hash[32];
        status = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) return std::string();
        static const char* hex = "0123456789abcdef";
        std::string out; out.reserve(64);
        for (int i = 0; i < 32; ++i) { out.push_back(hex[(hash[i]>>4)&0xF]); out.push_back(hex[hash[i]&0xF]); }
        return out;
    }

    void NetworkReporter::StartHeartbeat() {
        // CATATAN KEAMANAN: heartbeat TIDAK bisa dimatikan lewat environment variable
        // (sebelumnya OBLV_HB_DISABLE = 0 memungkinkan pemain menonaktifkan lapisan
        // ini sepenuhnya). Override timing (interval/jitter/timeout) tetap diizinkan
        // karena tidak menghilangkan lapisan proteksinya.
        if (m_hbSocket == INVALID_SOCKET) return; // No socket available
        if (m_hbThread.joinable()) return;        // Sudah berjalan

        m_hbRunning = true;

        m_hbThread = std::thread([this]() {
            const SOCKET s = m_hbSocket; // Socket tetap milik objek ini, bukan thread
            
            // Derive session key: key' = HMAC_SHA256(secretKey, hwid|nonce)
            std::string sessionKey = HmacSha256(m_secretKey, m_hwid + ":" + std::to_string(m_sessionNonce));

            // Heartbeat loop: receive Ping, reply Pong
            Oblivion::HeartbeatConfig cfg;
            // Optional client-side overrides
            auto readEnvUint = [](const char* name, uint32_t defVal){
                char buf[64]; DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
                if (n == 0 || n >= sizeof(buf)) return defVal; 
                try { return (uint32_t)std::stoul(std::string(buf)); } catch (...) { return defVal; }
            };
            cfg.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", cfg.interval_ms);
            cfg.jitter_ms = readEnvUint("OBLV_HB_JITTER_MS", cfg.jitter_ms);
            cfg.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", cfg.timeout_ms);
            uint32_t lastSeq = 0;
            while (m_hbRunning) {
                // Wait for server ping line: PING:seq:ts:nonce;
                char buf[256] = {0};
                int n = recv(s, buf, sizeof(buf)-1, 0);
                if (n <= 0) break;
                std::string msg(buf, n);
                
                // Handle multiple PING messages in one recv (buffer may contain multiple messages)
                size_t pos = 0;
                while (pos < msg.length()) {
                    size_t pingStart = msg.find("PING:", pos);
                    if (pingStart == std::string::npos) break;
                    
                    size_t pingEnd = msg.find(';', pingStart);
                    if (pingEnd == std::string::npos) break;
                    
                    std::string singlePing = msg.substr(pingStart, pingEnd - pingStart);
                    
                    // Parse this single PING
                    // PING:seq:ts:nonce
                    size_t p1 = singlePing.find(':');
                    size_t p2 = singlePing.find(':', p1+1);
                    size_t p3 = singlePing.find(':', p2+1);
                    if (p1!=std::string::npos && p2!=std::string::npos && p3!=std::string::npos) {
                        try {
                            uint32_t seq = std::stoul(singlePing.substr(p1+1, p2-p1-1));
                            uint64_t ts = std::stoull(singlePing.substr(p2+1, p3-p2-1));
                            uint64_t nonce = std::stoull(singlePing.substr(p3+1)); // Ambil sisanya setelah p3
                            lastSeq = seq;

                            // Build client status dari provider yang dipasang dllmain.
                            // Tanpa provider, status di-default true (fail-open) karena
                            // komponen pengawas melaporkan sendiri saat mendeteksi masalah.
                            Oblivion::ClientStatus st = m_statusProvider
                                ? m_statusProvider()
                                : Oblivion::ClientStatus{true, true};
                            // Compose data string for HMAC
                            std::string data = std::to_string(seq) + ":" + std::to_string(ts) + ":" + std::to_string(nonce) + ":" + m_hwid;
                            std::string hmac = HmacSha256(sessionKey, data);

                            // Send PONG line: PONG:seq:ts_client:nonce:statusAS|statusIG:hwid:hmac;
                            uint64_t t_client = (uint64_t)GetTickCount64();
                            std::string statusStr = std::string(st.antiSuspendOk?"1":"0") + std::string("|") + (st.integrityOk?"1":"0");
                            std::string pong = "PONG:" + std::to_string(seq) + ":" + std::to_string(t_client) + ":" + std::to_string(nonce) + ":" + statusStr + ":" + m_hwid + ":" + hmac + ";";
                            send(s, pong.c_str(), (int)pong.length(), 0);
                        } catch (const std::exception&) {
                            // Parse error, skip this PING
                        }
                    }
                    
                    pos = pingEnd + 1;
                }
            }
            // JANGAN menutup socket di sini. Pemilik socket adalah StopHeartbeat()
            // dan destruktor; menutupnya dari thread ini menyebabkan double-close dan
            // berpotensi menutup handle socket yang sudah dipakai ulang pihak lain.
            m_hbRunning = false;
        });
    }

    void NetworkReporter::StopHeartbeat() {
        m_hbRunning = false;

        // shutdown() membangunkan recv() yang sedang blocking supaya thread bisa
        // keluar; tanpa ini join() bisa menggantung selamanya.
        if (m_hbSocket != INVALID_SOCKET) {
            shutdown(m_hbSocket, SD_BOTH);
        }

        // join() tanpa syarat: thread harus benar-benar berhenti sebelum objek
        // (dan anggota-anggotanya) dihancurkan.
        if (m_hbThread.joinable()) {
            m_hbThread.join();
        }
    }

    void NetworkReporter::ReportViolation(const std::string& type, const std::string& details) {
        // Best-effort: kirim laporan pelanggaran ke server. Pemanggil
        // (ReportViolationAndExit) yang menentukan sanction lokal, sehingga di sini
        // kegagalan jaringan HANYA dicatat + diantrikan, bukan menutup proses.
        std::string activeHost;
        int activePort = 0;
        SOCKET connectSocket = ConnectToAnyEndpoint(activeHost, activePort);

        if (connectSocket == INVALID_SOCKET) {
            // --- SERVER TIDAK TERHUBUNG ---
            // Laporan disimpan ke antrian memori + log lokal supaya jejaknya tidak
            // hilang walaupun server sedang tidak dapat dihubungi.
            QueuePendingViolation(type, details);
            LogClientIssue("VIOLATION_REPORT_UNREACHABLE", type + " - " + details);
            std::cerr << "[WARN] Laporan " << type << " tidak terkirim (server tidak terhubung)" << std::endl;
            return;
        }

        std::cout << "[NET] Melaporkan " << type << " ke " << activeHost << ":" << activePort << std::endl;

        // --- FORMAT LAPORAN BARU MENGGUNAKAN HWID ---
        // Sanitasi details: replace colon dengan pipe untuk menghindari konflik parsing
        std::string sanitizedDetails = details;
        for (char& c : sanitizedDetails) {
            if (c == ':') c = '|';  // Replace colon dengan pipe
            if (c == ';') c = ',';  // Replace semicolon dengan comma (delimiter utama)
        }
        
        std::string report = type + ":" + sanitizedDetails + ":" + m_hwid + ":" + m_secretKey + ";";
        int bytesSent = send(connectSocket, report.c_str(), (int)report.length(), 0);
        if (bytesSent == SOCKET_ERROR || bytesSent == 0) {
            // Gagal kirim = kegagalan jaringan, bukan bukti cheat -> antrikan saja.
            closesocket(connectSocket);
            QueuePendingViolation(type, details);
            LogClientIssue("VIOLATION_SEND_FAILED", type);
            std::cerr << "[WARN] Gagal mengirim laporan " << type << " - diantrikan" << std::endl;
            return;
        }

        // Tunggu keputusan server dengan timeout.
        char recvbuf[512] = { 0 };
        fd_set fdset;
        struct timeval tv;
        tv.tv_sec = m_handshakeTimeoutMs / 1000;
        tv.tv_usec = (m_handshakeTimeoutMs % 1000) * 1000;
        FD_ZERO(&fdset);
        FD_SET(connectSocket, &fdset);

        const int selectResult = select(0, &fdset, NULL, NULL, &tv);
        if (selectResult <= 0) {
            // Timeout menunggu keputusan server: laporan sudah terkirim, jadi cukup
            // dicatat. Sanction lokal tetap ditangani pemanggil (ReportViolationAndExit).
            closesocket(connectSocket);
            LogClientIssue("VIOLATION_ACK_TIMEOUT", type);
            std::cerr << "[WARN] Timeout menunggu respons server untuk " << type << std::endl;
            return;
        }

        const int bytesReceived = recv(connectSocket, recvbuf, (int)sizeof(recvbuf) - 1, 0);

        // Socket ditutup tepat sekali, apa pun hasil pembacaan respons.
        closesocket(connectSocket);

        if (bytesReceived > 0) {
            std::string response(recvbuf, bytesReceived);
            // Buang null terminator lalu trim whitespace dari awal dan akhir.
            response.erase(std::remove(response.begin(), response.end(), '\0'), response.end());

            const size_t start = response.find_first_not_of(" \t\n\r");
            if (start != std::string::npos) {
                response = response.substr(start);
            }
            const size_t end = response.find_last_not_of(" \t\n\r");
            if (end != std::string::npos) {
                response = response.substr(0, end + 1);
            }

            // "KICK;" = server menyetujui pelanggaran: tampilkan pesan lalu tutup client.
            if (response == "KICK;") {
                MessageBoxW(NULL, L"Server mendeteksi pelanggaran.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }
        }
    }

    void NetworkReporter::QueuePendingViolation(const std::string& type, const std::string& details) const {
        // Simpan laporan yang gagal terkirim sebagai jejak audit lokal.
        // Dibatasi jumlahnya (best-effort) agar tidak tumbuh tanpa batas.
        const size_t kMaxPending = 32;
        bool queued = false;
        bool isFirstPending = false;

        EnterCriticalSection(&m_pendingLock);
        if (m_pendingViolations.size() < kMaxPending) {
            m_pendingViolations.push_back(std::make_pair(type, details));
            queued = true;
            isFirstPending = (m_pendingViolations.size() == 1);
        }
        LeaveCriticalSection(&m_pendingLock);

        if (isFirstPending) {
            // Catat laporan pertama yang masuk antrian (laporan berikutnya tidak
            // di-log ulang agar file log tidak membanjir).
            LogClientIssue("VIOLATION_QUEUED", type + " - " + details);
        } else if (!queued) {
            LogClientIssue("VIOLATION_QUEUE_FULL", type + " - antrian penuh, laporan tidak diantrikan");
        }
    }

    void NetworkReporter::LogClientIssue(const std::string& type, const std::string& details) const {
        // Catat masalah infrastruktur jaringan ke log lokal (bukan pelanggaran pemain),
        // sehingga admin tetap bisa mengaudit walaupun server sedang tidak bisa dihubungi.
        std::cerr << "[CLIENT_ISSUE] " << type << " - " << details << std::endl;

        wchar_t exePath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
            return;
        }

        wchar_t* lastSlash = wcsrchr(exePath, L'\\');
        if (!lastSlash) {
            return;
        }
        *(lastSlash + 1) = L'\0';

        std::ofstream logFile(std::wstring(exePath) + L"oblivion_client_errors.log", std::ios::app);
        if (!logFile.is_open()) {
            return;
        }

        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << st.wYear << '-' << st.wMonth << '-' << st.wDay << ' '
                << st.wHour << ':' << st.wMinute << ':' << st.wSecond
                << " [" << type << "] " << details << std::endl;
    }
}