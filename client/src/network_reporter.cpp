#include "pch.h"
#include "network_reporter.h"
#include "heartbeat_protocol.h"
#include "../../common/heartbeat_auth.h"
#include "hwid_generator.h"
#include "win_path_utils.h"
#include "../../common/tls_transport.h"
#include "../include/production_network_config.generated.h"
#include <memory>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include <algorithm>
#include <limits>
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

    constexpr size_t kMinSharedSecretLength = 32;
    constexpr size_t kMaxSharedSecretLength = 128;
    constexpr size_t kMaxReportDetailsBytes = 2048;

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
        std::string tlsPinSpec;
    };

    // Fail-open dapat melewati pemeriksaan ban ketika server tidak tersedia.
    // Default produksi selalu fail-closed. Hanya build development yang secara
    // eksplisit mendefinisikan macro ini ke 1 yang boleh memakai fail_mode=open.
#ifndef OBLIVION_ALLOW_NETWORK_FAIL_OPEN
#define OBLIVION_ALLOW_NETWORK_FAIL_OPEN 0
#endif

#if defined(OBLIVION_PRODUCTION_BUILD) && OBLIVION_PRODUCTION_BUILD
#if OBLIVION_PRODUCTION_NETWORK_CONFIG_READY != 1
#error Production Release requires a generated, pinned endpoint/TLS policy header
#endif
#if OBLIVION_ALLOW_NETWORK_FAIL_OPEN
#error Production Release must never permit OBLIVION_ALLOW_NETWORK_FAIL_OPEN
#endif
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

    // The HWIDGenerator derives SHA-256, so the wire format is exactly 64 hex characters.
    bool IsValidHwidFormat(const std::string& hwid) {
        if (hwid.size() != 64) {
            return false;
        }
        for (unsigned char c : hwid) {
            if (!std::isxdigit(c)) {
                return false;
            }
        }
        return true;
    }

    // Folder tempat executable (client game) berada; config & log diletakkan di sini.
    std::wstring GetExecutableDirectory() {
        std::vector<wchar_t> pathBuffer(MAX_PATH, L'\0');
        constexpr size_t kMaxPathCapacity = 32768;
        while (pathBuffer.size() <= kMaxPathCapacity) {
            const DWORD len = GetModuleFileNameW(
                NULL, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()));
            if (len == 0) {
                return L"";
            }
            if (static_cast<size_t>(len) < pathBuffer.size()) {
                const std::wstring path(pathBuffer.data(), len);
                const size_t lastSlash = path.find_last_of(L"\\/");
                return lastSlash == std::wstring::npos
                    ? std::wstring()
                    : path.substr(0, lastSlash + 1);
            }
            if (pathBuffer.size() == kMaxPathCapacity) {
                break;
            }
            pathBuffer.resize((std::min)(pathBuffer.size() * 2, kMaxPathCapacity), L'\0');
        }
        return L"";
    }

    // Pisahkan "host:port" (port opsional). Mendukung IPv6 dalam kurung: [::1]:54321
    bool ParsePortStrict(const std::string& text, int& port) {
        if (text.empty()) {
            return false;
        }
        unsigned int parsed = 0;
        for (unsigned char c : text) {
            if (c < '0' || c > '9') {
                return false;
            }
            parsed = parsed * 10U + static_cast<unsigned int>(c - '0');
            if (parsed > 65535U) {
                return false;
            }
        }
        if (parsed == 0U) {
            return false;
        }
        port = static_cast<int>(parsed);
        return true;
    }

    bool SplitHostPort(const std::string& spec, int defaultPort, std::string& outHost, int& outPort) {
        outHost.clear();
        outPort = defaultPort;

        const std::string value = TrimCopy(spec);
        if (value.empty()) {
            return false;
        }

        if (value.front() == '[') {
            const size_t close = value.find(']');
            if (close == std::string::npos || close == 1) {
                return false;
            }
            outHost = value.substr(1, close - 1);
            if (close + 1 < value.size()) {
                if (value[close + 1] != ':' ||
                    !ParsePortStrict(value.substr(close + 2), outPort)) {
                    return false;
                }
            }
        } else {
            const size_t colon = value.rfind(':');
            if (colon != std::string::npos && value.find(':') == colon) {
                outHost = value.substr(0, colon);
                if (!ParsePortStrict(value.substr(colon + 1), outPort)) {
                    return false;
                }
            } else {
                // Unbracketed IPv6 addresses are treated as host-only values.
                outHost = value;
            }
        }

        if (outHost.empty() || outHost.size() > 253) {
            return false;
        }
        for (unsigned char c : outHost) {
            if (std::isspace(c) || c < 0x21 || c > 0x7e || c == '/' || c == '\\') {
                return false;
            }
        }
        return outPort > 0 && outPort <= 65535;
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
        const std::wstring executableDirectory = GetExecutableDirectory();
        std::ifstream configFile;
        // Never let an unresolved executable path turn into a current-working-
        // directory lookup for endpoint or TLS pin configuration.
        if (!executableDirectory.empty()) {
            configFile.open(executableDirectory + L"oblivion.cfg");
        }
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
            else if (entry.first == "tls_pin_sha256") {
                cfg.tlsPinSpec = entry.second;
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

        // Pin override is deliberately strict. An oversized override becomes an
        // invalid setting so it cannot silently fall back to a weaker value.
        char tlsPinEnv[4096] = {};
        const DWORD tlsPinLength =
            GetEnvironmentVariableA("OBLIVION_TLS_PIN_SHA256", tlsPinEnv, sizeof(tlsPinEnv));
        if (tlsPinLength > 0) {
            cfg.tlsPinSpec = tlsPinLength < sizeof(tlsPinEnv)
                ? std::string(tlsPinEnv, tlsPinLength)
                : std::string("INVALID_TLS_PIN_SETTING_TOO_LONG");
        }

        // Batas aman supaya nilai config yang salah tidak membuat client "hang"
        if (cfg.connectTimeoutMs < 500) cfg.connectTimeoutMs = 500;
        if (cfg.connectTimeoutMs > 30000) cfg.connectTimeoutMs = 30000;
        if (cfg.retryCount < 1) cfg.retryCount = 1;
        if (cfg.retryCount > 10) cfg.retryCount = 10;
        if (cfg.handshakeTimeoutMs < 500) cfg.handshakeTimeoutMs = 500;
        if (cfg.handshakeTimeoutMs > 30000) cfg.handshakeTimeoutMs = 30000;

#if defined(OBLIVION_PRODUCTION_BUILD) && OBLIVION_PRODUCTION_BUILD
        // Release builds trust only the generated, reviewed endpoint/pin policy.
        // Editable oblivion.cfg and environment variables remain available to
        // development builds, but cannot redirect production check-in to another server.
        cfg.endpoints.clear();
        AppendEndpointList(cfg, OBLIVION_PRODUCTION_SERVER_ENDPOINTS);
        cfg.tlsPinSpec = OBLIVION_PRODUCTION_TLS_PIN_SHA256;
        cfg.endpointsFromLocalConfig = false;
        cfg.failClosed = true;
        if (cfg.endpoints.empty()) {
            // Never fall back to the constructor's development endpoint in Release.
            cfg.tlsPinSpec.clear();
        }
#else
        // ---- 3) Default dari kode (fallback terakhir) ----
        if (cfg.endpoints.empty()) {
            AppendEndpointList(cfg, fallbackHost + ":" + std::to_string(cfg.defaultPort));
        }
#endif

        return cfg;
    }
    bool WaitForTlsIo(SOCKET socket, SSL* tls, int sslResult, int timeoutMs) {
        const int sslError = SSL_get_error(tls, sslResult);
        if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE) {
            return false;
        }
        fd_set readSet;
        fd_set writeSet;
        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
        if (sslError == SSL_ERROR_WANT_READ) FD_SET(socket, &readSet);
        else FD_SET(socket, &writeSet);
        timeval timeout{};
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;
        return select(0, &readSet, &writeSet, nullptr, &timeout) > 0;
    }

    bool SendAllBytes(SOCKET socket, const std::string& payload, SSL* tls = nullptr) {
        size_t sent = 0;
        while (sent < payload.size()) {
            const size_t remaining = payload.size() - sent;
            const int chunk = static_cast<int>((std::min<size_t>)(remaining, 0x7fffffff));
            const int result = tls
                ? SSL_write(tls, payload.data() + sent, chunk)
                : send(socket, payload.data() + sent, chunk, 0);
            if (tls && result <= 0) {
                if (WaitForTlsIo(socket, tls, result, 5000)) continue;
                return false;
            }
            if (result <= 0 || (!tls && result == SOCKET_ERROR)) return false;
            sent += static_cast<size_t>(result);
        }
        return true;
    }

    size_t CountSemicolons(const std::string& value) {
        return static_cast<size_t>(std::count(value.begin(), value.end(), ';'));
    }

    bool ReceiveSemicolonCount(
        SOCKET socket,
        std::string& buffer,
        size_t requiredCount,
        size_t maxBytes,
        int timeoutMs,
        SSL* tls = nullptr
    ) {
        const ULONGLONG started = GetTickCount64();
        while (CountSemicolons(buffer) < requiredCount) {
            if (buffer.size() >= maxBytes) {
                return false;
            }

            const ULONGLONG elapsed = GetTickCount64() - started;
            if (elapsed >= static_cast<ULONGLONG>(timeoutMs)) {
                return false;
            }

            const int remainingMs = timeoutMs - static_cast<int>(elapsed);
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(socket, &readSet);

            timeval timeout{};
            timeout.tv_sec = remainingMs / 1000;
            timeout.tv_usec = (remainingMs % 1000) * 1000;

            if ((!tls || SSL_pending(tls) <= 0) &&
                select(0, &readSet, nullptr, nullptr, &timeout) <= 0) {
                return false;
            }

            char chunk[256] = {};
            const int received = tls
                ? SSL_read(tls, chunk, static_cast<int>(sizeof(chunk)))
                : recv(socket, chunk, static_cast<int>(sizeof(chunk)), 0);
            if (tls && received <= 0) {
                if (WaitForTlsIo(socket, tls, received, remainingMs)) continue;
                return false;
            }
            if (received <= 0 || (!tls && received == SOCKET_ERROR)) return false;

            if (buffer.size() + static_cast<size_t>(received) > maxBytes) {
                return false;
            }
            buffer.append(chunk, static_cast<size_t>(received));
        }
        return true;
    }

    bool ParseUnsigned64(const std::string& text, uint64_t& value) {
        if (text.empty()) {
            return false;
        }
        uint64_t parsed = 0;
        for (unsigned char c : text) {
            if (c < '0' || c > '9') {
                return false;
            }
            const uint64_t digit = static_cast<uint64_t>(c - '0');
            if (parsed > (UINT64_MAX - digit) / 10ULL) {
                return false;
            }
            parsed = parsed * 10ULL + digit;
        }
        value = parsed;
        return true;
    }


    std::string EncodeProtocolDetails(const std::string& details) {
        // The marker distinguishes the reversible format from legacy reports.
        // Encode '%' first, so a literal "%3A" survives a full round trip.
        static const std::string prefix = "!OBLV1!";
        std::string encoded = prefix;
        const size_t length = (std::min)(details.size(), kMaxReportDetailsBytes);
        encoded.reserve(prefix.size() + length);
        for (size_t i = 0; i < length; ++i) {
            switch (details[i]) {
            case '%': encoded += "%25"; break;
            case ':': encoded += "%3A"; break;
            case ';': encoded += "%3B"; break;
            default: encoded.push_back(details[i]); break;
            }
        }
        return encoded;
    }

}

namespace Oblivion {
    NetworkReporter::NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey)
        : m_serverIP(serverIP), m_serverPort(serverPort), m_secretKey(secretKey), m_hbSocket(INVALID_SOCKET) {
        // Resolve configuration before acquiring OS resources.
        m_secretValid = (m_secretKey.size() >= kMinSharedSecretLength &&
                         m_secretKey.size() <= kMaxSharedSecretLength &&
                         m_secretKey.find_first_of(":;") == std::string::npos);
        LoadConfiguration();

        InitializeCriticalSection(&m_pendingLock);
        m_pendingLockInitialized = true;

        WSADATA wsaData{};
        const int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            m_hwid = "UNKNOWN";
            return;
        }
        m_winsockInitialized = true;

        std::string tlsContextError;
        m_tlsContext = Oblivion::Tls::CreateClientContext(tlsContextError);
        if (m_tlsContext == nullptr) {
            LogClientIssue("TLS_CONTEXT_FAILED", tlsContextError);
        }
        if (m_tlsPins.empty()) {
            LogClientIssue("TLS_PIN_INVALID", m_tlsPinError.empty()
                ? "TLS certificate pin is missing" : m_tlsPinError);
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
        if (m_hbTls != nullptr) {
            SSL_free(m_hbTls);
            m_hbTls = nullptr;
        }
        if (m_hbSocket != INVALID_SOCKET) {
            closesocket(m_hbSocket);
            m_hbSocket = INVALID_SOCKET;
        }
        if (m_tlsContext != nullptr) {
            SSL_CTX_free(m_tlsContext);
            m_tlsContext = nullptr;
        }
        // Release only resources that were successfully initialized.
        if (m_pendingLockInitialized) {
            DeleteCriticalSection(&m_pendingLock);
            m_pendingLockInitialized = false;
        }
        if (m_winsockInitialized) {
            WSACleanup();
            m_winsockInitialized = false;
        }
    }

    void NetworkReporter::SetStatusProvider(std::function<ClientStatus()> provider) {
        // Dipasang oleh dllmain; dipakai thread heartbeat untuk mengisi status pada PONG.
        m_statusProvider = std::move(provider);
    }

    void NetworkReporter::LoadConfiguration() {
        const NetworkConfiguration cfg = LoadNetworkConfiguration(m_serverIP, m_serverPort);

        if (!Oblivion::Tls::ParseSha256PinList(cfg.tlsPinSpec, m_tlsPins, m_tlsPinError)) {
            m_tlsPins.clear();
        } else {
            m_tlsPinError.clear();
        }

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
#if OBLIVION_ALLOW_NETWORK_FAIL_OPEN
        m_failClosed = cfg.failClosed;
#else
        // Jangan izinkan oblivion.cfg/OBLIVION_FAIL_MODE menonaktifkan ban-check
        // hanya dengan mengubah fail_mode menjadi open.
        m_failClosed = true;
        if (!cfg.failClosed) {
            std::cout << "[NET] Production policy: fail_mode dipaksa 'closed'" << std::endl;
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
        const size_t startingEndpoint = m_activeEndpoint.load(std::memory_order_relaxed) % endpointCount;
        const int attempts = (m_retryCount < 1) ? 1 : m_retryCount;

        for (int attempt = 0; attempt < attempts; ++attempt) {
            for (size_t i = 0; i < endpointCount; ++i) {
                // Mulai dari endpoint yang terakhir berhasil supaya server utama tetap dipakai.
                const size_t index = (startingEndpoint + i) % endpointCount;
                const Endpoint& ep = m_endpoints[index];
                SOCKET s = ConnectWithTimeout(ep.host, ep.port);
                if (s == INVALID_SOCKET) {
                    continue;
                }
                m_activeEndpoint.store(index, std::memory_order_relaxed);
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

    bool NetworkReporter::PerformCheckin(SOCKET s, SSL* tls, bool& isBanned, std::string& errorOut) {
        isBanned = false;
        errorOut.clear();

        const std::string checkin = "CHECKIN::" + m_hwid + ":" + m_secretKey + ";";
        if (!SendAllBytes(s, checkin, tls)) {
            errorOut = "gagal mengirim check-in";
            return false;
        }

        // Server mengirim KICK; atau ERROR; sebagai satu token, sedangkan
        // check-in yang berhasil mengirim OK;SESSION_NONCE:<n>;.
        std::string response;
        if (!ReceiveSemicolonCount(s, response, 1, 1024, m_handshakeTimeoutMs, tls)) {
            errorOut = "timeout menunggu respons check-in";
            return false;
        }

        const size_t firstSemi = response.find(';');
        if (firstSemi == std::string::npos) {
            errorOut = "respons check-in tidak lengkap";
            return false;
        }

        std::string firstToken = response.substr(0, firstSemi);
        std::transform(firstToken.begin(), firstToken.end(), firstToken.begin(),
            [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        if (firstToken == "KICK") {
            isBanned = true;
            return true;
        }

        if (firstToken.rfind("ERROR:AUTH", 0) == 0) {
            errorOut = "autentikasi ditolak server (secret/config tidak cocok)";
            return false;
        }

        if (firstToken != "OK") {
            errorOut = "respons server tidak dikenali: " + firstToken;
            return false;
        }

        if (!ReceiveSemicolonCount(s, response, 2, 1024, m_handshakeTimeoutMs, tls)) {
            errorOut = "respons OK tidak menyertakan SESSION_NONCE lengkap";
            return false;
        }

        const size_t secondSemi = response.find(';', firstSemi + 1);
        if (secondSemi == std::string::npos) {
            errorOut = "SESSION_NONCE tidak lengkap";
            return false;
        }

        const std::string nonceField = response.substr(firstSemi + 1, secondSemi - firstSemi - 1);
        const std::string noncePrefix = "SESSION_NONCE:";
        if (nonceField.rfind(noncePrefix, 0) != 0) {
            errorOut = "field SESSION_NONCE tidak ditemukan";
            return false;
        }

        uint64_t nonce = 0;
        if (!ParseUnsigned64(nonceField.substr(noncePrefix.size()), nonce) || nonce == 0) {
            errorOut = "SESSION_NONCE tidak valid";
            return false;
        }

        m_sessionNonce = nonce;
        // Server may have already sent the first PING in the same TCP packet.
        m_pendingHeartbeatData = response.substr(secondSemi + 1);
        return true;
    }

    bool NetworkReporter::CheckBanStatus() {
        if (!m_secretValid) {
            const std::string reason =
                "Shared secret harus memiliki panjang 32 sampai 128 byte dan tidak boleh mengandung ':' atau ';'.";
            LogClientIssue("SECRET_INVALID", reason);
            if (m_failClosed) {
                MessageBoxW(nullptr,
                    L"Konfigurasi secret Oblivion tidak valid.\n\nGunakan secret acak 32 sampai 128 byte yang sama pada client dan server, tanpa ':' atau ';'.",
                    L"Oblivion Hack Shield - Configuration Error",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(1);
            }
            std::cerr << "[WARN] " << reason << " (development fail-open)" << std::endl;
            return true;
        }

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

        if (m_tlsContext == nullptr || m_tlsPins.empty()) {
            const std::string reason = m_tlsContext == nullptr
                ? "TLS client context is unavailable"
                : (m_tlsPinError.empty() ? "TLS certificate pin is missing" : m_tlsPinError);
            LogClientIssue("TLS_CONFIG_INVALID", reason);
            if (m_failClosed) {
                MessageBoxW(nullptr,
                    L"Konfigurasi TLS Oblivion tidak lengkap atau tidak valid.\n\nClient akan ditutup untuk mencegah koneksi tidak terenkripsi.",
                    L"Oblivion Hack Shield - TLS Configuration Error",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(1);
            }
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

        std::cout << "[NET] TLS check-in ke " << activeHost << ":" << activePort << std::endl;

        // OpenSSL's handshake loop uses select against a total deadline.
        u_long tlsNonBlocking = 1;
        if (ioctlsocket(connectSocket, FIONBIO, &tlsNonBlocking) != 0) {
            closesocket(connectSocket);
            LogClientIssue("TLS_SOCKET_MODE_FAILED", "failed to set nonblocking mode before TLS handshake");
            if (m_failClosed) ExitProcess(1);
            return true;
        }

        std::string tlsError;
        SSL* tls = Oblivion::Tls::Connect(
            m_tlsContext, static_cast<int>(connectSocket), activeHost, m_tlsPins, tlsError);

        if (tls == nullptr) {
            closesocket(connectSocket);
            LogClientIssue("TLS_HANDSHAKE_FAILED", tlsError);
            if (m_failClosed) {
                MessageBoxW(nullptr,
                    L"Identitas server keamanan tidak dapat diverifikasi melalui TLS.\n\nClient akan ditutup.",
                    L"Oblivion Hack Shield - TLS Verification Failed",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(1);
            }
            return true;
        }

        // Handshake: send the first protocol frame only after the server
        // certificate pin, expiry and hostname/IP SAN have been validated.
        bool isBanned = false;
        std::string handshakeError;
        const bool handshakeOk = PerformCheckin(connectSocket, tls, isBanned, handshakeError);

        if (!handshakeOk) {
            // Handshake gagal = kegagalan infrastruktur, bukan bukti cheat.
            SSL_free(tls);
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
            // HWID di-ban: tutup TLS lalu akhiri sesi pemain.
            SSL_free(tls);
            closesocket(connectSocket);
            MessageBoxW(NULL, L"HWID Anda telah di-ban dari server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Banned", MB_OK | MB_ICONERROR | MB_TOPMOST);

            Sleep(100); // Beri waktu singkat untuk MessageBox ditutup

            ExitProcess(0); // Paksa tutup proses

            // Fallback jika ExitProcess tidak bekerja
            TerminateProcess(GetCurrentProcess(), 0);

            // Tidak akan sampai di sini
            return false;
        }

        // Sesi sah: keep the authenticated TLS session for all heartbeats.
        m_hbTls = tls;
        m_hbSocket = connectSocket;
        StartHeartbeat();
        return true; // Jangan close socket, akan digunakan untuk heartbeat
    }

    // --- HEARTBEAT IMPLEMENTATION (basic ping/pong) ---
    // Secure HMAC-SHA256 via Windows CNG (bcrypt)
    static std::string HmacSha256(const std::string& key, const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
        if (status != 0 || hAlg == NULL) {
            if (hAlg != NULL) BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::string();
        }

        DWORD objLen = 0;
        DWORD dataLen = 0;
        status = BCryptGetProperty(
            hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen),
            sizeof(objLen), &dataLen, 0);
        if (status != 0 || objLen == 0 || dataLen < sizeof(objLen)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::string();
        }

        std::vector<UCHAR> obj(objLen);
        status = BCryptCreateHash(
            hAlg, &hHash, obj.data(), objLen,
            reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
            static_cast<ULONG>(key.size()), 0);
        if (status != 0 || hHash == NULL) {
            if (hHash != NULL) BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::string();
        }

        status = BCryptHashData(
            hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0);
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::string();
        }

        UCHAR hash[32] = {};
        status = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) return std::string();

        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (int i = 0; i < 32; ++i) {
            out.push_back(hex[(hash[i] >> 4) & 0xF]);
            out.push_back(hex[hash[i] & 0xF]);
        }
        return out;
    }

    void NetworkReporter::StartHeartbeat() {
        if (m_hbSocket == INVALID_SOCKET || m_hbThread.joinable()) {
            return;
        }

        m_hbRunning = true;
        std::string initialData = std::move(m_pendingHeartbeatData);

        try {
        m_hbThread = std::thread([this, receiveBuffer = std::move(initialData), tls = m_hbTls]() mutable {
            const SOCKET socket = m_hbSocket;
            const std::string sessionKey =
                HmacSha256(m_secretKey, m_hwid + ":" + std::to_string(m_sessionNonce));

            if (sessionKey.empty()) {
                LogClientIssue("HEARTBEAT_CRYPTO_FAILED", "gagal membuat session HMAC");
                m_hbRunning = false;
                if (m_failClosed) {
                    MessageBoxW(nullptr, L"Proteksi heartbeat gagal diinisialisasi.\n\nClient akan ditutup.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
                    ExitProcess(1);
                }
                return;
            }

            Oblivion::HeartbeatConfig cfg;
            auto readEnvUint = [](const char* name, uint32_t defaultValue) {
                char value[64] = {};
                const DWORD length = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
                if (length == 0 || length >= sizeof(value)) {
                    return defaultValue;
                }
                try {
                    size_t consumed = 0;
                    const unsigned long parsed = std::stoul(value, &consumed, 10);
                    return consumed == length ? static_cast<uint32_t>(parsed) : defaultValue;
                } catch (...) {
                    return defaultValue;
                }
            };

            cfg.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", cfg.interval_ms);
            cfg.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", cfg.timeout_ms);
            cfg.interval_ms = (std::max)(500U, (std::min)(cfg.interval_ms, 30000U));
            cfg.timeout_ms = (std::max)(500U, (std::min)(cfg.timeout_ms, 30000U));
            const uint64_t receiveTimeout64 =
                static_cast<uint64_t>(cfg.interval_ms) + cfg.timeout_ms + 1500ULL;
            const int receiveTimeoutMs = static_cast<int>((std::min<uint64_t>)(receiveTimeout64, 60000ULL));

            uint32_t lastSequence = 0;
            auto failHeartbeat = [this](const std::string& reason) {
                if (!m_hbRunning.load()) {
                    return;
                }
                LogClientIssue("HEARTBEAT_FAILED", reason);
                m_hbRunning = false;
                if (m_failClosed) {
                    MessageBoxW(nullptr, L"Koneksi heartbeat ke server keamanan terputus.\n\nClient akan ditutup.",
                        L"Oblivion Hack Shield - Connection Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
                    ExitProcess(1);
                }
            };

            while (m_hbRunning.load()) {
                if (!ReceiveSemicolonCount(socket, receiveBuffer, 1, 512, receiveTimeoutMs, tls)) {
                    failHeartbeat("timeout atau koneksi terputus saat menunggu PING");
                    break;
                }

                const size_t frameEnd = receiveBuffer.find(';');
                if (frameEnd == std::string::npos) {
                    failHeartbeat("frame PING tidak lengkap");
                    break;
                }

                const std::string ping = receiveBuffer.substr(0, frameEnd);
                receiveBuffer.erase(0, frameEnd + 1);

                if (ping.rfind("PING:", 0) != 0) {
                    failHeartbeat("menerima frame heartbeat yang tidak dikenal");
                    break;
                }

                const size_t p1 = ping.find(':');
                const size_t p2 = ping.find(':', p1 + 1);
                const size_t p3 = ping.find(':', p2 + 1);
                if (p1 == std::string::npos || p2 == std::string::npos ||
                    p3 == std::string::npos || ping.find(':', p3 + 1) != std::string::npos) {
                    failHeartbeat("format PING tidak valid");
                    break;
                }

                uint64_t sequenceValue = 0;
                uint64_t timestamp = 0;
                uint64_t nonce = 0;
                // Sequence IDs must increase, but gaps are allowed after a lost PONG.
                if (!ParseUnsigned64(ping.substr(p1 + 1, p2 - p1 - 1), sequenceValue) ||
                    sequenceValue > static_cast<uint64_t>((std::numeric_limits<uint32_t>::max)()) ||
                    !ParseUnsigned64(ping.substr(p2 + 1, p3 - p2 - 1), timestamp) ||
                    !ParseUnsigned64(ping.substr(p3 + 1), nonce) ||
                    nonce == 0 || sequenceValue == 0 || sequenceValue <= static_cast<uint64_t>(lastSequence)) {
                    failHeartbeat("sequence, timestamp, atau nonce PING tidak valid");
                    break;
                }

                const uint32_t sequence = static_cast<uint32_t>(sequenceValue);
                Oblivion::ClientStatus status{ false, false };
                try {
                    if (m_statusProvider) {
                        status = m_statusProvider();
                    }
                } catch (...) {
                    status = { false, false };
                }

                const uint64_t clientTimestamp = static_cast<uint64_t>(GetTickCount64());
                const std::string statusText =
                    std::string(status.antiSuspendOk ? "1" : "0") + "|" +
                    (status.integrityOk ? "1" : "0");

                // Authenticate every PONG field (including status) so an observer
                // cannot alter client protection flags without invalidating HMAC.
                const std::string signedData = Oblivion::Protocol::BuildPongAuthPayload(
                    sequence, clientTimestamp, timestamp, nonce, statusText, m_hwid);
                const std::string hmac = HmacSha256(sessionKey, signedData);
                if (hmac.empty()) {
                    failHeartbeat("gagal menghitung HMAC PONG");
                    break;
                }
                const std::string pong =
                    "PONG:" + std::to_string(sequence) + ":" + std::to_string(clientTimestamp) +
                    ":" + std::to_string(nonce) + ":" + statusText + ":" + m_hwid + ":" + hmac + ";";

                if (!SendAllBytes(socket, pong, tls)) {
                    failHeartbeat("gagal mengirim PONG ke server");
                    break;
                }

                lastSequence = sequence;
            }

            m_hbRunning = false;
        });
        } catch (...) {
            m_hbRunning = false;
            throw;
        }
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

        u_long reportNonBlocking = 1;
        if (ioctlsocket(connectSocket, FIONBIO, &reportNonBlocking) != 0) {
            closesocket(connectSocket);
            QueuePendingViolation(type, details);
            LogClientIssue("TLS_SOCKET_MODE_FAILED", "failed to set nonblocking mode for violation report");
            return;
        }

        std::string tlsError;
        SSL* rawTls = Oblivion::Tls::Connect(
            m_tlsContext, static_cast<int>(connectSocket), activeHost, m_tlsPins, tlsError);

        if (rawTls == nullptr) {
            closesocket(connectSocket);
            QueuePendingViolation(type, details);
            LogClientIssue("TLS_REPORT_FAILED", tlsError);
            return;
        }
        std::unique_ptr<SSL, decltype(&SSL_free)> tls(rawTls, &SSL_free);

        std::cout << "[NET] TLS melaporkan " << type << " ke " << activeHost << ":" << activePort << std::endl;

        // Escape protocol delimiters reversibly so paths and detection metadata
        // retain their original ':' / ';' characters in server logs.
        const std::string encodedDetails = EncodeProtocolDetails(details);
        std::string report = type + ":" + encodedDetails + ":" + m_hwid + ":" + m_secretKey + ";";
        if (!SendAllBytes(connectSocket, report, tls.get())) {
            // Gagal kirim = kegagalan jaringan, bukan bukti cheat -> antrikan saja.
            closesocket(connectSocket);
            QueuePendingViolation(type, details);
            LogClientIssue("VIOLATION_SEND_FAILED", type);
            std::cerr << "[WARN] Gagal mengirim laporan " << type << " - diantrikan" << std::endl;
            return;
        }

        // Baca satu frame ACK utuh; TCP dapat memecah "KICK;" menjadi beberapa recv().
        std::string response;
        const bool receivedAck = ReceiveSemicolonCount(
            connectSocket, response, 1, 512, m_handshakeTimeoutMs, tls.get());
        closesocket(connectSocket);

        if (!receivedAck) {
            LogClientIssue("VIOLATION_ACK_TIMEOUT", type);
            std::cerr << "[WARN] Timeout menunggu respons server untuk " << type << std::endl;
            return;
        }

        const size_t ackEnd = response.find(';');
        if (ackEnd == std::string::npos) {
            LogClientIssue("VIOLATION_ACK_INVALID", "Respons server tidak memiliki terminator");
            return;
        }

        const std::string acknowledgement = response.substr(0, ackEnd);
        if (acknowledgement == "KICK") {
            MessageBoxW(nullptr, L"Server mendeteksi pelanggaran.\n\nClient akan ditutup.",
                L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
        } else if (acknowledgement != "ACK") {
            LogClientIssue("VIOLATION_ACK_INVALID", acknowledgement);
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

        // Resolve the complete executable path; MAX_PATH can silently
        // truncate deep game installations and lose infrastructure diagnostics.
        const std::wstring executablePath = Oblivion::WinPath::GetModulePath(nullptr);
        if (executablePath.empty()) {
            return;
        }

        const size_t lastSlash = executablePath.find_last_of(L"\\/");
        if (lastSlash == std::wstring::npos) {
            return;
        }

        const std::wstring logPath =
            executablePath.substr(0, lastSlash + 1) + L"oblivion_client_errors.log";
        std::ofstream logFile(logPath, std::ios::app);
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