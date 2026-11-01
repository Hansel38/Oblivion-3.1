#include "../common/tls_transport.h"

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fcntl.h>
#else
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace {
void CloseSocket(int fd) {
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(fd));
#else
    close(fd);
#endif
}

bool SetNonBlocking(int fd) {
#ifdef _WIN32
    u_long nonBlocking = 1;
    return ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &nonBlocking) == 0;
#else
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

int ConnectTcp(const std::string& host, const std::string& port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) {
        return -1;
    }

    int connected = -1;
    for (addrinfo* item = result; item != nullptr; item = item->ai_next) {
#ifdef _WIN32
        const SOCKET candidate = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (candidate == INVALID_SOCKET) continue;
        if (connect(candidate, item->ai_addr, static_cast<int>(item->ai_addrlen)) == 0) {
            connected = static_cast<int>(candidate);
            break;
        }
        closesocket(candidate);
#else
        const int candidate = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (candidate < 0) continue;
        if (connect(candidate, item->ai_addr, item->ai_addrlen) == 0) {
            connected = candidate;
            break;
        }
        close(candidate);
#endif
    }
    freeaddrinfo(result);
    return connected;
}

bool ExpectPinParserBehavior() {
    std::vector<std::string> pins;
    std::string error;
    const std::string validA(64, 'A');
    const std::string validB(64, 'b');
    if (!Oblivion::Tls::ParseSha256PinList(validA + ";" + validB + "," + validA, pins, error) ||
        pins.size() != 2 || pins[0] != std::string(64, 'a') || pins[1] != validB) {
        std::cerr << "TLS pin parser rejected valid pins or failed normalization/deduplication: " << error << "\n";
        return false;
    }

    const std::vector<std::string> invalidSettings = {
        "", "a", std::string(63, 'a'), std::string(64, 'g'),
        std::string(64, 'a') + ",not-a-pin"
    };
    for (const auto& invalid : invalidSettings) {
        pins.clear();
        error.clear();
        if (Oblivion::Tls::ParseSha256PinList(invalid, pins, error)) {
            std::cerr << "TLS pin parser accepted invalid input\n";
            return false;
        }
    }
    return true;
}
}

int main(int argc, char** argv) {
    if (!ExpectPinParserBehavior()) return 2;

    if (argc != 6) {
        std::cerr << "Usage: tls_client_probe CONNECT_HOST EXPECTED_HOST PORT SHA256_PIN accept|reject\n";
        return 2;
    }

#ifdef _WIN32
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 2;
    }
#endif

    const std::string connectHost = argv[1];
    const std::string expectedHost = argv[2];
    const std::string port = argv[3];
    const std::string pin = argv[4];
    const bool expectAccept = std::strcmp(argv[5], "accept") == 0;
    if (!expectAccept && std::strcmp(argv[5], "reject") != 0) {
        std::cerr << "Expected final argument to be accept or reject\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 2;
    }

    std::vector<std::string> pins;
    std::string error;
    if (!Oblivion::Tls::ParseSha256PinList(pin, pins, error)) {
        std::cerr << "Invalid test pin: " << error << "\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 2;
    }

    const int socketFd = ConnectTcp(connectHost, port);
    if (socketFd < 0) {
        std::cerr << "TCP connection failed\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 3;
    }
    if (!SetNonBlocking(socketFd)) {
        std::cerr << "Could not set TCP socket nonblocking\n";
        CloseSocket(socketFd);
#ifdef _WIN32
        WSACleanup();
#endif
        return 3;
    }

    SSL_CTX* context = Oblivion::Tls::CreateClientContext(error);
    if (context == nullptr) {
        std::cerr << "TLS client context failed: " << error << "\n";
        CloseSocket(socketFd);
#ifdef _WIN32
        WSACleanup();
#endif
        return 3;
    }

    SSL* session = Oblivion::Tls::Connect(
        context, socketFd, expectedHost, pins, error);
    const bool accepted = session != nullptr;
    if (session != nullptr) {
        SSL_free(session);
    }
    SSL_CTX_free(context);
    CloseSocket(socketFd);
#ifdef _WIN32
    WSACleanup();
#endif

    if (accepted != expectAccept) {
        std::cerr << "TLS acceptance mismatch; expected " << (expectAccept ? "accept" : "reject")
                  << ", result was " << (accepted ? "accept" : "reject")
                  << " (" << error << ")\n";
        return 1;
    }
    return 0;
}
