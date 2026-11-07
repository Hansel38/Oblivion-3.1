#include "../common/tls_transport.h"

#include <chrono>
#include <iostream>
#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    std::cout << "TLS handshake deadline socketpair test: skipped on Windows\n";
    return 0;
#else
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        std::cerr << "socketpair failed\n";
        return 1;
    }

    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (context == nullptr) {
        close(sockets[0]);
        close(sockets[1]);
        std::cerr << "SSL_CTX_new failed\n";
        return 2;
    }

    SSL* session = SSL_new(context);
    if (session == nullptr || SSL_set_fd(session, sockets[0]) != 1) {
        if (session != nullptr) SSL_free(session);
        SSL_CTX_free(context);
        close(sockets[0]);
        close(sockets[1]);
        std::cerr << "SSL session setup failed\n";
        return 3;
    }

    std::string error;
    constexpr auto timeout = std::chrono::milliseconds(200);
    const auto started = std::chrono::steady_clock::now();
    const bool completed = Oblivion::Tls::PerformHandshake(
        session, sockets[0], false, error, timeout);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    const int flags = fcntl(sockets[0], F_GETFL, 0);
    const bool socketIsNonBlocking = flags >= 0 && (flags & O_NONBLOCK) != 0;

    SSL_free(session);
    SSL_CTX_free(context);
    close(sockets[0]);
    close(sockets[1]);

    if (completed) {
        std::cerr << "TLS handshake unexpectedly succeeded without a peer handshake\n";
        return 4;
    }
    if (error.find("deadline") == std::string::npos) {
        std::cerr << "TLS handshake did not report its deadline: " << error << '\n';
        return 5;
    }
    if (elapsed < std::chrono::milliseconds(150) ||
        elapsed > std::chrono::seconds(2)) {
        std::cerr << "TLS handshake deadline was not respected; elapsed="
                  << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                  << "ms\n";
        return 6;
    }
    if (!socketIsNonBlocking) {
        std::cerr << "TLS handshake did not make the underlying socket nonblocking\n";
        return 7;
    }

    std::cout << "TLS handshake deadline on initially blocking socket: PASS ("
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
              << "ms)\n";
    return 0;
#endif
}
