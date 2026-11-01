#include "../common/server_listen_port.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
void Expect(bool condition, const char* description) {
    if (!condition) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}
}

int main() {
    std::string port;
    std::string error;

    Expect(Oblivion::ServerConfig::ResolveListenPort(
        nullptr, "54321", port, error) && port == "54321",
        "unset listen port uses the default");
    Expect(Oblivion::ServerConfig::ResolveListenPort(
        "", "54321", port, error) && port == "54321",
        "empty listen port uses the default");
    Expect(Oblivion::ServerConfig::ResolveListenPort(
        "443", "54321", port, error) && port == "443",
        "configured HTTPS-style TCP port is accepted");
    Expect(Oblivion::ServerConfig::ResolveListenPort(
        "65535", "54321", port, error) && port == "65535",
        "maximum TCP port is accepted");
    Expect(Oblivion::ServerConfig::ResolveListenPort(
        "00080", "54321", port, error) && port == "80",
        "valid leading zeroes normalize to the numeric port");

    for (const char* invalid : {
            "0", "65536", "-1", "+443", "54x21", "1.5", " 54321",
            "54321 ", "100000", "123456", "999999999999", "abc"}) {
        port.clear();
        error.clear();
        Expect(!Oblivion::ServerConfig::ResolveListenPort(
            invalid, "54321", port, error) && port.empty() && !error.empty(),
            "invalid explicit listen port is rejected without fallback");
    }

    port.clear();
    error.clear();
    Expect(!Oblivion::ServerConfig::ResolveListenPort(
        nullptr, nullptr, port, error) && !error.empty(),
        "missing default port is rejected");

    std::cout << "Server listen-port configuration tests passed\n";
    return 0;
}
