#include "../common/client_yaml_config.h"

#include <cstdlib>
#include <iostream>
#include <sstream>
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
    using Oblivion::Config::ClientSettings;
    using Oblivion::Config::ParseClientYaml;

    ClientSettings settings;
    std::string error;
    std::istringstream valid(
        "version: 1\n"
        "server:\n"
        "  default_port: 54321\n"
        "  endpoints:\n"
        "    - shield.example.com:54321\n"
        "    - 192.0.2.10:54321\n"
        "tls:\n"
        "  pin_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "connection:\n"
        "  connect_timeout_ms: 4500\n"
        "  retry_count: 4\n"
        "  handshake_timeout_ms: 6500\n"
        "policy:\n"
        "  fail_closed: true\n");
    Expect(ParseClientYaml(valid, settings, error), "valid client YAML is accepted");
    Expect(settings.endpoints.size() == 2, "client endpoint list is loaded");
    Expect(settings.endpoints[0] == "shield.example.com:54321", "hostname endpoint remains intact");
    Expect(settings.connectTimeoutMs == 4500, "connection timeout is loaded");
    Expect(settings.retryCount == 4, "retry count is loaded");
    Expect(settings.handshakeTimeoutMs == 6500, "TLS handshake timeout is loaded");
    Expect(settings.failClosed, "fail-closed policy is loaded");
    Expect(settings.tlsPinSha256.size() == 64, "development pin is read from YAML");

    for (const std::string invalidYaml : {
            "version: 2\n",
            "version: 1\nserver:\n  endpoints: shield.example.com:54321\n",
            "version: 1\nserver:\n  endpoints:\n    - ''\n",
            "version: 1\nserver:\n  endpoints:\n    - 'host name:54321'\n",
            "version: 1\nserver:\n  endpoints:\n    - 'host-a:54321,host-b:54321'\n",
            "version: 1\nserver:\n  default_port: 0\n",
            "version: 1\nconnection:\n  retry_count: 0\n",
            "version: 1\nconnection:\n  connect_timeout_ms: 999999\n",
            "version: 1\ntls:\n  pin_sha256: not-a-valid-sha256-pin\n  disable_verification: true\n",
            "version: 1\npolicy:\n  fail_closed: maybe\n",
            "version: 1\nshared_secret: not-allowed-here\n"}) {
        settings = ClientSettings{};
        error.clear();
        std::istringstream input(invalidYaml);
        Expect(!ParseClientYaml(input, settings, error) && !error.empty(),
               "invalid client YAML is rejected with a diagnostic");
    }

    std::cout << "Client YAML configuration tests passed\n";
    return 0;
}
