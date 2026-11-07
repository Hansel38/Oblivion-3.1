#include "../common/server_yaml_config.h"

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
    using Oblivion::Config::ParseServerYaml;
    using Oblivion::Config::ServerSettings;

    ServerSettings settings;
    std::string error;
    std::istringstream valid(
        "version: 1\n"
        "server:\n"
        "  bind_address: 127.0.0.1\n"
        "  listen_port: 55443\n"
        "tls:\n"
        "  certificate_file: cert.pem\n"
        "  private_key_file: key.pem\n"
        "heartbeat:\n"
        "  interval_ms: 2500\n"
        "  jitter_ms: 100\n"
        "  timeout_ms: 3500\n"
        "  max_consecutive_misses: 4\n"
        "  rtt_warn_ms: 900\n"
        "connections:\n"
        "  max_concurrent_clients: 128\n"
        "  per_ip_burst: 80\n"
        "  per_ip_refill_per_second: 3\n"
        "  max_tracked_ips: 32768\n"
        "  ip_idle_expiration_seconds: 900\n"
        "  ip_cleanup_interval: 128\n");
    Expect(ParseServerYaml(valid, settings, error), "valid server YAML is accepted");
    Expect(settings.bindAddress == "127.0.0.1", "bind address is loaded");
    Expect(settings.listenPort == "55443", "listen port is normalized");
    Expect(settings.tlsCertificateFile == "cert.pem", "TLS certificate path is loaded");
    Expect(settings.tlsPrivateKeyFile == "key.pem", "TLS private key path is loaded");
    Expect(settings.heartbeat.intervalMs == 2500, "heartbeat interval is loaded");
    Expect(settings.heartbeat.jitterMs == 100, "heartbeat jitter is loaded");
    Expect(settings.heartbeat.maxConsecutiveMisses == 4, "heartbeat miss limit is loaded");
    Expect(settings.connections.maxConcurrentClients == 128, "worker limit is loaded");
    Expect(settings.connections.perIpBurst == 80, "per-IP burst is loaded");
    Expect(settings.connections.perIpRefillPerSecond == 3, "per-IP refill rate is loaded");
    Expect(settings.connections.maxTrackedIps == 32768, "IP table capacity is loaded");
    Expect(settings.connections.ipIdleExpirationSeconds == 900, "IP idle expiry is loaded");
    Expect(settings.connections.ipCleanupInterval == 128, "IP cleanup interval is loaded");

    settings = ServerSettings{};
    error.clear();
    std::istringstream defaults("version: 1\n");
    Expect(ParseServerYaml(defaults, settings, error), "minimal valid server YAML is accepted");
    Expect(settings.listenPort == "54321", "default port remains backwards-compatible");
    Expect(settings.bindAddress == "0.0.0.0", "default bind address listens on all IPv4 interfaces");
    Expect(settings.connections.maxConcurrentClients == 256, "default worker limit remains stable");
    Expect(settings.connections.perIpBurst == 120, "default per-IP burst remains stable");

    for (const std::string invalidYaml : {
            "version: 2\n",
            "version: 1\nserver:\n  listen_port: 65536\n",
            "version: 1\nserver:\n  listen_port: 0\n",
            "version: 1\nheartbeat:\n  interval_ms: 200\n",
            "version: 1\nheartbeat:\n  interval_ms: 1000\n  jitter_ms: 1000\n",
            "version: 1\nshared_secret: should-never-be-accepted\n",
            "version: 1\nserver:\n  unknown_key: true\n",
            "version: 1\nserver:\n  bind_address: 999.1.1.1\n",
            "version: 1\nconnections:\n  max_concurrent_clients: 0\n",
            "version: 1\nconnections:\n  max_concurrent_clients: 1025\n",
            "version: 1\nconnections:\n  per_ip_burst: 0\n",
            "version: 1\nconnections:\n  per_ip_refill_per_second: 1001\n",
            "version: 1\nconnections:\n  max_tracked_ips: 1000001\n",
            "version: 1\nconnections:\n  ip_idle_expiration_seconds: 10\n",
            "version: 1\nconnections:\n  ip_cleanup_interval: 0\n",
            "version: 1\nconnections:\n  unknown_key: true\n",
            "version: [not, an, integer]\n"}) {
        settings = ServerSettings{};
        error.clear();
        std::istringstream input(invalidYaml);
        Expect(!ParseServerYaml(input, settings, error) && !error.empty(),
               "invalid server YAML is rejected with a diagnostic");
    }

    settings = ServerSettings{};
    error.clear();
    std::istringstream oversized(std::string(70 * 1024, 'x'));
    Expect(!ParseServerYaml(oversized, settings, error) &&
           error.find("64 KiB") != std::string::npos,
           "oversized server YAML is rejected before parsing");

    std::cout << "Server YAML configuration tests passed\n";
    return 0;
}
