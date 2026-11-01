#pragma once

#include "server_listen_port.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <istream>
#include <iterator>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace Oblivion {
namespace Config {

constexpr std::size_t kMaxYamlConfigBytes = 64U * 1024U;

struct HeartbeatSettings {
    std::uint32_t intervalMs = 3000;
    std::uint32_t jitterMs = 250;
    std::uint32_t timeoutMs = 4000;
    std::uint32_t maxConsecutiveMisses = 3;
    std::uint32_t rttWarnMs = 1500;
};

struct ServerSettings {
    std::string bindAddress = "0.0.0.0";
    std::string listenPort = "54321";
    std::string tlsCertificateFile = "server-cert.pem";
    std::string tlsPrivateKeyFile = "server-key.pem";
    HeartbeatSettings heartbeat;
};

namespace Detail {

inline bool ReadYamlText(std::istream& input, std::string& text, std::string& error) {
    text.clear();
    error.clear();
    text.resize(kMaxYamlConfigBytes + 1);
    input.read(&text[0], static_cast<std::streamsize>(text.size()));
    const std::streamsize count = input.gcount();
    if (count < 0) {
        error = "unable to read YAML configuration";
        text.clear();
        return false;
    }
    if (static_cast<std::size_t>(count) > kMaxYamlConfigBytes) {
        error = "YAML configuration exceeds 64 KiB";
        text.clear();
        return false;
    }
    if (input.bad()) {
        error = "I/O error while reading YAML configuration";
        text.clear();
        return false;
    }
    text.resize(static_cast<std::size_t>(count));
    return true;
}

inline bool HasOnlyKeys(
    const YAML::Node& node,
    const std::vector<std::string>& allowed,
    const std::string& context,
    std::string& error) {
    if (!node || !node.IsMap()) {
        error = context + " must be a YAML mapping";
        return false;
    }

    std::set<std::string> seenKeys;
    for (const auto& item : node) {
        if (!item.first.IsScalar()) {
            error = context + " contains a non-scalar key";
            return false;
        }
        const std::string key = item.first.as<std::string>();
        if (!seenKeys.insert(key).second) {
            error = context + " contains duplicate key '" + key + "'";
            return false;
        }
        bool found = false;
        for (const auto& candidate : allowed) {
            if (key == candidate) {
                found = true;
                break;
            }
        }
        if (!found) {
            error = context + " contains unsupported key '" + key + "'";
            return false;
        }
    }
    return true;
}

inline bool ReadString(
    const YAML::Node& mapping,
    const char* key,
    std::string& target,
    const std::string& context,
    std::string& error) {
    const YAML::Node value = mapping[key];
    if (!value) {
        return true;
    }
    if (!value.IsScalar()) {
        error = context + "." + key + " must be a string";
        return false;
    }

    try {
        target = value.as<std::string>();
    } catch (const YAML::Exception&) {
        error = context + "." + key + " must be a string";
        return false;
    }
    if (target.empty() || target.size() > 4096 ||
        std::any_of(target.begin(), target.end(), [](unsigned char ch) {
            return ch < 0x20 || ch == 0x7f;
        })) {
        error = context + "." + key + " must contain 1 to 4096 printable characters";
        return false;
    }
    return true;
}

inline bool ReadUint(
    const YAML::Node& mapping,
    const char* key,
    std::uint32_t& target,
    const std::string& context,
    std::string& error) {
    const YAML::Node value = mapping[key];
    if (!value) {
        return true;
    }
    if (!value.IsScalar()) {
        error = context + "." + key + " must be an integer";
        return false;
    }

    try {
        const unsigned long long parsed = value.as<unsigned long long>();
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            error = context + "." + key + " is out of range";
            return false;
        }
        target = static_cast<std::uint32_t>(parsed);
    } catch (const YAML::Exception&) {
        error = context + "." + key + " must be a non-negative integer";
        return false;
    }
    return true;
}

} // namespace Detail

// The YAML file contains deployment settings only. The shared secret is
// deliberately not a supported key: keep it in OBLIVION_SECRET or secret.dat.
inline bool ParseServerYaml(
    std::istream& input,
    ServerSettings& settings,
    std::string& error) {
    error.clear();
    std::string text;
    if (!Detail::ReadYamlText(input, text, error)) {
        return false;
    }

    try {
        const YAML::Node root = YAML::Load(text);
        if (!Detail::HasOnlyKeys(root, {"version", "server", "tls", "heartbeat"},
                                 "root", error)) {
            return false;
        }

        if (!root["version"] || !root["version"].IsScalar() ||
            root["version"].as<int>() != 1) {
            error = "version must be the integer 1";
            return false;
        }

        const YAML::Node server = root["server"];
        if (server) {
            if (!Detail::HasOnlyKeys(server, {"bind_address", "listen_port"},
                                     "server", error) ||
                !Detail::ReadString(server, "bind_address", settings.bindAddress,
                                    "server", error) ||
                !Detail::ReadString(server, "listen_port", settings.listenPort,
                                    "server", error)) {
                return false;
            }
        }

        if (settings.bindAddress != "0.0.0.0") {
            // This implementation uses an IPv4 listener; accept numeric IPv4
            // addresses only so a typo cannot silently bind a different host.
            unsigned int parts = 0;
            std::size_t start = 0;
            while (start <= settings.bindAddress.size()) {
                const std::size_t dot = settings.bindAddress.find('.', start);
                const std::string part = settings.bindAddress.substr(
                    start, dot == std::string::npos ? std::string::npos : dot - start);
                if (part.empty() || part.size() > 3) {
                    error = "server.bind_address must be 0.0.0.0 or a valid IPv4 address";
                    return false;
                }
                unsigned int number = 0;
                for (char ch : part) {
                    if (ch < '0' || ch > '9') {
                        error = "server.bind_address must be 0.0.0.0 or a valid IPv4 address";
                        return false;
                    }
                    number = number * 10U + static_cast<unsigned int>(ch - '0');
                }
                if (number > 255U) {
                    error = "server.bind_address contains an IPv4 octet above 255";
                    return false;
                }
                ++parts;
                if (dot == std::string::npos) {
                    break;
                }
                start = dot + 1;
            }
            if (parts != 4) {
                error = "server.bind_address must be 0.0.0.0 or a valid IPv4 address";
                return false;
            }
        }

        std::string normalizedPort;
        if (!Oblivion::ServerConfig::ResolveListenPort(settings.listenPort.c_str(), "54321",
                               normalizedPort, error)) {
            error = "server.listen_port: " + error;
            return false;
        }
        settings.listenPort = normalizedPort;

        const YAML::Node tls = root["tls"];
        if (tls) {
            if (!Detail::HasOnlyKeys(tls, {"certificate_file", "private_key_file"},
                                     "tls", error) ||
                !Detail::ReadString(tls, "certificate_file", settings.tlsCertificateFile,
                                    "tls", error) ||
                !Detail::ReadString(tls, "private_key_file", settings.tlsPrivateKeyFile,
                                    "tls", error)) {
                return false;
            }
        }

        const YAML::Node heartbeat = root["heartbeat"];
        if (heartbeat) {
            if (!Detail::HasOnlyKeys(
                    heartbeat,
                    {"interval_ms", "jitter_ms", "timeout_ms",
                     "max_consecutive_misses", "rtt_warn_ms"},
                    "heartbeat", error) ||
                !Detail::ReadUint(heartbeat, "interval_ms", settings.heartbeat.intervalMs,
                                  "heartbeat", error) ||
                !Detail::ReadUint(heartbeat, "jitter_ms", settings.heartbeat.jitterMs,
                                  "heartbeat", error) ||
                !Detail::ReadUint(heartbeat, "timeout_ms", settings.heartbeat.timeoutMs,
                                  "heartbeat", error) ||
                !Detail::ReadUint(heartbeat, "max_consecutive_misses",
                                  settings.heartbeat.maxConsecutiveMisses,
                                  "heartbeat", error) ||
                !Detail::ReadUint(heartbeat, "rtt_warn_ms", settings.heartbeat.rttWarnMs,
                                  "heartbeat", error)) {
                return false;
            }
        }

        const auto& hb = settings.heartbeat;
        if (hb.intervalMs < 250 || hb.intervalMs > 60000) {
            error = "heartbeat.interval_ms must be in the range 250..60000";
            return false;
        }
        if (hb.jitterMs >= hb.intervalMs || hb.jitterMs > 30000) {
            error = "heartbeat.jitter_ms must be smaller than interval_ms and at most 30000";
            return false;
        }
        if (hb.timeoutMs < 250 || hb.timeoutMs > 60000) {
            error = "heartbeat.timeout_ms must be in the range 250..60000";
            return false;
        }
        if (hb.maxConsecutiveMisses < 1 || hb.maxConsecutiveMisses > 10) {
            error = "heartbeat.max_consecutive_misses must be in the range 1..10";
            return false;
        }
        if (hb.rttWarnMs > 60000) {
            error = "heartbeat.rtt_warn_ms must be in the range 0..60000";
            return false;
        }
    } catch (const YAML::Exception& exception) {
        error = std::string("invalid server YAML: ") + exception.what();
        return false;
    } catch (const std::exception& exception) {
        error = std::string("cannot parse server YAML: ") + exception.what();
        return false;
    }

    return true;
}


inline bool LoadServerYamlFileIfPresent(
    const std::string& path,
    ServerSettings& settings,
    bool& found,
    std::string& error) {
    found = false;
    error.clear();

    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        std::error_code filesystemError;
        const bool exists = std::filesystem::exists(path, filesystemError);
        if (filesystemError || exists) {
            error = "cannot open server YAML configuration: " + path;
            return false;
        }
        return true; // Missing optional config preserves compiled defaults.
    }

    if (!ParseServerYaml(input, settings, error)) {
        error = path + ": " + error;
        return false;
    }
    found = true;
    return true;
}

} // namespace Config
} // namespace Oblivion
