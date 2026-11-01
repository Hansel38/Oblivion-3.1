#pragma once

#include "server_yaml_config.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace Oblivion {
namespace Config {

struct ClientSettings {
    int defaultPort = 54321;
    std::vector<std::string> endpoints;
    int connectTimeoutMs = 3000;
    int retryCount = 3;
    int handshakeTimeoutMs = 4000;
    bool failClosed = true;
    std::string tlsPinSha256; // Development only; Release uses the compiled trust policy.
};

namespace ClientDetail {

inline bool ReadInt(
    const YAML::Node& mapping,
    const char* key,
    int& target,
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
        target = value.as<int>();
    } catch (const YAML::Exception&) {
        error = context + "." + key + " must be an integer";
        return false;
    }
    return true;
}

inline bool ReadBool(
    const YAML::Node& mapping,
    const char* key,
    bool& target,
    const std::string& context,
    std::string& error) {
    const YAML::Node value = mapping[key];
    if (!value) {
        return true;
    }
    if (!value.IsScalar()) {
        error = context + "." + key + " must be true or false";
        return false;
    }
    try {
        target = value.as<bool>();
    } catch (const YAML::Exception&) {
        error = context + "." + key + " must be true or false";
        return false;
    }
    return true;
}

} // namespace ClientDetail

// Runtime YAML can choose an endpoint, but it cannot replace the Release
// certificate pin. The caller must always override tlsPinSha256 with the
// compiled production pin when OBLIVION_PRODUCTION_BUILD is enabled.
inline bool ParseClientYaml(
    std::istream& input,
    ClientSettings& settings,
    std::string& error) {
    error.clear();
    std::string text;
    if (!Detail::ReadYamlText(input, text, error)) {
        return false;
    }

    try {
        const YAML::Node root = YAML::Load(text);
        if (!Detail::HasOnlyKeys(root, {"version", "server", "tls", "connection", "policy"},
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
            if (!Detail::HasOnlyKeys(server, {"default_port", "endpoints"},
                                     "server", error) ||
                !ClientDetail::ReadInt(server, "default_port", settings.defaultPort,
                                       "server", error)) {
                return false;
            }
            const YAML::Node endpoints = server["endpoints"];
            if (endpoints) {
                if (!endpoints.IsSequence()) {
                    error = "server.endpoints must be a YAML sequence";
                    return false;
                }
                if (endpoints.size() > 16) {
                    error = "server.endpoints may contain at most 16 entries";
                    return false;
                }
                settings.endpoints.clear();
                for (const auto& endpoint : endpoints) {
                    if (!endpoint.IsScalar()) {
                        error = "each server.endpoints item must be a string";
                        return false;
                    }
                    const std::string value = endpoint.as<std::string>();
                    if (value.empty() || value.size() > 300 ||
                        std::any_of(value.begin(), value.end(), [](unsigned char ch) {
                            return std::isspace(ch) || ch < 0x21 || ch > 0x7e ||
                                   ch == ';' || ch == '\\' || ch == '/';
                        })) {
                        error = "server.endpoints entries must be non-empty host[:port] values without whitespace or path separators";
                        return false;
                    }
                    settings.endpoints.push_back(value);
                }
            }
        }

        if (settings.defaultPort < 1 || settings.defaultPort > 65535) {
            error = "server.default_port must be in the range 1..65535";
            return false;
        }

        const YAML::Node tls = root["tls"];
        if (tls) {
            if (!Detail::HasOnlyKeys(tls, {"pin_sha256"}, "tls", error)) {
                return false;
            }
            const YAML::Node pin = tls["pin_sha256"];
            if (pin) {
                if (!pin.IsScalar()) {
                    error = "tls.pin_sha256 must be a string";
                    return false;
                }
                try {
                    settings.tlsPinSha256 = pin.as<std::string>();
                } catch (const YAML::Exception&) {
                    error = "tls.pin_sha256 must be a string";
                    return false;
                }
                if (settings.tlsPinSha256.size() > 4096) {
                    error = "tls.pin_sha256 exceeds 4096 characters";
                    return false;
                }
            }
        }

        const YAML::Node connection = root["connection"];
        if (connection) {
            if (!Detail::HasOnlyKeys(
                    connection,
                    {"connect_timeout_ms", "retry_count", "handshake_timeout_ms"},
                    "connection", error) ||
                !ClientDetail::ReadInt(connection, "connect_timeout_ms",
                                       settings.connectTimeoutMs, "connection", error) ||
                !ClientDetail::ReadInt(connection, "retry_count",
                                       settings.retryCount, "connection", error) ||
                !ClientDetail::ReadInt(connection, "handshake_timeout_ms",
                                       settings.handshakeTimeoutMs, "connection", error)) {
                return false;
            }
        }

        if (settings.connectTimeoutMs < 500 || settings.connectTimeoutMs > 30000) {
            error = "connection.connect_timeout_ms must be in the range 500..30000";
            return false;
        }
        if (settings.retryCount < 1 || settings.retryCount > 10) {
            error = "connection.retry_count must be in the range 1..10";
            return false;
        }
        if (settings.handshakeTimeoutMs < 500 || settings.handshakeTimeoutMs > 30000) {
            error = "connection.handshake_timeout_ms must be in the range 500..30000";
            return false;
        }
        const YAML::Node policy = root["policy"];
        if (policy) {
            if (!Detail::HasOnlyKeys(policy, {"fail_closed"}, "policy", error) ||
                !ClientDetail::ReadBool(policy, "fail_closed", settings.failClosed,
                                        "policy", error)) {
                return false;
            }
        }
    } catch (const YAML::Exception& exception) {
        error = std::string("invalid client YAML: ") + exception.what();
        return false;
    } catch (const std::exception& exception) {
        error = std::string("cannot parse client YAML: ") + exception.what();
        return false;
    }

    return true;
}

} // namespace Config
} // namespace Oblivion
