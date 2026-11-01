#pragma once

#include <string>

namespace Oblivion {
namespace ServerConfig {

// Resolve the TCP port used by the server listener. An unset/empty environment
// setting uses the compiled default; an invalid explicit value is a startup
// error rather than silently selecting a different port.
inline bool ResolveListenPort(
    const char* configuredValue,
    const char* defaultValue,
    std::string& normalizedPort,
    std::string& error) {
    normalizedPort.clear();
    error.clear();

    const char* value =
        configuredValue != nullptr && configuredValue[0] != '\0'
            ? configuredValue
            : defaultValue;

    if (value == nullptr || value[0] == '\0') {
        error = "default listen port is empty";
        return false;
    }

    // A decimal TCP port has at most five digits. Reject overlong values (even
    // those with leading zeroes) to keep configuration unambiguous.
    std::size_t length = 0;
    while (value[length] != '\0' && length <= 5) {
        ++length;
    }
    if (length == 0 || length > 5) {
        error = "port must contain 1 to 5 decimal digits";
        return false;
    }

    unsigned int port = 0;
    for (std::size_t i = 0; i < length; ++i) {
        const char digitChar = value[i];
        if (digitChar < '0' || digitChar > '9') {
            error = "port must contain decimal digits only";
            return false;
        }
        const unsigned int digit = static_cast<unsigned int>(digitChar - '0');
        if (port > (65535U - digit) / 10U) {
            error = "port must be between 1 and 65535";
            return false;
        }
        port = port * 10U + digit;
    }

    if (port == 0U || port > 65535U) {
        error = "port must be between 1 and 65535";
        return false;
    }

    normalizedPort = std::to_string(port);
    return true;
}

} // namespace ServerConfig
} // namespace Oblivion
