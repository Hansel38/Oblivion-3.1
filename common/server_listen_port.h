#pragma once

#include <cstdint>
#include <limits>
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

inline bool ParseUint32Decimal(const std::string& text, std::uint32_t& parsedValue, std::string& error) {
    parsedValue = 0;
    error.clear();
    if (text.empty()) { error = "value must not be empty"; return false; }
    std::uint32_t value = 0;
    const std::uint32_t maximum = (std::numeric_limits<std::uint32_t>::max)();
    for (unsigned char ch : text) {
        if (ch < '0' || ch > '9') { error = "value must contain decimal digits only"; return false; }
        const std::uint32_t digit = static_cast<std::uint32_t>(ch - '0');
        if (value > (maximum - digit) / 10U) { error = "value exceeds the unsigned 32-bit range"; return false; }
        value = value * 10U + digit;
    }
    parsedValue = value;
    return true;
}

} // namespace ServerConfig
} // namespace Oblivion
