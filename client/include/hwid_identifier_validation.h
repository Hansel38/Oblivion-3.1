#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace Oblivion {
namespace HWIDIdentity {

// Trim only surrounding ASCII whitespace. This value is used for validation;
// the existing HWID hash input is intentionally left unchanged for compatibility.
inline std::string TrimHardwareValue(const std::string& value) {
    const size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

inline bool IsUsableHardwareIdentifier(const std::string& value) {
    const std::string trimmed = TrimHardwareValue(value);
    std::string compact;
    compact.reserve(trimmed.size());
    for (unsigned char c : trimmed) {
        if (std::isalnum(c)) {
            compact.push_back(static_cast<char>(std::tolower(c)));
        }
    }

    if (compact.size() < 4) {
        return false;
    }

    const bool allZeros = std::all_of(compact.begin(), compact.end(),
        [](char c) { return c == '0'; });
    const bool allFs = std::all_of(compact.begin(), compact.end(),
        [](char c) { return c == 'f'; });
    if (allZeros || allFs) {
        return false;
    }

    // Common motherboard/disk firmware placeholders, normalized to
    // alphanumeric lowercase so punctuation and spacing do not bypass checks.
    static const std::vector<std::string> kPlaceholderValues = {
        "unknown",
        "none",
        "na",
        "notavailable",
        "notspecified",
        "notpresent",
        "default",
        "defaultstring",
        "tobefilledbyoem",
        "systemserialnumber",
        "oemserialnumber",
        "serialnumber",
        "123456789",
        "1234567890"
    };
    return std::find(kPlaceholderValues.begin(), kPlaceholderValues.end(), compact)
        == kPlaceholderValues.end();
}

} // namespace HWIDIdentity
} // namespace Oblivion
