#include "../client/include/hwid_identifier_validation.h"

#include <iostream>
#include <string>
#include <vector>

int main() {
    struct TestCase {
        const char* value;
        bool expected;
    };

    const std::vector<TestCase> cases = {
        {"4C4C4544-004A-3210-8058-B6C04F4D4D32", true},
        {"WD-WX12AB34CD56", true},
        {"SN1234XYZ", true},
        {"UNKNOWN", false},
        {"unknown", false},
        {"N/A", false},
        {"None", false},
        {"Default String", false},
        {"To be filled by O.E.M.", false},
        {"System Serial Number", false},
        {"1234567890", false},
        {"00000000-0000-0000-0000-000000000000", false},
        {"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", false},
        {"   \t\r\n  ", false},
        {"----", false},
        {"ABC", false}
    };

    for (const auto& test : cases) {
        const bool actual = Oblivion::HWIDIdentity::IsUsableHardwareIdentifier(test.value);
        if (actual != test.expected) {
            std::cerr << "HWID validation failed for [" << test.value
                      << "]: expected " << test.expected << ", got " << actual << '\n';
            return 1;
        }
    }

    if (Oblivion::HWIDIdentity::TrimHardwareValue("  SN1234  ") != "SN1234") {
        std::cerr << "HWID whitespace trimming failed\n";
        return 2;
    }

    std::cout << "HWID identifier validation: PASS (" << cases.size() << " cases)\n";
    return 0;
}
