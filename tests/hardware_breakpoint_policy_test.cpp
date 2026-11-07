#include "../common/hardware_breakpoint_policy.h"

#include <cstdint>
#include <iostream>

int main() {
    using Oblivion::Windows::HasEnabledHardwareBreakpoints;

    if (HasEnabledHardwareBreakpoints(0)) {
        std::cerr << "empty DR7 was incorrectly classified as an active breakpoint\n";
        return 1;
    }
    if (HasEnabledHardwareBreakpoints(0x100) ||
        HasEnabledHardwareBreakpoints(0x200) ||
        HasEnabledHardwareBreakpoints(0x2000) ||
        HasEnabledHardwareBreakpoints(0x10000)) {
        std::cerr << "DR7 control fields were incorrectly treated as enable bits\n";
        return 2;
    }
    for (std::uint64_t enableBit = 0x01; enableBit <= 0x80; enableBit <<= 1) {
        if (!HasEnabledHardwareBreakpoints(enableBit)) {
            std::cerr << "DR7 local/global enable bit was not recognized\n";
            return 3;
        }
    }

    std::cout << "Hardware breakpoint DR7 policy: PASS\n";
    return 0;
}
