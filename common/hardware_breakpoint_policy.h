#pragma once

#include <cstdint>

namespace Oblivion {
namespace Windows {

// DR7 local/global enable bits are the first eight bits. Nonzero DR0-DR3
// register values alone do not mean a hardware breakpoint is active.
constexpr std::uint64_t kDr7HardwareBreakpointEnableMask = 0xFFULL;

constexpr bool HasEnabledHardwareBreakpoints(std::uint64_t dr7) noexcept {
    return (dr7 & kDr7HardwareBreakpointEnableMask) != 0;
}

} // namespace Windows
} // namespace Oblivion
