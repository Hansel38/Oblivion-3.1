#pragma once

#include <cstddef>
#include <cstdint>

namespace Oblivion {
namespace Windows {

// PEB fields used by the anti-debug checks. The first two bytes are reserved,
// and BeingDebugged is at offset 0x02 for both native x86 and x64 processes.
constexpr std::size_t kPebBeingDebuggedOffset = 0x02;

// NtGlobalFlag is not at a pointer-size-independent location. These offsets
// correspond to the native PEB layout returned by ProcessBasicInformation.
constexpr std::size_t kPebNtGlobalFlagOffset32 = 0x68;
constexpr std::size_t kPebNtGlobalFlagOffset64 = 0xBC;

constexpr std::size_t PebNtGlobalFlagOffset(std::size_t pointerSize) noexcept {
    return pointerSize == 4 ? kPebNtGlobalFlagOffset32
         : pointerSize == 8 ? kPebNtGlobalFlagOffset64
                            : 0;
}

// These are debug-heap/process-creation indicators, not proof that a debugger
// is currently attached. Callers should treat them as corroborating evidence.
constexpr std::uint32_t kPebNtGlobalFlagDebugMask = 0x70;

constexpr bool HasPebNtGlobalFlagDebugIndicators(std::uint32_t flags) noexcept {
    return (flags & kPebNtGlobalFlagDebugMask) != 0;
}

} // namespace Windows
} // namespace Oblivion
