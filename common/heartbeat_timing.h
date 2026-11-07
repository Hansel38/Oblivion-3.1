#pragma once

#include <cstdint>

namespace Oblivion {
namespace Heartbeat {

// Return a delay in [intervalMs - jitterMs, intervalMs + jitterMs].
// The random seed is supplied by the caller from the OS CSPRNG.
inline std::uint32_t CalculateDelayMs(
    std::uint32_t intervalMs,
    std::uint32_t jitterMs,
    std::uint64_t randomSeed) noexcept {
    if (intervalMs == 0 || jitterMs == 0 || jitterMs >= intervalMs) {
        return intervalMs;
    }
    const std::uint64_t range = static_cast<std::uint64_t>(jitterMs) * 2ULL + 1ULL;
    const std::int64_t offset =
        static_cast<std::int64_t>(randomSeed % range) - static_cast<std::int64_t>(jitterMs);
    const std::int64_t delay = static_cast<std::int64_t>(intervalMs) + offset;
    return delay > 0 ? static_cast<std::uint32_t>(delay) : 1U;
}
} // namespace Heartbeat
} // namespace Oblivion
