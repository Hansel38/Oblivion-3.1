#include "../common/heartbeat_timing.h"

#include <cstdint>
#include <iostream>

int main() {
    using Oblivion::Heartbeat::CalculateDelayMs;
    if (CalculateDelayMs(3000U, 0U, 123U) != 3000U) return 1;
    if (CalculateDelayMs(3000U, 250U, 0U) != 2750U) return 2;
    if (CalculateDelayMs(3000U, 250U, 250U) != 3000U) return 3;
    if (CalculateDelayMs(3000U, 250U, 500U) != 3250U) return 4;
    if (CalculateDelayMs(250U, 250U, 99U) != 250U ||
        CalculateDelayMs(0U, 10U, 99U) != 0U) return 5;
    for (std::uint64_t seed = 0; seed < 10000U; ++seed) {
        const std::uint32_t delay = CalculateDelayMs(1000U, 125U, seed);
        if (delay < 875U || delay > 1125U) return 6;
    }
    std::cout << "Heartbeat timing contract: PASS\n";
    return 0;
}
