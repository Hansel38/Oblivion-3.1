#include "../common/ip_rate_limiter.h"

#include <cassert>
#include <chrono>
#include <iostream>
#include <string>

int main() {
    using Limiter = Oblivion::Security::IpRateLimiter;
    using namespace std::chrono;

    const Limiter::Clock::time_point start{};

    // Burst capacity is enforced independently for each source IP.
    Limiter limiter(2.0, 1.0, 8, seconds(10), 100);
    assert(limiter.Allow("192.0.2.10", start));
    assert(limiter.Allow("192.0.2.10", start));
    assert(!limiter.Allow("192.0.2.10", start));
    assert(limiter.Allow("192.0.2.11", start));

    // One token is replenished after one second.
    assert(limiter.Allow("192.0.2.10", start + seconds(1)));
    assert(!limiter.Allow("192.0.2.10", start + seconds(1)));

    // Invalid keys are rejected and do not allocate state.
    const std::size_t beforeInvalid = limiter.TrackedIpCount();
    assert(!limiter.Allow(""));
    assert(!limiter.Allow(std::string(65, 'x')));
    assert(limiter.TrackedIpCount() == beforeInvalid);

    // State remains bounded, and an expired entry can be reclaimed.
    Limiter bounded(1.0, 0.0, 1, seconds(5), 100);
    assert(bounded.Allow("198.51.100.1", start));
    assert(!bounded.Allow("198.51.100.2", start));
    assert(bounded.Allow("198.51.100.2", start + seconds(6)));
    assert(bounded.TrackedIpCount() == 1);

    std::cout << "ip_rate_limiter_test: PASS\n";
    return 0;
}
