#include "../common/ip_rate_limiter.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

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

    // Concurrent calls against one IP must never overspend the shared bucket.
    Limiter concurrent(100.0, 0.0, 8, seconds(10), 100);
    std::atomic<int> accepted{0};
    std::vector<std::thread> workers;
    for (int worker = 0; worker < 20; ++worker) {
        workers.emplace_back([&]() {
            for (int attempt = 0; attempt < 20; ++attempt) {
                if (concurrent.Allow("203.0.113.7", start)) {
                    accepted.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    assert(accepted.load(std::memory_order_relaxed) == 100);

    // State remains bounded, and an expired entry can be reclaimed.
    Limiter bounded(1.0, 0.0, 1, seconds(5), 1);
    assert(bounded.Allow("198.51.100.1", start));
    assert(!bounded.Allow("198.51.100.2", start));
    assert(bounded.Allow("198.51.100.2", start + seconds(6)));
    assert(bounded.TrackedIpCount() == 1);

    // When the cache is full, reclaim expired entries immediately even if the
    // global maintenance operation interval has not elapsed.
    Limiter capacityPressure(1.0, 0.0, 1, seconds(5), 100);
    assert(capacityPressure.Allow("198.51.100.10", start));
    assert(capacityPressure.Allow("198.51.100.11", start + seconds(6)));
    assert(capacityPressure.TrackedIpCount() == 1);

    // Expired entries are pruned even while operations hit a known address.
    Limiter busyKnownIp(1.0, 0.0, 2, seconds(5), 2);
    assert(busyKnownIp.Allow("192.0.2.20", start));              // operation 1
    assert(busyKnownIp.Allow("192.0.2.21", start));              // operation 2
    assert(!busyKnownIp.Allow("192.0.2.21", start + seconds(6))); // operation 3
    assert(!busyKnownIp.Allow("192.0.2.21", start + seconds(6))); // operation 4 prunes expired .20
    assert(busyKnownIp.TrackedIpCount() == 1);
    assert(busyKnownIp.Allow("192.0.2.22", start + seconds(6)));
    assert(busyKnownIp.TrackedIpCount() == 2);

    std::cout << "ip_rate_limiter_test: PASS\n";
    return 0;
}
