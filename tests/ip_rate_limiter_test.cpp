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
    Limiter bounded(1.0, 0.0, 1, seconds(5), 100);
    assert(bounded.Allow("198.51.100.1", start));
    assert(!bounded.Allow("198.51.100.2", start));
    assert(bounded.Allow("198.51.100.2", start + seconds(6)));
    assert(bounded.TrackedIpCount() == 1);

    std::cout << "ip_rate_limiter_test: PASS\n";
    return 0;
}
