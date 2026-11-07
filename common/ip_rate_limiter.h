#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace Oblivion {
namespace Security {

// Per-source-IP token bucket for connection attempts. This is intentionally
// user-mode and runs before TLS negotiation so unauthenticated clients cannot
// consume a worker thread for every reconnect attempt.
class IpRateLimiter {
public:
    using Clock = std::chrono::steady_clock;

    explicit IpRateLimiter(
        double burstCapacity = 60.0,
        double refillTokensPerSecond = 1.0,
        std::size_t maximumTrackedIps = 65536,
        std::chrono::seconds idleExpiration = std::chrono::minutes(10),
        std::size_t cleanupInterval = 256)
        : capacity_(burstCapacity > 0.0 ? burstCapacity : 1.0),
          refillRate_(refillTokensPerSecond > 0.0 ? refillTokensPerSecond : 0.0),
          maximumTrackedIps_(maximumTrackedIps > 0 ? maximumTrackedIps : 1),
          idleExpiration_(idleExpiration.count() > 0
              ? idleExpiration : std::chrono::seconds(600)),
          cleanupInterval_(cleanupInterval > 0 ? cleanupInterval : 1) {
    }

    // Pass a numeric IP address (not a reverse-DNS hostname). The time argument
    // is injectable for deterministic tests; production callers use the default.
    bool Allow(
        const std::string& ipAddress,
        Clock::time_point now = Clock::now()) {
        if (ipAddress.empty() || ipAddress.size() > 64) {
            return false;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        ++operations_;
        // Run pruning on the global operation cadence, not only on new IPs.
        // Continuous traffic from known addresses must not starve expiry cleanup.
        if ((operations_ % cleanupInterval_) == 0) {
            PruneExpiredLocked(now);
        }

        auto entry = buckets_.find(ipAddress);
        if (entry == buckets_.end()) {
            // Keep memory bounded even when an attacker rotates source addresses.
            if (buckets_.size() >= maximumTrackedIps_) {
                // Capacity pressure must not reject a legitimate new IP solely
                // because expired entries have not reached the normal sweep cadence.
                PruneExpiredLocked(now);
                if (buckets_.size() >= maximumTrackedIps_) {
                    return false;
                }
            }

            Bucket fresh;
            fresh.tokens = capacity_ - 1.0;
            fresh.updatedAt = now;
            fresh.lastSeenAt = now;
            buckets_.emplace(ipAddress, fresh);
            return true;
        }

        Bucket& bucket = entry->second;
        double elapsed = std::chrono::duration<double>(
            now - bucket.updatedAt).count();
        if (elapsed < 0.0) {
            elapsed = 0.0;
        }

        bucket.tokens = (std::min)(
            capacity_,
            bucket.tokens + elapsed * refillRate_);
        bucket.updatedAt = now;
        bucket.lastSeenAt = now;

        if (bucket.tokens < 1.0) {
            return false;
        }

        bucket.tokens -= 1.0;
        return true;
    }

    std::size_t TrackedIpCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return buckets_.size();
    }

private:
    struct Bucket {
        double tokens = 0.0;
        Clock::time_point updatedAt{};
        Clock::time_point lastSeenAt{};
    };

    void PruneExpiredLocked(Clock::time_point now) {
        for (auto it = buckets_.begin(); it != buckets_.end();) {
            if (now - it->second.lastSeenAt >= idleExpiration_) {
                it = buckets_.erase(it);
            } else {
                ++it;
            }
        }
    }

    const double capacity_;
    const double refillRate_;
    const std::size_t maximumTrackedIps_;
    const std::chrono::seconds idleExpiration_;
    const std::size_t cleanupInterval_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
    std::size_t operations_ = 0;
};

} // namespace Security
} // namespace Oblivion
