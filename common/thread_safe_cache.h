#pragma once

#include <cstddef>
#include <map>
#include <mutex>

namespace Oblivion {
namespace Security {

// A small synchronized associative cache. Each operation is atomic with
// respect to every other operation on the same cache; callers never receive
// iterators or references that outlive the internal lock.
template <typename Key, typename Value, typename Compare = std::less<Key>>
class ThreadSafeCache {
public:
    bool TryGet(const Key& key, Value& value) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = entries_.find(key);
        if (found == entries_.end()) {
            return false;
        }
        value = found->second;
        return true;
    }

    void Erase(const Key& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.erase(key);
    }

    void Store(const Key& key, const Value& value, std::size_t maximumEntries = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = entries_.find(key);
        if (existing == entries_.end() &&
            maximumEntries > 0 &&
            entries_.size() >= maximumEntries) {
            entries_.clear();
        }
        entries_.insert_or_assign(key, value);
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
    }

    std::size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

private:
    mutable std::mutex mutex_;
    std::map<Key, Value, Compare> entries_;
};

} // namespace Security
} // namespace Oblivion
