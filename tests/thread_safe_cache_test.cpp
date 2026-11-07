#include "../common/thread_safe_cache.h"

#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

int main() {
    using Cache = Oblivion::Security::ThreadSafeCache<int, int>;
    Cache cache;

    cache.Store(1, 10);
    int value = 0;
    assert(cache.TryGet(1, value));
    assert(value == 10);
    assert(!cache.TryGet(2, value));

    cache.Store(2, 20, 2);
    cache.Store(3, 30, 2);
    assert(cache.Size() == 1);
    assert(cache.TryGet(3, value) && value == 30);

    constexpr int workerCount = 12;
    constexpr int writesPerWorker = 5000;
    Cache concurrent;
    std::atomic<bool> failed{false};
    std::vector<std::thread> workers;
    workers.reserve(workerCount);

    for (int worker = 0; worker < workerCount; ++worker) {
        workers.emplace_back([worker, &concurrent, &failed]() {
            for (int index = 0; index < writesPerWorker; ++index) {
                const int key = worker * writesPerWorker + index;
                concurrent.Store(key, key);
                int retrieved = -1;
                if (!concurrent.TryGet(key, retrieved) || retrieved != key) {
                    failed.store(true, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    assert(!failed.load(std::memory_order_relaxed));
    assert(concurrent.Size() == static_cast<std::size_t>(workerCount * writesPerWorker));

    concurrent.Clear();
    assert(concurrent.Size() == 0);

    std::cout << "thread_safe_cache_test: PASS\n";
    return 0;
}
