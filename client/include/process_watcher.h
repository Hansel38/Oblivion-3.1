#pragma once

#include <windows.h>
#include <thread>
#include <atomic>

namespace Oblivion {
    // Forward declaration agar tidak perlu include anti_debug.h di sini
    class AntiDebug;

    class ProcessWatcher {
    public:
        ProcessWatcher();
        ~ProcessWatcher();

        void Start();
        void Stop();

    private:
        void WatcherLoop();
        void PerformScan();

        std::thread m_watcherThread;
        std::atomic<bool> m_isRunning;

        // Pointer untuk mengelola objek AntiDebug
        AntiDebug* m_pAntiDebug;
    };
}