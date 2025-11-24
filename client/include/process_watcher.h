#pragma once

#include <windows.h>
#include <thread>
#include <atomic>

namespace Oblivion {
    // Forward declarations
    class AntiDebug;
    class InjectionScanner;

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

        AntiDebug* m_pAntiDebug;
        InjectionScanner* m_pInjectionScanner; // <-- Tambahkan pointer ini
    };
}