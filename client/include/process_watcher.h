#pragma once

#include <windows.h>
#include <thread>
#include <memory>
#include <atomic>
#include <unordered_set>

namespace Oblivion {
    // Forward declarations
    class AntiDebug;
    class InjectionScanner;
    class AntiSuspend;
    class OverlayScanner;
    class MemoryScanner;
    class DigitalSignatureValidator;
    class IATHookScanner;
    class AdvancedProcessHeuristics;

    class ProcessWatcher {
    public:
        ProcessWatcher();
        ~ProcessWatcher();

        void Start();
        void Stop();

        // True bila guardian anti-suspend milik watcher ini sedang berjalan.
        // Dipakai dllmain untuk mengisi bit status pada heartbeat (PONG).
        bool IsAntiSuspendRunning() const;

    private:
        void WatcherLoop();
        void PerformScan();

        std::thread m_watcherThread;
        std::atomic<bool> m_isRunning;

        std::unique_ptr<AntiDebug> m_pAntiDebug;
        std::unique_ptr<InjectionScanner> m_pInjectionScanner;
        std::unique_ptr<AntiSuspend> m_pAntiSuspend;
        std::unique_ptr<OverlayScanner> m_pOverlayScanner;
        std::unique_ptr<MemoryScanner> m_pMemoryScanner;
        std::unique_ptr<DigitalSignatureValidator> m_pDigitalSignatureValidator;
        std::unique_ptr<IATHookScanner> m_pIATHookScanner;
        std::unique_ptr<AdvancedProcessHeuristics> m_pAdvancedHeuristics;
        
        // PID aktif yang sudah diperiksa. Cache ini dibersihkan setiap siklus agar
        // PID yang dipakai ulang tetap diperlakukan sebagai proses baru.
        std::unordered_set<DWORD> m_scannedProcesses;
    };
}
