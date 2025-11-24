#include "pch.h"
#include "process_watcher.h"
#include "blacklist.h"
#include "AntiDebug.h"
#include "injection_scanner.h"
#include "anti_suspend.h"
#include "overlay_scanner.h"
#include "memory_scanner.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    ProcessWatcher::ProcessWatcher() : m_isRunning(false) {
        m_pAntiDebug = new AntiDebug();
        m_pInjectionScanner = new InjectionScanner();
        m_pAntiSuspend = new AntiSuspend();
        m_pOverlayScanner = new OverlayScanner();
        m_pMemoryScanner = new MemoryScanner();
    }

    ProcessWatcher::~ProcessWatcher() {
        Stop();
        delete m_pAntiDebug;
        m_pAntiDebug = nullptr;
        delete m_pInjectionScanner;
        m_pInjectionScanner = nullptr;
        delete m_pAntiSuspend;
        m_pAntiSuspend = nullptr;
        delete m_pOverlayScanner;
        m_pOverlayScanner = nullptr;
        delete m_pMemoryScanner;
        m_pMemoryScanner = nullptr;
    }

    void ProcessWatcher::Start() {
        if (m_isRunning) {
            return;
        }
        m_isRunning = true;
        
        // Mulai thread pengawas terlebih dahulu
        m_pAntiSuspend->Start();
        
        // Lalu mulai thread pemantauan utama
        m_watcherThread = std::thread(&ProcessWatcher::WatcherLoop, this);
    }

    void ProcessWatcher::Stop() {
        if (!m_isRunning) {
            return;
        }
        m_isRunning = false;
        if (m_watcherThread.joinable()) {
            m_watcherThread.join();
        }
        // Hentikan thread pengawas setelah thread utama berhenti
        m_pAntiSuspend->Stop();
    }

    void ProcessWatcher::WatcherLoop() {
        // Pemindaian awal
        PerformScan();

        if (m_isRunning) m_pAntiDebug->PerformCheck();

        if (m_isRunning) m_pInjectionScanner->PerformScan();

        if (m_isRunning) m_pOverlayScanner->PerformScan();

        if (m_isRunning) m_pMemoryScanner->PerformScan();

        // Loop pemantauan real-time
        while (m_isRunning) {
            m_pAntiSuspend->UpdateHeartbeat();

            PerformScan();

            if (m_isRunning) m_pAntiDebug->PerformCheck();

            if (m_isRunning) m_pInjectionScanner->PerformScan();

            if (m_isRunning) m_pOverlayScanner->PerformScan();

            if (m_isRunning) m_pMemoryScanner->PerformScan();

            Sleep(2000); // Interval 2 detik
        }
    }

    void ProcessWatcher::PerformScan() {
        // ... (Kode di dalam fungsi ini tidak berubah) ...
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;

                if (IsProcessBlacklisted(processName)) {
                    m_isRunning = false;
                    
                    // Konversi processName ke UTF-8 untuk details
                    std::string details_utf8;
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), NULL, 0, NULL, NULL);
                    if (size_needed > 0) {
                        details_utf8.assign(size_needed, 0);
                        WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), &details_utf8[0], size_needed, NULL, NULL);
                    }
                    
                    // Panggil fungsi pelaporan global
                    ReportViolationAndExit(L"", "PROCESS_DETECTED", details_utf8);
                }

            } while (Process32Next(hSnapshot, &pe32) && m_isRunning);
        }

        CloseHandle(hSnapshot);
    }
}