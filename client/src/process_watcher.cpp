#include "pch.h"
#include "process_watcher.h"
#include "blacklist.h"
#include "AntiDebug.h"
#include "injection_scanner.h"
#include "anti_suspend.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>

namespace Oblivion {
    ProcessWatcher::ProcessWatcher() : m_isRunning(false) {
        m_pAntiDebug = new AntiDebug();
        m_pInjectionScanner = new InjectionScanner();
        m_pAntiSuspend = new AntiSuspend();
    }

    ProcessWatcher::~ProcessWatcher() {
        Stop();
        delete m_pAntiDebug;
        m_pAntiDebug = nullptr;
        delete m_pInjectionScanner;
        m_pInjectionScanner = nullptr;
        delete m_pAntiSuspend;
        m_pAntiSuspend = nullptr;
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
        // Lakukan pemindaian awal
        PerformScan();

        if (m_isRunning) m_pAntiDebug->PerformCheck();

        if (m_isRunning) m_pInjectionScanner->PerformScan();

        // Loop pemantauan real-time
        while (m_isRunning) {
            // Update heartbeat di awal loop untuk memberi tahu Guardian bahwa kita masih hidup
            m_pAntiSuspend->UpdateHeartbeat();

            PerformScan();

            if (m_isRunning) m_pAntiDebug->PerformCheck();

            if (m_isRunning) m_pInjectionScanner->PerformScan();

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
                    std::wstring message = L"Software ilegal terdeteksi: " + processName + L"\n\nClient akan ditutup.";
                    MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                    ExitProcess(0);
                }

            } while (Process32Next(hSnapshot, &pe32) && m_isRunning);
        }

        CloseHandle(hSnapshot);
    }
}