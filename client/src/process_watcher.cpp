#include "pch.h"
#include "process_watcher.h"
#include "blacklist.h"
#include "AntiDebug.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>

namespace Oblivion {
    ProcessWatcher::ProcessWatcher() : m_isRunning(false) {
        // Buat instance dari AntiDebug
        m_pAntiDebug = new AntiDebug();
    }

    ProcessWatcher::~ProcessWatcher() {
        Stop();
        // Hapus instance AntiDebug
        delete m_pAntiDebug;
        m_pAntiDebug = nullptr;
    }

    void ProcessWatcher::Start() {
        if (m_isRunning) {
            return;
        }
        m_isRunning = true;
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
    }

    void ProcessWatcher::WatcherLoop() {
        // Lakukan pemindaian awal
        PerformScan();

        // Lakukan pemeriksaan anti-debug awal
        if (m_isRunning) {
            m_pAntiDebug->PerformCheck();
        }

        // Loop pemantauan real-time
        while (m_isRunning) {
            PerformScan();

            // Lakukan pemeriksaan anti-debug secara berkala
            if (m_isRunning) {
                m_pAntiDebug->PerformCheck();
            }

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