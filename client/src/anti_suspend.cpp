#include "pch.h"
#include "anti_suspend.h"
#include <windows.h>
#include <string>

namespace Oblivion {
    AntiSuspend::AntiSuspend() : m_isRunning(false) {
        // Inisialisasi heartbeat ke waktu saat ini
        m_lastHeartbeat.store(std::chrono::steady_clock::now());
    }

    AntiSuspend::~AntiSuspend() {
        Stop();
    }

    void AntiSuspend::Start() {
        if (m_isRunning) {
            return;
        }
        m_isRunning = true;
        m_guardianThread = std::thread(&AntiSuspend::GuardianLoop, this);
    }

    void AntiSuspend::Stop() {
        if (!m_isRunning) {
            return;
        }
        m_isRunning = false;
        if (m_guardianThread.joinable()) {
            m_guardianThread.join();
        }
    }

    void AntiSuspend::UpdateHeartbeat() {
        // Perbarui timestamp ke waktu saat ini
        m_lastHeartbeat.store(std::chrono::steady_clock::now());
    }

    void AntiSuspend::GuardianLoop() {
        // Timeout dalam milidetik. Harus lebih besar dari interval sleep ProcessWatcher.
        // ProcessWatcher sleep 2000ms, jadi kita beri jeda 3000ms.
        const auto timeout = std::chrono::milliseconds(3000);

        while (m_isRunning) {
            // Guardian tidur sebentar sebelum memeriksa
            Sleep(500);

            auto now = std::chrono::steady_clock::now();
            auto lastBeat = m_lastHeartbeat.load();

            // Hitung selisih waktu sejak heartbeat terakhir
            auto elapsed = now - lastBeat;

            if (elapsed > timeout) {
                // Heartbeat terlalu lama, ProcessWatcher kemungkinan di-suspend!
                // Hentikan Guardian untuk mencegah race condition
                m_isRunning = false;

                std::wstring message = L"Thread pemantauan dihentikan secara paksa!\n\nClient akan ditutup.";
                MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }
        }
    }
}