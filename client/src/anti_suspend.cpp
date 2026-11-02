#include "pch.h"
#include "anti_suspend.h"
#include <windows.h>
#include <string>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

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
        try {
            m_guardianThread = std::thread(&AntiSuspend::GuardianLoop, this);
        } catch (...) {
            m_isRunning = false;
            throw;
        }
    }

    void AntiSuspend::Stop() {
        // KRITIS: jangan early-return berdasar m_isRunning. GuardianLoop mematok
        // flag ini `false` sendiri saat mendeteksi suspend, sehingga early-return
        // akan melewati join() dan std::thread yang masih joinable dihancurkan ->
        // std::terminate. Operasi ini idempotent: join() hanya dijalankan bila
        // thread memang masih joinable.
        m_isRunning = false;
        if (m_guardianThread.joinable()) {
            m_guardianThread.join();
        }
    }

    void AntiSuspend::UpdateHeartbeat() {
        // Perbarui timestamp ke waktu saat ini
        m_lastHeartbeat.store(std::chrono::steady_clock::now());
    }

    bool AntiSuspend::IsRunning() const {
        return m_isRunning.load();
    }

    void AntiSuspend::GuardianLoop() {
        // Timeout berlaku untuk tidak adanya progres, bukan total durasi semua scan.
        // MemoryScanner dan DigitalSignatureValidator sekarang memperbarui heartbeat
        // pada tiap section/modul; 30 detik memberi ruang untuk satu panggilan API
        // sistem yang lambat tanpa membiarkan watcher yang benar-benar macet terlalu lama.
        const auto timeout = std::chrono::milliseconds(30000);

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

                auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                std::string details = "Monitoring thread suspended or terminated - heartbeat timeout exceeded (" + 
                                     std::to_string(elapsedSeconds) + " seconds)";
                ReportViolationAndExit(L"", "THREAD_SUSPENDED", details);
            }
        }
    }
}