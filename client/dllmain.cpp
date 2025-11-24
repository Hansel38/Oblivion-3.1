#include "pch.h"
#include "process_watcher.h"
#include "file_integrity_check.h"
#include "network_reporter.h"
#include <windows.h>

// Global instance dari ProcessWatcher
static Oblivion::ProcessWatcher* g_pProcessWatcher = nullptr;

// Buat instance global NetworkReporter agar bisa diakses
// Ganti 127.0.0.1 dengan IP server Anda
static Oblivion::NetworkReporter* g_pNetworkReporter = nullptr;

// Fungsi export dari Stud_PE
// Ini adalah fungsi yang akan dipanggil oleh client setelah DLL di-inject.
// Untuk saat ini kita biarkan kosong karena inisialisasi utama ada di DllMain.
extern "C" __declspec(dllexport) void Oblivion_Entry() {
    // Potensial untuk trigger manual jika diperlukan di masa depan
}

// Fungsi helper untuk melaporkan pelanggaran
void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details) {
    // Kirim laporan ke server (BLOCKING - menunggu respons)
    // ReportViolation akan menunggu respons dari server dan menampilkan message box
    // Jika server mengirim KICK, ReportViolation akan memanggil ExitProcess
    if (g_pNetworkReporter) {
        g_pNetworkReporter->ReportViolation(type, details);
        // Jika sampai di sini, berarti server tidak mengirim KICK atau timeout
        // Tampilkan pesan default dan tutup client
        if (!message.empty()) {
            MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
        }
        ExitProcess(0);
    } else {
        // Jika reporter belum siap, fallback ke penutupan lokal
        if (!message.empty()) {
            MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
        }
        ExitProcess(0);
    }
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Mencegah thread detach notification untuk performa yang lebih baik
        DisableThreadLibraryCalls(hModule);

        // --- LANGKAH PERTAMA: BUAT NETWORK REPORTER ---
        g_pNetworkReporter = new Oblivion::NetworkReporter("127.0.0.1", 54321);

        // --- LANGKAH KEDUA: PERIKSA INTEGRITAS FILE ---
        // Jika ini gagal, ExitProcess(0) akan dipanggil dan game tidak akan berjalan lebih lanjut.
        {
            Oblivion::FileIntegrityChecker integrityChecker;
            integrityChecker.PerformCheck();
        }


        // --- KETIGA: MULAI SISTEM PEMANTAUAN --
        g_pProcessWatcher = new Oblivion::ProcessWatcher();
        g_pProcessWatcher->Start();
        break;

    case DLL_PROCESS_DETACH:
        // Hentikan dan dealokasikan ProcessWatcher
        if (g_pProcessWatcher) {
            g_pProcessWatcher->Stop();
            delete g_pProcessWatcher;
            g_pProcessWatcher = nullptr;
        }
        if (g_pNetworkReporter) {
            delete g_pNetworkReporter;
            g_pNetworkReporter = nullptr;
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}