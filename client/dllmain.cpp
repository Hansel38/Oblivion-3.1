#include "pch.h"
#include "process_watcher.h"
#include "file_integrity_check.h"
#include "network_reporter.h"
#include "self_integrity_guard.h"
#include "secret_obf.h"
#include <windows.h>
#include <thread>
#include <iostream>

// Global instance dari ProcessWatcher
static Oblivion::ProcessWatcher* g_pProcessWatcher = nullptr;

// Buat instance global NetworkReporter agar bisa diakses
// Ganti 127.0.0.1 dengan IP server Anda
static Oblivion::NetworkReporter* g_pNetworkReporter = nullptr;
static Oblivion::SelfIntegrityGuard* g_pSelfIntegrityGuard = nullptr;
static HMODULE g_hSelfModule = nullptr;

// Fungsi export dari Stud_PE
// Ini adalah fungsi yang akan dipanggil oleh client setelah DLL di-inject.
// Untuk saat ini kita biarkan kosong karena inisialisasi utama ada di DllMain.
extern "C" __declspec(dllexport) void Oblivion_Entry() {
    // Potensial untuk trigger manual jika diperlukan di masa depan
}

// Fungsi helper untuk melaporkan pelanggaran
void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details) {
    // Tunggu maksimal 5 detik untuk NetworkReporter siap (jika belum siap)
    int waitCount = 0;
    while (!g_pNetworkReporter && waitCount < 50) {
        Sleep(100); // Tunggu 100ms
        waitCount++;
    }
    
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
        // Jika reporter belum siap setelah timeout, fallback ke penutupan lokal
        if (!message.empty()) {
            MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
        }
        ExitProcess(0);
    }
}

// Fungsi inisialisasi yang dijalankan di thread terpisah
void InitializeSecuritySystem() {
    // --- LANGKAH PERTAMA: BUAT CONSOLE UNTUK DEBUGGING ---
    // Sesuai requirement: client menggunakan Console
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();
    
    SetConsoleTitleW(L"Oblivion Hack Shield - Debug Console");
    std::cout << "==================================================" << std::endl;
    std::cout << "  OBLIVION HACK SHIELD - Anti-Cheat System" << std::endl;
    std::cout << "  Version 1.0 - Ragnarok Online Protection" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "[INIT] Console initialized" << std::endl;
    
    // --- LANGKAH KEDUA: BUAT NETWORK REPORTER ---
    std::cout << "[INIT] Creating network reporter..." << std::endl;
    try {
        // Ambil secret yang di-obfuscate (bukan string literal langsung)
        const std::string kClientSecret = Oblivion::GetClientSecret();
        g_pNetworkReporter = new Oblivion::NetworkReporter("127.0.0.1", 54321, kClientSecret);
        std::cout << "[INIT] Network reporter created" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to create network reporter: " << e.what() << std::endl;
        MessageBoxW(NULL, L"Gagal menginisialisasi network reporter.\n\nClient akan ditutup.", 
                    L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    } catch (...) {
        std::cerr << "[ERROR] Unknown error creating network reporter" << std::endl;
        MessageBoxW(NULL, L"Kesalahan tidak diketahui saat inisialisasi.\n\nClient akan ditutup.", 
                    L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    }

    // --- LANGKAH KETIGA: CEK BAN STATUS DARI SERVER ---
    std::cout << "[INIT] Checking ban status with server..." << std::endl;
    try {
        if (!g_pNetworkReporter->CheckBanStatus()) {
            // Jika di-ban, CheckBanStatus sudah memanggil ExitProcess, jadi tidak akan sampai di sini
            return;
        }
        std::cout << "[INIT] Ban check passed" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception during ban check: " << e.what() << std::endl;
        MessageBoxW(NULL, L"Kesalahan saat memeriksa status ban.\n\nClient akan ditutup.", 
                    L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    }

    // --- LANGKAH KEEMPAT: PERIKSA INTEGRITAS FILE ---
    std::cout << "[INIT] Performing file integrity check..." << std::endl;
    try {
        Oblivion::FileIntegrityChecker integrityChecker;
        integrityChecker.PerformCheck();
        std::cout << "[INIT] File integrity check passed" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] File integrity check failed: " << e.what() << std::endl;
        ReportViolationAndExit(L"", "FILE_INTEGRITY_EXCEPTION", e.what());
        return;
    } catch (...) {
        std::cerr << "[ERROR] Unknown error during file integrity check" << std::endl;
        ReportViolationAndExit(L"", "FILE_INTEGRITY_UNKNOWN_ERROR", "Unknown exception");
        return;
    }

    // --- LANGKAH KELIMA: AKTIFKAN SELF-INTEGRITY GUARD ---
    std::cout << "[INIT] Starting self-integrity guard..." << std::endl;
    try {
        if (!g_pSelfIntegrityGuard) {
            g_pSelfIntegrityGuard = new Oblivion::SelfIntegrityGuard(g_hSelfModule);
            if (!g_pSelfIntegrityGuard->Start()) {
                std::cerr << "[ERROR] Self-integrity guard failed to start" << std::endl;
                ReportViolationAndExit(L"", "SELF_GUARD_INIT_FAILED", "Unable to initialize self integrity guard");
                return;
            }
            std::cout << "[INIT] Self-integrity guard active" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception starting self-integrity guard: " << e.what() << std::endl;
        ReportViolationAndExit(L"", "SELF_GUARD_EXCEPTION", e.what());
        return;
    }

    // --- LANGKAH KEENAM: MULAI SISTEM PEMANTAUAN ---
    std::cout << "[INIT] Starting process watcher..." << std::endl;
    try {
        g_pProcessWatcher = new Oblivion::ProcessWatcher();
        g_pProcessWatcher->Start();
        std::cout << "[SUCCESS] Oblivion Hack Shield fully initialized!" << std::endl;
        std::cout << "[INFO] Protection active - monitoring for threats..." << std::endl;
        std::cout << "==================================================" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception starting process watcher: " << e.what() << std::endl;
        ReportViolationAndExit(L"", "PROCESS_WATCHER_EXCEPTION", e.what());
        return;
    }
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Mencegah thread detach notification untuk performa yang lebih baik
        DisableThreadLibraryCalls(hModule);
        g_hSelfModule = hModule;

        // PENTING: Jangan melakukan operasi blocking di DllMain!
        // Pindahkan semua inisialisasi berat ke thread terpisah agar aplikasi bisa menampilkan window
        // Buat thread untuk inisialisasi sistem keamanan
        std::thread initThread(InitializeSecuritySystem);
        initThread.detach(); // Detach thread agar bisa berjalan mandiri
        break;
    }

    case DLL_PROCESS_DETACH:
        std::cout << "[CLEANUP] Shutting down Oblivion Hack Shield..." << std::endl;
        
        // Stop process watcher terlebih dahulu (ini akan stop monitoring)
        if (g_pProcessWatcher) {
            std::cout << "[CLEANUP] Stopping process watcher..." << std::endl;
            try {
                g_pProcessWatcher->Stop();
                delete g_pProcessWatcher;
                g_pProcessWatcher = nullptr;
            } catch (...) {
                // Ignore exceptions during cleanup
            }
        }
        
        // Kemudian stop self-integrity guard
        if (g_pSelfIntegrityGuard) {
            std::cout << "[CLEANUP] Stopping self-integrity guard..." << std::endl;
            try {
                g_pSelfIntegrityGuard->Stop();
                delete g_pSelfIntegrityGuard;
                g_pSelfIntegrityGuard = nullptr;
            } catch (...) {
                // Ignore exceptions during cleanup
            }
        }
        
        // Terakhir cleanup network reporter
        if (g_pNetworkReporter) {
            std::cout << "[CLEANUP] Cleaning up network reporter..." << std::endl;
            try {
                delete g_pNetworkReporter;
                g_pNetworkReporter = nullptr;
            } catch (...) {
                // Ignore exceptions during cleanup
            }
        }
        
        std::cout << "[CLEANUP] Shutdown complete" << std::endl;
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}