#include "pch.h"
#include "process_watcher.h"
#include "file_integrity_check.h"
#include "network_reporter.h"
#include "self_integrity_guard.h"
#include "secret_obf.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <iostream>
#include <fstream>
#include <string>
#include <objidl.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

// Global instance dari ProcessWatcher
//
// Pointer ini diakses dari beberapa thread (thread inisialisasi, thread heartbeat
// di NetworkReporter, dan jalur pelaporan), sehingga disimpan sebagai atomic supaya
// pembacaan/penulisan tidak menjadi data race (secara formal UB) dan tidak membaca
// pointer yang sedang dihapus.
static std::atomic<Oblivion::ProcessWatcher*> g_pProcessWatcher{ nullptr };

// Buat instance global NetworkReporter agar bisa diakses
// Ganti 127.0.0.1 dengan IP server Anda
static std::atomic<Oblivion::NetworkReporter*> g_pNetworkReporter{ nullptr };
static std::atomic<Oblivion::SelfIntegrityGuard*> g_pSelfIntegrityGuard{ nullptr };
static HMODULE g_hSelfModule = nullptr;

// Menandai bahwa seluruh komponen pengaman sudah selesai diinisialisasi.
// Dipakai sebagai gerbang status heartbeat supaya startup tidak pernah
// dilaporkan sebagai "komponen mati" (lihat BuildClientStatus).
static std::atomic<bool> g_initCompleted{ false };


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
    while (g_pNetworkReporter.load() == nullptr && waitCount < 50) {
        Sleep(100); // Tunggu 100ms
        waitCount++;
    }

    // Ambil pointer sekali saja: instance bisa dihapus oleh shutdown (FreeLibrary)
    // di thread lain, sehingga pemeriksaan null harus memakai nilai lokal ini.
    Oblivion::NetworkReporter* reporter = g_pNetworkReporter.load();
    
    // Kirim laporan ke server (BLOCKING - menunggu respons)
    // ReportViolation akan menunggu respons dari server dan menampilkan message box
    // Jika server mengirim KICK, ReportViolation akan memanggil ExitProcess
    if (reporter) {
        reporter->ReportViolation(type, details);
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

// Catat masalah internal client (bukan pelanggaran cheat).
// Dipakai supaya kegagalan infrastruktur tetap bisa diaudit oleh admin melalui
// file log lokal, tanpa men-kick / melaporkan pemain yang tidak bersalah.
static void LogClientIssue(const std::string& type, const std::string& details) {
    std::cerr << "[CLIENT_ISSUE] " << type << " - " << details << std::endl;

    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        return;
    }

    wchar_t* lastSlash = wcsrchr(exePath, L'\\');
    if (!lastSlash) {
        return;
    }
    *(lastSlash + 1) = L'\0';

    // Log ditulis di direktori executable (best-effort, kegagalan diabaikan).
    std::ofstream logFile(std::wstring(exePath) + L"oblivion_client_errors.log", std::ios::app);
    if (!logFile.is_open()) {
        return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    logFile << st.wYear << '-' << st.wMonth << '-' << st.wDay << ' '
            << st.wHour << ':' << st.wMinute << ':' << st.wSecond
            << " [" << type << "] " << details << std::endl;
}

// Laporkan pelanggaran TANPA menutup client (report-only).
//
// Dipakai untuk temuan yang belum cukup kuat untuk men-kick pemain (mis. hash
// integritas file yang belum diverifikasi pada build produksi). Laporan tetap
// dikirim ke server supaya admin bisa memutuskan, dan kegagalan jaringan hanya
// dicatat lokal sehingga tidak pernah menutup client pemain sah.
void ReportViolationSoft(const std::string& type, const std::string& details) {
    Oblivion::NetworkReporter* reporter = g_pNetworkReporter.load();
    if (!reporter) {
        LogClientIssue("VIOLATION_SOFT_NOT_READY", type + " - " + details);
        return;
    }
    try {
        reporter->ReportViolation(type, details);
    } catch (...) {
        LogClientIssue("VIOLATION_SOFT_FAILED", type + " - " + details);
    }
}

// Sumber status runtime untuk heartbeat (PONG) yang dikirim ke server.
static Oblivion::ClientStatus BuildClientStatus() {
    // Sebelum inisialisasi selesai, komponen memang belum berjalan; status tetap
    // "true" agar startup tidak salah dilaporkan sebagai kegagalan pengaman.
    Oblivion::ClientStatus status{ true, true };
    if (!g_initCompleted.load()) {
        return status;
    }

    // Setelah inisialisasi selesai, laporkan kondisi nyata: false berarti lapisan
    // pengaman tidak berjalan (pelanggaran sendiri tetap dilaporkan komponennya).
    status.antiSuspendOk = (g_pProcessWatcher.load() != nullptr) && g_pProcessWatcher.load()->IsAntiSuspendRunning();
    status.integrityOk = (g_pSelfIntegrityGuard.load() != nullptr) && g_pSelfIntegrityGuard.load()->IsRunning();

    return status;
}

// buat disable atau enable debug console
bool ShouldHideDebugConsole() {
    constexpr int kConsoleToggle = 1; // 0 = console tampil, 1 = console tersembunyi
    return kConsoleToggle == 1;
}

// Fungsi inisialisasi yang dijalankan di thread terpisah
void InitializeSecuritySystem() {
    // Tampilkan Splash Screen (non-blocking terhadap loader, tapi menjalankan loop singkat)
    auto ShowSplash = []() {
        using namespace Gdiplus;
        ULONG_PTR gdiplusToken = 0;
        GdiplusStartupInput gdiplusStartupInput;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Ok) {
            return; // Jika GDI+ gagal, lanjut tanpa splash
        }

        wchar_t modulePath[MAX_PATH] = { 0 };
        const DWORD modulePathLength = GetModuleFileNameW(
            g_hSelfModule ? g_hSelfModule : GetModuleHandleW(nullptr),
            modulePath, MAX_PATH);
        if (modulePathLength == 0 || modulePathLength >= MAX_PATH) {
            GdiplusShutdown(gdiplusToken);
            return;
        }
        wchar_t* lastSlash = wcsrchr(modulePath, L'\\');
        if (!lastSlash) {
            GdiplusShutdown(gdiplusToken);
            return;
        }
        *lastSlash = L'\0';
        const std::wstring imagePath = std::wstring(modulePath) + L"\\logo\\OblivionHS.png";

        HWND hwndSplash = nullptr;
        HBITMAP hBmp = nullptr;
        Bitmap *img = nullptr;
        img = Bitmap::FromFile(imagePath.c_str(), FALSE);
        if (!img || img->GetLastStatus() != Ok) {
            delete img;
            GdiplusShutdown(gdiplusToken);
            return; // Tidak ada gambar, abaikan
        }

        const int imgW = static_cast<int>(img->GetWidth());
        const int imgH = static_cast<int>(img->GetHeight());

        WNDCLASSW wc{};
        wc.lpfnWndProc = [](HWND h, UINT m, WPARAM w, LPARAM l)->LRESULT {
            if (m == WM_PAINT) {
                PAINTSTRUCT ps; HDC hdc = BeginPaint(h, &ps);
                RECT rc; GetClientRect(h, &rc);
                Graphics g(hdc);
                g.SetInterpolationMode(InterpolationModeHighQualityBicubic);
                g.SetPixelOffsetMode(PixelOffsetModeHighQuality);
                g.SetSmoothingMode(SmoothingModeHighQuality);
                // Tarik pointer image dari properti window
                Bitmap* pImg = reinterpret_cast<Bitmap*>(GetPropW(h, L"__OBV_IMG"));
                if (pImg) {
                    // Render image dengan ukuran penuh sesuai client area
                    g.DrawImage(pImg, 0, 0, rc.right, rc.bottom);
                }
                EndPaint(h, &ps);
                return 0;
            }
            return DefWindowProcW(h, m, w, l);
        };
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = L"OblivionSplashClass";
        RegisterClassW(&wc);

        // Hitung ukuran window dengan border adjustment untuk WS_POPUP
        RECT rect = {0, 0, imgW, imgH};
        AdjustWindowRectEx(&rect, WS_POPUP, FALSE, WS_EX_TOPMOST | WS_EX_TOOLWINDOW);
        int windowW = rect.right - rect.left;
        int windowH = rect.bottom - rect.top;

        // Posisi center layar
        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);
        int x = (screenW - windowW) / 2;
        int y = (screenH - windowH) / 2;

        hwndSplash = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            wc.lpszClassName,
            L"Oblivion Hack Shield",
            WS_POPUP,
            x, y, windowW, windowH,
            nullptr, nullptr, wc.hInstance, nullptr);

        if (!hwndSplash) {
            delete img;
            GdiplusShutdown(gdiplusToken);
            return;
        }

        SetPropW(hwndSplash, L"__OBV_IMG", reinterpret_cast<HANDLE>(img));
        ShowWindow(hwndSplash, SW_SHOW);
        UpdateWindow(hwndSplash);

        // Jalankan message loop singkat selama 2000 ms
        const ULONGLONG durationMs = 2000;
        ULONGLONG start = GetTickCount64();
        MSG msg;
        while (GetTickCount64() - start < durationMs) {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Sleep(10);
        }

        RemovePropW(hwndSplash, L"__OBV_IMG");
        DestroyWindow(hwndSplash);
        delete img;
        GdiplusShutdown(gdiplusToken);
    };

    // Tampilkan splash sebelum console init
    ShowSplash();

    // --- LANGKAH PERTAMA: BUAT CONSOLE UNTUK DEBUGGING ---
    const bool hideConsole = ShouldHideDebugConsole();
    if (!hideConsole) {
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
    } else {
        OutputDebugStringW(L"[INFO] Oblivion Hack Shield debug console disabled via configuration.");
    }
    
    // --- LANGKAH KEDUA: BUAT NETWORK REPORTER ---
    std::cout << "[INIT] Creating network reporter..." << std::endl;
    try {
        // Ambil secret yang di-obfuscate (bukan string literal langsung)
        const std::string kClientSecret = Oblivion::GetClientSecret();
        // 127.0.0.1:54321 hanya FALLBACK (dev). Untuk produksi arahkan client ke VPS
        // lewat "oblivion.cfg" di folder executable, atau environment variable:
        //   oblivion.cfg       -> server=your-vps.example.com:54321
        //   OBLIVION_SERVER    -> your-vps.example.com:54321
        //   OBLIVION_FAIL_MODE -> open | closed
        Oblivion::NetworkReporter* reporter = new Oblivion::NetworkReporter("45.66.153.148", 54321, kClientSecret);
        g_pNetworkReporter.store(reporter);
        std::cout << "[INIT] Network reporter created" << std::endl;

        // Pasang sumber status heartbeat SEBELUM check-in, karena CheckBanStatus()
        // memulai thread heartbeat.
        reporter->SetStatusProvider(BuildClientStatus);
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
        Oblivion::NetworkReporter* reporter = g_pNetworkReporter.load();
        if (!reporter || !reporter->CheckBanStatus()) {
            // Jalur ban normal sudah memanggil ExitProcess di dalam CheckBanStatus.
            // Jika tidak (mis. reporter gagal dibuat), JANGAN lanjut dengan proteksi
            // setengah jadi sambil melaporkan status "OK" ke server.
            LogClientIssue("BAN_CHECK_ABORTED", "check-in gagal tanpa penutupan proses");
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
        // CATATAN KEBIJAKAN: kegagalan internal client (exception, file terkunci oleh
        // antivirus, permission, dsb) DULU dilaporkan ke server sebagai pelanggaran
        // sehingga pemain sah ikut di-kick sebagai cheater (false positive besar).
        // Sekarang kegagalan infrastruktur hanya dicatat secara lokal dan client
        // lanjut dengan lapisan proteksi yang masih bisa berjalan.
        std::cerr << "[ERROR] File integrity check failed (dilanjutkan tanpa layer ini): " << e.what() << std::endl;
        LogClientIssue("FILE_INTEGRITY_EXCEPTION", e.what());
    } catch (...) {
        std::cerr << "[ERROR] Unknown error during file integrity check (dilanjutkan tanpa layer ini)" << std::endl;
        LogClientIssue("FILE_INTEGRITY_UNKNOWN_ERROR", "Unknown exception");
    }

    // --- LANGKAH KELIMA: AKTIFKAN SELF-INTEGRITY GUARD ---
    std::cout << "[INIT] Starting self-integrity guard..." << std::endl;
    try {
        if (g_pSelfIntegrityGuard.load() == nullptr) {
            Oblivion::SelfIntegrityGuard* guard = new Oblivion::SelfIntegrityGuard(g_hSelfModule);
            g_pSelfIntegrityGuard.store(guard);
            if (!guard->Start()) {
                // Kegagalan infrastruktur (mis. DLL sendiri tidak bisa dibaca karena
                // dikunci antivirus) -> catat lokal, jangan ban pemain.
                std::cerr << "[ERROR] Self-integrity guard failed to start (dilanjutkan)" << std::endl;
                LogClientIssue("SELF_GUARD_INIT_FAILED", "Unable to initialize self integrity guard");
            } else {
                std::cout << "[INIT] Self-integrity guard active" << std::endl;
            }
        }
    } catch (const std::exception& e) {
        // Kegagalan infrastruktur (bukan bukti cheat) -> catat lokal, jangan ban.
        std::cerr << "[ERROR] Exception starting self-integrity guard (dilanjutkan): " << e.what() << std::endl;
        LogClientIssue("SELF_GUARD_EXCEPTION", e.what());
    }

    // --- LANGKAH KEENAM: MULAI SISTEM PEMANTAUAN ---
    std::cout << "[INIT] Starting process watcher..." << std::endl;
    try {
        Oblivion::ProcessWatcher* watcher = new Oblivion::ProcessWatcher();
        g_pProcessWatcher.store(watcher);
        watcher->Start();
        std::cout << "[SUCCESS] Oblivion Hack Shield fully initialized!" << std::endl;
        std::cout << "[INFO] Protection active - monitoring for threats..." << std::endl;
        std::cout << "==================================================" << std::endl;
    } catch (const std::exception& e) {
        // Kegagalan infrastruktur (bukan bukti cheat) -> catat lokal, jangan ban.
        std::cerr << "[ERROR] Exception starting process watcher (dilanjutkan): " << e.what() << std::endl;
        LogClientIssue("PROCESS_WATCHER_EXCEPTION", e.what());
    }

    // --- LANGKAH KETUJUH: TANDAI INISIALISASI SELESAI ---
    // Mulai titik ini, bit status heartbeat mencerminkan kondisi komponen nyata
    // (anti-suspend guard & self-integrity guard), bukan lagi nilai default.
    g_initCompleted = true;
}

// Dedicated initialization entry point. The module is pinned at load time,
// so this detached worker and the security workers cannot execute unmapped code.
static DWORD WINAPI InitializeSecurityThread(LPVOID) {
    try {
        InitializeSecuritySystem();
    } catch (...) {
        OutputDebugStringW(L"[Oblivion] Fatal exception during security initialization.");
        ExitProcess(1);
    }
    return 0;
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);

        // Worker threads execute code in this DLL for the whole game session.
        // Pin the module so an external FreeLibrary cannot unmap active code.
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(&Oblivion_Entry),
                &g_hSelfModule)) {
            OutputDebugStringW(L"[Oblivion] Failed to pin security DLL; load aborted.");
            return FALSE;
        }

        HANDLE initThread = CreateThread(nullptr, 0, InitializeSecurityThread, nullptr, 0, nullptr);
        if (initThread == nullptr) {
            OutputDebugStringW(L"[Oblivion] Failed to create initialization thread.");
            return FALSE;
        }
        CloseHandle(initThread);
        break;
    }

    case DLL_PROCESS_DETACH:
        // The DLL is pinned and remains loaded until process termination.
        // Do not join workers or perform I/O while the loader lock is held.
        (void)lpReserved;
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}