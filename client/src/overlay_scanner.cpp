#include "pch.h"
#include "overlay_scanner.h"
#include "digital_signature_validator.h"
#include <string>
#include <array>
#include <map>
#include <algorithm>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    // Minimal area irisan (dalam persen dari luas jendela game) sebelum sebuah
    // jendela topmost dianggap overlay yang menutupi gameplay. Jendela always-on-top
    // kecil (chat, mini tool, notifikasi) tidak lagi salah ditandai.
    constexpr LONG kMinCoveragePercent = 25;

    // Overlay cheat selalu tidak bertanda tangan; aplikasi sah (browser, chat, media
    // player, overlay vendor GPU) ditandatangani publisher tepercaya. Cache dipakai
    // karena WinVerifyTrust relatif mahal (scan berjalan single-threaded).
    bool IsFileSignedByTrustedPublisher(const std::wstring& filePath) {
        if (filePath.empty()) {
            return false;
        }

        std::wstring key = filePath;
        std::transform(key.begin(), key.end(), key.begin(), ::towlower);

        static std::map<std::wstring, bool> cache;
        auto cached = cache.find(key);
        if (cached != cache.end()) {
            return cached->second;
        }

        std::wstring publisher;
        const bool trusted =
            Oblivion::DigitalSignatureValidator::GetSignatureVerdict(filePath, publisher) ==
            Oblivion::DigitalSignatureValidator::SignatureVerdict::TrustedPublisher;

        cache[key] = trusted;
        return trusted;
    }

    std::wstring GetWindowProcessPath(HWND hwnd) {
        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);
        if (windowPid == 0) {
            return L"";
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, windowPid);
        if (hProcess == NULL) {
            return L"";
        }

        wchar_t processPath[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;
        std::wstring result;

        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
            result = processPath;
        }

        CloseHandle(hProcess);
        return result;
    }
}

namespace Oblivion {
    OverlayScanner::OverlayScanner() : m_gameWindow(NULL), m_gameRect{0, 0, 0, 0}, m_gameProcessId(0) {
        // Coba cari handle jendela game. "RagWindow" adalah class name default untuk Ragnarok.
        // Jika client Anda menggunakan class name berbeda, sesuaikan di sini.
        m_gameWindow = FindWindowW(L"RagWindow", NULL);
        if (m_gameWindow) {
            GetWindowRect(m_gameWindow, &m_gameRect);
            GetWindowThreadProcessId(m_gameWindow, &m_gameProcessId);
        }
    }

    OverlayScanner::~OverlayScanner() {}

    void OverlayScanner::PerformScan() {
        // Jika jendela game belum ditemukan (misalnya saat DLL pertama kali dimuat),
        // coba cari lagi di setiap scan.
        if (!m_gameWindow) {
            m_gameWindow = FindWindowW(L"RagWindow", NULL);
            if (m_gameWindow) {
                GetWindowRect(m_gameWindow, &m_gameRect);
                GetWindowThreadProcessId(m_gameWindow, &m_gameProcessId);
            }
        }

        // Jika masih tidak ditemukan, tidak ada yang bisa dipindai.
        if (!m_gameWindow) {
            return;
        }

        // Enumerasi semua jendela tingkat atas dan jalankan callback untuk masing-masing jendela
        EnumWindows(EnumWindowsCallback, (LPARAM)this);
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        // Dapatkan instance OverlayScanner dari lParam
        OverlayScanner* pThis = reinterpret_cast<OverlayScanner*>(lParam);

        // Abaikan jendela kita sendiri
        if (hwnd == pThis->m_gameWindow) {
            return TRUE;
        }

        // 1. Periksa apakah jendela visible
        if (!IsWindowVisible(hwnd)) {
            return TRUE; // Lanjut ke jendela berikutnya
        }

        // 2. Periksa apakah jendela berpotongan dengan jendela game
        RECT overlayRect;
        GetWindowRect(hwnd, &overlayRect);
        RECT intersectionRect;
        if (!IntersectRect(&intersectionRect, &pThis->m_gameRect, &overlayRect)) {
            return TRUE; // Tidak berpotongan, lanjut
        }

        // 3. Periksa apakah jendela adalah topmost
        LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        if (!(exStyle & WS_EX_TOPMOST)) {
            return TRUE; // Bukan topmost, lanjut
        }

        // 4. Abaikan semua jendela milik process game sendiri.
        // Versi sebelumnya hanya mengabaikan m_gameWindow sehingga window lain milik
        // client (splash, tooltip, dialog bantu, window topmost internal) bisa salah
        // dianggap overlay ilegal dan langsung men-kick pemain.
        if (pThis->m_gameProcessId != 0) {
            DWORD windowPid = 0;
            GetWindowThreadProcessId(hwnd, &windowPid);
            if (windowPid == pThis->m_gameProcessId) {
                return TRUE;
            }
        }

        // 5. Jendela harus menutupi sebagian besar area game. Jendela always-on-top
        // kecil (chat, mini tool, notifikasi) bukan overlay cheat.
        // Perhitungan memakai 64-bit untuk menghindari overflow pada resolusi besar.
        const long long gameArea =
            static_cast<long long>(pThis->m_gameRect.right - pThis->m_gameRect.left) *
            static_cast<long long>(pThis->m_gameRect.bottom - pThis->m_gameRect.top);
        const long long intersectionArea =
            static_cast<long long>(intersectionRect.right - intersectionRect.left) *
            static_cast<long long>(intersectionRect.bottom - intersectionRect.top);
        if (gameArea <= 0 || intersectionArea * 100 < gameArea * kMinCoveragePercent) {
            return TRUE; // Cakupan terlalu kecil, lanjut
        }

        // 6. Periksa apakah jendela ada di whitelist
        wchar_t className[256];
        GetClassNameW(hwnd, className, 256);
        if (pThis->IsWhitelisted(className)) {
            return TRUE; // Ada di whitelist, aman. Lanjut.
        }

        // 7. Abaikan jendela dari aplikasi yang executable-nya ditandatangani publisher
        // tepercaya. Overlay cheat selalu unsigned, sedangkan browser/chat/media player
        // /overlay vendor GPU umumnya bertanda tangan sehingga sebelumnya salah ditandai.
        if (IsFileSignedByTrustedPublisher(GetWindowProcessPath(hwnd))) {
            return TRUE;
        }

        // Jika sampai di sini, berarti semua kriteria terpenuhi:
        // - Visible
        // - Berpotongan signifikan dengan game
        // - Topmost
        // - Bukan milik process game
        // - Tidak ada di whitelist
        // - Bukan aplikasi bertanda tangan publisher tepercaya
        // Ini adalah overlay ilegal!

        // Konversi className ke UTF-8 untuk details
        std::string details_utf8;
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, className, -1, NULL, 0, NULL, NULL);
        if (size_needed > 0) {
            details_utf8.assign(size_needed - 1, 0); // -1 untuk menghilangkan null terminator
            WideCharToMultiByte(CP_UTF8, 0, className, -1, &details_utf8[0], size_needed, NULL, NULL);
        }
        
        // Panggil fungsi pelaporan global
        ReportViolationAndExit(L"", "OVERLAY_DETECTED", details_utf8);

        // Kode tidak akan mencapai sini karena ExitProcess
        return FALSE;
    }

    bool OverlayScanner::IsWhitelisted(const wchar_t* className) {
        // Daftar class name dari overlay yang diizinkan.
        // PERHATIAN: Daftar ini sangat penting untuk mencegah false positive.
        // Tambahkan jika menemukan software sah yang diblokir.
        static constexpr std::array<const wchar_t*, 23> whitelistedClasses = {
            L"Windows.UI.Core.CoreWindow", // UWP apps
            L"ApplicationFrameWindow", // UWP apps
            L"Shell_TrayWnd", // Taskbar
            L"DV2ControlHost", // Volume control
            L"ForegroundStaging", // Volume control
            L"Windows.UI.Input.InputSite.WindowClass", // Keyboard on-screen
            L"MSCTFIME UI", // IME
            L"IME", // IME
            L"tooltips_class32", // Tooltip
            L"SysShadow", // Shadow
            L"Button", // Standard button (rarely topmost)
            L"Static", // Static text
            L"Chrome_WidgetWin_1", // Chrome-based app notifications/overlays
            L"MozillaWindowClass", // Firefox-based overlays
            L"DiscordOverlay", // Discord Overlay
            L"SteamOverlay001", // Steam Overlay
            L"NotificationFlyout", // Windows 10/11 notifications
            L"ForegroundStaging", // Volume flyout
            L"OverlayClass", // Generic, but often used by benign tools. Use with caution.
            // Tambahan untuk menekan false positive: variasi class Chromium/Electron,
            // tray overflow, dan bridge UWP overlay. Semuanya milik aplikasi biasa.
            L"Chrome_WidgetWin_0",
            L"Chrome_WidgetWin_2",
            L"NotifyIconOverflowWindow",
            L"Windows.UI.Composition.DesktopWindowContentBridge"
        };

        for (const auto& whitelistedName : whitelistedClasses) {
            if (wcscmp(className, whitelistedName) == 0) {
                return true;
            }
        }

        return false;
    }
}
