#include "pch.h"
#include "injection_scanner.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cwctype> // Untuk towlower

namespace Oblivion {
    InjectionScanner::InjectionScanner() {}

    InjectionScanner::~InjectionScanner() {}

    void InjectionScanner::PerformScan() {
        // Ambil snapshot dari semua modul yang dimuat oleh proses saat ini
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            // Gagal mengambil snapshot, log error jika perlu
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        // Dapatkan informasi modul pertama
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                // Periksa apakah modul (DLL) ini ada di daftar hitam
                if (IsDllBlacklisted(me32.szModule)) {
                    // Jika iya, hentikan client
                    std::wstring message = L"Modul ilegal terdeteksi: ";
                    message += me32.szModule;
                    message += L"\n\nClient akan ditutup.";
                    MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                    ExitProcess(0);
                }

            } while (Module32NextW(hSnapshot, &me32));
        }

        // Tutup handle snapshot
        CloseHandle(hSnapshot);
    }

    bool InjectionScanner::IsDllBlacklisted(const wchar_t* dllName) {
        // Daftar nama DLL yang dicurigai.
        // PERHATIAN: Hati-hati menambahkan daftar ini untuk menghindari false positive.
        // Fokus pada DLL yang spesifik untuk cheat.
        static const std::vector<std::wstring> blacklistedDlls = {
            L"wexdist.dll", // Sering digunakan oleh OpenKore
            L"macro.dll",
            L"rpehook.dll",
            L"wpehook.dll",
            L"cheat.dll",
            L"injector.dll",
            L"autopot.dll",
            L"bot.dll"
        };

        std::wstring moduleName = dllName;
        // Ubah ke lowercase untuk perbandingan case-insensitive
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::towlower);

        for (const auto& blacklistedName : blacklistedDlls) {
            if (moduleName == blacklistedName) {
                return true;
            }
        }

        return false;
    }
}