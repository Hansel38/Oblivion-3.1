#include "pch.h"
#include "AntiDebug.h"
#include <windows.h>
#include <winternl.h> // Untuk fungsi-fungsi NT yang tidak berdokumentasi

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

// Fungsi pointer untuk NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

namespace Oblivion {
    AntiDebug::AntiDebug() {}

    AntiDebug::~AntiDebug() {}

    void AntiDebug::PerformCheck() {
        // Jalankan semua metode pemeriksaan
        if (CheckDebuggerPresentAPI() || CheckNtQueryInfoProcess() || CheckInt3Trap()) {
            // Jika salah satu metode mendeteksi debugger, hentikan client
            std::string details = "Debugger detected via multiple checks";
            ReportViolationAndExit(L"", "DEBUGGER_DETECTED", details);
        }
    }

    bool AntiDebug::CheckDebuggerPresentAPI() {
        // Metode paling sederhana, mudah di-bypass tapi wajib ada.
        return IsDebuggerPresent() != FALSE;
    }

    bool AntiDebug::CheckNtQueryInfoProcess() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            return false; // Tidak bisa mendapatkan handle, asumsikan aman
        }

        pNtQueryInformationProcess NtQueryInfoProc = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInfoProc) {
            return false; // Fungsi tidak ditemukan, asumsikan aman
        }

        DWORD processDebugPort = 0;
        NTSTATUS status = NtQueryInfoProc(
            GetCurrentProcess(),
            ProcessDebugPort, // Kelas informasi: 0x7
            &processDebugPort,
            sizeof(DWORD),
            NULL
        );

        // Jika status berhasil dan port debug bukan nol, debugger terdeteksi.
        if (status == 0x00000000 && processDebugPort != 0) {
            return true;
        }

        return false;
    }

    bool AntiDebug::CheckInt3Trap() {
        // Metode yang sangat kuat.
        // Kita mencoba menjalankan __debugbreak() yang memicu INT 3.
        // Jika debugger ada, ia akan menangkap exception.
        // Jika tidak, exception handler kita (dalam __except) yang akan menanganinya.
        __try {
            __debugbreak(); // Ini setara dengan int 3
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Kode di dalam blok ini hanya dijalankan jika TIDAK ADA debugger.
            // Jika kita sampai di sini, berarti aman.
            return false;
        }

        // Jika eksekusi berlanjut ke sini, berarti exception ditangkap oleh debugger,
        // bukan oleh handler kita.
        return true;
    }
}