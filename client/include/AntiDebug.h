#pragma once

#include <windows.h>
#include <string>

namespace Oblivion {
    class AntiDebug {
    public:
        AntiDebug();
        ~AntiDebug();

        // Fungsi utama untuk menjalankan semua pemeriksaan anti-debug
        void PerformCheck();

    private:
        // Metode 1: Menggunakan API IsDebuggerPresent
        bool CheckDebuggerPresentAPI();

        // Metode 2: Menggunakan NtQueryInformationProcess
        bool CheckNtQueryInfoProcess();

        // Metode 3: Jebakan dengan software exception (INT 3)
        bool CheckInt3Trap();
    };
}