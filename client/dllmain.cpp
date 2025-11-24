#include "pch.h"
#include "include/process_watcher.h"
#include <windows.h>

// Global instance dari ProcessWatcher
static Oblivion::ProcessWatcher* g_pProcessWatcher = nullptr;

// Fungsi export dari Stud_PE
// Ini adalah fungsi yang akan dipanggil oleh client setelah DLL di-inject.
// Untuk saat ini kita biarkan kosong karena inisialisasi utama ada di DllMain.
extern "C" __declspec(dllexport) void Oblivion_Entry() {
    // Potensial untuk trigger manual jika diperlukan di masa depan
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Mencegah thread detach notification untuk performa yang lebih baik
        DisableThreadLibraryCalls(hModule);

        // Alokasikan dan mulai ProcessWatcher
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
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}