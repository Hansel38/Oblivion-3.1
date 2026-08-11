#include "pch.h"
#include "iat_hook_scanner.h"
#include <iostream>

// Semua temuan harus melalui reporter agar server dapat menyimpan bukti dan
// menerapkan policy yang sama untuk setiap jenis pelanggaran.
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    IATHookScanner::IATHookScanner() {}

    IATHookScanner::~IATHookScanner() {}

    void IATHookScanner::PerformScan() {
        // Dapatkan base address dari modul utama (rro.exe)
        HMODULE hMod = GetModuleHandle(NULL);
        if (!hMod) {
            return;
        }

        // Konversi ke byte pointer untuk perhitungan offset
        BYTE* pBase = (BYTE*)hMod;

        // Dapatkan DOS Header
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return; // Bukan PE yang valid
        }

        // Dapatkan NT Headers
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return; // Bukan PE yang valid
        }

        // Dapatkan Import Descriptor
        PIMAGE_IMPORT_DESCRIPTOR pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        if (!pImportDir) {
            return; // Tidak ada tabel impor
        }

        // Iterasi melalui semua DLL yang diimpor
        while (pImportDir->Characteristics && pImportDir->Name) {
            // Dapatkan nama DLL yang diimpor
            char* szDllName = (char*)(pBase + pImportDir->Name);
            HMODULE hImportedDll = GetModuleHandleA(szDllName);
            if (!hImportedDll) {
                pImportDir++;
                continue; // Lanjut jika DLL tidak dimuat (seharusnya tidak terjadi)
            }

            // Dapatkan pointer ke OriginalFirstThunk (berisi nama fungsi) dan FirstThunk (IAT)
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)(pBase + pImportDir->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pBase + pImportDir->FirstThunk);

            // Iterasi melalui semua fungsi yang diimpor dari DLL ini
            while (pOrigThunk->u1.AddressOfData && pThunk->u1.Function) {
                // Kita hanya memeriksa fungsi yang diimpor dengan nama, bukan dengan ordinal
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pBase + pOrigThunk->u1.AddressOfData);
                    char* szFuncName = pImportName->Name;

                    // Dapatkan alamat asli fungsi menggunakan GetProcAddress
                    FARPROC pRealAddr = GetProcAddress(hImportedDll, szFuncName);
                    if (!pRealAddr) {
                        pOrigThunk++;
                        pThunk++;
                        continue; // Fungsi tidak ditemukan, lanjut
                    }

                    // Dapatkan al fungsi dari IAT
                    FARPROC pIatAddr = (FARPROC)pThunk->u1.Function;

                    // BANDINGKAN! Jika tidak cocok, berarti ada HOOK.
                    if (pRealAddr != pIatAddr) {
                        const std::string functionName(szFuncName);
                        const std::string moduleName(szDllName);
                        const std::string details = "Function=" + functionName + " | Module=" + moduleName;
                        ReportViolationAndExit(
                            L"IAT hook terdeteksi.\n\nClient akan ditutup.",
                            "IAT_HOOK_DETECTED",
                            details);
                        return;
                    }
                }
                pOrigThunk++;
                pThunk++;
            }
            pImportDir++;
        }
    }
}
