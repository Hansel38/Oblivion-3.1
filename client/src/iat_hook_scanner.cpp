#include "pch.h"
#include "iat_hook_scanner.h"
#include <iostream>
#include <cstdio>

// Forward declaration (pelaporan + sanction lokal yang juga mengirim ke server)
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    namespace {
        // Batas jumlah entri yang diperiksa: melindungi dari tabel impor yang
        // rusak/berbahaya yang bisa membuat loop tak berujung.
        constexpr size_t kMaxImportDescriptors = 4096;
        constexpr size_t kMaxThunksPerModule = 65536;

        // True bila alamat target IAT TIDAK berada di dalam image (module) mana pun,
        // yaitu hook diarahkan ke memori privat (VirtualAlloc/heap) alih-alih ke kode
        // module yang sebenarnya. Dipakai saat tabel nama fungsi tidak tersedia.
        bool IsPrivateMemoryTarget(const void* address) {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
                return true; // Tidak bisa di-query: anggap mencurigakan
            }
            return mbi.Type != MEM_IMAGE;
        }

        // Laporkan IAT hook: kirim ke server (best-effort) lalu tutup client.
        // Versi lama langsung memanggil MessageBox + ExitProcess tanpa laporan,
        // sehingga pelanggaran tidak terlihat oleh admin sama sekali.
        void ReportIatHook(const char* szFuncName, const char* szDllName, const void* iatAddr) {
            const std::string funcName = szFuncName ? szFuncName : "(ordinal/tanpa nama)";
            const std::string dllName = szDllName ? szDllName : "(dll tidak dikenal)";

            std::wstring message = L"IAT Hook terdeteksi!\n\nFungsi: ";
            message += std::wstring(funcName.begin(), funcName.end());
            message += L"\nDLL: ";
            message += std::wstring(dllName.begin(), dllName.end());
            message += L"\n\nClient akan ditutup.";

            char buffer[512] = { 0 };
            sprintf_s(buffer, "IAT hook pada %s!%s -> alamat IAT %p",
                      dllName.c_str(), funcName.c_str(), iatAddr);

            ReportViolationAndExit(message, "IAT_HOOK_DETECTED", std::string(buffer));
        }
    }

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

        // Seluruh penelusuran PE dibungkus SEH: header/tabel impor yang sudah
        // dimodifikasi tidak boleh membuat client game crash (DoS lokal).
        __try {

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

        // Dapatkan Import Descriptor.
        // PENTING: validasi VirtualAddress/Size SEBELUM menghitung pointer. Pada
        // binary tanpa tabel impor VirtualAddress == 0 sehingga (pBase + 0) == pBase:
        // pointer-nya NON-null, jadi pemeriksaan `if (!pImportDir)` versi lama tidak
        // pernah aktif dan parser menelusuri DOS header sebagai import descriptor.
        const IMAGE_DATA_DIRECTORY& importDirEntry =
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirEntry.VirtualAddress == 0 || importDirEntry.Size == 0) {
            return; // Tidak ada tabel impor
        }

        PIMAGE_IMPORT_DESCRIPTOR pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importDirEntry.VirtualAddress);

        size_t descriptorCount = 0;
        // Terminator tabel impor adalah descriptor dengan Name == 0. Versi lama memakai
        // `Characteristics && Name`, sehingga tabel yang field Characteristics-nya 0
        // dilewati SELURUHNYA (deteksi mudah di-bypass).
        while (pImportDir->Name != 0) {
            if (++descriptorCount > kMaxImportDescriptors) {
                return;
            }
            // Dapatkan nama DLL yang diimpor
            char* szDllName = (char*)(pBase + pImportDir->Name);
            HMODULE hImportedDll = GetModuleHandleA(szDllName);
            if (!hImportedDll) {
                pImportDir++;
                continue; // Lanjut jika DLL tidak dimuat (seharusnya tidak terjadi)
            }

            // OriginalFirstThunk berisi NAMA fungsi. Pada image yang sudah di-bound
            // (atau PE tertentu) field ini bernilai 0, dan (pBase + 0) menunjuk ke DOS
            // header sehingga AddressOfData diperlakukan sebagai RVA -> pointer sampah
            // (crash / deteksi palsu). Karena itu jalur ini dipisahkan.
            const bool hasNameTable = (pImportDir->OriginalFirstThunk != 0);
            PIMAGE_THUNK_DATA pOrigThunk = hasNameTable
                ? (PIMAGE_THUNK_DATA)(pBase + pImportDir->OriginalFirstThunk)
                : nullptr;
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pBase + pImportDir->FirstThunk);

            size_t thunkCount = 0;
            // Iterasi melalui semua fungsi yang diimpor dari DLL ini
            while (pThunk->u1.Function != 0) {
                if (++thunkCount > kMaxThunksPerModule) {
                    break;
                }

                if (!hasNameTable) {
                    // Tanpa tabel nama kita tidak bisa membandingkan lewat
                    // GetProcAddress. Gunakan pemeriksaan generik: target IAT harus
                    // berada di dalam image module; hook ke memori privat terdeteksi.
                    const void* target = (const void*)pThunk->u1.Function;
                    if (IsPrivateMemoryTarget(target)) {
                        ReportIatHook(nullptr, szDllName, target);
                        return;
                    }
                    pThunk++;
                    continue;
                }

                if (pOrigThunk->u1.AddressOfData == 0) {
                    break;
                }
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
                    // (pRealAddr null = nama tidak ada di DLL -> bukan bukti hook.)
                    if (pRealAddr && pRealAddr != pIatAddr) {
                        // Lapor ke server + sanction lokal. Versi lama hanya menampilkan
                        // MessageBox lalu ExitProcess, sehingga pelanggaran tidak pernah
                        // tercatat di sisi admin.
                        ReportIatHook(szFuncName, szDllName, (const void*)pIatAddr);
                        return;
                    }
                }
                pThunk++;
                if (pOrigThunk) {
                    pOrigThunk++;
                }
            }
            pImportDir++;
        }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Header/tabel impor tidak dapat dibaca dengan aman: lewati pemeriksaan
            // ini (kegagalan infrastruktur, bukan pelanggaran pemain).
            std::cerr << "[IATHookScanner] Tabel impor tidak dapat dibaca (dilewati)" << std::endl;
        }
    }
}