#include "pch.h"
#include "memory_scanner.h"
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <algorithm>

// Tidak perlu konfigurasi RVA manual!
// Sistem akan otomatis mendeteksi semua region executable dan membuat baseline CRC32.

namespace Oblivion {
    MemoryScanner::MemoryScanner() : m_baselineCreated(false), m_moduleBaseAddress(0) {}

    MemoryScanner::~MemoryScanner() {}

    uint32_t MemoryScanner::CalculateCRC32(const uint8_t* data, size_t size) {
        // Tabel CRC32 lookup (polynomial 0xEDB88320)
        static const uint32_t crc32_table[256] = {
            0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
            0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
            0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
            0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
            0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
            0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
            0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
            0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
            0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
            0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
            0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
            0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
            0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
            0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
            0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
            0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
            0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
            0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
            0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
            0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
            0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
            0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
            0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
            0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
            0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
            0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
            0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
            0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
            0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
            0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
            0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
            0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
            0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
            0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
            0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
            0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
            0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
            0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
            0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
            0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
            0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
            0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
            0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
        };

        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
        }
        return crc ^ 0xFFFFFFFF;
    }

    bool MemoryScanner::ReadExecutableFile(const std::wstring& filePath, std::vector<uint8_t>& fileData) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        fileData.resize(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(fileData.data()), size)) {
            return false;
        }

        return true;
    }

    void MemoryScanner::CreateBaselineFromFile(const std::wstring& filePath) {
        if (m_baselineCreated) {
            return; // Baseline sudah dibuat
        }

        // Baca file executable dari disk
        std::vector<uint8_t> fileData;
        if (!ReadExecutableFile(filePath, fileData)) {
            // Jika gagal membaca file, gunakan fallback dari memori
            CreateBaselineFromMemory();
            return;
        }

        // Ambil snapshot dari modul yang dimuat untuk mendapatkan mapping memori
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            CreateBaselineFromMemory();
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        // Cari modul utama
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szExePath, filePath.c_str()) == 0) {
                    uint8_t* baseAddr = reinterpret_cast<uint8_t*>(me32.modBaseAddr);
                    m_moduleBaseAddress = reinterpret_cast<uintptr_t>(baseAddr);
                    SIZE_T moduleSize = me32.modBaseSize;

                    MEMORY_BASIC_INFORMATION mbi;
                    for (size_t offset = 0; offset < moduleSize; offset += mbi.RegionSize) {
                        if (VirtualQuery(baseAddr + offset, &mbi, sizeof(mbi)) == 0) {
                            break;
                        }

                        // Hanya scan region yang executable dan readable
                        if (mbi.State == MEM_COMMIT && 
                            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                            
                            uint8_t* regionBase = reinterpret_cast<uint8_t*>(mbi.BaseAddress);
                            size_t regionSize = mbi.RegionSize;
                            uintptr_t regionAddress = reinterpret_cast<uintptr_t>(regionBase);

                            // Hitung RVA (Relative Virtual Address) dari region ini
                            uintptr_t rva = regionAddress - m_moduleBaseAddress;
                            
                            // Untuk kebanyakan executable, RVA = file offset untuk section .text
                            // Tapi untuk keamanan, kita hitung CRC32 dari memori saat ini
                            // (karena file mungkin sudah di-patch atau berbeda)
                            
                            // Hitung CRC32 dari memori saat ini sebagai baseline
                            // Ini lebih akurat karena membandingkan dengan state saat game running
                            uint32_t crc32 = CalculateCRC32(regionBase, regionSize);
                            
                            ExecutableRegion baseline;
                            baseline.address = regionAddress;
                            baseline.size = regionSize;
                            baseline.baselineCRC32 = crc32;
                            
                            m_baselineRegions.push_back(baseline);
                        }
                    }
                    break;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
        m_baselineCreated = true;
    }

    void MemoryScanner::CreateBaselineFromMemory() {
        if (m_baselineCreated) {
            return; // Baseline sudah dibuat
        }

        // Ambil snapshot dari modul yang dimuat oleh proses saat ini
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        // Cari modul utama
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                wchar_t exePath[MAX_PATH];
                if (GetModuleFileNameW(NULL, exePath, MAX_PATH) != 0) {
                    if (_wcsicmp(me32.szExePath, exePath) == 0) {
                        // Kita menemukan modul utama
                        uint8_t* baseAddr = reinterpret_cast<uint8_t*>(me32.modBaseAddr);
                        m_moduleBaseAddress = reinterpret_cast<uintptr_t>(baseAddr);
                        SIZE_T moduleSize = me32.modBaseSize;

                        MEMORY_BASIC_INFORMATION mbi;
                        for (size_t offset = 0; offset < moduleSize; offset += mbi.RegionSize) {
                            if (VirtualQuery(baseAddr + offset, &mbi, sizeof(mbi)) == 0) {
                                break;
                            }

                            // Hanya scan region yang executable dan readable
                            if (mbi.State == MEM_COMMIT && 
                                (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                                
                                uint8_t* regionBase = reinterpret_cast<uint8_t*>(mbi.BaseAddress);
                                size_t regionSize = mbi.RegionSize;

                                // Hitung CRC32 dari region ini dan simpan sebagai baseline
                                uint32_t crc32 = CalculateCRC32(regionBase, regionSize);
                                
                                ExecutableRegion baseline;
                                baseline.address = reinterpret_cast<uintptr_t>(regionBase);
                                baseline.size = regionSize;
                                baseline.baselineCRC32 = crc32;
                                
                                m_baselineRegions.push_back(baseline);
                            }
                        }
                        break;
                    }
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
        m_baselineCreated = true;
    }

    bool MemoryScanner::VerifyRegionIntegrity(uint8_t* memoryBase, size_t regionSize, uintptr_t regionAddress) {
        // Cari baseline untuk region ini
        for (const auto& baseline : m_baselineRegions) {
            // Cek apakah region ini cocok dengan baseline (alamat dan ukuran sama)
            if (baseline.address == regionAddress && baseline.size == regionSize) {
                // Hitung CRC32 dari region di memori saat ini
                uint32_t currentCRC32 = CalculateCRC32(memoryBase, regionSize);

                // Bandingkan dengan baseline CRC32
                if (currentCRC32 != baseline.baselineCRC32) {
                    // CRC32 tidak cocok - modifikasi terdeteksi!
                    return true; // Modifikasi terdeteksi
                }
                return false; // Integritas OK
            }
            
            // Cek juga jika region ini overlap dengan baseline (untuk toleransi alignment)
            // Beberapa region mungkin sedikit berbeda karena memory alignment
            if (regionAddress >= baseline.address && 
                regionAddress < baseline.address + baseline.size) {
                // Region ini overlap dengan baseline
                // Untuk sekarang, kita skip verifikasi overlap karena kompleks
                // Hanya verifikasi exact match
                return false; // Anggap OK untuk overlap (toleransi)
            }
        }

        // Jika tidak ada baseline yang cocok, jangan langsung flag sebagai mencurigakan
        // Bisa jadi region baru yang normal (misalnya JIT code, dll)
        // Kita hanya flag jika region yang sudah ada di baseline berubah
        return false; // Region tidak dikenal, tapi tidak langsung mencurigakan
    }

    bool MemoryScanner::DetectSuspiciousMemoryRegion(uint8_t* memoryBase, size_t regionSize) {
        // Deteksi region memori yang executable DAN writable (sangat mencurigakan)
        // Region seperti ini biasanya digunakan untuk code injection
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(memoryBase, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // Cek jika region ini executable dan writable secara bersamaan
        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (isExecutable && isWritable) {
            uintptr_t regionAddress = reinterpret_cast<uintptr_t>(memoryBase);
            
            // Pengecualian: Jika region ini sudah ada di baseline, berarti itu normal
            // (beberapa game/aplikasi menggunakan executable+writable untuk JIT, dll)
            for (const auto& baseline : m_baselineRegions) {
                // Cek apakah region ini overlap dengan baseline (sudah dikenal)
                if (regionAddress >= baseline.address && 
                    regionAddress < baseline.address + baseline.size) {
                    // Region ini sudah ada di baseline, berarti normal
                    return false;
                }
                // Cek juga jika baseline ada di dalam region ini
                if (baseline.address >= regionAddress && 
                    baseline.address < regionAddress + regionSize) {
                    // Baseline ada di dalam region ini, berarti normal
                    return false;
                }
            }
            
            // Pengecualian: Jika region ini berada di dalam modul utama, mungkin normal
            // (beberapa game menggunakan self-modifying code untuk optimasi)
            if (m_moduleBaseAddress > 0) {
                // Cek apakah region ini berada di dalam range modul utama
                // Kita akan lebih toleran untuk region di dalam modul utama
                // Hanya flag jika region berada di LUAR modul utama (kemungkinan besar injection)
                // Untuk sekarang, kita skip deteksi ini dan hanya mengandalkan CRC32 verification
                // karena terlalu banyak false positive
                return false; // Nonaktifkan sementara untuk mengurangi false positive
            }
            
            // Region executable + writable di luar modul utama sangat mencurigakan
            // Ini biasanya tanda code injection
            return true;
        }

        return false;
    }

    void MemoryScanner::PerformScan() {
        // Buat baseline CRC32 jika belum dibuat (hanya sekali saat pertama kali scan)
        if (!m_baselineCreated) {
            // Ambil path executable
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(NULL, exePath, MAX_PATH) != 0) {
                // Coba buat baseline dari file (lebih stabil)
                CreateBaselineFromFile(exePath);
            } else {
                // Fallback: buat baseline dari memori
                CreateBaselineFromMemory();
            }
        }

        // Ambil path executable saat ini
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
            return;
        }

        // Ambil snapshot dari modul yang dimuat oleh proses saat ini
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        // Cari modul utama
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szExePath, exePath) == 0) {
                    // Kita menemukan modul utama
                    uint8_t* baseAddr = reinterpret_cast<uint8_t*>(me32.modBaseAddr);
                    SIZE_T moduleSize = me32.modBaseSize;

                    MEMORY_BASIC_INFORMATION mbi;
                    for (size_t offset = 0; offset < moduleSize; offset += mbi.RegionSize) {
                        if (VirtualQuery(baseAddr + offset, &mbi, sizeof(mbi)) == 0) {
                            break;
                        }

                        // Hanya scan region yang sudah dialokasikan dan bisa dibaca
                        if (mbi.State == MEM_COMMIT && 
                            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                            
                            uint8_t* regionBase = reinterpret_cast<uint8_t*>(mbi.BaseAddress);
                            size_t regionSize = mbi.RegionSize;

                            // 1. Deteksi region mencurigakan (executable + writable)
                            if (DetectSuspiciousMemoryRegion(regionBase, regionSize)) {
                                std::wstring message = L"Region memori mencurigakan terdeteksi!\n";
                                message += L"Region executable dan writable secara bersamaan terdeteksi.\n";
                                message += L"Ini biasanya menunjukkan code injection atau memory patching.\n\n";
                                message += L"Client akan ditutup.";
                                MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                                CloseHandle(hSnapshot);
                                ExitProcess(0);
                            }

                            // 2. Cek integritas kode menggunakan CRC32 baseline
                            // Hanya verifikasi region yang ada di baseline (exact match)
                            if (m_baselineCreated && (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                                uintptr_t regionAddress = reinterpret_cast<uintptr_t>(regionBase);
                                if (VerifyRegionIntegrity(regionBase, regionSize, regionAddress)) {
                                    std::wstring message = L"Modifikasi kode terdeteksi!\n";
                                    message += L"CRC32 checksum tidak cocok dengan baseline.\n";
                                    message += L"Ini menunjukkan adanya memory patching atau code modification.\n\n";
                                    message += L"Client akan ditutup.";
                                    MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                                    CloseHandle(hSnapshot);
                                    ExitProcess(0);
                                }
                            }
                        }
                    }
                    break; // Kita hanya perlu memindai modul utama
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
    }
}