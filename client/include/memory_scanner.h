#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>

namespace Oblivion {
    // Struktur untuk menyimpan baseline CRC32 dari region executable
    struct ExecutableRegion {
        uintptr_t address;          // Alamat memori region
        size_t size;                // Ukuran region dalam bytes
        uint32_t baselineCRC32;     // CRC32 checksum baseline (dari scan pertama)
    };

    class MemoryScanner {
    public:
        MemoryScanner();
        ~MemoryScanner();

        // Fungsi utama untuk memindai memori
        void PerformScan();

    private:
        // Menghitung CRC32 checksum dari data
        uint32_t CalculateCRC32(const uint8_t* data, size_t size);
        
        // Membaca file executable dari disk
        bool ReadExecutableFile(const std::wstring& filePath, std::vector<uint8_t>& fileData);
        
        // Membuat baseline CRC32 dari file executable (lebih stabil daripada dari memori)
        void CreateBaselineFromFile(const std::wstring& filePath);
        
        // Membuat baseline CRC32 dari memori (fallback jika file tidak bisa dibaca)
        void CreateBaselineFromMemory();
        
        // Memverifikasi integritas region menggunakan CRC32 baseline
        bool VerifyRegionIntegrity(uint8_t* memoryBase, size_t regionSize, uintptr_t regionAddress);
        
        // Mendeteksi region memori yang mencurigakan (executable + writable)
        bool DetectSuspiciousMemoryRegion(uint8_t* memoryBase, size_t regionSize);

        // Daftar baseline CRC32 dari region executable yang terdeteksi
        std::vector<ExecutableRegion> m_baselineRegions;
        
        // Flag untuk menandai apakah baseline sudah dibuat
        bool m_baselineCreated;
        
        // Base address dari modul utama
        uintptr_t m_moduleBaseAddress;
    };
}