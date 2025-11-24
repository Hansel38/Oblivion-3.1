#include "pch.h"
#include "file_integrity_check.h"
#include <windows.h>
#include <bcrypt.h> // Header untuk CNG API
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

// Definisi NTSTATUS jika ntstatus.h tidak tersedia
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#pragma comment(lib, "bcrypt.lib") // Linker library untuk CNG

// DAFTAR FILE DAN HASH YANG DIHARAPKAN
// ANDA HARUS MEMPERBAIKI BAGIAN INI!
// Gunakan tool untuk menghasilkan hash SHA-256 dari file-file ANDA yang bersih.
const std::vector<Oblivion::FileIntegrityChecker::FileHashPair> Oblivion::FileIntegrityChecker::m_filesToCheck = {
    // Contoh: { L"rro.exe", "HASH_SHA_256_DARI_RRO.EXE_ANDA" },
    // Contoh: { L"data.grf", "HASH_SHA_256_DARI_DATA.GRF_ANDA" },
    // Contoh: { L"ragexe.exe", "HASH_SHA_256_DARI_RAGEXE.EXE_ANDA" },
    // TAMBAHKAN FILE LAIN YANG PENTING DI SINI
    { L"rro.exe", "d645bec120dc9335519acc6db25a32859602b6ab6dfd471fc9e0830c72a48678" }, // CONTOH HASH (ini adalah hash dari file kosong)
    { L"Republic.grf", "cf85bc1965fa4ca3b4a1469f7de46b8ba61ecab7098e878a3cdce613e31fe9e9" }  // CONTOH HASH
};

namespace Oblivion {
    void FileIntegrityChecker::PerformCheck() {
        // Dapatkan direktori tempat client berada
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring exeDir = exePath;
        size_t lastSlash = exeDir.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            exeDir = exeDir.substr(0, lastSlash + 1);
        }

        for (const auto& filePair : m_filesToCheck) {
            std::wstring fullFilePath = exeDir + filePair.relativePath;
            std::string calculatedHash = CalculateSHA256(fullFilePath);

            if (calculatedHash.empty()) {
                // Gagal membaca file (mungkin tidak ada)
                std::wstring message = L"File penting tidak ditemukan atau rusak: ";
                message += filePair.relativePath;
                message += L"\n\nClient akan ditutup.";
                MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }

            // Bandingkan hash (case-insensitive)
            if (_stricmp(calculatedHash.c_str(), filePair.expectedHash.c_str()) != 0) {
                // Hash tidak cocok, file telah dimodifikasi
                std::wstring message = L"File telah dimodifikasi: ";
                message += filePair.relativePath;
                message += L"\n\nClient akan ditutup.";
                MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(0);
            }
        }
        // Jika semua lolos, tidak ada yang perlu dilakukan
    }

    std::string FileIntegrityChecker::CalculateSHA256(const std::wstring& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return ""; // File tidak bisa dibuka
        }

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        std::string result = ""; // Inisialisasi di awal untuk menghindari masalah dengan goto
        const DWORD BUFFER_SIZE = 4096; // Pindahkan ke atas untuk menghindari masalah dengan goto

        // Buka algoritma SHA-256
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            file.close();
            return ""; 
        }

        // Hitung ukuran buffer yang diperlukan
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptCloseAlgorithmProvider(hAlg, 0);
            file.close();
            return ""; 
        }

        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptCloseAlgorithmProvider(hAlg, 0);
            file.close();
            return ""; 
        }

        // Alokasikan buffer
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHashObject || !pbHash) { 
            if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
            if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            file.close();
            return ""; 
        }

        // Buat handle hash
        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            file.close();
            return ""; 
        }

        // Baca file dan hashkan kontennya
        BYTE buffer[BUFFER_SIZE];
        while (file.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE)) {
            status = BCryptHashData(hHash, buffer, (ULONG)file.gcount(), 0);
            if (!BCRYPT_SUCCESS(status)) { 
                BCryptDestroyHash(hHash);
                HeapFree(GetProcessHeap(), 0, pbHashObject);
                HeapFree(GetProcessHeap(), 0, pbHash);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                file.close();
                return ""; 
            }
        }
        // Hash sisa byte terakhir jika ada
        if (file.gcount() > 0) {
            status = BCryptHashData(hHash, buffer, (ULONG)file.gcount(), 0);
            if (!BCRYPT_SUCCESS(status)) { 
                BCryptDestroyHash(hHash);
                HeapFree(GetProcessHeap(), 0, pbHashObject);
                HeapFree(GetProcessHeap(), 0, pbHash);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                file.close();
                return ""; 
            }
        }

        // Selesaikan perhitungan hash
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            file.close();
            return ""; 
        }

        // Konversi hash byte ke string hex
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::setw(2) << static_cast<unsigned int>(pbHash[i]);
        }
        result = ss.str();

        // Cleanup
        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        file.close();

        return result;
    }
}