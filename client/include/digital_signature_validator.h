#pragma once

#include <windows.h>
#include <vector>
#include <string>

namespace Oblivion {
    class DigitalSignatureValidator {
    public:
        DigitalSignatureValidator();
        ~DigitalSignatureValidator();

        // Fungsi utama untuk memindai semua modul
        void PerformScan();

    private:
        // Fungsi untuk memeriksa apakah sebuah modul tepercaya
        bool IsModuleTrusted(HMODULE hModule, std::wstring& moduleName);

        // Fungsi untuk mendapatkan nama penerbit dari sertifikat
        bool GetCertificateSubjectName(HMODULE hModule, std::wstring& subjectName);

        // Daftar penerbit yang dipercaya
        static const std::vector<std::wstring> m_trustedPublishers;
        
        // Daftar DLL yang diizinkan meskipun tidak ditandatangani (DLL legitimate dari game/engine)
        static const std::vector<std::wstring> m_allowedUnsignedDlls;
    };
}