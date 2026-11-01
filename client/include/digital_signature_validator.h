#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>

namespace Oblivion {
    class DigitalSignatureValidator {
    public:
        DigitalSignatureValidator();
        ~DigitalSignatureValidator();

        // Fungsi utama untuk memindai semua modul
        void PerformScan();

        // Fungsi untuk verifikasi process executable (untuk whitelist verification)
        // Mengembalikan true jika signature valid dan publisher sesuai ekspektasi
        static bool VerifyProcessSignature(const std::wstring& processPath, const std::wstring& expectedPublisher);
        
        // Fungsi untuk mendapatkan publisher dari file executable
        static bool GetFilePublisher(const std::wstring& filePath, std::wstring& publisherName);

        // Hasil verifikasi signature file.
        // Dibuat untuk membedakan "file tidak ditandatangani" dari "signature ada
        // tetapi tidak dapat divalidasi" (client offline, revocation check gagal,
        // root certificate belum di-update). Kegagalan infrastruktur seperti ini
        // BUKAN bukti spoofing dan sebelumnya menyebabkan false positive: pemain
        // sah (Chrome/Steam/Discord) di-kick hanya karena jaringan bermasalah.
        enum class SignatureVerdict {
            TrustedPublisher,    // Signature valid dan publisher ada di daftar tepercaya
            UntrustedPublisher,  // Signature valid tetapi publisher di luar daftar tepercaya
            Unsigned,            // File tidak memiliki signature Authenticode
            InvalidSignature,    // Signature terbukti gagal integritas/trust policy
            VerificationError    // Status tidak konklusif (misalnya trust-chain infrastructure)
        };

        // Verifikasi signature file dan kategorikan hasilnya (tri-state).
        // publisherName diisi bila file memang memiliki signature yang bisa dibaca.
        static SignatureVerdict GetSignatureVerdict(const std::wstring& filePath, std::wstring& publisherName);

        // Public access ke expected publishers map untuk cross-verification
        static const std::map<std::wstring, std::wstring> m_expectedPublishers;

    private:
        struct ModuleTrustCacheEntry {
            ULONGLONG fileSize;
            FILETIME lastWriteTime;
            bool isTrusted;
        };

        // Fungsi untuk memeriksa apakah sebuah modul tepercaya
        bool IsModuleTrusted(
            HMODULE hModule,
            std::wstring& moduleName,
            const std::wstring& filePath,
            const std::wstring& gameDirectory);

        // Fungsi untuk mendapatkan nama penerbit dari sertifikat
        bool GetCertificateSubjectName(HMODULE hModule, std::wstring& subjectName);

        // Fungsi helper untuk verifikasi signature file
        static LONG VerifyFileSignatureStatus(const std::wstring& filePath);

        // Daftar penerbit yang dipercaya
        static const std::vector<std::wstring> m_trustedPublishers;
        
        // Daftar DLL yang diizinkan meskipun tidak ditandatangani (DLL legitimate dari game/engine)
        static const std::vector<std::wstring> m_allowedUnsignedDlls;

        // WinVerifyTrust relatif mahal. Cache dibatalkan otomatis bila ukuran atau
        // waktu modifikasi file berubah, sehingga modul yang diganti tetap diverifikasi.
        std::unordered_map<std::wstring, ModuleTrustCacheEntry> m_moduleTrustCache;
    };
}
