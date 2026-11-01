#include "pch.h"
#include "digital_signature_validator.h"
#include "win_path_utils.h"
#include "../../common/windows_path_policy.h"
#include "../../common/authenticode_verdict_policy.h"
#include <tlhelp32.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <psapi.h>
#include <softpub.h>
#include <iostream>
#include <algorithm>
#include <cwctype>
#include <map>
#include <sstream>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
std::wstring ReadEnvironmentDirectory(const wchar_t* variableName) {
    const DWORD required = GetEnvironmentVariableW(variableName, nullptr, 0);
    if (required == 0) {
        return L"";
    }

    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(variableName, value.data(), required);
    if (written == 0 || written >= required) {
        return L"";
    }
    value.resize(written);
    return value;
}

std::wstring ResolveWindowsDirectory() {
    // Use the actual Windows directory instead of searching for a "\\windows\\"
    // substring anywhere in the path (which also matches unrelated game folders).
    std::wstring value(32768, L'\0');
    const UINT written = GetWindowsDirectoryW(value.data(), static_cast<UINT>(value.size()));
    if (written == 0 || written >= value.size()) {
        return L"";
    }
    value.resize(written);
    return value;
}
} // namespace

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")

// Daftar nama penerbit yang diizinkan.
// PERHATIAN: Daftar ini sangat penting. Jika terlalu ketat, akan menyebabkan false positive.
// Jika terlalu longgar, akan mengurangi keamanan.
const std::vector<std::wstring> Oblivion::DigitalSignatureValidator::m_trustedPublishers = {
    L"Microsoft Corporation",
    L"Microsoft Windows",
    L"Microsoft Windows Publisher",
    L"NVIDIA Corporation",
    L"Advanced Micro Devices, Inc.",
    L"Intel Corporation",
    L"Valve Corporation", // Untuk DLL Steam
    L"Discord Inc.",      // Untuk DLL Discord
    L"Google LLC",        // Untuk DLL Chrome/Gecko
    L"Mozilla Corporation", // Untuk DLL Firefox
    L"VideoLAN"              // VLC (explicitly listed process publisher)
    // Tambahkan penerbit lain yang Anda percaya di sini
};

// Mapping process name -> expected publisher untuk whitelist verification
// Ini digunakan untuk memverifikasi bahwa proses yang di-whitelist adalah BENAR-BENAR dari publisher yang sah
const std::map<std::wstring, std::wstring> Oblivion::DigitalSignatureValidator::m_expectedPublishers = {
    // Browser applications
    {L"chrome.exe", L"Google LLC"},
    {L"firefox.exe", L"Mozilla Corporation"},
    {L"msedge.exe", L"Microsoft Corporation"},
    {L"msedgewebview2.exe", L"Microsoft Corporation"},  // Microsoft Edge WebView2 Runtime
    
    // Communication apps
    {L"discord.exe", L"Discord Inc."},
    {L"skype.exe", L"Microsoft Corporation"},
    {L"teams.exe", L"Microsoft Corporation"},
    
    // Gaming platforms
    {L"steam.exe", L"Valve Corporation"},
    {L"steamwebhelper.exe", L"Valve Corporation"},
    
    // Development tools
    {L"vscode.exe", L"Microsoft Corporation"},
    {L"code.exe", L"Microsoft Corporation"},
    {L"devenv.exe", L"Microsoft Corporation"},
    
    // Media & Entertainment
    {L"spotify.exe", L"Spotify AB"},
    {L"vlc.exe", L"VideoLAN"},
    
    // Gaming platforms & launchers
    {L"epicgameslauncher.exe", L"Epic Games"},
    {L"easyanticheat.exe", L"Epic Games"},
    {L"battlenet.exe", L"Blizzard Entertainment"},
    {L"origin.exe", L"Electronic Arts"},
    {L"uplay.exe", L"Ubisoft"},
    {L"upc.exe", L"Ubisoft"},
    
    // Cloud storage & productivity
    {L"dropbox.exe", L"Dropbox"},
    {L"onedrive.exe", L"Microsoft Corporation"},
    {L"googledrivesync.exe", L"Google LLC"},
    
    // NOTE: Open-source apps seperti notepad++, 7zip, vlc sering tidak ditandatangani
    // Mereka dipindahkan ke whitelist biasa (tanpa signature verification)
    
    // Add more as needed
};

// Daftar DLL yang diizinkan meskipun tidak ditandatangani
// DLL ini adalah DLL legitimate dari game engine/library yang biasanya tidak ditandatangani
const std::vector<std::wstring> Oblivion::DigitalSignatureValidator::m_allowedUnsignedDlls = {
    // Game engine/library DLLs
    L"granny2.dll",       // Granny 3D animation library
    L"binkw32.dll",       // Bink video codec
    L"binkw64.dll",       // Bink video codec (64-bit)
    L"fmodex.dll",        // FMOD audio library
    L"fmodex64.dll",      // FMOD audio library (64-bit)
    L"physx.dll",         // NVIDIA PhysX
    L"physxcudart_20.dll", // NVIDIA PhysX CUDA
    L"cps.dll",           // Game engine/library DLL
    L"Mp3dec.asi",        // MP3 decoder (ASI file)
    L"Mssfast.m3d",       // Miles Sound System audio file
    
    // Intel Graphics Library
    L"ijl15.dll",         // Intel Graphics Library (Intel JPEG Library)
    L"ijl11.dll",         // Intel Graphics Library (versi lain)
    L"ijl20.dll",         // Intel Graphics Library (versi lain)
    
    // Microsoft DLLs
    L"gdiplus.dll",       // Microsoft GDI+ Graphics Library
    L"ddraw.dll",         // Microsoft DirectDraw Library
    L"dinput.dll",        // Microsoft DirectInput
    L"DCIMAN32.dll",      // Microsoft DirectX Color Management
    L"uxtheme.dll",       // Microsoft Windows UX Theme Library
    L"amsi.dll",          // Microsoft AMSI (Antimalware Scan Interface)
    L"aswAMSI.dll",       // Avast Antivirus AMSI
    L"D3DX9_42.dll",      // DirectX 9
    L"D3DX9_43.dll",      // DirectX 9
    
    // Visual C++ Runtime DLLs
    L"msvcp60.dll",       // Visual C++ Runtime
    L"msvcp90.dll",       // Visual C++ Runtime
    L"msvcp100.dll",      // Visual C++ Runtime
    L"msvcp110.dll",      // Visual C++ Runtime
    L"msvcp140.dll",      // Visual C++ Runtime
    L"msvcp140_1.dll",    // Visual C++ Runtime
    L"msvcp140_2.dll",    // Visual C++ Runtime
    L"msvcr90.dll",       // Visual C++ Runtime
    L"msvcr100.dll",      // Visual C++ Runtime
    L"msvcr110.dll",      // Visual C++ Runtime
    L"vcruntime140.dll",  // Visual C++ Runtime
    L"vccorlib140.dll",   // Visual C++ Runtime
    L"concrt140.dll",     // Visual C++ Runtime
    L"msvcm90.dll",       // Visual C++ Runtime
    
    // MFC DLLs
    L"mfc90.dll",         // Microsoft Foundation Classes
    L"mfc90u.dll",        // Microsoft Foundation Classes (Unicode)
    L"mfc100.dll",        // Microsoft Foundation Classes
    L"mfc100u.dll",       // Microsoft Foundation Classes (Unicode)
    L"mfc110.dll",        // Microsoft Foundation Classes
    L"mfc110u.dll",       // Microsoft Foundation Classes (Unicode)
    L"mfc140.dll",        // Microsoft Foundation Classes
    L"mfc140u.dll",       // Microsoft Foundation Classes (Unicode)
    L"mfcm90.dll",        // Microsoft Foundation Classes MFC
    L"mfcm90u.dll",       // Microsoft Foundation Classes MFC (Unicode)
    L"mfcm100.dll",       // Microsoft Foundation Classes MFC
    L"mfcm100u.dll",      // Microsoft Foundation Classes MFC (Unicode)
    L"mfcm140.dll",       // Microsoft Foundation Classes MFC
    L"mfcm140u.dll",      // Microsoft Foundation Classes MFC (Unicode)
    
    // Game-specific DLLs
    L"client.dll",        // Client DLL
    L"BaseSDK.dll",       // Base SDK
    L"IAPSDK.dll",        // IAP SDK
    L"libcurl.dll",       // libcurl library
    L"WebView2Loader.dll", // WebView2 Loader
    L"dbghelp.dll",       // Debug Help Library
    L"Mss32.dll",         // Miles Sound System
    L"aossdk.dll",        // AOS SDK
    L"bz32ex.dll",        // BZ32 Extension
    L"suipre.dll",        // SUI Pre
    L"v3hunt.dll",        // V3 Hunt
    
    // GameGuard/HShield DLLs
    L"NPCHK.DLL",         // GameGuard
    L"NPCIPHER.DLL",      // GameGuard
    L"NPPSK.DLL",         // GameGuard
    L"NPX.DLL",           // GameGuard
    L"npupdate.dll",      // GameGuard
    L"NPUPDATE0.DLL",     // GameGuard
    L"npkeysdk.dll",      // GameGuard
    L"npkpdb.dll",        // GameGuard
    L"npkcrypt.dll",      // GameGuard
    L"V3InetGS.dll",      // HShield
    L"V3Hunt.dll",        // HShield
    L"HSInst.dll",        // HShield
    L"AhnUpGS.dll",       // HShield
    L"AhnUpCtl.dll",      // HShield
    L"asc_main.dll",      // HShield
    L"gfs_util.dll",      // HShield
    L"gfs_proc.dll",      // HShield
    L"gfs_os.dll",        // HShield
    L"gfs_mem.dll",       // HShield
    L"gfs_file.dll",      // HShield
    L"gfs_fact.dll",      // HShield
    L"gfs_base.dll",      // HShield
    L"fse_pe.dll",        // HShield
    L"fse_fact.dll",      // HShield
    L"fse_base.dll",      // HShield
    L"asc_unp.dll",       // HShield
    L"asc_mmgr.dll",      // HShield
    L"asc_intg.dll",      // HShield
    L"asc_fse.dll",       // HShield
    L"asc_dh.dll",        // HShield
    L"asc_com.dll",       // HShield
    L"EhSvc.dll",         // HShield
    L"v3pro32s.dll",      // HShield
    L"v3bz32.dll",        // HShield
    L"ahnupctl.dll",      // HShield
    L"ahni2.dll",         // HShield
    L"Bz32Ex.dll",        // HShield
    L"AspINet.dll",       // HShield
    L"psapi.dll",         // HShield
    L"mspatcha.dll"       // HShield
};

namespace Oblivion {
    DigitalSignatureValidator::DigitalSignatureValidator() {}

    DigitalSignatureValidator::~DigitalSignatureValidator() {}

    void DigitalSignatureValidator::PerformScan() {
        // Dapatkan path folder game untuk membandingkan dengan path modul
        const std::wstring gameExePath = Oblivion::WinPath::GetModulePath(nullptr);
        if (gameExePath.empty()) {
            return; // Tidak bisa mendapatkan path game secara lengkap
        }
        std::wstring gameDir = gameExePath;
        size_t lastSlash = gameDir.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            gameDir = gameDir.substr(0, lastSlash + 1);
        }
        std::transform(gameDir.begin(), gameDir.end(), gameDir.begin(), ::towlower);

        // Resolve exempt roots once per scan. The game directory itself is never
        // exempted by location alone, even when installed below Program Files.
        const std::wstring windowsDirectory = ResolveWindowsDirectory();
        const std::wstring programFiles = ReadEnvironmentDirectory(L"ProgramFiles");
        const std::wstring programFilesX86 = ReadEnvironmentDirectory(L"ProgramFiles(x86)");

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                // Lewati modul utama (rro.exe) karena seringkali tidak ditandatangani
                if (me32.hModule == GetModuleHandle(NULL)) {
                    continue;
                }

                // Dapatkan path lengkap modul
                const std::wstring modulePath = Oblivion::WinPath::GetModulePath(me32.hModule);
                if (modulePath.empty()) {
                    continue; // Skip jika path modul tidak dapat diselesaikan lengkap
                }

                std::wstring modulePathStr = modulePath;
                std::transform(modulePathStr.begin(), modulePathStr.end(), modulePathStr.begin(), ::towlower);

                // Never skip a game-local module based only on its parent directory:
                // Ragnarok is commonly installed under Program Files, and the old substring
                // checks also skipped unrelated paths such as C:\\Games\\Windows\\Injected.dll.
                const bool isGameModule =
                    Oblivion::PathPolicy::IsPathWithinDirectory(modulePathStr, gameDir);

                if (!isGameModule && !windowsDirectory.empty() &&
                    Oblivion::PathPolicy::IsPathWithinDirectory(modulePathStr, windowsDirectory)) {
                    continue; // Actual Windows directory, not any path containing "\\windows\\"
                }

                // Keep the compatibility exemption for third-party Program Files modules,
                // but never let it suppress modules loaded from the game directory.
                const bool isUnderProgramFiles =
                    (!programFiles.empty() &&
                     Oblivion::PathPolicy::IsPathWithinDirectory(modulePathStr, programFiles)) ||
                    (!programFilesX86.empty() &&
                     Oblivion::PathPolicy::IsPathWithinDirectory(modulePathStr, programFilesX86));
                if (!isGameModule && isUnderProgramFiles) {
                    continue;
                }

                // Hanya periksa modul yang berasal dari folder game atau folder lain yang mencurigakan
                // (seperti modul yang di-inject dari cheat engine, wpe, rpe, openkore)
                std::wstring moduleName(me32.szModule);
                if (!IsModuleTrusted(me32.hModule, moduleName, modulePath, gameDir)) {
                    // Modul tidak tepercaya!
                    std::wstring message = L"Modul tidak tepercaya (tidak ditandatangani atau penerbit tidak dikenal) terdeteksi: ";
                    message += me32.szModule;
                    message += L"\n\nPath: ";
                    message += modulePath;
                    message += L"\n\nClient akan ditutup.";
                    
                    // Build details untuk server report
                    std::wstringstream detailsStream;
                    detailsStream << L"Module: " << me32.szModule
                                  << L" | Path: " << modulePath;
                    
                    std::wstring detailsWide = detailsStream.str();
                    
                    // Convert ke UTF-8 untuk server
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, detailsWide.c_str(), (int)detailsWide.length(), NULL, 0, NULL, NULL);
                    std::string details_utf8;
                    if (size_needed > 0) {
                        details_utf8.resize(size_needed);
                        WideCharToMultiByte(CP_UTF8, 0, detailsWide.c_str(), (int)detailsWide.length(), &details_utf8[0], size_needed, NULL, NULL);
                    }
                    
                    // Report ke server dan exit (ReportViolationAndExit akan mengirim laporan ke server sebelum ExitProcess)
                    ReportViolationAndExit(message, "UNTRUSTED_MODULE", details_utf8);
                }

            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
    }

    bool DigitalSignatureValidator::IsModuleTrusted(
        HMODULE hModule,
        std::wstring& moduleName,
        const std::wstring& filePath,
        const std::wstring& gameDirectory) {
        if (filePath.empty()) {
            return false; // Tidak bisa mendapatkan path lengkap, anggap tidak tepercaya
        }

        // A filename-only allowlist is not sufficient: an unsigned DLL with a
        // familiar name could be loaded from a temp/download folder or another
        // unrelated location. Only preserve the legacy unsigned-DLL exemption
        // when the loaded module is actually inside this game's directory.
        std::wstring moduleNameLower = moduleName;
        std::transform(moduleNameLower.begin(), moduleNameLower.end(), moduleNameLower.begin(), ::towlower);
        bool isAllowlistedName = false;
        for (const auto& allowedDll : m_allowedUnsignedDlls) {
            std::wstring allowedDllLower = allowedDll;
            std::transform(allowedDllLower.begin(), allowedDllLower.end(), allowedDllLower.begin(), ::towlower);
            if (moduleNameLower == allowedDllLower) {
                isAllowlistedName = true;
                break;
            }
        }

        if (Oblivion::PathPolicy::CanTrustUnsignedModuleByName(
                isAllowlistedName, filePath, gameDirectory)) {
            return true; // Legacy unsigned DLL exemption restricted to the game directory
        }

        std::wstring cacheKey = filePath;
        std::transform(cacheKey.begin(), cacheKey.end(), cacheKey.begin(), ::towlower);

        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        const bool hasAttributes = GetFileAttributesExW(
            filePath.c_str(), GetFileExInfoStandard, &attributes) != FALSE;
        if (hasAttributes) {
            const ULARGE_INTEGER size = {
                attributes.nFileSizeLow, attributes.nFileSizeHigh
            };
            const auto cached = m_moduleTrustCache.find(cacheKey);
            if (cached != m_moduleTrustCache.end() &&
                cached->second.fileSize == size.QuadPart &&
                CompareFileTime(&cached->second.lastWriteTime, &attributes.ftLastWriteTime) == 0) {
                return cached->second.isTrusted;
            }
        }

        // Catatan: Pengecekan folder Windows system dan Program Files sudah dilakukan di PerformScan()
        // Jadi fungsi ini hanya akan dipanggil untuk modul yang berasal dari folder game atau folder mencurigakan

        // Struktur untuk WinVerifyTrust
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        WINTRUST_DATA winTrustData = { 0 };
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = NULL;
        winTrustData.pSIPClientData = NULL;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = NULL;
        winTrustData.pwszURLReference = NULL;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // Verifikasi signature
        LONG result = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

        bool isSignatureValid = (result == ERROR_SUCCESS);

        // Cleanup state
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &winTrustData);

        if (!isSignatureValid) {
            if (hasAttributes) {
                const ULARGE_INTEGER size = {
                    attributes.nFileSizeLow, attributes.nFileSizeHigh
                };
                m_moduleTrustCache[cacheKey] = { size.QuadPart, attributes.ftLastWriteTime, false };
            }
            return false; // Signature tidak valid atau tidak ada
        }

        // Jika signature valid, periksa penerbitnya
        std::wstring publisherName;
        if (GetCertificateSubjectName(hModule, publisherName)) {
            for (const auto& trustedName : m_trustedPublishers) {
                if (publisherName.find(trustedName) != std::wstring::npos) {
                    if (hasAttributes) {
                        const ULARGE_INTEGER size = {
                            attributes.nFileSizeLow, attributes.nFileSizeHigh
                        };
                        m_moduleTrustCache[cacheKey] = { size.QuadPart, attributes.ftLastWriteTime, true };
                    }
                    return true; // Penerbit tepercaya
                }
            }
        }

        if (hasAttributes) {
            const ULARGE_INTEGER size = {
                attributes.nFileSizeLow, attributes.nFileSizeHigh
            };
            m_moduleTrustCache[cacheKey] = { size.QuadPart, attributes.ftLastWriteTime, false };
        }
        return false; // Penerbit tidak ada di whitelist
    }

    bool DigitalSignatureValidator::GetCertificateSubjectName(HMODULE hModule, std::wstring& subjectName) {
        const std::wstring filePath = Oblivion::WinPath::GetModulePath(hModule);
        if (filePath.empty()) {
            return false;
        }

        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        PCCERT_CONTEXT pCertContext = NULL;
        bool result = false;

        DWORD encoding, contentType, formatType;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &encoding, &contentType, &formatType,
            &hStore, &hMsg, NULL)) {
            return false;
        }

        // Dapatkan sertifikat penandatangan (biasanya hanya ada satu)
        PCMSG_SIGNER_INFO pSignerInfo = nullptr;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &formatType)) {
            goto cleanup;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, formatType);
        if (!pSignerInfo) {
            goto cleanup;
        }

        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerInfo, &formatType)) {
            LocalFree(pSignerInfo);
            goto cleanup;
        }

        // Cari sertifikat yang cocok di toko
        pCertContext = CertFindCertificateInStore(hStore, encoding, 0, CERT_FIND_SUBJECT_CERT, pSignerInfo, NULL);
        LocalFree(pSignerInfo);

        if (pCertContext) {
            DWORD nameSize = 0;
            // Dapatkan ukuran nama
            nameSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            if (nameSize > 0) {
                std::vector<WCHAR> nameBuffer(nameSize);
                // Dapatkan nama sebenarnya
                if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuffer.data(), nameSize) > 0) {
                    subjectName = nameBuffer.data();
                    result = true;
                }
            }
            CertFreeCertificateContext(pCertContext);
        }

    cleanup:
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return result;
    }

    // Preserve the actual WinVerifyTrust status so a tampered file is not
    // mistaken for an infrastructure-only verification failure.
    LONG DigitalSignatureValidator::VerifyFileSignatureStatus(const std::wstring& filePath) {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        WINTRUST_DATA winTrustData = { 0 };
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = NULL;
        winTrustData.pSIPClientData = NULL;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = NULL;
        winTrustData.pwszURLReference = NULL;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        const LONG result = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

        // Cleanup state without overwriting the original verification status.
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &winTrustData);
        return result;
    }

    // Static function untuk mendapatkan publisher dari file
    bool DigitalSignatureValidator::GetFilePublisher(const std::wstring& filePath, std::wstring& publisherName) {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        PCCERT_CONTEXT pCertContext = NULL;
        PCMSG_SIGNER_INFO pSignerInfo = NULL;
        bool result = false;

        DWORD encoding, contentType, formatType;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &encoding, &contentType, &formatType,
            &hStore, &hMsg, NULL)) {
            return false;
        }

        DWORD dwSize = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &dwSize)) {
            goto cleanup;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
        if (!pSignerInfo) {
            goto cleanup;
        }

        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerInfo, &dwSize)) {
            LocalFree(pSignerInfo);
            pSignerInfo = NULL;
            goto cleanup;
        }

        pCertContext = CertFindCertificateInStore(hStore, encoding, 0, CERT_FIND_SUBJECT_CERT, pSignerInfo, NULL);
        LocalFree(pSignerInfo);
        pSignerInfo = NULL;

        if (pCertContext) {
            DWORD nameSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            if (nameSize > 0) {
                std::vector<WCHAR> nameBuffer(nameSize);
                if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuffer.data(), nameSize) > 0) {
                    publisherName = nameBuffer.data();
                    result = true;
                }
            }
            CertFreeCertificateContext(pCertContext);
        }

    cleanup:
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return result;
    }

    // Static function untuk verifikasi process signature dengan expected publisher
    bool DigitalSignatureValidator::VerifyProcessSignature(const std::wstring& processPath, const std::wstring& expectedPublisher) {
        // Step 1: Verify digital signature
        if (VerifyFileSignatureStatus(processPath) != ERROR_SUCCESS) {
            // Signature tidak valid atau tidak ada
            return false;
        }

        // Step 2: Get publisher name
        std::wstring actualPublisher;
        if (!GetFilePublisher(processPath, actualPublisher)) {
            // Tidak bisa mendapatkan publisher
            return false;
        }

        // Step 3: Compare with expected publisher (case-insensitive contains check)
        std::wstring lowerActual = actualPublisher;
        std::wstring lowerExpected = expectedPublisher;
        std::transform(lowerActual.begin(), lowerActual.end(), lowerActual.begin(), ::towlower);
        std::transform(lowerExpected.begin(), lowerExpected.end(), lowerExpected.begin(), ::towlower);

        // Check if actual publisher contains expected publisher name
        if (lowerActual.find(lowerExpected) != std::wstring::npos) {
            return true;
        }

        // Publisher mismatch
        return false;
    }

    // Verifikasi signature file + kategorikan hasilnya.
    // Tujuan: memisahkan "benar-benar spoofing" dari "tidak bisa diverifikasi".
    // Perbedaan ini penting karena kegagalan verifikasi (offline, revocation check
    // gagal, chain tidak lengkap) sebelumnya membuat pemain sah di-kick sebagai cheater.
    DigitalSignatureValidator::SignatureVerdict DigitalSignatureValidator::GetSignatureVerdict(
        const std::wstring& filePath,
        std::wstring& publisherName) {
        publisherName.clear();

        if (filePath.empty()) {
            return SignatureVerdict::VerificationError;
        }

        // Certificate extraction alone does not prove the PE image signature is
        // valid: a modified executable can retain its embedded PKCS#7 certificate.
        // Keep the trust-provider status so known integrity failures are distinct
        // from chain/network/provider failures.
        std::wstring actualPublisher;
        const bool hasEmbeddedSignature = GetFilePublisher(filePath, actualPublisher);
        const LONG verificationStatus = VerifyFileSignatureStatus(filePath);
        const auto resultClass = Oblivion::SignaturePolicy::ClassifyWinTrustResult(
            static_cast<std::uint32_t>(verificationStatus));

        switch (resultClass) {
        case Oblivion::SignaturePolicy::WinTrustResultClass::Trusted:
            publisherName = actualPublisher;

            if (!actualPublisher.empty()) {
                for (const auto& trustedPublisher : m_trustedPublishers) {
                    // A trusted brand appearing as a substring is not enough:
                    // exact publisher identity avoids names such as "Microsoft Corporation Fake".
                    if (Oblivion::SignaturePolicy::IsExactPublisherMatch(
                            actualPublisher, trustedPublisher)) {
                        return SignatureVerdict::TrustedPublisher;
                    }
                }
            }

            return SignatureVerdict::UntrustedPublisher;

        case Oblivion::SignaturePolicy::WinTrustResultClass::Rejected:
            // Do not expose the extracted publisher to the caller as a fallback:
            // BAD_DIGEST/revoked/distrusted signatures must never be whitelisted.
            return SignatureVerdict::InvalidSignature;

        case Oblivion::SignaturePolicy::WinTrustResultClass::NoSignature:
            return SignatureVerdict::Unsigned;

        case Oblivion::SignaturePolicy::WinTrustResultClass::Inconclusive:
            // A nonzero status not recognized as a definite signature failure may
            // reflect unavailable trust-chain infrastructure. Preserve the existing
            // anti-false-positive behavior only when an embedded signature exists.
            return hasEmbeddedSignature
                ? SignatureVerdict::VerificationError
                : SignatureVerdict::Unsigned;
        }

        return SignatureVerdict::VerificationError;
    }
}
