#include "pch.h"
#include "digital_signature_validator.h"
#include "win_path_utils.h"
#include "../../common/windows_path_policy.h"
#include "../../common/authenticode_verdict_policy.h"
#include <tlhelp32.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <mscat.h>
#include <bcrypt.h>
#include <psapi.h>
#include <softpub.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <objbase.h>
#include <iostream>
#include <algorithm>
#include <cwctype>
#include <map>
#include <sstream>

// Forward declarations
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);
extern void ReportViolationSoft(const std::string& type, const std::string& details);

namespace {
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

std::wstring ResolveKnownFolderPath(const KNOWNFOLDERID& folderId) {
    PWSTR rawPath = nullptr;
    const HRESULT result = SHGetKnownFolderPath(
        folderId, KF_FLAG_DEFAULT, nullptr, &rawPath);
    if (FAILED(result) || rawPath == nullptr) {
        if (rawPath != nullptr) {
            CoTaskMemFree(rawPath);
        }
        return L"";
    }

    const std::wstring value(rawPath);
    CoTaskMemFree(rawPath);
    return value;
}

struct ModuleFileStamp {
    ULONGLONG size = 0;
    FILETIME lastWriteTime{};
    DWORD volumeSerial = 0;
    DWORD fileIndexHigh = 0;
    DWORD fileIndexLow = 0;
    LONGLONG changeTime = 0;
};

enum class ModuleFileStampResult {
    Success,
    Unavailable,
    Invalid
};

ModuleFileStampResult GetModuleFileStamp(
    const std::wstring& path,
    ModuleFileStamp& stamp) {
    stamp = ModuleFileStamp{};
    HANDLE file = CreateFileW(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return ModuleFileStampResult::Unavailable;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo{};
    FILE_BASIC_INFO basicInfo{};
    const bool okay =
        GetFileInformationByHandle(file, &fileInfo) != FALSE &&
        GetFileInformationByHandleEx(
            file, FileBasicInfo, &basicInfo, sizeof(basicInfo)) != FALSE;
    CloseHandle(file);
    if (!okay) {
        return ModuleFileStampResult::Unavailable;
    }

    if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return ModuleFileStampResult::Invalid;
    }

    stamp.size =
        (static_cast<ULONGLONG>(fileInfo.nFileSizeHigh) << 32) |
        fileInfo.nFileSizeLow;
    stamp.lastWriteTime = fileInfo.ftLastWriteTime;
    stamp.volumeSerial = fileInfo.dwVolumeSerialNumber;
    stamp.fileIndexHigh = fileInfo.nFileIndexHigh;
    stamp.fileIndexLow = fileInfo.nFileIndexLow;
    stamp.changeTime = basicInfo.ChangeTime.QuadPart;
    return ModuleFileStampResult::Success;
}

bool SameModuleFileStamp(
    const ModuleFileStamp& left,
    const ModuleFileStamp& right) {
    return left.size == right.size &&
        CompareFileTime(&left.lastWriteTime, &right.lastWriteTime) == 0 &&
        left.volumeSerial == right.volumeSerial &&
        left.fileIndexHigh == right.fileIndexHigh &&
        left.fileIndexLow == right.fileIndexLow &&
        left.changeTime == right.changeTime;
}


using CatAcquireContext2Fn = BOOL (WINAPI*)(
    HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
using CatCalcHash2Fn = BOOL (WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);
using CatEnumFromHashFn = HCATINFO (WINAPI*)(HCATADMIN, BYTE*, DWORD, DWORD, HCATINFO*);
using CatCatalogInfoFn = BOOL (WINAPI*)(HCATINFO, CATALOG_INFO*, DWORD);
using CatReleaseCatalogFn = BOOL (WINAPI*)(HCATADMIN, HCATINFO, DWORD);
using CatReleaseContextFn = BOOL (WINAPI*)(HCATADMIN, DWORD);

LONG Win32ErrorToTrustStatus(DWORD error) {
    if (error == ERROR_SUCCESS) {
        error = ERROR_GEN_FAILURE;
    }
    return static_cast<LONG>(HRESULT_FROM_WIN32(error));
}

bool GetCatalogPublisherName(const std::wstring& catalogPath, std::wstring& publisherName) {
    publisherName.clear();
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    PCCERT_CONTEXT signerCertificate = nullptr;
    PCERT_INFO signerInfo = nullptr;
    bool success = false;

    DWORD encoding = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            catalogPath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &contentType,
            &formatType,
            &store,
            &message,
            nullptr)) {
        return false;
    }

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(
            message, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
        goto cleanup;
    }

    signerInfo = static_cast<PCERT_INFO>(LocalAlloc(LPTR, signerInfoSize));
    if (signerInfo == nullptr) {
        goto cleanup;
    }
    if (!CryptMsgGetParam(
            message, CMSG_SIGNER_CERT_INFO_PARAM, 0, signerInfo, &signerInfoSize)) {
        LocalFree(signerInfo);
        signerInfo = nullptr;
        goto cleanup;
    }

    signerCertificate = CertFindCertificateInStore(
        store, encoding, 0, CERT_FIND_SUBJECT_CERT, signerInfo, nullptr);
    LocalFree(signerInfo);
    signerInfo = nullptr;
    if (signerCertificate != nullptr) {
        const DWORD nameSize = CertGetNameStringW(
            signerCertificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        if (nameSize > 1) {
            std::vector<WCHAR> nameBuffer(nameSize);
            const DWORD written = CertGetNameStringW(
                signerCertificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                nameBuffer.data(), nameSize);
            if (written > 1 && nameBuffer[written - 1] == L'\0') {
                publisherName.assign(nameBuffer.data(), written - 1);
                success = !publisherName.empty();
            }
        }
        CertFreeCertificateContext(signerCertificate);
        signerCertificate = nullptr;
    }

cleanup:
    if (signerInfo != nullptr) {
        LocalFree(signerInfo);
    }
    if (signerCertificate != nullptr) {
        CertFreeCertificateContext(signerCertificate);
    }
    if (store != nullptr) {
        CertCloseStore(store, 0);
    }
    if (message != nullptr) {
        CryptMsgClose(message);
    }
    return success;
}

// Verify Windows catalog signatures for modules with no embedded PE signature.
// Only SHA-256 catalog APIs are accepted; missing APIs yield an inconclusive result.
LONG VerifyCatalogSignatureStatus(
    const std::wstring& filePath,
    std::wstring& publisherName) {
    publisherName.clear();

    HMODULE wintrustModule = LoadLibraryW(L"wintrust.dll");
    if (wintrustModule == nullptr) {
        return TRUST_E_PROVIDER_UNKNOWN;
    }

    const auto acquireContext2 = reinterpret_cast<CatAcquireContext2Fn>(
        GetProcAddress(wintrustModule, "CryptCATAdminAcquireContext2"));
    const auto calcHash2 = reinterpret_cast<CatCalcHash2Fn>(
        GetProcAddress(wintrustModule, "CryptCATAdminCalcHashFromFileHandle2"));
    const auto enumCatalog = reinterpret_cast<CatEnumFromHashFn>(
        GetProcAddress(wintrustModule, "CryptCATAdminEnumCatalogFromHash"));
    const auto getCatalogInfo = reinterpret_cast<CatCatalogInfoFn>(
        GetProcAddress(wintrustModule, "CryptCATCatalogInfoFromContext"));
    const auto releaseCatalog = reinterpret_cast<CatReleaseCatalogFn>(
        GetProcAddress(wintrustModule, "CryptCATAdminReleaseCatalogContext"));
    const auto releaseContext = reinterpret_cast<CatReleaseContextFn>(
        GetProcAddress(wintrustModule, "CryptCATAdminReleaseContext"));

    if (acquireContext2 == nullptr || calcHash2 == nullptr ||
        enumCatalog == nullptr || getCatalogInfo == nullptr ||
        releaseCatalog == nullptr || releaseContext == nullptr) {
        FreeLibrary(wintrustModule);
        return TRUST_E_PROVIDER_UNKNOWN;
    }

    HANDLE file = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const LONG error = Win32ErrorToTrustStatus(GetLastError());
        FreeLibrary(wintrustModule);
        return error;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo{};
    if (!GetFileInformationByHandle(file, &fileInfo)) {
        const LONG error = Win32ErrorToTrustStatus(GetLastError());
        CloseHandle(file);
        FreeLibrary(wintrustModule);
        return error;
    }
    if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        CloseHandle(file);
        FreeLibrary(wintrustModule);
        return TRUST_E_BAD_DIGEST;
    }

    HCATADMIN catalogAdmin = nullptr;
    const BOOL acquired = acquireContext2(
        &catalogAdmin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!acquired || catalogAdmin == nullptr) {
        const LONG error = Win32ErrorToTrustStatus(GetLastError());
        CloseHandle(file);
        FreeLibrary(wintrustModule);
        return error;
    }

    DWORD hashLength = 0;
    const BOOL sized = calcHash2(catalogAdmin, file, &hashLength, nullptr, 0);
    if (!sized || hashLength == 0 || hashLength > 128) {
        const LONG error = Win32ErrorToTrustStatus(GetLastError());
        releaseContext(catalogAdmin, 0);
        CloseHandle(file);
        FreeLibrary(wintrustModule);
        return error;
    }

    std::vector<BYTE> hash(hashLength);
    const BOOL hashed = calcHash2(catalogAdmin, file, &hashLength, hash.data(), 0);
    if (!hashed || hashLength != hash.size()) {
        const LONG error = Win32ErrorToTrustStatus(GetLastError());
        releaseContext(catalogAdmin, 0);
        CloseHandle(file);
        FreeLibrary(wintrustModule);
        return error;
    }

    static constexpr wchar_t kHex[] = L"0123456789ABCDEF";
    std::wstring memberTag;
    memberTag.reserve(hash.size() * 2);
    for (BYTE byte : hash) {
        memberTag.push_back(kHex[(byte >> 4) & 0x0f]);
        memberTag.push_back(kHex[byte & 0x0f]);
    }

    LONG bestFailure = TRUST_E_NOSIGNATURE;
    bool foundCatalog = false;
    HCATINFO catalogContext = nullptr;
    while ((catalogContext = enumCatalog(
                catalogAdmin, hash.data(), hashLength, 0, &catalogContext)) != nullptr) {
        foundCatalog = true;
        CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        if (!getCatalogInfo(catalogContext, &catalogInfo, 0)) {
            bestFailure = Win32ErrorToTrustStatus(GetLastError());
            break;
        }

        WINTRUST_CATALOG_INFO trustCatalog{};
        trustCatalog.cbStruct = sizeof(trustCatalog);
        trustCatalog.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
        trustCatalog.pcwszMemberTag = memberTag.c_str();
        trustCatalog.pcwszMemberFilePath = filePath.c_str();
        trustCatalog.hMemberFile = file;
        trustCatalog.pbCalculatedFileHash = hash.data();
        trustCatalog.cbCalculatedFileHash = hashLength;
        trustCatalog.hCatAdmin = catalogAdmin;

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_DISABLE_MD2_MD4;
        trustData.pCatalog = &trustCatalog;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &trustData);

        if (status == ERROR_SUCCESS) {
            std::wstring catalogPublisher;
            if (GetCatalogPublisherName(catalogInfo.wszCatalogFile, catalogPublisher)) {
                publisherName = std::move(catalogPublisher);
                releaseCatalog(catalogAdmin, catalogContext, 0);
                releaseContext(catalogAdmin, 0);
                CloseHandle(file);
                FreeLibrary(wintrustModule);
                return ERROR_SUCCESS;
            }
            bestFailure = TRUST_E_PROVIDER_UNKNOWN;
        } else {
            const auto failureClass = Oblivion::SignaturePolicy::ClassifyWinTrustResult(
                static_cast<std::uint32_t>(status));
            if (failureClass == Oblivion::SignaturePolicy::WinTrustResultClass::Inconclusive ||
                (failureClass == Oblivion::SignaturePolicy::WinTrustResultClass::Rejected &&
                 bestFailure == TRUST_E_NOSIGNATURE)) {
                bestFailure = status;
            }
        }
    }

    if (catalogContext != nullptr) {
        releaseCatalog(catalogAdmin, catalogContext, 0);
    }
    releaseContext(catalogAdmin, 0);
    CloseHandle(file);
    FreeLibrary(wintrustModule);

    return foundCatalog ? bestFailure : TRUST_E_NOSIGNATURE;
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
    {L"msmpeng.exe", L"Microsoft Corporation"},   // Windows Defender antimalware
    {L"mssense.exe", L"Microsoft Corporation"},    // Microsoft Defender for Endpoint
    
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

        // Only actual Windows servicing roots are protected system locations.
        // Do not exempt every module under C:\Windows: writable paths such as
        // Windows\Temp must still be checked.
        const std::wstring windowsDirectory = ResolveWindowsDirectory();
        const std::vector<std::wstring> protectedWindowsRoots = windowsDirectory.empty()
            ? std::vector<std::wstring>()
            : std::vector<std::wstring>{
                windowsDirectory + L"\System32",
                windowsDirectory + L"\SysWOW64",
                windowsDirectory + L"\WinSxS"
            };

        // Resolve Program Files from the Known Folder API, not environment variables
        // controlled by the launching process.
        std::vector<std::wstring> programFilesRoots;
        const std::wstring programFiles = ResolveKnownFolderPath(FOLDERID_ProgramFiles);
        const std::wstring programFilesX86 = ResolveKnownFolderPath(FOLDERID_ProgramFilesX86);
        if (!programFiles.empty()) {
            programFilesRoots.push_back(programFiles);
        }
        if (!programFilesX86.empty() &&
            Oblivion::PathPolicy::NormalizeWindowsPath(programFilesX86) !=
                Oblivion::PathPolicy::NormalizeWindowsPath(programFiles)) {
            programFilesRoots.push_back(programFilesX86);
        }

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

                bool isProtectedWindowsModule = false;
                for (const auto& root : protectedWindowsRoots) {
                    if (Oblivion::PathPolicy::IsPathWithinDirectory(modulePathStr, root)) {
                        isProtectedWindowsModule = true;
                        break;
                    }
                }

                bool isUnderProgramFiles = false;
                for (const auto& root : programFilesRoots) {
                    if (Oblivion::PathPolicy::IsPathWithinDirectory(modulePathStr, root)) {
                        isUnderProgramFiles = true;
                        break;
                    }
                }

                // Protected Windows modules and third-party Program Files modules may
                // have valid publishers outside the product allowlist, but a valid
                // Authenticode verdict is still required.
                const bool allowAnyValidSigner =
                    !isGameModule && (isProtectedWindowsModule || isUnderProgramFiles);

                std::wstring moduleName(me32.szModule);
                const ModuleTrustResult trustResult = IsModuleTrusted(
                    moduleName, modulePath, gameDir, allowAnyValidSigner);

                if (trustResult == ModuleTrustResult::Inconclusive) {
                    const std::wstring warningKey =
                        Oblivion::PathPolicy::NormalizeWindowsPath(modulePath);
                    if (!m_reportedSignatureProviderIssue) {
                        m_reportedSignatureProviderIssue = true;
                        std::wstringstream detailsStream;
                        detailsStream << L"Module: " << me32.szModule
                                      << L" | Path: " << modulePath
                                      << L" | Authenticode trust provider returned an inconclusive result";
                        const std::wstring detailsWide = detailsStream.str();
                        const int size_needed = WideCharToMultiByte(
                            CP_UTF8, 0, detailsWide.c_str(),
                            static_cast<int>(detailsWide.size()), nullptr, 0, nullptr, nullptr);
                        std::string details_utf8;
                        if (size_needed > 0) {
                            details_utf8.resize(static_cast<size_t>(size_needed));
                            WideCharToMultiByte(
                                CP_UTF8, 0, detailsWide.c_str(),
                                static_cast<int>(detailsWide.size()), &details_utf8[0],
                                size_needed, nullptr, nullptr);
                        }
                        ReportViolationSoft("SIGNATURE_VERIFICATION_INCONCLUSIVE", details_utf8);
                    }
                    continue; // Retry later; an inconclusive result is not cheating evidence.
                }

                if (trustResult == ModuleTrustResult::Untrusted) {
                    std::wstring message = L"Modul tidak tepercaya (tidak ditandatangani atau penerbit tidak dikenal) terdeteksi: ";
                    message += me32.szModule;
                    message += L"\n\nPath: ";
                    message += modulePath;
                    message += L"\n\nClient akan ditutup.";

                    std::wstringstream detailsStream;
                    detailsStream << L"Module: " << me32.szModule
                                  << L" | Path: " << modulePath;
                    const std::wstring detailsWide = detailsStream.str();
                    const int size_needed = WideCharToMultiByte(
                        CP_UTF8, 0, detailsWide.c_str(),
                        static_cast<int>(detailsWide.size()), nullptr, 0, nullptr, nullptr);
                    std::string details_utf8;
                    if (size_needed > 0) {
                        details_utf8.resize(static_cast<size_t>(size_needed));
                        WideCharToMultiByte(
                            CP_UTF8, 0, detailsWide.c_str(),
                            static_cast<int>(detailsWide.size()), &details_utf8[0],
                            size_needed, nullptr, nullptr);
                    }
                    ReportViolationAndExit(message, "UNTRUSTED_MODULE", details_utf8);
                }

            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
    }

    DigitalSignatureValidator::ModuleTrustResult
    DigitalSignatureValidator::IsModuleTrusted(
        std::wstring& moduleName,
        const std::wstring& filePath,
        const std::wstring& gameDirectory,
        bool allowAnyValidSigner) {
        if (filePath.empty()) {
            return ModuleTrustResult::Inconclusive;
        }

        // Preserve the legacy unsigned library exception only for exact names inside
        // the game directory. Every external module must receive a signature verdict.
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
            return ModuleTrustResult::Trusted;
        }

        ModuleFileStamp initialStamp;
        const ModuleFileStampResult stampResult = GetModuleFileStamp(filePath, initialStamp);
        if (stampResult == ModuleFileStampResult::Invalid) {
            return ModuleTrustResult::Untrusted;
        }
        if (stampResult != ModuleFileStampResult::Success) {
            return ModuleTrustResult::Inconclusive;
        }

        const std::wstring cacheKey =
            Oblivion::PathPolicy::NormalizeWindowsPath(filePath);
        const auto cached = m_moduleTrustCache.find(cacheKey);
        if (cached != m_moduleTrustCache.end() &&
            cached->second.fileSize == initialStamp.size &&
            CompareFileTime(&cached->second.lastWriteTime, &initialStamp.lastWriteTime) == 0 &&
            cached->second.volumeSerial == initialStamp.volumeSerial &&
            cached->second.fileIndexHigh == initialStamp.fileIndexHigh &&
            cached->second.fileIndexLow == initialStamp.fileIndexLow &&
            cached->second.changeTime == initialStamp.changeTime) {
            return cached->second.isTrusted
                ? ModuleTrustResult::Trusted
                : ModuleTrustResult::Untrusted;
        }

        // Reuse the centralized verdict logic: it checks the image digest and
        // matches trusted publishers exactly, rather than using substring matching.
        std::wstring publisherName;
        const SignatureVerdict verdict = GetSignatureVerdict(filePath, publisherName);

        ModuleTrustResult trustResult = ModuleTrustResult::Inconclusive;
        switch (verdict) {
        case SignatureVerdict::TrustedPublisher:
            trustResult = ModuleTrustResult::Trusted;
            break;
        case SignatureVerdict::UntrustedPublisher:
            trustResult = allowAnyValidSigner
                ? ModuleTrustResult::Trusted
                : ModuleTrustResult::Untrusted;
            break;
        case SignatureVerdict::Unsigned:
        case SignatureVerdict::InvalidSignature:
            trustResult = ModuleTrustResult::Untrusted;
            break;
        case SignatureVerdict::VerificationError:
            trustResult = ModuleTrustResult::Inconclusive;
            break;
        }

        // Never cache or punish a file that changed while WinVerifyTrust inspected it.
        ModuleFileStamp finalStamp;
        if (GetModuleFileStamp(filePath, finalStamp) != ModuleFileStampResult::Success ||
            !SameModuleFileStamp(initialStamp, finalStamp)) {
            return ModuleTrustResult::Inconclusive;
        }

        if (trustResult != ModuleTrustResult::Inconclusive) {
            m_moduleTrustCache[cacheKey] = {
                initialStamp.size,
                initialStamp.lastWriteTime,
                initialStamp.volumeSerial,
                initialStamp.fileIndexHigh,
                initialStamp.fileIndexLow,
                initialStamp.changeTime,
                trustResult == ModuleTrustResult::Trusted
            };
        }
        return trustResult;
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
        std::wstring actualPublisher;
        GetFilePublisher(filePath, actualPublisher);
        LONG verificationStatus = VerifyFileSignatureStatus(filePath);

        // Windows system modules commonly use a catalog signature instead of an
        // embedded PE signature. Verify the catalog with SHA-256 before deciding
        // that a file is unsigned.
        if (Oblivion::SignaturePolicy::ClassifyWinTrustResult(
                static_cast<std::uint32_t>(verificationStatus)) ==
            Oblivion::SignaturePolicy::WinTrustResultClass::NoSignature) {
            std::wstring catalogPublisher;
            const LONG catalogStatus = VerifyCatalogSignatureStatus(filePath, catalogPublisher);
            if (catalogStatus == ERROR_SUCCESS) {
                if (catalogPublisher.empty()) {
                    return SignatureVerdict::VerificationError;
                }
                actualPublisher = std::move(catalogPublisher);
                verificationStatus = ERROR_SUCCESS;
            } else {
                const auto catalogClass = Oblivion::SignaturePolicy::ClassifyWinTrustResult(
                    static_cast<std::uint32_t>(catalogStatus));
                if (catalogClass == Oblivion::SignaturePolicy::WinTrustResultClass::NoSignature) {
                    return SignatureVerdict::Unsigned;
                }
                verificationStatus = catalogStatus;
            }
        }

        const auto resultClass = Oblivion::SignaturePolicy::ClassifyWinTrustResult(
            static_cast<std::uint32_t>(verificationStatus));

        switch (resultClass) {
        case Oblivion::SignaturePolicy::WinTrustResultClass::Trusted:
            publisherName = actualPublisher;
            if (actualPublisher.empty()) {
                return SignatureVerdict::VerificationError;
            }

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
            return SignatureVerdict::VerificationError;
        }

        return SignatureVerdict::VerificationError;
    }
}
