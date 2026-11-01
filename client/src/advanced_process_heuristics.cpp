#include "pch.h"
#include "advanced_process_heuristics.h"
#include "win_path_utils.h"
#include "digital_signature_validator.h"
#include "../../common/windows_path_policy.h"
#include <tlhelp32.h>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <sstream>
#include <iostream>
#include <map>
#include <psapi.h>
#include <winternl.h>

// NtQuerySystemInformation for handle enumeration
typedef NTSTATUS (NTAPI* NtQuerySystemInformationFn)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// System handle information structures
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define SYSTEM_HANDLE_INFORMATION_CLASS 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// NtQueryObject dipakai untuk menentukan TIPE objek sebuah handle secara dinamis.
// Nomor ObjectTypeNumber pada SYSTEM_HANDLE tidak stabil antar versi Windows
// (7 di Win10 22H2, berbeda di sebagian build Win11), sehingga pengecekan tipe
// harus memakai nama tipe dari object manager, bukan angka hardcoded.
typedef NTSTATUS(NTAPI* NtQueryObjectFn)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

#define OBLIVION_OBJECT_TYPE_INFORMATION_CLASS 2

// Field pertama OBJECT_TYPE_INFORMATION adalah TypeName (UNICODE_STRING).
// Struct lengkap tidak didefinisikan di winternl.h, dan kita hanya membaca field
// pertama tersebut sehingga struct minimal ini aman dipakai.
typedef struct _OBLIVION_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
} OBLIVION_OBJECT_TYPE_INFORMATION, *POBLIVION_OBJECT_TYPE_INFORMATION;

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    struct FileTrustStamp {
        ULONGLONG size = 0;
        FILETIME lastWriteTime{};
        DWORD volumeSerialNumber = 0;
        DWORD fileIndexHigh = 0;
        DWORD fileIndexLow = 0;
    };

    struct FileTrustCacheEntry {
        FileTrustStamp stamp;
        bool trusted = false;
    };

    using FileTrustCache = std::map<std::wstring, FileTrustCacheEntry>;
    constexpr size_t kMaximumCachedFileTrustEntries = 4096;
    FileTrustCache g_signatureCache;
    FileTrustCache g_trustedFileCache;

    DWORD GetProtectedProcessId() {
        return GetCurrentProcessId();
    }

    std::wstring ToLowerCopy(const std::wstring& input) {
        std::wstring lowered = input;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(towlower(ch));
            });
        return lowered;
    }

    std::wstring GetWindowsDirectoryPath() {
        std::wstring path(32768, L'\\0');
        const UINT written = GetWindowsDirectoryW(path.data(), static_cast<UINT>(path.size()));
        if (written == 0 || written >= path.size()) {
            return L"";
        }
        path.resize(written);
        return path;
    }

    bool GetFileTrustStamp(const std::wstring& filePath, FileTrustStamp& stamp) {
        if (filePath.empty()) {
            return false;
        }
        HANDLE file = CreateFileW(
            filePath.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            return false;
        }

        BY_HANDLE_FILE_INFORMATION info{};
        const BOOL ok = GetFileInformationByHandle(file, &info);
        CloseHandle(file);
        if (!ok || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            return false;
        }

        stamp.size = (static_cast<ULONGLONG>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
        stamp.lastWriteTime = info.ftLastWriteTime;
        stamp.volumeSerialNumber = info.dwVolumeSerialNumber;
        stamp.fileIndexHigh = info.nFileIndexHigh;
        stamp.fileIndexLow = info.nFileIndexLow;
        return true;
    }

    bool SameFileTrustStamp(const FileTrustStamp& left, const FileTrustStamp& right) {
        return left.size == right.size &&
            CompareFileTime(&left.lastWriteTime, &right.lastWriteTime) == 0 &&
            left.volumeSerialNumber == right.volumeSerialNumber &&
            left.fileIndexHigh == right.fileIndexHigh &&
            left.fileIndexLow == right.fileIndexLow;
    }

    bool TryGetCachedTrust(
        FileTrustCache& cache,
        const std::wstring& key,
        const FileTrustStamp& currentStamp,
        bool& trusted) {
        const auto found = cache.find(key);
        if (found == cache.end()) {
            return false;
        }
        if (!SameFileTrustStamp(found->second.stamp, currentStamp)) {
            cache.erase(found);
            return false;
        }
        trusted = found->second.trusted;
        return true;
    }

    bool StoreTrustIfUnchanged(
        FileTrustCache& cache,
        const std::wstring& key,
        const std::wstring& filePath,
        const FileTrustStamp& initialStamp,
        bool trusted) {
        FileTrustStamp currentStamp;
        if (!GetFileTrustStamp(filePath, currentStamp) ||
            !SameFileTrustStamp(initialStamp, currentStamp)) {
            cache.erase(key);
            return false;
        }
        if (cache.find(key) == cache.end() && cache.size() >= kMaximumCachedFileTrustEntries) {
            cache.clear();
        }
        cache[key] = FileTrustCacheEntry{ currentStamp, trusted };
        return true;
    }

    bool IsFileTrustedPublisher(const std::wstring& filePath) {
        FileTrustStamp initialStamp;
        if (!GetFileTrustStamp(filePath, initialStamp)) {
            return false;
        }
        const std::wstring key = Oblivion::PathPolicy::NormalizeWindowsPath(filePath);
        bool cachedTrust = false;
        if (TryGetCachedTrust(g_trustedFileCache, key, initialStamp, cachedTrust)) {
            return cachedTrust;
        }

        std::wstring publisher;
        const auto verdict =
            Oblivion::DigitalSignatureValidator::GetSignatureVerdict(filePath, publisher);
        const bool trusted =
            verdict == Oblivion::DigitalSignatureValidator::SignatureVerdict::TrustedPublisher;
        if (verdict ==
            Oblivion::DigitalSignatureValidator::SignatureVerdict::VerificationError) {
            return false;
        }
        if (!StoreTrustIfUnchanged(g_trustedFileCache, key, filePath, initialStamp, trusted)) {
            return false;
        }
        return trusted;
    }

    // Cek apakah satu komponen path (nama folder atau nama file) menandakan tool cheat.
    // Pencocokan dilakukan per komponen, bukan substring bebas, karena keyword pendek
    // seperti "hack" atau "patch" menghasilkan false positive nyata:
    //   "C:\Program Files\HackShield\..."    (anti-cheat resmi game)
    //   "C:\Program Files (x86)\RO\Patcher\..."  (patcher resmi)
    // Keyword harus sama persis dengan komponen, atau menjadi awalan komponen yang
    // diikuti pemisah ("cheat engine 7.5", "cheatengine-x86_64.exe", "newce_1.2").
    bool PathComponentMatchesKeyword(const std::wstring& component, const std::wstring& keyword) {
        if (component.empty() || keyword.empty() || component.size() < keyword.size()) {
            return false;
        }

        if (component.compare(0, keyword.size(), keyword) != 0) {
            return false;
        }

        if (component.size() == keyword.size()) {
            return true;
        }

        const wchar_t next = component[keyword.size()];
        return next == L' ' || next == L'-' || next == L'_' || next == L'.' ||
               next == L'(' || next == L'[' || next == L'+';
    }

    // Cek apakah full path (sudah di-lowercase) mengandung komponen yang menandakan cheat.
    // outKeyword diisi keyword yang cocok untuk keperluan logging/report.
    bool PathContainsSuspiciousComponent(const std::wstring& lowerPath,
                                        const std::vector<std::wstring>& keywords,
                                        std::wstring& outKeyword) {
        outKeyword.clear();

        std::wstring component;
        for (size_t i = 0; i <= lowerPath.size(); ++i) {
            const bool isSeparator = (i == lowerPath.size() ||
                                      lowerPath[i] == L'\\' ||
                                      lowerPath[i] == L'/');
            if (!isSeparator) {
                component.push_back(lowerPath[i]);
                continue;
            }

            for (const auto& keyword : keywords) {
                if (PathComponentMatchesKeyword(component, keyword)) {
                    outKeyword = keyword;
                    return true;
                }
            }
            component.clear();
        }

        return false;
    }

    // Ambil nama tipe objek dari sebuah handle (mis. "Process", "File", "Key").
    // hOwnerProcess harus dibuka dengan PROCESS_DUP_HANDLE.
    std::wstring GetHandleTypeName(HANDLE hOwnerProcess, HANDLE handleValue) {
        static NtQueryObjectFn pNtQueryObject = []() -> NtQueryObjectFn {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll == NULL) {
                return nullptr;
            }
            return reinterpret_cast<NtQueryObjectFn>(GetProcAddress(hNtdll, "NtQueryObject"));
        }();

        if (pNtQueryObject == nullptr) {
            return L"";
        }

        HANDLE hDuplicate = NULL;
        if (!DuplicateHandle(hOwnerProcess, handleValue, GetCurrentProcess(), &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            return L"";
        }

        std::vector<BYTE> buffer(4096);
        ULONG returnLength = 0;
        const NTSTATUS status = pNtQueryObject(
            hDuplicate,
            OBLIVION_OBJECT_TYPE_INFORMATION_CLASS,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &returnLength);
        CloseHandle(hDuplicate);

        if (status < 0) {
            return L"";
        }

        const auto* typeInfo = reinterpret_cast<const OBLIVION_OBJECT_TYPE_INFORMATION*>(buffer.data());
        if (typeInfo->TypeName.Buffer == nullptr || typeInfo->TypeName.Length == 0) {
            return L"";
        }

        return std::wstring(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(wchar_t));
    }

    // True jika handle tersebut menunjuk ke objek Process.
    // Nama tipe dibaca lewat NtQueryObject dan hasilnya di-cache per nomor tipe,
    // sehingga biaya query hanya sekali per tipe objek (bukan per handle).
    bool IsProcessHandleType(DWORD ownerProcessId, HANDLE handleValue, BYTE objectTypeNumber) {
        static std::map<BYTE, bool> typeCache;

        auto cached = typeCache.find(objectTypeNumber);
        if (cached != typeCache.end()) {
            return cached->second;
        }

        HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ownerProcessId);
        if (hOwnerProcess == NULL) {
            // Belum bisa dipastikan: jangan cache supaya dicoba lagi pada scan berikutnya.
            return false;
        }

        const std::wstring typeName = GetHandleTypeName(hOwnerProcess, handleValue);
        CloseHandle(hOwnerProcess);

        if (typeName.empty()) {
            return false;
        }

        const bool isProcess = (_wcsicmp(typeName.c_str(), L"Process") == 0);
        typeCache[objectTypeNumber] = isProcess;
        return isProcess;
    }

    struct WindowSearchContext {
        DWORD targetProcessId = 0;
        std::wstring matchedClass;
        std::wstring matchedTitle;
        bool matched = false;
        bool searchingTitle = false; // true = searching for title patterns, false = searching for class
        int suspiciousControlCount = 0; // Count of suspicious child controls (for UI element detection)
    };

    // Nama DLL yang SANGAT spesifik milik Cheat Engine / tool cheat. Nama-nama ini
    // tidak dipakai perangkat lunak sah, sehingga satu kecocokan nama saja sudah cukup.
    const std::vector<std::wstring> kHighConfidenceModules = {
        // Core CE DLLs
        L"dbk32.dll",
        L"dbk64.dll",
        L"dbvm.dll",
        L"dbvm32.dll",
        L"dbvm64.dll",

        // CE Client & Components
        L"ceclient.dll",
        L"ceserver.dll",
        L"celua.dll",

        // Speedhack modules
        L"speedhack-i386.dll",
        L"speedhack-x86_64.dll",

        // Kernel modules & drivers
        L"kernelmoduleunloader.dll",
        L"vehdebug-x86_64.dll",
        L"vehdebug-i386.dll",

        // Plugin CE dengan penamaan khusus
        L"xinput1_3ce.dll",
        L"xinput9_1_0ce.dll"
    };

    // Nama modul yang MIRIP komponen cheat tetapi juga dipakai library/aplikasi sah
    // (Lua 5.3 dipakai banyak game, d3dhook dipakai overlay, dst). Modul di daftar ini
    // hanya dianggap mencurigakan jika file-nya TIDAK ditandatangani publisher tepercaya.
    const std::vector<std::wstring> kLowConfidenceModules = {
        L"lua53-64.dll",
        L"lua53-32.dll",
        L"speedhack.dll",
        L"d3dhook.dll",
        L"d3dhook64.dll",
        L"autoassembler.dll",
        L"symbolhandler.dll",
        L"disassembler.dll"
    };

    // Window class signatures untuk berbagai versi CE dan tools
    const std::vector<std::wstring> kSuspiciousWindowClasses = {
        // Cheat Engine main forms (Lazarus/FPC classes)
        L"tceform",
        L"tcemainform",
        L"tcheatengine",
        
        // CE dialogs & windows
        L"tmemoryview",
        L"tmemorybrowser",
        L"tmemoryviewer",
        L"tdissectwindow",
        L"tformaddresslist",
        L"tfoundlistform",
        L"tfoundcodeform",
        L"tscanform",
        L"tadvancedoptionsform",
        
        // CE utilities & tools
        L"tautoassembler",
        L"tautoassemblerform",
        L"tstructurefrm",
        L"tpointerscanner",
        L"tpointerfinder",
        L"theaplist",
        L"tdbvmform",
        
        // CE Lua windows
        L"tluaengine",
        L"tluaform",
        
        // x64dbg
        // NOTE: class "Qt5QWindowIcon" / "Qt5QWindowOwnDC" sengaja TIDAK dipakai.
        // Semua aplikasi berbasis Qt (OBS, qBittorrent, Wireshark, Telegram, video
        // player lokal) memakai class itu sehingga menjadi sumber false positive besar.
        // Deteksi x64dbg mengandalkan nama process (blacklist) dan window title.
        L"x64dbgmain",
        
        // OllyDbg variants
        L"ollydbg",
        L"odbg",
        
        // IDA Pro
        // NOTE: "qt5156qwindowicon" (Qt 5.15) juga dihapus dengan alasan yang sama
        // seperti class Qt lain di atas.
        L"idawindow",
        
        // Automation/macro tool yang dipakai untuk cheat auto-potion / auto-buff.
        // Meski aplikasinya "sah", memakainya untuk memainkan game secara otomatis
        // adalah cheating, jadi tetap diblokir - termasuk saat nama exe diganti
        // (nama window class AutoHotkey/AutoIt tetap sama).
        L"autohotkey",
        L"autohotkeygui",
        L"autoit v3 gui",
        L"autoit v3",

        // Other debuggers
        L"windbgframeclass",
        L"procmon_window_class"
    };

    // Windows system executable names require the real Windows path and a trusted signature.
    const std::vector<std::wstring> kWindowsSystemProcessWhitelist = {
        L"explorer.exe", L"svchost.exe", L"services.exe", L"lsass.exe",
        L"csrss.exe", L"smss.exe", L"wininit.exe", L"winlogon.exe",
        L"dwm.exe", L"taskhostw.exe", L"taskhost.exe", L"sihost.exe",
        L"ctfmon.exe", L"conhost.exe", L"fontdrvhost.exe", L"runtimebroker.exe",
        L"dllhost.exe", L"searchhost.exe", L"searchindexer.exe",
        L"searchprotocolhost.exe", L"searchfilterhost.exe", L"msmpeng.exe",
        L"securityhealthservice.exe", L"securityhealthsystray.exe",
        L"smartscreen.exe", L"sgrmbroker.exe", L"wuauclt.exe",
        L"trustedinstaller.exe", L"tiworker.exe", L"usocoreworker.exe",
        L"shellexperiencehost.exe", L"startmenuexperiencehost.exe",
        L"textinputhost.exe", L"applicationframehost.exe", L"systemsettings.exe",
        L"audiodg.exe"
    };

    // Other process names are accepted only after explicit signature verification.
    const std::vector<std::wstring> kSystemProcessWhitelist = {
        // Windows Core Processes
        L"explorer.exe",
        L"svchost.exe",
        L"services.exe",
        L"lsass.exe",
        L"csrss.exe",
        L"smss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"dwm.exe",
        L"taskhostw.exe",
        L"taskhost.exe",
        L"sihost.exe",
        L"ctfmon.exe",
        L"conhost.exe",
        L"fontdrvhost.exe",
        L"runtimebroker.exe",
        L"dllhost.exe",
        L"system",
        L"system idle process",
        L"registry",
        
        // Windows Search & Indexing
        L"searchhost.exe",
        L"searchindexer.exe",
        L"searchprotocolhost.exe",
        L"searchfilterhost.exe",
        
        // Windows Defender & Security
        L"msmpeng.exe",
        L"mssense.exe",
        L"securityhealthservice.exe",
        L"securityhealthsystray.exe",
        L"smartscreen.exe",
        L"sgrmbroker.exe",
        
        // Windows Update & Maintenance
        L"wuauclt.exe",
        L"trustedinstaller.exe",
        L"tiworker.exe",
        L"usocoreworker.exe",
        
        // Windows Shell & UI
        L"shellexperiencehost.exe",
        L"startmenuexperiencehost.exe",
        L"textinputhost.exe",
        L"applicationframehost.exe",
        L"systemsettings.exe",
        
        // Windows Audio Services
        L"audiodg.exe",  // Audio Device Graph Isolation (Windows audio service)
        
        // Unsigned utilities are deliberately not name-whitelisted.
        // VLC is listed below but requires signature/publisher verification.
        
        // Common legitimate software (REQUIRES SIGNATURE VERIFICATION)
        // These processes MUST be verified with digital signature to prevent spoofing
        L"chrome.exe",
        L"firefox.exe",
        L"msedge.exe",
        L"msedgewebview2.exe",  // Microsoft Edge WebView2 Runtime
        L"vlc.exe",
        L"discord.exe",
        L"steam.exe",
        L"steamwebhelper.exe",
        L"vscode.exe",
        L"code.exe",
        L"devenv.exe",
        L"skype.exe",
        L"teams.exe",
        // Media & Entertainment
        L"spotify.exe",
        // Gaming platforms
        L"epicgameslauncher.exe",
        L"easyanticheat.exe",
        L"battlenet.exe",
        L"origin.exe",
        L"uplay.exe",
        L"upc.exe",
        // Cloud & Productivity
        L"dropbox.exe",
        L"onedrive.exe",
        L"googledrivesync.exe"
    };

    // Proses yang HARUS diverifikasi dengan digital signature (tidak boleh di-spoof)
    // Ini adalah subset dari whitelist yang rentan terhadap spoofing
    const std::vector<std::wstring> kSignatureVerificationRequired = {
        L"chrome.exe",
        L"firefox.exe",
        L"msedge.exe",
        L"msedgewebview2.exe",  // Microsoft Edge WebView2 Runtime
        L"msmpeng.exe",          // Windows Defender antimalware; must pass signer validation
        L"mssense.exe",          // Microsoft Defender for Endpoint; must pass signer validation
        L"vlc.exe",
        L"discord.exe",
        L"steam.exe",
        L"steamwebhelper.exe",
        L"vscode.exe",
        L"code.exe",
        L"devenv.exe",
        L"skype.exe",
        L"teams.exe",
        L"spotify.exe",
        L"epicgameslauncher.exe",
        L"easyanticheat.exe",
        L"battlenet.exe",
        L"origin.exe",
        L"uplay.exe",
        L"upc.exe",
        L"dropbox.exe",
        L"onedrive.exe",
        L"googledrivesync.exe"
        // VLC is verified against its expected publisher. Unsigned utilities such as
        // Notepad++, 7-Zip and WinRAR are intentionally not exempted by name alone.
    };

    // Proses sah yang secara normal membuka handle ke proses game lain (game capture,
    // overlay, tool monitoring, antivirus). Tanpa daftar ini deteksi handle menjadi
    // sumber false positive besar: OBS / RTSS / capture driver / antivirus membuka
    // process game dengan hak akses memory untuk mengambil frame atau memindai malware.
    //
    // CATATAN TRADE-OFF: daftar ini berbasis nama process, sehingga tool tidak sah
    // secara teori bisa menyaru memakai nama ini. Deteksi tetap memerlukan bukti
    // tambahan (handle dengan hak tulis + konfirmasi DuplicateHandle + owner tidak
    // ada di whitelist bersignature), dan keuntungan menekan false positive dinilai
    // lebih besar daripada risiko penyaruan nama.
    const std::vector<std::wstring> kKnownLegitimateHandleOwners = {
        L"obs.exe", L"obs32.exe", L"obs64.exe",                      // OBS Studio (game capture)
        L"streamlabsdesktop.exe", L"streamlabs obs.exe",             // Streamlabs Desktop
        L"msiafterburner.exe", L"rtss.exe", L"rtsshooksloader.exe",  // MSI AB / RivaTuner
        L"fraps.exe", L"bandicam.exe", L"bdcam.exe", L"dxtory.exe", L"action.exe",
        L"nvidia share.exe", L"nvidia web helper.exe", L"nvcontainer.exe", L"nvsphelper64.exe",
        L"nvidia geforce experience.exe", L"nvidia app.exe", L"nvspcaps64.exe",
        L"radeonsoftware.exe", L"amdrsserv.exe", L"amdow.exe", L"amfencoder.exe",
        L"gamebar.exe", L"gamebarftserver.exe", L"gamebarpresencewriter.exe",
        L"msmpeng.exe", L"mpcmdrun.exe", L"nissrv.exe", L"mssense.exe",  // Windows Defender
        L"avp.exe", L"avastsvc.exe", L"avastui.exe", L"avguard.exe",     // Antivirus umum
        L"werfault.exe", L"wermgr.exe",                                  // Crash dump / WER
        L"taskmgr.exe", L"procexp.exe", L"procexp64.exe"                 // Task Manager / Process Explorer
    };

    bool IsKnownLegitimateHandleOwner(const std::wstring& processName) {
        if (processName.empty()) {
            return false;
        }

        const std::wstring lowerName = ToLowerCopy(processName);
        for (const auto& allowedName : kKnownLegitimateHandleOwners) {
            if (lowerName == allowedName) {
                return true;
            }
        }
        return false;
    }

    // Fungsi helper untuk mendapatkan full path dari process
    std::wstring GetProcessPath(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return L"";
        }

        std::wstring result = Oblivion::WinPath::GetProcessImagePath(hProcess);
        CloseHandle(hProcess);
        return result;
    }

    bool IsProcessWhitelisted(const std::wstring& processName, DWORD processId = 0) {
        const std::wstring lowerName = ToLowerCopy(processName);
        const bool isInWhitelist = std::find(
            kSystemProcessWhitelist.begin(), kSystemProcessWhitelist.end(), lowerName) !=
            kSystemProcessWhitelist.end();
        if (!isInWhitelist) {
            return false;
        }

        // PID 0 and 4 are reserved identities; callers normally skip them explicitly.
        if (processId == 0 || processId == 4) {
            return false;
        }

        const std::wstring processPath = GetProcessPath(processId);
        if (processPath.empty()) {
            // An unreadable path is not proof of cheating, but cannot grant a bypass.
            std::wcout << L"[AdvHeuristics] WARNING: Cannot resolve whitelisted process image: "
                       << processName << L" (PID: " << processId
                       << L"); continuing inspection" << std::endl;
            return false;
        }

        const bool isWindowsSystemProcess = std::find(
            kWindowsSystemProcessWhitelist.begin(),
            kWindowsSystemProcessWhitelist.end(),
            lowerName) != kWindowsSystemProcessWhitelist.end();
        if (isWindowsSystemProcess) {
            const std::wstring windowsDirectory = GetWindowsDirectoryPath();
            const bool insideWindowsDirectory = !windowsDirectory.empty() &&
                Oblivion::PathPolicy::IsPathWithinDirectory(processPath, windowsDirectory);
            const bool trustedSignature = insideWindowsDirectory &&
                IsFileTrustedPublisher(processPath);
            const bool accepted = Oblivion::PathPolicy::ShouldWhitelistWindowsSystemProcess(
                true, true, insideWindowsDirectory, trustedSignature);
            if (!accepted) {
                std::wcout << L"[AdvHeuristics] WARNING: Windows process failed identity validation: "
                           << processName << L" (PID: " << processId << L", path: "
                           << processPath << L"); continuing inspection" << std::endl;
            }
            return accepted;
        }

        const bool needsSignatureVerification = std::find(
            kSignatureVerificationRequired.begin(),
            kSignatureVerificationRequired.end(),
            lowerName) != kSignatureVerificationRequired.end();
        if (!needsSignatureVerification) {
            return false; // No unsigned third-party process is accepted by name alone.
        }

        FileTrustStamp initialStamp;
        if (!GetFileTrustStamp(processPath, initialStamp)) {
            return false;
        }
        const std::wstring cacheKey = Oblivion::PathPolicy::NormalizeWindowsPath(processPath);
        bool cachedVerdict = false;
        if (TryGetCachedTrust(g_signatureCache, cacheKey, initialStamp, cachedVerdict)) {
            return cachedVerdict;
        }

        const auto& publisherMap = Oblivion::DigitalSignatureValidator::m_expectedPublishers;
        const auto publisherEntry = publisherMap.find(lowerName);
        if (publisherEntry == publisherMap.end()) {
            return false;
        }

        std::wstring verifiedPublisher;
        const auto verdict =
            Oblivion::DigitalSignatureValidator::GetSignatureVerdict(processPath, verifiedPublisher);

        bool accepted = verdict ==
            Oblivion::DigitalSignatureValidator::SignatureVerdict::TrustedPublisher;
        if (verdict ==
            Oblivion::DigitalSignatureValidator::SignatureVerdict::VerificationError) {
            // Inconclusive signature infrastructure is not cheating evidence. Do not
            // cache it or grant a whitelist bypass; continue normal heuristic inspection.
            std::wcout << L"[AdvHeuristics] WARNING: Inconclusive signature result for: "
                       << processName << L" (PID: " << processId
                       << L"); continuing inspection" << std::endl;
            return false;
        }

        if (!accepted &&
            verdict == Oblivion::DigitalSignatureValidator::SignatureVerdict::UntrustedPublisher &&
            !verifiedPublisher.empty()) {
            const std::wstring actual = ToLowerCopy(verifiedPublisher);
            const std::wstring expected = ToLowerCopy(publisherEntry->second);
            accepted = !expected.empty() && actual.find(expected) != std::wstring::npos;
        }

        if (!StoreTrustIfUnchanged(g_signatureCache, cacheKey, processPath, initialStamp, accepted)) {
            return false;
        }
        if (!accepted) {
            std::wcout << L"[AdvHeuristics] Process whitelist signature/publisher mismatch: "
                       << processName << L" (PID: " << processId << L", path: "
                       << processPath << L")" << std::endl;
        }
        return accepted;
    }

    bool EnableDebugPrivilege() {
        HANDLE hToken = NULL;
        TOKEN_PRIVILEGES tokenPrivileges;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            return false;
        }

        if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bool result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL) != 0;
        CloseHandle(hToken);
        return result;
    }

    // Get process name from PID
    std::wstring GetProcessName(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL) {
            return L"";
        }

        std::wstring result;
        const std::wstring fullPath = Oblivion::WinPath::GetProcessImagePath(hProcess);
        if (!fullPath.empty()) {
            // Extract filename from the complete process image path.
            const size_t lastSlash = fullPath.find_last_of(L"\\/");
            result = lastSlash != std::wstring::npos
                ? fullPath.substr(lastSlash + 1)
                : fullPath;
        }

        CloseHandle(hProcess);
        return result;
    }
    
    // Memory signatures - pola byte khas CE di memory (IMPROVED - lebih spesifik)
    struct MemorySignature {
        const wchar_t* name;
        const BYTE* pattern;
        size_t patternSize;
        const BYTE* mask;
        bool requiresExecutableMemory; // True jika harus di executable region
    };
    
    // CE specific code signature - DBK driver initialization pattern
    const BYTE dbkInitPattern[] = { 
        0x44, 0x42, 0x4B, 0x33, 0x32, // "DBK32" signature
        0x2E, 0x73, 0x79, 0x73         // ".sys"
    };
    const BYTE dbkInitMask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    
    // CE Lua engine specific pattern
    const BYTE luaEnginePattern[] = {
        0x43, 0x45, 0x4C, 0x75, 0x61,  // "CELua"
        0x00, 0x00, 0x00, 0x00
    };
    const BYTE luaEngineMask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    
    // CATATAN PENTING: signature "SPEEDHACK_CODE" yang lama memakai byte
    // 48 89 5C 24 08 57 48 83 EC 20 (mov [rsp+8],rbx; push rdi; sub rsp,20h).
    // Itu adalah PROLOG FUNGSI MSVC x64 yang generik sehingga cocok dengan hampir
    // semua binary x64 - sumber false positive terbesar di pemeriksaan memory.
    // Signature tersebut dihapus; DLL speedhack CE tetap terdeteksi melalui
    // pemeriksaan nama modul (speedhack-i386.dll / speedhack-x86_64.dll).
    const std::vector<MemorySignature> kMemorySignatures = {
        { L"DBK_DRIVER", dbkInitPattern, sizeof(dbkInitPattern), dbkInitMask, false },
        { L"CE_LUA_ENGINE", luaEnginePattern, sizeof(luaEnginePattern), luaEngineMask, false }
    };

    BOOL CALLBACK EnumWindowsForProcess(HWND hwnd, LPARAM lParam) {
        auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
        if (!ctx) {
            return FALSE;
        }

        DWORD windowProcessId = 0;
        GetWindowThreadProcessId(hwnd, &windowProcessId);
        if (windowProcessId != ctx->targetProcessId) {
            return TRUE;
        }

        if (ctx->searchingTitle) {
            // Search for suspicious window titles
            wchar_t windowTitle[512] = { 0 };
            const int titleLen = GetWindowTextW(hwnd, windowTitle, static_cast<int>(sizeof(windowTitle) / sizeof(windowTitle[0])));
            
#ifdef _DEBUG
            if (titleLen > 0) {
                std::wstring debugMsg = L"[AdvHeuristics] Found window title: " + std::wstring(windowTitle, titleLen) + L"\n";
                OutputDebugStringW(debugMsg.c_str());
            }
#endif
            
            if (titleLen > 0) {
                std::wstring title(windowTitle, titleLen);
                std::wstring lowerTitle = ToLowerCopy(title);
                
                // Pattern 1: format title CE = "<PID 8 digit hex>-<NamaProcess>"
                // Contoh: "00001C0C-Republic-RO" atau "00001234-game.exe"
                // STRICT: CE memakai IntToHex(processid, 8), jadi prefix WAJIB tepat 8
                // digit hex. Versi lama hanya memeriksa 1-8 karakter pertama berupa hex,
                // sehingga title sah seperti "7-Zip 19.00" (prefix "7" lalu "-") ikut
                // ditandai sebagai Cheat Engine (false positive).
                constexpr size_t kCePidLength = 8;
                if (title.length() > kCePidLength + 1 &&
                    title[0] >= L'0' && title[0] <= L'9' &&
                    title[kCePidLength] == L'-') {
                    bool isHexPID = true;
                    for (size_t i = 0; i < kCePidLength; ++i) {
                        wchar_t ch = title[i];
                        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'F') || (ch >= L'a' && ch <= L'f'))) {
                            isHexPID = false;
                            break;
                        }
                    }
                    // Setelah '-' langsung nama proses (CE tidak memakai spasi di sini)
                    if (isHexPID && title[kCePidLength + 1] != L' ') {
                        ctx->matchedTitle = L"CE_PID_PATTERN: " + title;
                        ctx->matched = true;
#ifdef _DEBUG
                        OutputDebugStringW(L"[AdvHeuristics] DETECTED CE PID PATTERN!\n");
#endif
                        return FALSE;
                    }
                }
                
                // Pattern 2: Contains "cheat engine" dalam title
                if (lowerTitle.find(L"cheat engine") != std::wstring::npos ||
                    lowerTitle.find(L"cheatengine") != std::wstring::npos) {
                    ctx->matchedTitle = L"CE_TITLE: " + title;
                    ctx->matched = true;
#ifdef _DEBUG
                    OutputDebugStringW(L"[AdvHeuristics] DETECTED CE TITLE!\n");
#endif
                    return FALSE;
                }
                
                // Pattern 3 & 4 DIHAPUS karena terbukti menghasilkan false positive:
                //  - "ce " + "7."/"6."  -> cocok dengan title sah apa pun yang memuat
                //    potongan tersebut (mis. "Service CE 7.1", "Source CE 7.0").
                //  - "no process selected" -> string ini juga muncul di aplikasi sah
                //    (task manager, tool capture) yang belum memilih target.
                // Deteksi CE tetap kuat melalui Pattern 1 (format title khas CE),
                // Pattern 2 ("cheat engine"), dan Pattern 5 (build modifikasi).
                
                // Pattern 5: Modified CE versions (bossb, etc)
                if (lowerTitle.find(L"bossb") != std::wstring::npos ||
                    lowerTitle.find(L"boss b") != std::wstring::npos) {
                    ctx->matchedTitle = L"CE_MODIFIED: " + title;
                    ctx->matched = true;
#ifdef _DEBUG
                    OutputDebugStringW(L"[AdvHeuristics] DETECTED MODIFIED CE (bossb)!\n");
#endif
                    return FALSE;
                }
            }
        } else {
            // Search for suspicious window classes
            wchar_t className[256] = { 0 };
            const int len = GetClassNameW(hwnd, className, static_cast<int>(sizeof(className) / sizeof(className[0])));
            if (len == 0) {
                return TRUE;
            }

            std::wstring lowered = ToLowerCopy(className);
            for (const auto& suspiciousClass : kSuspiciousWindowClasses) {
                if (lowered == suspiciousClass) {
                    ctx->matchedClass.assign(className, len);
                    ctx->matched = true;
                    return FALSE;
                }
            }
        }

        return TRUE;
    }
    
    // Callback untuk enumerate child controls di dalam window
    BOOL CALLBACK EnumChildControlsForCE(HWND hwnd, LPARAM lParam) {
        auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
        if (!ctx) {
            return FALSE;
        }
        
        wchar_t controlText[256] = { 0 };
        const int textLen = GetWindowTextW(hwnd, controlText, static_cast<int>(sizeof(controlText) / sizeof(controlText[0])));
        
        if (textLen > 0) {
            std::wstring text = ToLowerCopy(controlText);
            
            // CE-specific UI elements yang sangat khas.
            // PERHATIAN: label generik ("hex", "float", "double", "address",
            // "4 bytes", "8 bytes") sudah DIHAPUS karena muncul juga di tool sah
            // (hex editor, viewer data, aplikasi lokal) dan dengan ambang 3 kecocokan
            // langsung men-kick pemain. Label yang tersisa bersifat khas Cheat Engine.
            const std::vector<std::wstring> ceUIElements = {
                L"first scan",
                L"next scan",
                L"new scan",
                L"undo scan",
                L"value type",
                L"scan type",
                L"exact value",
                L"array of byte",
                L"lua formula",
                L"memory view",
                L"pointer scan",
                L"dissect data",
                L"auto assemble",
                L"speedhack",
                L"enable speedhack",
                L"bossb" // Modified CE branding
            };
            
            for (const auto& element : ceUIElements) {
                if (text.find(element) != std::wstring::npos) {
                    ctx->suspiciousControlCount++;
#ifdef _DEBUG
                    std::wstring debugMsg = L"[AdvHeuristics] Found CE UI element: " + std::wstring(controlText) + L"\n";
                    OutputDebugStringW(debugMsg.c_str());
#endif
                    // Jika sudah menemukan 3+ CE-specific controls, sangat yakin ini CE
                    if (ctx->suspiciousControlCount >= 3) {
                        ctx->matchedTitle = L"CE_UI_ELEMENTS: Found " + std::to_wstring(ctx->suspiciousControlCount) + L" CE controls";
                        ctx->matched = true;
                        return FALSE; // Stop enumeration
                    }
                    break;
                }
            }
        }
        
        return TRUE;
    }
}

namespace Oblivion {
    // Tentukan apakah process ini perlu di-scan memory-nya
    // Memory scanning hanya untuk process dengan karakteristik mencurigakan
    bool ShouldPerformMemoryScan(const std::wstring& processName) {
        std::wstring lowerName = ::ToLowerCopy(processName);
        
        // Whitelist untuk proses inti Windows
        const std::vector<std::wstring> systemWhitelist = {
            L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe"
        };
        
        // Whitelist untuk proses legitimate dari vendor hardware/software
        const std::vector<std::wstring> legitimatePatterns = {
            L"nvdisplay", L"nvcontainer", L"nvidia", L"nvbackend", L"nvspcap", L"nvstreamer",
            L"amd", L"radeon", L"amdrsserv", L"amddvr",
            L"intel", L"igfx", L"hkcmd",
            L"realtek", L"rthdcpl",
            L"microsoft", L"windows", L"skype", L"teams", L"msedge", L"msedgewebview",
            L"audiodg", L"audio",  // Windows audio services
            L"vcpkgsrv",  // Visual Studio Package Server
            L"adobe", L"acrobat", L"creative cloud",
            L"google", L"chrome", L"drive",
            L"steam", L"origin", L"uplay", L"epicgames", L"battlenet",
            L"discord", L"obs", L"streamlabs",
            L"logitech", L"razer", L"corsair", L"steelseries",
            L"dropbox", L"onedrive", L"icloud",
            L"vscode", L"code.exe", L"cpptools", L"omnisharp",
            L"devenv", L"msbuild", L"cl.exe", L"link.exe"
        };
        
        // Cek whitelist sistem
        for (const auto& pattern : systemWhitelist) {
            if (lowerName == pattern) {
                return false;
            }
        }
        
        // Cek whitelist legitimate (partial match)
        for (const auto& pattern : legitimatePatterns) {
            if (lowerName.find(pattern) != std::wstring::npos) {
                return false;
            }
        }
        
        // Scan semua proses lain
        return true;
    }

    // Cek nama modul (DLL) terhadap daftar modul cheat yang sangat spesifik.
    // Pemeriksaan substring "hook"/"inject"/"cheat" pada versi sebelumnya dihapus
    // karena menandai modul sah apa pun yang namanya memuat kata tersebut
    // (mis. DiscordHook64.dll, komponen overlay, atau hook milik antivirus).
    bool IsKnownCheatModuleName(const std::wstring& moduleName) {
        if (moduleName.empty()) {
            return false;
        }

        const std::wstring lowerName = ::ToLowerCopy(moduleName);
        return std::find(kHighConfidenceModules.begin(), kHighConfidenceModules.end(), lowerName) != kHighConfidenceModules.end();
    }

    // Heuristik perilaku: deteksi proses dengan aktivitas mencurigakan
    bool IsSuspiciousBehavior(DWORD processId) {
        // Deteksi sederhana: cek apakah proses menggunakan CreateRemoteThread atau WriteProcessMemory
        // (Biasanya digunakan untuk DLL injection atau manipulasi memory)
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return false;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool suspicious = false;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring modName = szModName;
                    if (IsKnownCheatModuleName(modName)) {
                        suspicious = true;
                        break;
                    }
                }
            }
        }
        CloseHandle(hProcess);
        return suspicious;
    }

    void LogSuspiciousProcess(const std::wstring& processName, DWORD processId, const std::string& reason) {
        // Logging/reporting detail untuk proses mencurigakan
        std::wcout << L"[Heuristics] Suspicious process detected: " << processName << L" (PID: " << processId << L") Reason: " << reason.c_str() << std::endl;
        // Integrasi blokir langsung dengan report ke server
        // Build details
        std::wstringstream detailsStream;
        detailsStream << L"Process: " << processName << L" (PID: " << processId << L") | Reason: " << std::wstring(reason.begin(), reason.end());
        // Convert ke UTF-8
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, detailsStream.str().c_str(), (int)detailsStream.str().length(), NULL, 0, NULL, NULL);
        std::string details_utf8;
        if (size_needed > 0) {
            details_utf8.resize(size_needed);
            WideCharToMultiByte(CP_UTF8, 0, detailsStream.str().c_str(), (int)detailsStream.str().length(), &details_utf8[0], size_needed, NULL, NULL);
        }
        // Report dan exit
        ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details_utf8);
    }

    AdvancedProcessHeuristics::AdvancedProcessHeuristics() : m_heartbeatCallback(nullptr) {}

    AdvancedProcessHeuristics::~AdvancedProcessHeuristics() = default;
    
    void AdvancedProcessHeuristics::SetHeartbeatCallback(std::function<void()> callback) {
        m_heartbeatCallback = callback;
    }

    void AdvancedProcessHeuristics::PerformScan() {
        // Update heartbeat di awal scan
        if (m_heartbeatCallback) {
            m_heartbeatCallback();
        }
        
        // ULTIMATE DETECTION: Handle-Based Heuristics
        // Use the process ID of the host game (current process)
        const DWORD gameProcessId = GetProtectedProcessId();

        // Check for suspicious handles to game process (ULTIMATE - detects ANY memory scanner)
        if (gameProcessId != 0) {
            std::wstring suspiciousProcess;
            if (HasSuspiciousHandleToGame(gameProcessId, suspiciousProcess)) {
                const auto details = BuildHeuristicDetails(
                    L"Handle-Based Detection",
                    gameProcessId,
                    L"HANDLE_BASED",
                    suspiciousProcess
                );
                ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
            }
        }

        // Continue with traditional detection methods
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        const DWORD selfPid = GetCurrentProcessId();

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                // Update heartbeat setiap iterasi untuk mencegah timeout
                if (m_heartbeatCallback) {
                    m_heartbeatCallback();
                }
                
                if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4 || pe32.th32ProcessID == selfPid) {
                    continue;
                }

                std::wstring processName = pe32.szExeFile;

                // Skip whitelisted system processes untuk menghindari false positive
                // IMPORTANT: Sekarang dengan signature verification untuk mencegah spoofing
                if (IsProcessWhitelisted(processName, pe32.th32ProcessID)) {
                    continue;
                }

                // Skip proses yang executable-nya ditandatangani publisher tepercaya.
                // Tool/cheat tidak pernah memiliki signature resmi, sedangkan aplikasi
                // sah (launcher resmi, overlay, software komersial) adalah sumber utama
                // false positive pada heuristik nama window, nama DLL, dan isi memory.
                if (IsFileTrustedPublisher(GetProcessPath(pe32.th32ProcessID))) {
                    continue;
                }

#ifdef _DEBUG
                // Debug logging untuk tracking
                std::wstring debugMsg = L"[AdvHeuristics] Scanning process: " + processName + 
                                       L" (PID: " + std::to_wstring(pe32.th32ProcessID) + L")\n";
                OutputDebugStringW(debugMsg.c_str());
#endif

                std::wstring indicator;
                bool hasSuspiciousIndicator = false;

                // Check 1: Suspicious Path Detection (Priority #1 - Most reliable for this case)
                // Deteksi path mencurigakan seperti "cheatprogram", "newce", "hack", dll
                if (HasSuspiciousPath(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"SUSPICIOUS_PATH", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 2: Suspicious Module (DLL) Detection
                if (ContainsSuspiciousModule(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"MODULE", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 3: Suspicious Window Class Detection
                if (HasSuspiciousWindowClass(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"WINDOW_CLASS", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 4: Suspicious Window Title Pattern Detection + UI Elements
                // CRITICAL: Deteksi pattern window title khas CE seperti "00001C0C-Republic-RO"
                // ATAU deteksi CE-specific UI controls seperti "First Scan", "Next Scan", dll
                if (HasSuspiciousWindowTitle(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"WINDOW_TITLE", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 5: Suspicious Behavior Detection - DISABLED (too many false positives)
                // Behavioral detection seperti handle count tidak reliable karena:
                // - System processes (SearchHost.exe, Chrome, etc) naturally have 500-2000+ handles
                // - No reliable way to differentiate legitimate high handle usage vs malicious
                // 
                // Detection layers 1-4 (DLL + Window Class + Path + Window Title) sudah cukup kuat!
                /*
                if (HasSuspiciousBehavior(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"BEHAVIOR", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }
                */

                indicator.clear();

                // Check 6: Suspicious Memory Signature Detection
                // IMPROVED: Memory scanning sekarang selective - hanya untuk process mencurigakan
                // Dengan signature yang lebih spesifik (DBK driver, CE Lua, Speedhack code)
                // dan whitelist yang ketat untuk menghindari false positive
                if (ShouldPerformMemoryScan(processName)) {
                    if (HasSuspiciousMemorySignature(pe32.th32ProcessID, indicator)) {
                        const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"MEMORY_PATTERN", indicator);
                        ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                    }
                }

            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    bool AdvancedProcessHeuristics::ContainsSuspiciousModule(DWORD processId, std::wstring& matchedModule) const {
        HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        bool detected = false;

        if (Module32FirstW(hModuleSnapshot, &me32)) {
            do {
                std::wstring moduleLower = ToLowerCopy(me32.szModule);

                // Tier 1: nama modul yang sangat spesifik milik tool cheat.
                if (std::find(kHighConfidenceModules.begin(), kHighConfidenceModules.end(), moduleLower) != kHighConfidenceModules.end()) {
                    matchedModule = me32.szModule;
                    detected = true;
                    break;
                }

                // Tier 2: nama modul yang juga dipakai library/aplikasi sah
                // (lua53-*.dll, d3dhook.dll, dst). Modul seperti ini hanya dianggap
                // mencurigakan bila file-nya TIDAK ditandatangani publisher tepercaya,
                // sehingga aplikasi komersial/game resmi tidak ikut tertandai.
                if (std::find(kLowConfidenceModules.begin(), kLowConfidenceModules.end(), moduleLower) != kLowConfidenceModules.end()) {
                    bool unsignedModule = true;
                    if (me32.szExePath[0] != L'\0') {
                        unsignedModule = !IsFileTrustedPublisher(me32.szExePath);
                    }

                    if (unsignedModule) {
                        matchedModule = me32.szModule;
                        detected = true;
                        break;
                    }
                }
            } while (Module32NextW(hModuleSnapshot, &me32));
        }

        CloseHandle(hModuleSnapshot);
        return detected;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousWindowClass(DWORD processId, std::wstring& matchedClass) const {
        WindowSearchContext ctx;
        ctx.targetProcessId = processId;
        ctx.searchingTitle = false;

        EnumWindows(EnumWindowsForProcess, reinterpret_cast<LPARAM>(&ctx));

        if (!ctx.matched) {
            return false;
        }

        matchedClass = ctx.matchedClass;
        return true;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousWindowTitle(DWORD processId, std::wstring& matchedPattern) const {
        WindowSearchContext ctx;
        ctx.targetProcessId = processId;
        ctx.searchingTitle = true;
        ctx.suspiciousControlCount = 0;

        // First, try to detect by window title
        EnumWindows(EnumWindowsForProcess, reinterpret_cast<LPARAM>(&ctx));

        if (ctx.matched) {
            matchedPattern = ctx.matchedTitle;
            return true;
        }

        // If not found by title, enumerate all windows of this process
        // and check their child controls for CE-specific UI elements
        HWND hwnd = NULL;
        do {
            hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
            if (hwnd != NULL) {
                DWORD windowPID = 0;
                GetWindowThreadProcessId(hwnd, &windowPID);
                
                if (windowPID == processId) {
                    // Found a window belonging to target process
                    // Enumerate its child controls
                    ctx.suspiciousControlCount = 0;
                    EnumChildWindows(hwnd, EnumChildControlsForCE, reinterpret_cast<LPARAM>(&ctx));
                    
                    if (ctx.matched) {
                        matchedPattern = ctx.matchedTitle;
#ifdef _DEBUG
                        OutputDebugStringW(L"[AdvHeuristics] DETECTED CE by UI elements!\n");
#endif
                        return true;
                    }
                }
            }
        } while (hwnd != NULL);

        return false;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousHandleToGame(DWORD gameProcessId, std::wstring& suspiciousProcess) const {
        // Enable SeDebugPrivilege untuk akses system-wide handles
        EnableDebugPrivilege();

        // Load NtQuerySystemInformation dari ntdll.dll
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll == NULL) {
            return false;
        }

        NtQuerySystemInformationFn pNtQuerySystemInformation =
            reinterpret_cast<NtQuerySystemInformationFn>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        if (pNtQuerySystemInformation == NULL) {
            return false;
        }

        // Query system handles - start dengan buffer kecil, expand jika perlu
        ULONG bufferSize = 0x10000; // 64KB initial
        std::vector<BYTE> buffer;
        NTSTATUS status;

        do {
            buffer.resize(bufferSize);
            ULONG returnLength = 0;
            status = pNtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buffer.data(),
                bufferSize,
                &returnLength);

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                bufferSize = returnLength + 0x1000; // Add extra space
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (status != 0) {
            return false;
        }

        PSYSTEM_HANDLE_INFORMATION handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.data());
        const DWORD selfPid = GetCurrentProcessId();

        // Access mask yang benar-benar berbahaya: kemampuan MENULIS / memanipulasi
        // memory game. PROCESS_VM_READ saja sengaja TIDAK dihitung karena terlalu
        // umum: OBS/game capture, antivirus, Windows Error Reporting, dan Task Manager
        // membuka process game dengan VM_READ sehingga sebelumnya pemain sah di-kick.
        const ACCESS_MASK dangerousMasks = 
            PROCESS_VM_WRITE |          // Write memory (required for modification)
            PROCESS_VM_OPERATION;       // VirtualProtect, VirtualAlloc (required for advanced manipulation)

        // Iterate through all handles
        for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& handle = handleInfo->Handles[i];

            // Skip handles owned by game process itself or system processes
            if (handle.ProcessId == gameProcessId || 
                handle.ProcessId == 0 || 
                handle.ProcessId == 4 || 
                handle.ProcessId == selfPid) {
                continue;
            }

            // Handle harus menunjuk ke objek Process (tipe ditentukan dinamis via
            // NtQueryObject, bukan angka hardcoded) DAN memiliki hak tulis/manipulasi
            // memory. PROCESS_VM_READ saja tidak dihitung (lihat dangerousMasks).
            if ((handle.GrantedAccess & dangerousMasks) != 0 &&
                IsProcessHandleType(handle.ProcessId, (HANDLE)(ULONG_PTR)handle.Handle, handle.ObjectTypeNumber)) {
                // Get process name that owns this suspicious handle
                std::wstring processName = GetProcessName(handle.ProcessId);
                
                // Lewati pemilik handle yang memang sah membuka proses lain
                // (OBS/RTSS/capture/AV) maupun yang sudah ada di whitelist.
                //
                // KEAMANAN: nama tool sah HANYA dipercaya bila exe-nya benar-benar
                // bertanda tangan publisher tepercaya. Tanpa syarat ini, tool cheat
                // cukup mengganti namanya menjadi "obs64.exe" untuk lolos.
                bool trustedToolName = false;
                if (!processName.empty() && IsKnownLegitimateHandleOwner(processName)) {
                    trustedToolName = IsFileTrustedPublisher(GetProcessPath(handle.ProcessId));
                    if (!trustedToolName) {
                        std::wcout << L"[AdvHeuristics] WARNING: Process memakai nama tool sah TANPA signature valid: "
                                   << processName << L" (PID: " << handle.ProcessId << L") - tetap diperiksa" << std::endl;
                    }
                }

                if (!processName.empty() && !trustedToolName &&
                    !IsProcessWhitelisted(processName, handle.ProcessId)) {
                    // Verify: Try to duplicate the handle and check if it points to our game
                    HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
                    if (hOwnerProcess != NULL) {
                        HANDLE hDuplicated = NULL;
                        
                        // Try to duplicate the handle
                        if (DuplicateHandle(
                            hOwnerProcess,
                            (HANDLE)(ULONG_PTR)handle.Handle,
                            GetCurrentProcess(),
                            &hDuplicated,
                            0,
                            FALSE,
                            DUPLICATE_SAME_ACCESS)) {

                            // Check if duplicated handle points to our game process
                            DWORD targetPid = GetProcessId(hDuplicated);
                            if (targetPid == gameProcessId) {
                                // CONFIRMED: This handle points to our game with dangerous access!
                                suspiciousProcess = processName + L" (PID:" + std::to_wstring(handle.ProcessId) + 
                                                   L", Access:0x" + std::to_wstring(handle.GrantedAccess) + L")";
#ifdef _DEBUG
                                std::wstring debugMsg = L"[AdvHeuristics] DETECTED SUSPICIOUS HANDLE to game: " + suspiciousProcess + L"\n";
                                OutputDebugStringW(debugMsg.c_str());
#endif
                                CloseHandle(hDuplicated);
                                CloseHandle(hOwnerProcess);
                                return true;
                            }
                            
                            CloseHandle(hDuplicated);
                        }
                        CloseHandle(hOwnerProcess);
                    }
                }
            }
        }

        return false;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousPath(DWORD processId, std::wstring& matchedPath) const {
        // Buka handle ke process untuk query path
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return false;
        }

        const std::wstring fullPath = Oblivion::WinPath::GetProcessImagePath(hProcess);
        bool detected = false;

        // Get full executable path; do not analyze a truncated path.
        if (!fullPath.empty()) {
            std::wstring lowerPath = ToLowerCopy(fullPath);

#ifdef _DEBUG
            std::wstring debugMsg = L"[AdvHeuristics] Process path: " + fullPath + L"\n";
            OutputDebugStringW(debugMsg.c_str());
#endif

            // Suspicious path keywords (dicocokkan PER-KOMPONEN path, bukan substring).
            //
            // FALSE POSITIVE YANG DIPERBAIKI:
            //  - "hack"   menandai "C:\Program Files\HackShield\..." (anti-cheat resmi game)
            //  - "patch"  menandai folder patcher resmi game ("...\Patcher\RagPatch.exe")
            //  - "mod\"   menandai folder mods/data sah milik game
            //  - "inject" menandai komponen overlay/AV yang sah
            // Keyword tersebut kini hanya cocok bila SELURUH komponen path sama dengan
            // keyword (mis. "C:\Tools\ce\...") atau komponen diawali keyword + pemisah
            // (mis. "Cheat Engine 7.5", "cheatengine-x86_64.exe").
            const std::vector<std::wstring> suspiciousPathKeywords = {
                L"cheat",
                L"hack",
                L"ce",
                L"ce2",
                L"ce6",
                L"ce7",
                L"cheatengine",
                L"cheatprogram",
                L"newce",
                L"bossb",
                L"trainer",
                L"crack",
                L"keygen",
                L"memory scanner",
                L"memoryscanner",
                // Automation/macro & bot tool (aplikasi sah yang dipakai untuk cheat).
                // Pencocokan per-komponen tetap berlaku sehingga "autohotkey" hanya
                // cocok dengan folder/file bernama itu atau berawalan itu.
                L"autohotkey",
                L"ahk",
                L"autoit",
                L"openkore",
                L"wexdist",
                L"wpepro"
            };

            std::wstring matchedKeyword;
            if (PathContainsSuspiciousComponent(lowerPath, suspiciousPathKeywords, matchedKeyword)) {
                // Penyaring tambahan: keyword pada path saja belum cukup. Bila executable
                // ditandatangani publisher tepercaya, itu bukan tool cheat (tool cheat
                // tidak pernah ditandatangani secara resmi).
                if (!IsFileTrustedPublisher(fullPath)) {
                    matchedPath = L"SUSPICIOUS_PATH: " + fullPath + L" (keyword: " + matchedKeyword + L")";
                    detected = true;
#ifdef _DEBUG
                    std::wstring debugMsg2 = L"[AdvHeuristics] DETECTED SUSPICIOUS PATH with keyword: " + matchedKeyword + L"\n";
                    OutputDebugStringW(debugMsg2.c_str());
#endif
                } else {
#ifdef _DEBUG
                    std::wstring debugMsg3 = L"[AdvHeuristics] Path keyword ignored (trusted publisher): " + fullPath + L"\n";
                    OutputDebugStringW(debugMsg3.c_str());
#endif
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousBehavior(DWORD processId, std::wstring& behaviorType) const {
        // DISABLED: Behavioral detection terlalu prone to false positive
        // System processes seperti SearchHost.exe, Chrome.exe, dll bisa punya 500+ handles
        // dan ini normal behavior untuk software yang complex.
        // 
        // Alternative approach: Kombinasi dengan indicator lain (DLL, window class, window title)
        // sudah cukup kuat untuk mendeteksi CE tanpa perlu behavioral detection.
        //
        // Jika ingin menggunakan behavioral detection, perlu:
        // 1. Threshold yang jauh lebih tinggi (>1000 handles)
        // 2. Kombinasi dengan additional checks (ReadProcessMemory call tracking, etc)
        // 3. Machine learning untuk pattern recognition
        
        return false;
        
        /* ORIGINAL CODE - DISABLED
        // Buka handle ke process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return false;
        }

        bool detected = false;
        DWORD handleCount = 0;

        // Check 1: Handle Count - CE biasanya membuka banyak handle ke process lain
        if (GetProcessHandleCount(hProcess, &handleCount)) {
            // CE typically has 500+ handles when actively scanning/attached
            // Naikkan threshold untuk menghindari false positive
            if (handleCount > 800) {
                // Verifikasi lebih lanjut: cek apakah ada handle ke process lain
                // Ini adalah indikasi kuat bahwa process sedang mengakses memory process lain
                DWORD currentSessionId = 0;
                ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId);
                
                DWORD targetSessionId = 0;
                if (ProcessIdToSessionId(processId, &targetSessionId) && targetSessionId == currentSessionId) {
                    behaviorType = L"HIGH_HANDLE_COUNT: " + std::to_wstring(handleCount);
                    detected = true;
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
        */
    }

    bool AdvancedProcessHeuristics::HasSuspiciousMemorySignature(DWORD processId, std::wstring& matchedPattern) const {
        // Buka handle ke process target dengan akses PROCESS_VM_READ dan PROCESS_QUERY_INFORMATION
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            // Tidak bisa buka process - mungkin system process atau access denied
            return false;
        }

        bool detected = false;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        BYTE* address = nullptr;
        const size_t maxScanSize = 10 * 1024 * 1024; // Limit 10 MB per region untuk performa
        size_t totalScanned = 0;
        const size_t maxTotalScan = 100 * 1024 * 1024; // Max total 100 MB scan per process

        // Enumerate memory regions
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // Hanya scan region yang committed, readable, dan bukan guard page
            bool isExecutable = (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE);
            bool isReadable = (mbi.Protect == PAGE_READWRITE ||
                              mbi.Protect == PAGE_READONLY ||
                              isExecutable);
            
            if (mbi.State == MEM_COMMIT &&
                isReadable &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS)) {

                // Limit ukuran region yang di-scan
                size_t regionSize = mbi.RegionSize;
                if (regionSize > maxScanSize) {
                    regionSize = maxScanSize;
                }

                // Check total scan limit
                if (totalScanned + regionSize > maxTotalScan) {
                    break; // Stop scanning jika sudah terlalu banyak
                }

                // Allocate buffer untuk membaca memory
                std::vector<BYTE> buffer(regionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionSize, &bytesRead) && bytesRead > 0) {
                    // Scan buffer untuk setiap signature
                    for (const auto& sig : kMemorySignatures) {
                        // Skip signature jika requires executable memory tapi region ini bukan executable
                        if (sig.requiresExecutableMemory && !isExecutable) {
                            continue;
                        }
                        
                        if (bytesRead < sig.patternSize) {
                            continue;
                        }

                        // Pattern matching dengan mask
                        for (size_t i = 0; i <= bytesRead - sig.patternSize; ++i) {
                            bool match = true;
                            for (size_t j = 0; j < sig.patternSize; ++j) {
                                if ((buffer[i + j] & sig.mask[j]) != (sig.pattern[j] & sig.mask[j])) {
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                matchedPattern = sig.name;
                                detected = true;
                                break;
                            }
                        }

                        if (detected) {
                            break;
                        }
                    }

                    totalScanned += bytesRead;
                }

                if (detected) {
                    break;
                }
            }

            // Move ke region berikutnya
            address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        CloseHandle(hProcess);
        return detected;
    }

    std::string AdvancedProcessHeuristics::BuildHeuristicDetails(const std::wstring& processName,
        DWORD processId,
        const std::wstring& detectionType,
        const std::wstring& indicator) const {
        std::wstringstream wss;
        wss << L"[" << detectionType << L"] " << processName << L" (PID:" << processId << L") => " << indicator;
        return ConvertWideToUtf8(wss.str());
    }

    std::string AdvancedProcessHeuristics::ConvertWideToUtf8(const std::wstring& input) const {
        if (input.empty()) {
            return std::string();
        }

        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) {
            return std::string();
        }

        std::string result(static_cast<size_t>(sizeNeeded) - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &result[0], sizeNeeded, nullptr, nullptr);
        return result;
    }
}

