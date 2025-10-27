#include "../pch.h"
#include "DigitalSignatureValidator.h"
#include <Softpub.h>
#include <wincrypt.h>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

static std::wstring tolower_ws3(const std::wstring& s) { std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

bool DigitalSignatureValidator::RunOnceScan(SignatureFinding& out)
{
    out = SignatureFinding{};

    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) { CloseHandle(snap); return false; }

    do {
        std::wstring path = me.szExePath;
        std::wstring name = me.szModule;
        if (IsSkippedName(name)) continue; // skip configured names like rro.exe
        int score = 0;

        const bool whitelisted = IsWhitelisted(path);
        const bool suspPath = IsSuspiciousPath(path);
        const bool suspName = IsSuspiciousName(name);
        const bool trusted = IsSignedTrusted(path);

        // Only consider path if not whitelisted and looks suspicious
        if (!whitelisted && suspPath) score += 1;
        if (suspName) score += 1;

        // Unsigned/untrusted is a medium-strength indicator; combine with context to reach threshold
        if (!trusted) score += 1;

        if (score >= m_threshold) {
            out.modulePath = path;
            out.moduleName = name;
            out.indicators = score;
            CloseHandle(snap);
            return true;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return false;
}

bool DigitalSignatureValidator::IsWhitelisted(const std::wstring& path) const
{
    if (m_whitelist.empty()) return false;
    auto p = tolower_ws3(path);
    for (const auto& w : m_whitelist) {
        auto wl = tolower_ws3(w);
        if (!wl.empty() && p.rfind(wl, 0) == 0) return true;
    }
    return false;
}

bool DigitalSignatureValidator::IsSuspiciousName(const std::wstring& name) const
{
    auto n = tolower_ws3(name);
    static const wchar_t* terms[] = { L"inject", L"hook", L"cheat", L"proxy", L"debug" };
    for (auto t : terms) {
        if (n.find(t) != std::wstring::npos) return true;
    }
    return false;
}

bool DigitalSignatureValidator::IsSuspiciousPath(const std::wstring& path) const
{
    auto p = tolower_ws3(path);
    return p.find(L"\\temp\\") != std::wstring::npos ||
           p.find(L"\\appdata\\local\\") != std::wstring::npos ||
           p.find(L"\\users\\") != std::wstring::npos;
}

// Minimal WinVerifyTrust wrapper using static link (as project may already link WinTrust); if not, this still compiles due to pragmas above.
bool DigitalSignatureValidator::IsSignedTrusted(const std::wstring& path) const
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; // offline check

    LONG status = WinVerifyTrust(nullptr, &action, &data);
    return status == ERROR_SUCCESS;
}

bool DigitalSignatureValidator::IsSkippedName(const std::wstring& name) const
{
    if (m_skipNames.empty()) return false;
    auto n = tolower_ws3(name);
    for (const auto& s : m_skipNames) {
        if (tolower_ws3(s) == n) return true;
    }
    return false;
}
