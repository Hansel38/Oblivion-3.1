#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>

struct SignatureFinding {
    std::wstring modulePath;
    std::wstring moduleName;
    int indicators = 0;
};

// Validates code signatures of loaded modules in current process using WinVerifyTrust via dynamic load (no extra link libs).
class DigitalSignatureValidator {
public:
    void SetThreshold(int t) { m_threshold = t; }
    void SetWhitelistPrefixes(const std::vector<std::wstring>& prefixes) { m_whitelist = prefixes; }
    void SetSkipModuleNames(const std::vector<std::wstring>& names) { m_skipNames = names; }

    bool RunOnceScan(SignatureFinding& out);

private:
    int m_threshold = 2;
    std::vector<std::wstring> m_whitelist;
    std::vector<std::wstring> m_skipNames; // exact file names (e.g., rro.exe), case-insensitive

    bool IsWhitelisted(const std::wstring& path) const;
    bool IsSuspiciousName(const std::wstring& name) const;
    bool IsSuspiciousPath(const std::wstring& path) const;
    bool IsSignedTrusted(const std::wstring& path) const; // returns true if WinVerifyTrust says OK
    bool IsSkippedName(const std::wstring& name) const;
};
