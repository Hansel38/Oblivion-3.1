#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>

struct InjectionFinding {
    std::wstring modulePath;
    std::wstring moduleName;
    int indicators = 0;
};

class InjectionScanner {
public:
    void SetThreshold(int t) { m_threshold = t; }
    void SetWhitelistPrefixes(const std::vector<std::wstring>& prefixes) { m_whitelist = prefixes; }

    // Scan current process modules for suspicious injections
    bool RunOnceScan(InjectionFinding& out);

private:
    int m_threshold = 2;
    std::vector<std::wstring> m_whitelist;

    bool IsSuspiciousPath(const std::wstring& path);
    bool NameHasSuspiciousTerms(const std::wstring& name);
    bool IsWhitelisted(const std::wstring& path);
};
