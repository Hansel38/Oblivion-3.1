#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>

struct HijackedThreadFinding {
    DWORD tid = 0;
    PVOID startAddress = nullptr;
    std::wstring moduleName;
    int indicators = 0;
};

class HijackedThreadScanner {
public:
    void SetThreshold(int t) { m_threshold = t; }
    void SetWhitelistPrefixes(const std::vector<std::wstring>& prefixes) { m_whitelist = prefixes; }

    bool RunOnceScan(HijackedThreadFinding& out);

private:
    int m_threshold = 2;
    std::vector<std::wstring> m_whitelist;

    typedef LONG (NTAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PFN_NtQueryInformationThread ResolveNtQueryInformationThread();

    std::wstring ModuleFromAddress(PVOID addr);
    bool IsWhitelistedModule(const std::wstring& modulePathLower);
};
