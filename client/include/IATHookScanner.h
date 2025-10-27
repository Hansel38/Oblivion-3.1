#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct IATHookFinding {
    std::wstring moduleName;   // module whose IAT is hooked
    std::string importName;    // function name
    PVOID iatAddress = nullptr;   // address of IAT slot
    PVOID targetAddress = nullptr; // resolved target address in IAT
    std::wstring targetModule;  // module where targetAddress resides
    int indicators = 0;
};

class IATHookScanner {
public:
    void SetThreshold(int t) { m_threshold = t; }
    void SetWhitelistModules(const std::vector<std::wstring>& wl) { m_modWhitelist = wl; }

    // Scan IAT of the main module for suspicious entries
    bool RunOnceScan(IATHookFinding& out);

private:
    int m_threshold = 2;
    std::vector<std::wstring> m_modWhitelist; // lower-case full path prefixes or names

    bool IsWhitelistedModule(const std::wstring& moduleLower);
};
