#pragma once
#include <windows.h>
#include <string>

class CERegistryScanner {
public:
    struct RegistryFinding {
        bool detected = false;
        int indicators = 0; // sum of heuristics
        std::wstring reason; // aggregated details
    };

    CERegistryScanner() = default;
    ~CERegistryScanner() = default;

    // Scan HKCU\\Software\\Cheat Engine for presence, MRU files, and custom scan settings
    bool RunOnceScan(RegistryFinding& out);

private:
    bool KeyExists(HKEY root, const wchar_t* subkey);
    void EnumerateValues(HKEY hKey, int& indicators, std::wstring& reason);
    void EnumerateSubkeys(HKEY hKey, int& indicators, std::wstring& reason);
};
