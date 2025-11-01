#include "../pch.h"
#include "CERegistryScanner.h"
#include <vector>

static std::wstring ToLower(const std::wstring& s){ std::wstring t=s; for(auto& c:t) c=(wchar_t)towlower(c); return t; }

bool CERegistryScanner::KeyExists(HKEY root, const wchar_t* subkey)
{
    HKEY h; LONG r = RegOpenKeyExW(root, subkey, 0, KEY_READ, &h);
    if (r == ERROR_SUCCESS) { RegCloseKey(h); return true; }
    return false;
}

void CERegistryScanner::EnumerateValues(HKEY hKey, int& indicators, std::wstring& reason)
{
    DWORD idx = 0;
    wchar_t name[256]; DWORD nameLen;
    DWORD type; BYTE dataBuf[2048]; DWORD dataSize;
    while (true) {
        nameLen = (DWORD)(sizeof(name)/sizeof(name[0]));
        dataSize = sizeof(dataBuf);
        LONG r = RegEnumValueW(hKey, idx++, name, &nameLen, nullptr, &type, dataBuf, &dataSize);
        if (r != ERROR_SUCCESS) break;
        std::wstring n(name);
        std::wstring nl = ToLower(n);
        if (nl.find(L"mru") != std::wstring::npos || nl.find(L"recent") != std::wstring::npos) {
            indicators += 2;
            reason += L"MRU entry: '" + n + L"'; ";
        }
        if (nl.find(L"scan") != std::wstring::npos || nl.find(L"address") != std::wstring::npos) {
            indicators += 1;
            reason += L"Scan-related setting: '" + n + L"'; ";
        }
        if (type == REG_SZ && dataSize >= sizeof(wchar_t)) {
            std::wstring val((wchar_t*)dataBuf, dataSize/sizeof(wchar_t) - 1);
            std::wstring vl = ToLower(val);
            if (vl.find(L".ct") != std::wstring::npos || vl.find(L"cheat") != std::wstring::npos) {
                indicators += 2;
                reason += L"Recent file: '" + val + L"'; ";
            }
        }
    }
}

void CERegistryScanner::EnumerateSubkeys(HKEY hKey, int& indicators, std::wstring& reason)
{
    DWORD idx = 0; wchar_t name[256]; DWORD nameLen = 0;
    while (true) {
        nameLen = (DWORD)(sizeof(name)/sizeof(name[0]));
        FILETIME ft{};
        LONG r = RegEnumKeyExW(hKey, idx++, name, &nameLen, nullptr, nullptr, nullptr, &ft);
        if (r != ERROR_SUCCESS) break;
        std::wstring sub = name; std::wstring sl = ToLower(sub);
        if (sl.find(L"settings") != std::wstring::npos || sl.find(L"scan") != std::wstring::npos) {
            // Open and enumerate values for this subkey
            HKEY hSub{};
            if (RegOpenKeyExW(hKey, sub.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                EnumerateValues(hSub, indicators, reason);
                RegCloseKey(hSub);
            }
        }
    }
}

bool CERegistryScanner::RunOnceScan(RegistryFinding& out)
{
    out = {};
    // 1) Check for CE key presence
    const wchar_t* CEKEY = L"Software\\Cheat Engine";
    HKEY h{};
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, CEKEY, 0, KEY_READ, &h);
    if (r != ERROR_SUCCESS) {
        return false; // no CE key found
    }

    out.detected = true;
    out.indicators += 2; // base indicator for key presence
    out.reason += L"Key exists: HKCU\\"; out.reason += CEKEY; out.reason += L"; ";

    // 2) Enumerate values and subkeys
    EnumerateValues(h, out.indicators, out.reason);
    EnumerateSubkeys(h, out.indicators, out.reason);
    RegCloseKey(h);

    // 3) Additional heuristics: look for portable CE traces under HKCU\Software\Classes
    if (KeyExists(HKEY_CURRENT_USER, L"Software\\Classes\\.ct")) {
        out.indicators += 1; out.reason += L"File association for .ct present; ";
    }

    return out.indicators > 0;
}
