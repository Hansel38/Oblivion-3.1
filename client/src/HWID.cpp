#include "../pch.h"
#include "HWID.h"
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

static bool ReadRegStr(HKEY root, const wchar_t* subkey, const wchar_t* name, std::wstring& out)
{
    HKEY hKey{};
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return false;
    DWORD type=0; DWORD size=0;
    if (RegQueryValueExW(hKey, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_SZ) { RegCloseKey(hKey); return false; }
    std::wstring buf(size/sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(hKey, name, nullptr, &type, (LPBYTE)buf.data(), &size) == ERROR_SUCCESS) {
        buf.resize(wcslen(buf.c_str())); out = buf; RegCloseKey(hKey); return true;
    }
    RegCloseKey(hKey); return false;
}

static void AppendBytes(std::vector<BYTE>& v, const void* data, size_t sz)
{
    const BYTE* b = reinterpret_cast<const BYTE*>(data);
    v.insert(v.end(), b, b + sz);
}

static std::string ToHex(const BYTE* data, size_t len)
{
    static const char* hex = "0123456789abcdef";
    std::string s; s.resize(len*2);
    for (size_t i=0;i<len;++i) { s[2*i] = hex[(data[i]>>4)&0xF]; s[2*i+1] = hex[data[i]&0xF]; }
    return s;
}

std::string GetHWID()
{
    std::vector<BYTE> material;

    // MachineGuid
    std::wstring machineGuid;
    if (ReadRegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", machineGuid)) {
        AppendBytes(material, machineGuid.data(), (machineGuid.size()+1)*sizeof(wchar_t));
    }

    // Processor info
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    AppendBytes(material, &si.dwNumberOfProcessors, sizeof(si.dwNumberOfProcessors));
    AppendBytes(material, &si.dwProcessorType, sizeof(si.dwProcessorType));

    // Volume serial number of system drive
    wchar_t sysDir[MAX_PATH]{}; GetWindowsDirectoryW(sysDir, MAX_PATH);
    wchar_t root[] = L"C:\\";
    if (wcslen(sysDir) >= 2 && sysDir[1] == L':') { root[0] = sysDir[0]; }
    DWORD volSerial=0; GetVolumeInformationW(root, nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    AppendBytes(material, &volSerial, sizeof(volSerial));

    // Hash (SHA-256)
    HCRYPTPROV hProv{}; HCRYPTHASH hHash{};
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return {}; }
    if (!CryptHashData(hHash, material.data(), (DWORD)material.size(), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return {}; }
    BYTE digest[32]{}; DWORD dlen = sizeof(digest);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return {}; }
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);

    return ToHex(digest, dlen);
}
