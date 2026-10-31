#include "pch.h"
#include "hwid_generator.h"
#include "hwid_identifier_validation.h"
#include <intrin.h> // Untuk __cpuid
#include <vector>
#include <sstream>
#include <iomanip>
#include <bcrypt.h> // Untuk hashing
#include <comdef.h> // Untuk _bstr_t
#include <Wbemidl.h>
#include <algorithm>
#include <cctype>

// Definisi NTSTATUS jika ntstatus.h tidak tersedia
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wbemuuid.lib") // Untuk WMI
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace Oblivion {
    std::string HWIDGenerator::Generate() {
        const std::string cpuBrand = GetCpuBrand();
        const std::string motherboardUuid = GetWmiProperty("Win32_BaseBoard", "UUID");
        std::string hddSerial = GetWmiProperty("Win32_DiskDrive", "SerialNumber");

        // WMI may return OEM placeholders (or "UNKNOWN" after an error). Hashing
        // only those values together with a non-unique CPU model creates the same
        // HWID on many unrelated PCs, causing cross-player ban collisions.
        // Require at least one usable per-device identifier before generating HWID.
        if (hddSerial.find(",") != std::string::npos) {
            hddSerial = hddSerial.substr(0, hddSerial.find(","));
        }

        if (!HWIDIdentity::IsUsableHardwareIdentifier(motherboardUuid) &&
            !HWIDIdentity::IsUsableHardwareIdentifier(hddSerial)) {
            return "";
        }

        // Keep the existing hash input format for devices with usable identifiers
        // so their existing bans remain compatible across this bug fix.
        const std::string combined = cpuBrand + motherboardUuid + hddSerial;
        return HashString(combined);
    }

    std::string HWIDGenerator::GetCpuBrand() {
        int cpuInfo[4] = { -1 };
        char cpuBrandString[0x40] = { 0 };

        // CPUID extended brand leaves are 0x80000002..0x80000004. Do not loop
        // over every value reported by a potentially virtualized CPU; only query
        // the three leaves required for the brand string.
        __cpuid(cpuInfo, 0x80000000);
        const unsigned int maxExtendedLeaf = static_cast<unsigned int>(cpuInfo[0]);
        if (maxExtendedLeaf < 0x80000004U) {
            return "";
        }

        __cpuid(cpuInfo, 0x80000002);
        memcpy(cpuBrandString, cpuInfo, sizeof(cpuInfo));
        __cpuid(cpuInfo, 0x80000003);
        memcpy(cpuBrandString + 16, cpuInfo, sizeof(cpuInfo));
        __cpuid(cpuInfo, 0x80000004);
        memcpy(cpuBrandString + 32, cpuInfo, sizeof(cpuInfo));

        return std::string(cpuBrandString);
    }

    std::string HWIDGenerator::GetWmiProperty(const std::string& wmiClass, const std::string& wmiProperty) {
        HRESULT hres;
        std::string result = "UNKNOWN";

        // 1. Inisialisasi COM
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return result;

        // 2. Set security levels COM
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres) && hres != RPC_E_TOO_LATE) { CoUninitialize(); return result; }

        // 3. Dapatkan pointer ke WbemLocator
        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) { CoUninitialize(); return result; }

        // 4. Hubungkan ke WMI
        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return result; }

        // 5. Set security levels untuk WMI connection
        hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        if (FAILED(hres)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return result; }

        // 6. Gunakan WMI query
        IEnumWbemClassObject* pEnumerator = NULL;
        std::wstring query = L"SELECT " + std::wstring(wmiProperty.begin(), wmiProperty.end()) + L" FROM " + std::wstring(wmiClass.begin(), wmiClass.end());
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (FAILED(hres) || pEnumerator == NULL) {
            if (pEnumerator) pEnumerator->Release();
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return result;
        }

        // 7. Ambil data dari query
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        while (true) {
            const HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (FAILED(hr) || uReturn == 0 || pclsObj == NULL) {
                if (pclsObj) {
                    pclsObj->Release();
                    pclsObj = NULL;
                }
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);
            const HRESULT propertyResult = pclsObj->Get(
                _bstr_t(wmiProperty.c_str()), 0, &vtProp, 0, 0);
            if (SUCCEEDED(propertyResult) && vtProp.vt == VT_BSTR &&
                vtProp.bstrVal != NULL) {
                result = static_cast<const char*>(_bstr_t(vtProp.bstrVal));
            }
            VariantClear(&vtProp);
            pclsObj->Release();
            pclsObj = NULL;
            break; // Hanya ambil yang pertama
        }

        // 8. Cleanup
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        return result;
    }

    std::string HWIDGenerator::HashString(const std::string& input) {
        // Kode hashing sama seperti di FileIntegrityChecker
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) { return ""; }
        DWORD cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHashObject || !pbHash) { HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) { HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
        status = BCryptHashData(hHash, (PBYTE)input.c_str(), (ULONG)input.length(), 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) { ss << std::setw(2) << static_cast<unsigned int>(pbHash[i]); }

        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ss.str();
    }
}