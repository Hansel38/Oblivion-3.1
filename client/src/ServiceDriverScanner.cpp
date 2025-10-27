#include "../pch.h"
#include <windows.h>
#include <winsvc.h>
#include <string>
#include <vector>
#include <algorithm>

// Returns true if any kernel driver service name/path suggests Cheat Engine (dbk/cedriver)
static bool EnumCeDriverServices(std::wstring& outService, std::wstring& outPath)
{
 SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, GENERIC_READ);
 if (!scm) return false;

 DWORD bytesNeeded =0, servicesReturned =0, resume =0;
 bool found = false;
 do {
 EnumServicesStatusExW(
 scm,
 SC_ENUM_PROCESS_INFO,
 SERVICE_DRIVER,
 SERVICE_STATE_ALL,
 nullptr,
0,
 &bytesNeeded,
 &servicesReturned,
 &resume,
 nullptr);
 DWORD err = GetLastError();
 if (err != ERROR_MORE_DATA) break;
 std::vector<BYTE> buf(bytesNeeded);
 if (!EnumServicesStatusExW(
 scm,
 SC_ENUM_PROCESS_INFO,
 SERVICE_DRIVER,
 SERVICE_STATE_ALL,
 buf.data(),
 (DWORD)buf.size(),
 &bytesNeeded,
 &servicesReturned,
 &resume,
 nullptr)) {
 break;
 }
 auto entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
 for (DWORD i =0; i < servicesReturned; ++i) {
 std::wstring name = entries[i].lpServiceName ? entries[i].lpServiceName : L"";
 std::wstring disp = entries[i].lpDisplayName ? entries[i].lpDisplayName : L"";
 auto low = [](std::wstring s){ std::transform(s.begin(), s.end(), s.begin(), ::towlower); return s; };
 std::wstring nlow = low(name), dlow = low(disp);
 if (nlow.find(L"dbk") != std::wstring::npos || nlow.find(L"cedriver") != std::wstring::npos ||
 dlow.find(L"dbk") != std::wstring::npos || dlow.find(L"cedriver") != std::wstring::npos) {
 // query config for path
 SC_HANDLE svc = OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
 if (svc) {
 DWORD need =0;
 QueryServiceConfigW(svc, nullptr,0, &need);
 std::vector<BYTE> cfgBuf(need);
 QUERY_SERVICE_CONFIGW* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
 if (QueryServiceConfigW(svc, cfg, need, &need) && cfg && cfg->lpBinaryPathName) {
 outService = entries[i].lpServiceName;
 outPath = cfg->lpBinaryPathName;
 found = true;
 }
 CloseServiceHandle(svc);
 } else {
 outService = entries[i].lpServiceName;
 outPath = L"";
 found = true;
 }
 break;
 }
 }
 } while (!found && servicesReturned >0);

 CloseServiceHandle(scm);
 return found;
}

extern "C" bool CE_ScanDriverService(std::wstring& outService, std::wstring& outPath)
{
 return EnumCeDriverServices(outService, outPath);
}
