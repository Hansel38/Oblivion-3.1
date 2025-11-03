#include "../pch.h"
#include "ProcessThreadWatcher.h"
#include "blacklist_process.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>
#include <string>
#include <winver.h>
#include <map>
#include <mutex>
#include "AntiTampering.h"

#pragma comment(lib, "version.lib")

namespace { // internal helpers

static std::wstring ToLowerW(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::wstring GetProcessImagePathW(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";

    wchar_t buf[MAX_PATH]; DWORD sz = MAX_PATH;
    std::wstring out;
    if (QueryFullProcessImageNameW(h,0, buf, &sz)) out.assign(buf);
    CloseHandle(h);
    return out;
}

// Enumerate modules in a process safely with Toolhelp; x86 target so SNAPMODULE32 applies
static bool AnyModuleNameContains(DWORD pid, const std::vector<std::wstring>& tokens, std::wstring& hitModule, std::wstring& hitPath)
{
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hs == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(hs, &me)) {
        do {
            std::wstring base = ToLowerW(me.szModule);
            std::wstring path = ToLowerW(me.szExePath);
            for (const auto& t : tokens) {
                if (t.empty()) continue;
                if (base.find(t) != std::wstring::npos || path.find(t) != std::wstring::npos) { hitModule = me.szModule; hitPath = me.szExePath; found = true; break; }
            }
            if (found) break;
        } while (Module32NextW(hs, &me));
    }
    CloseHandle(hs);
    return found;
}

// Version info extractor: search common string fields for tokens
static bool VersionInfoContainsTokens(const std::wstring& path, const std::vector<std::wstring>& tokens, std::wstring& fieldHit, std::wstring& valueHit)
{
    if (path.empty()) return false;
    DWORD handle =0; DWORD sz = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!sz) return false;
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(path.c_str(),0, sz, buf.data())) return false;
    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* lpTranslate = nullptr; UINT cbTranslate =0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) || !lpTranslate || !cbTranslate) return false;
    auto queryField = [&](WORD lang, WORD cp, const wchar_t* name, std::wstring& out)->bool {
        wchar_t subBlock[64]; swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s", lang, cp, name);
        LPWSTR val = nullptr; UINT len =0; if (VerQueryValueW(buf.data(), subBlock, (LPVOID*)&val, &len) && val && len) { out.assign(val); return true; } return false;
    };
    const wchar_t* fields[] = { L"OriginalFilename", L"FileDescription", L"ProductName", L"CompanyName" };
    for (UINT i =0; i < cbTranslate / sizeof(LANGANDCODEPAGE); ++i) {
        for (auto* f : fields) {
            std::wstring v; if (queryField(lpTranslate[i].wLanguage, lpTranslate[i].wCodePage, f, v)) {
                std::wstring lv = ToLowerW(v);
                for (const auto& t : tokens) {
                    if (!t.empty() && lv.find(t) != std::wstring::npos) { fieldHit = f; valueHit = v; return true; }
                }
            }
        }
    }
    return false;
}

// Enumerate visible top-level windows owned by pid and test tokens against title/class
static bool AnyWindowTextContains(DWORD pid, const std::vector<std::wstring>& tokens, std::wstring& winTitle, std::wstring& winClass)
{
    struct Local { static BOOL CALLBACK EnumProc(HWND h, LPARAM p){
        auto* data = reinterpret_cast<std::pair<DWORD, std::pair<std::vector<std::wstring>*, std::pair<std::wstring*, std::wstring*>>>*>(p);
        DWORD wndPid =0; GetWindowThreadProcessId(h, &wndPid);
        if (wndPid != data->first) return TRUE;
        if (!IsWindowVisible(h)) return TRUE;
        wchar_t title[256]; title[0]=0; GetWindowTextW(h, title,255);
        wchar_t cls[128]; cls[0]=0; GetClassNameW(h, cls,127);
        std::wstring ltitle = ToLowerW(title);
        std::wstring lcls = ToLowerW(cls);
        for (const auto& t : *data->second.first) {
            if (t.empty()) continue;
            if (ltitle.find(t) != std::wstring::npos || lcls.find(t) != std::wstring::npos) {
                *data->second.second.first = title; *data->second.second.second = cls; return FALSE; // stop
            }
        }
        return TRUE; } };
    std::pair<std::wstring*, std::wstring*> outs{ &winTitle, &winClass };
    std::pair<std::vector<std::wstring>*, std::pair<std::wstring*, std::wstring*>> inner{ const_cast<std::vector<std::wstring>*>(&tokens), outs };
    std::pair<DWORD, decltype(inner)> pack{ pid, inner };
    if (!ObfuscatedAPI::ObfEnumWindows(Local::EnumProc, reinterpret_cast<LPARAM>(&pack))) return true; // found and stopped
    return false;
}

} // namespace

ProcessThreadWatcher::ProcessThreadWatcher()
    : m_watcherThread(nullptr), m_stopWatcher(false), m_pollingIntervalMs(2000), m_closeThreshold(2)
{
}

ProcessThreadWatcher::~ProcessThreadWatcher()
{
    StopBackgroundWatcher();
}

bool ProcessThreadWatcher::Initialize()
{
    // Load blacklist
    m_processBlacklist = GetDefaultProcessBlacklist();

    // Initial snapshot
    m_previousProcessList = GetCurrentProcessList();

    return true;
}

DetectionResult ProcessThreadWatcher::RunOnceScan()
{
    DetectionResult result{};

    HANDLE hSnapshot = CreateToolhelp32Snapshot((TH32CS_SNAPPROCESS),0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return result;
    }
    PROCESSENTRY32W pe32{}; pe32.dwSize = sizeof(pe32);
    if (!Process32FirstW(hSnapshot, &pe32)) { CloseHandle(hSnapshot); return result; }

    const auto& ceTokens = GetDefaultCeArtifactTokens();

    // Track best candidate without aggregating across unrelated processes
    DetectionResult best{};

    do {
        std::wstring processName = pe32.szExeFile; DWORD pid = pe32.th32ProcessID;

        //1) Blacklist name is strong indicator
        if (IsBlacklisted(processName)) {
            DetectionResult strong{}; strong.detected = true; strong.pid = pid; strong.processName = processName; strong.reason = L"Blacklisted process detected: " + processName; strong.indicatorCount =2;
            CloseHandle(hSnapshot);
            return strong;
        }

        int localIndicators =0; std::wstringstream localReason;

        //2) Module artifacts (vehdebug/speedhack/dbk/etc.)
        std::wstring hitMod, hitPath;
        if (AnyModuleNameContains(pid, ceTokens, hitMod, hitPath)) { ++localIndicators; localReason << L"CE artifact module: '" << hitMod << L"' in '" << hitPath << L"'. "; }

        //3) Version info strings (OriginalFilename/FileDescription/ProductName/CompanyName)
        std::wstring path = GetProcessImagePathW(pid);
        std::wstring fieldHit, valueHit;
        if (!path.empty() && VersionInfoContainsTokens(path, ceTokens, fieldHit, valueHit)) { ++localIndicators; localReason << L"VersionInfo(" << fieldHit << L"): '" << valueHit << L"'. "; }

        //4) Window title/class tokens
        std::wstring winTitle, winClass;
        if (AnyWindowTextContains(pid, ceTokens, winTitle, winClass)) { ++localIndicators; localReason << L"Window hit: title='" << winTitle << L"' class='" << winClass << L"'. "; }

        //5) Suspicious install path
        if (IsSuspiciousPath(path)) { ++localIndicators; localReason << L"Suspicious path: '" << path << L"'. "; }

        if (localIndicators >0) {
            if (localIndicators >= m_closeThreshold) {
                DetectionResult hit{}; hit.detected = true; hit.pid = pid; hit.processName = processName; hit.reason = localReason.str(); hit.indicatorCount = localIndicators;
                CloseHandle(hSnapshot);
                return hit;
            }
            // Keep the strongest sub-threshold candidate for diagnostics (but don't trigger)
            if (localIndicators > best.indicatorCount) {
                best.detected = true;
                best.pid = pid;
                best.processName = processName;
                best.reason = localReason.str();
                best.indicatorCount = localIndicators;
            }
        }

    } while (Process32NextW(hSnapshot, &pe32));
    CloseHandle(hSnapshot);

    // Additional: detect attach/debug/injection against current process (RRO.exe host)
    {
        int localIndicators =0; std::wstringstream localReason;
        BOOL dbg = FALSE; if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg) { localIndicators +=2; localReason << L"Debugger attached to current process. "; }
        if (IsDebuggerPresent()) { localIndicators +=1; localReason << L"IsDebuggerPresent signaled. "; }
        std::wstring hitMod, hitPath;
        if (AnyModuleNameContains(GetCurrentProcessId(), ceTokens, hitMod, hitPath)) { localIndicators +=2; localReason << L"Injected CE artifact in current process: '" << hitMod << L"' ('" << hitPath << L"'). "; }
        if (localIndicators >= m_closeThreshold) {
            DetectionResult cur{}; cur.detected = true; cur.pid = GetCurrentProcessId(); cur.processName = L"<current>"; cur.reason = localReason.str(); cur.indicatorCount = localIndicators; return cur;
        }
        if (localIndicators > best.indicatorCount) {
            best.detected = true; best.pid = GetCurrentProcessId(); best.processName = L"<current>"; best.reason = localReason.str(); best.indicatorCount = localIndicators;
        }
    }

    // Thread-level deep check (kept conservative; not to trigger FP)
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32{}; te32.dwSize = sizeof(te32);
        if (Thread32First(hThreadSnapshot, &te32)) {
            do {
                std::wstring threadReason; if (IsThreadStartAddressSuspicious(te32.th32ThreadID, te32.th32OwnerProcessID, threadReason)) {
                    // Require per-thread threshold; currently IsThreadStartAddressSuspicious returns false (disabled)
                    DetectionResult td{}; td.detected = true; td.pid = te32.th32OwnerProcessID; td.processName = L"<thread>"; td.reason = threadReason; td.indicatorCount =1;
                    if (td.indicatorCount >= m_closeThreshold) { CloseHandle(hThreadSnapshot); return td; }
                    if (td.indicatorCount > best.indicatorCount) best = td;
                }
            } while (Thread32Next(hThreadSnapshot, &te32));
        }
        CloseHandle(hThreadSnapshot);
    }

    // Only report if a single subject meets the threshold. Otherwise, no detection.
    if (best.detected && best.indicatorCount >= m_closeThreshold) return best;

    // below threshold -> no detection
    return result;
}

void ProcessThreadWatcher::StartBackgroundWatcher()
{
    if (m_watcherThread != nullptr) return;
    m_stopWatcher = false;
    m_watcherThread = CreateThread(nullptr,0, WatcherThreadProc, this,0, nullptr);
}

void ProcessThreadWatcher::StopBackgroundWatcher()
{
    if (m_watcherThread != nullptr) {
        m_stopWatcher = true;
        WaitForSingleObject(m_watcherThread,5000);
        CloseHandle(m_watcherThread); m_watcherThread = nullptr;
    }
}

bool ProcessThreadWatcher::IsSuspiciousProcess(DWORD pid, std::wstring& reason)
{
    // legacy: keep simple heuristics; richer ones are in RunOnceScan aggregation
    std::wstring path = GetProcessPath(pid);
    if (!path.empty() && IsSuspiciousPath(path)) { reason = L"Process running from suspicious location: " + path; return true; }

    DWORD parentPid = GetParentProcessId(pid);
    if (parentPid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32{}; pe32.dwSize = sizeof(pe32);
            if (Process32FirstW(hSnapshot, &pe32)) {
                do { if (pe32.th32ProcessID == parentPid) { if (IsBlacklisted(pe32.szExeFile)) { reason = L"Child of blacklisted process: "; reason += pe32.szExeFile; CloseHandle(hSnapshot); return true; } break; } } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    return false;
}

bool ProcessThreadWatcher::IsSuspiciousThread(DWORD tid, std::wstring& reason)
{
    return IsThreadStartAddressSuspicious(tid,0, reason);
}

std::wstring ProcessThreadWatcher::ToLower(const std::wstring& str)
{
    std::wstring result = str; std::transform(result.begin(), result.end(), result.begin(), ::towlower); return result;
}

bool ProcessThreadWatcher::IsBlacklisted(const std::wstring& processName)
{
    std::wstring lowerName = ToLower(processName);
    for (const auto& blacklisted : m_processBlacklist) { if (ToLower(blacklisted) == lowerName) return true; }
    return false;
}

std::wstring ProcessThreadWatcher::GetProcessPath(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"";

    wchar_t path[MAX_PATH] = {0 }; DWORD size = MAX_PATH;
    std::wstring out;
    if (QueryFullProcessImageNameW(hProcess,0, path, &size)) out = path;
    CloseHandle(hProcess);
    return out;
}

bool ProcessThreadWatcher::IsSuspiciousPath(const std::wstring& path)
{
    std::wstring lowerPath = ToLower(path);
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
        lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
        return true;
    }
    return false;
}

DWORD ProcessThreadWatcher::GetParentProcessId(DWORD pid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe32{}; pe32.dwSize = sizeof(pe32);
    DWORD parentPid =0;
    if (Process32FirstW(hSnapshot, &pe32)) { do { if (pe32.th32ProcessID == pid) { parentPid = pe32.th32ParentProcessID; break; } } while (Process32NextW(hSnapshot, &pe32)); }
    CloseHandle(hSnapshot);
    return parentPid;
}

bool ProcessThreadWatcher::IsThreadStartAddressSuspicious(DWORD /*tid*/, DWORD /*ownerPid*/, std::wstring& /*reason*/)
{
    // Conservative: disabled in this module to prevent FPs; other specialized scanners handle this.
    return false;
}

DWORD WINAPI ProcessThreadWatcher::WatcherThreadProc(LPVOID lpParam)
{
    ProcessThreadWatcher* pThis = static_cast<ProcessThreadWatcher*>(lpParam);
    while (!pThis->m_stopWatcher) {
        std::vector<DWORD> currentList = pThis->GetCurrentProcessList();
        for (DWORD pid : currentList) {
            if (std::find(pThis->m_previousProcessList.begin(), pThis->m_previousProcessList.end(), pid) == pThis->m_previousProcessList.end()) {
                DetectionResult res = pThis->RunOnceScan(); if (res.detected && res.indicatorCount >= pThis->m_closeThreshold) {
                    // Notification/handling is performed by outer owner (dllmain) after calling RunOnceScan.
                }
            }
        }
        pThis->m_previousProcessList = std::move(currentList);
        Sleep(pThis->m_pollingIntervalMs);
    }
    return 0;
}

std::vector<DWORD> ProcessThreadWatcher::GetCurrentProcessList()
{
    std::vector<DWORD> processList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return processList;
    PROCESSENTRY32W pe32{}; pe32.dwSize = sizeof(pe32);
    if (Process32FirstW(hSnapshot, &pe32)) { do { processList.push_back(pe32.th32ProcessID); } while (Process32NextW(hSnapshot, &pe32)); }
    CloseHandle(hSnapshot);
    return processList;
}

// Monitoring excessive ReadProcessMemory/WriteProcessMemory
namespace {
    struct MemAccessRecord {
        DWORD pid;
        DWORD targetPid;
        size_t readCount = 0;
        size_t writeCount = 0;
        ULONGLONG lastAccessTick = 0;
    };
    std::map<std::pair<DWORD, DWORD>, MemAccessRecord> g_memAccessMap;
    std::mutex g_memAccessMutex;
    const size_t MEM_ACCESS_THRESHOLD = 100; // Example threshold
    const DWORD GAME_PID = GetCurrentProcessId(); // Assume game process is current

    void RecordReadProcessMemory(DWORD callerPid, DWORD targetPid) {
        if (targetPid != GAME_PID) return;
        std::lock_guard<std::mutex> lock(g_memAccessMutex);
        auto& rec = g_memAccessMap[{callerPid, targetPid}];
        rec.pid = callerPid;
        rec.targetPid = targetPid;
        rec.readCount++;
        rec.lastAccessTick = GetTickCount64();
        if (rec.readCount > MEM_ACCESS_THRESHOLD) {
            // Report excessive ReadProcessMemory
            // TODO: Integrate with detection reporting system
        }
    }
    void RecordWriteProcessMemory(DWORD callerPid, DWORD targetPid) {
        if (targetPid != GAME_PID) return;
        std::lock_guard<std::mutex> lock(g_memAccessMutex);
        auto& rec = g_memAccessMap[{callerPid, targetPid}];
        rec.pid = callerPid;
        rec.targetPid = targetPid;
        rec.writeCount++;
        rec.lastAccessTick = GetTickCount64();
        if (rec.writeCount > MEM_ACCESS_THRESHOLD) {
            // Report excessive WriteProcessMemory
            // TODO: Integrate with detection reporting system
        }
    }
}

// Untuk integrasi nyata, perlu hook API ReadProcessMemory/WriteProcessMemory dan panggil RecordReadProcessMemory/RecordWriteProcessMemory di hook tersebut.
