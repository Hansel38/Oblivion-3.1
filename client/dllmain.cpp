// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ProcessThreadWatcher.h"
#include "JsonBuilder.h"
#include "NetworkClient.h"
#include "ConfigLoader.h"
#include "OverlayScanner.h"
#include "AntiDebug.h"
#include "InjectionScanner.h"
#include "DigitalSignatureValidator.h"
#include "AntiSuspend.h"
#include "HijackedThreadScanner.h"
#include "IATHookScanner.h"
#include "HWID.h"
#include "FileIntegrityChecker.h"
#include "Heartbeat.h"
#include "PeriodicScanner.h"
#include "ClientVersion.h"
#include "MemorySignatureScanner.h"
#include "KernelBridge.h"
#include "EtwHeuristics.h"
#include "CodeIntegrityScanner.h"
#include "SignaturePackManager.h"
#include "SignatureDatabase.h"
#include "CEBehaviorMonitor.h"
#include "CERegistryScanner.h"
#include "CEWindowScanner.h"
#include "SpeedHackDetector.h"
// ===== PRIORITY 2: Advanced Pattern Detection Modules =====
#include "DeviceObjectScanner.h"
#include "NetworkArtifactScanner.h"
// ===== PRIORITY 3: Stealth & Evasion Detection Modules =====
#include "PEBManipulationDetector.h"
#include "ETHREADManipulationDetector.h"
#include "KernelCallbackScanner.h"
#include "VADManipulationDetector.h"
#include "HardwareBreakpointMonitor.h"
#include "SuspiciousMemoryScanner.h"
#include "HeapSprayAnalyzer.h"
// ===== PRIORITY 4: Infrastructure & Optimization Modules =====
#include "TelemetryCollector.h"
#include "MLFeatureExtractor.h"
#include "MLAnomalyDetector.h"
#include "AdaptiveThresholdManager.h"
#include "AdaptivePollingManager.h"
#include "SignatureTestFramework.h"
#include "ScanPrioritizationManager.h"
#include <string>
#include <unordered_map>
#include <cstring>
#include <TlHelp32.h>
#include <Psapi.h>
#include <mutex>

#pragma comment(lib, "psapi.lib")

// Local RAII for HANDLE
class UniqueHandle {
public:
 UniqueHandle() noexcept : h_(nullptr) {}
 explicit UniqueHandle(HANDLE h) noexcept : h_(h) {}
 UniqueHandle(const UniqueHandle&) = delete;
 UniqueHandle& operator=(const UniqueHandle&) = delete;
 UniqueHandle(UniqueHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
 UniqueHandle& operator=(UniqueHandle&& o) noexcept {
 if (this != &o) { reset(); h_ = o.h_; o.h_ = nullptr; }
 return *this;
 }
 ~UniqueHandle() { reset(); }
 void reset(HANDLE h = nullptr) noexcept { if (h_ && h_ != INVALID_HANDLE_VALUE) ::CloseHandle(h_); h_ = h; }
 HANDLE get() const noexcept { return h_; }
 explicit operator bool() const noexcept { return h_ && h_ != INVALID_HANDLE_VALUE; }
private:
 HANDLE h_;
};

// Forward declare to satisfy IntelliSense if include paths are not resolved
class AntiSuspend;

// Stud_PE export for DLL import compatibility
extern "C" __declspec(dllexport) void Garuda_Entry() {}

// Global watcher instance
ProcessThreadWatcher* g_pWatcher = nullptr;
NetworkClient* g_pNetClient = nullptr;
#include "SimdBenchmark.h"

static HMODULE g_hModule = nullptr;
static AntiSuspend* g_pAntiSuspend = nullptr;
static Heartbeat* g_pHeartbeat = nullptr;
static PeriodicScanner* g_pPeriodic = nullptr;
static EtwHeuristics* g_pEtw = nullptr;
static SignaturePackManager* g_pSigMgr = nullptr;
static SignatureDatabase* g_pSignatureDB = nullptr; // Signature database instance
static CEBehaviorMonitor* g_pCEBehavior = nullptr;
static CERegistryScanner* g_pCERegistry = nullptr;
static CEWindowScanner* g_pCEWindow = nullptr;
static SpeedHackDetector* g_pSpeedHack = nullptr;
// ===== PRIORITY 2: Advanced Pattern Detection Global Instances =====
static DeviceObjectScanner* g_pDeviceScanner = nullptr;
static NetworkArtifactScanner* g_pNetArtifact = nullptr;
// ===== PRIORITY 3: Stealth & Evasion Detection Global Instances =====
static PEBManipulationDetector* g_pPEBDetector = nullptr;
static ETHREADManipulationDetector* g_pETHREADDetector = nullptr;
static KernelCallbackScanner* g_pCallbackScanner = nullptr;
static VADManipulationDetector* g_pVADDetector = nullptr;
static HardwareBreakpointMonitor* g_pHWBPMonitor = nullptr;
static SuspiciousMemoryScanner* g_pMemScanner = nullptr;
static HeapSprayAnalyzer* g_pHeapSpray = nullptr;
// ===== PRIORITY 4: Infrastructure & Optimization Global Instances =====
static TelemetryCollector* g_pTelemetryCollector = nullptr;
TelemetryCollector* g_pTelemetry = nullptr; // Global alias for backward compatibility
static MLFeatureExtractor* g_pMLFeatureExtractor = nullptr;
static MLAnomalyDetector* g_pMLAnomalyDetector = nullptr;
static AdaptiveThresholdManager* g_pAdaptiveThresholdManager = nullptr;
static AdaptivePollingManager* g_pAdaptivePollingManager = nullptr;
AdaptivePollingManager* g_pAdaptivePolling = nullptr; // Global alias for backward compatibility
static std::mutex g_cleanupMutex; // protect cleanup from races
// ===== PRIORITY 4.3.1: Scan Prioritization =====
static ScanPrioritizationManager* g_pScanPrioritizer = nullptr;

// Runtime configuration
static ClientConfig g_cfg; // defaults will be used if file not found

// Forward decl
static void SchedulePeriodicScans();
static std::string WToUtf8(const std::wstring& ws);
static void CleanupGlobals();
extern "C" bool CE_ScanDriverService(std::wstring& outService, std::wstring& outPath); // from ServiceDriverScanner.cpp

// Inline replacement for missing HandleAccessScanner.cpp
namespace {
 // Use LONG to avoid needing NT headers for NTSTATUS
 using pfnNtQuerySystemInformation = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
 typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
 PVOID Object;
 ULONG_PTR UniqueProcessId;
 ULONG_PTR HandleValue;
 ULONG GrantedAccess;
 USHORT CreatorBackTraceIndex;
 USHORT ObjectTypeIndex;
 ULONG HandleAttributes;
 ULONG Reserved;
 } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
 typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
 ULONG_PTR NumberOfHandles;
 ULONG_PTR Reserved;
 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
 } SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

 static bool GetProcessNameByPid(DWORD pid, std::wstring& name)
 {
 name.clear();
 UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
 if (!snap) return false;
 PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
 if (Process32FirstW(snap.get(), &pe)) {
 do { if (pe.th32ProcessID == pid) { name = pe.szExeFile; return true; } } while (Process32NextW(snap.get(), &pe));
 }
 return false;
 }

 static bool ScanRemoteHandleToSelf(std::wstring& offenderExe, DWORD& offenderPid, std::wstring& outReason)
 {
 offenderExe.clear(); offenderPid =0; outReason.clear();
 HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"); if (!ntdll) return false;
 auto NtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
 if (!NtQuerySystemInformation) return false;
 ULONG len =1u <<20; //1MB
 std::vector<BYTE> buf; LONG st;
 for (;;) {
 buf.resize(len);
 st = NtQuerySystemInformation(0x40 /*SystemExtendedHandleInformation*/, buf.data(), len, &len);
 if (st ==0) break; // STATUS_SUCCESS
 if (st ==0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) { if (len > (1u<<26)) return false; continue; }
 return false;
 }
 auto shi = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buf.data());
 DWORD self = GetCurrentProcessId();
 for (ULONG_PTR i =0; i < shi->NumberOfHandles; ++i) {
 const auto& e = shi->Handles[i];
 if ((DWORD)e.UniqueProcessId == self) continue;
 UniqueHandle hSource(OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)e.UniqueProcessId));
 if (!hSource) continue;
 HANDLE hDup = nullptr; HANDLE srcHandle = (HANDLE)(ULONG_PTR)e.HandleValue;
 if (DuplicateHandle(hSource.get(), srcHandle, GetCurrentProcess(), &hDup,0, FALSE, DUPLICATE_SAME_ACCESS)) {
 UniqueHandle hold(hDup);
 DWORD target = GetProcessId(hold.get());
 if (target == self) {
 const ULONG READ =0x0010, WRITE =0x0020, OP =0x0008, CREATE_THREAD =0x0002;
 ULONG suspiciousMask = READ | WRITE | OP | CREATE_THREAD;
 if (e.GrantedAccess & suspiciousMask) {
 offenderPid = (DWORD)e.UniqueProcessId;
 GetProcessNameByPid(offenderPid, offenderExe);
 wchar_t bufReason[256]; swprintf_s(bufReason, L"Remote handle with suspicious access0x%X to our process", e.GrantedAccess);
 outReason = bufReason;
 return true;
 }
 }
 }
 }
 return false;
 }
}

static std::wstring GetDllDirectory(HMODULE hModule)
{
 wchar_t path[MAX_PATH] = {0 };
 GetModuleFileNameW(hModule, path, MAX_PATH);
 std::wstring p(path);
 size_t pos = p.find_last_of(L"\\/");
 if (pos != std::wstring::npos) p = p.substr(0, pos);
 return p;
}

static void LogIfEnabled(const wchar_t* msg)
{
 if (g_cfg.enableLogging) OutputDebugStringW(msg);
}

static void LogPerf(const wchar_t* feature, ULONGLONG ms)
{
 if (!g_cfg.enableLogging) return;
 wchar_t buf[128];
 swprintf_s(buf, L"[Oblivion] %s took %llums\n", feature, ms);
 OutputDebugStringW(buf);
}

static void ClampConfig()
{
    auto clampInt = [](int v, int lo, int hi) { if (v < lo) return lo; if (v > hi) return hi; return v; };
    auto clampDw = [](DWORD v, DWORD lo, DWORD hi) { if (v < lo) return lo; if (v > hi) return hi; return v; };

    g_cfg.closeThreshold = clampInt(g_cfg.closeThreshold, 1, 5);
    g_cfg.overlayThreshold = clampInt(g_cfg.overlayThreshold, 1, 5);
    g_cfg.antiDebugThreshold = clampInt(g_cfg.antiDebugThreshold, 1, 5);
    g_cfg.injectionThreshold = clampInt(g_cfg.injectionThreshold, 1, 5);
    g_cfg.signatureThreshold = clampInt(g_cfg.signatureThreshold, 1, 5);

    g_cfg.pollingIntervalMs = clampDw(g_cfg.pollingIntervalMs, 200, 10000);
    g_cfg.antiSuspendHeartbeatMs = clampDw(g_cfg.antiSuspendHeartbeatMs, 50, 1000);
    g_cfg.antiSuspendStallWindowMs = clampDw(g_cfg.antiSuspendStallWindowMs, 1000, 10000);
    g_cfg.antiSuspendMissesThreshold = clampInt(g_cfg.antiSuspendMissesThreshold, 1, 5);
}

// ===== PRIORITY 4.3.1: CPU Usage Monitoring =====
static float GetCurrentCpuUsage()
{
    static ULONGLONG s_lastCheckTime = 0;
    static ULONGLONG s_lastKernelTime = 0;
    static ULONGLONG s_lastUserTime = 0;
    static float s_lastCpuPercent = 0.0f;

    ULONGLONG now = GetTickCount64();
    // Update every 2 seconds to avoid overhead
    if (now - s_lastCheckTime < 2000 && s_lastCheckTime != 0) {
        return s_lastCpuPercent;
    }

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(GetCurrentProcess(), &ftCreation, &ftExit, &ftKernel, &ftUser)) {
        return s_lastCpuPercent;
    }

    auto FileTimeToULL = [](const FILETIME& ft) -> ULONGLONG {
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return uli.QuadPart;
    };

    ULONGLONG kernelTime = FileTimeToULL(ftKernel);
    ULONGLONG userTime = FileTimeToULL(ftUser);

    if (s_lastCheckTime != 0) {
        ULONGLONG elapsedWall = (now - s_lastCheckTime) * 10000ULL; // ms to 100ns units
        ULONGLONG elapsedCpu = (kernelTime - s_lastKernelTime) + (userTime - s_lastUserTime);
        
        if (elapsedWall > 0) {
            s_lastCpuPercent = (float)(elapsedCpu * 100.0 / elapsedWall);
            if (s_lastCpuPercent > 100.0f) s_lastCpuPercent = 100.0f;
            if (s_lastCpuPercent < 0.0f) s_lastCpuPercent = 0.0f;
        }
    }

    s_lastCheckTime = now;
    s_lastKernelTime = kernelTime;
    s_lastUserTime = userTime;

    return s_lastCpuPercent;
}


static void SendDetectionJson(const DetectionResult& result, const char* subtype)
{
    if (g_pNetClient != nullptr) {
        std::string hwid = GetHWID();
        
        // ===== PRIORITY 4.1.5: Use ML-aware JSON builder if ML was evaluated =====
        std::string jsonReport;
        if (result.mlEvaluated && g_cfg.mlLogScores) {
            jsonReport = JsonBuilder::BuildDetectionReportWithML(result, subtype, hwid, OBLIVION_CLIENT_VERSION);
        } else {
            jsonReport = JsonBuilder::BuildDetectionReport(result.pid, result.processName, result.reason, subtype, 1, hwid, OBLIVION_CLIENT_VERSION, result.indicatorCount);
        }
        
        g_pNetClient->SendMessage(jsonReport);
    }
}

static bool ShouldSuppressDetection(const DetectionResult& result, const char* subtype)
{
    static std::unordered_map<std::string, ULONGLONG> s_lastSeen;
    static unsigned s_calls = 0;
    const ULONGLONG now = GetTickCount64();

    ULONGLONG cooldown = g_cfg.detectionCooldownMs ? g_cfg.detectionCooldownMs : 5000ULL;
    if (subtype) {
        if (strcmp(subtype, "process") == 0 && g_cfg.cooldownProcessMs) cooldown = g_cfg.cooldownProcessMs;
        else if (strcmp(subtype, "overlay") == 0 && g_cfg.cooldownOverlayMs) cooldown = g_cfg.cooldownOverlayMs;
        else if (strcmp(subtype, "antidebug") == 0 && g_cfg.cooldownAntiDebugMs) cooldown = g_cfg.cooldownAntiDebugMs;
        else if (strcmp(subtype, "injection") == 0 && g_cfg.cooldownInjectionMs) cooldown = g_cfg.cooldownInjectionMs;
        else if (strcmp(subtype, "sigcheck") == 0 && g_cfg.cooldownSigcheckMs) cooldown = g_cfg.cooldownSigcheckMs;
        else if (strcmp(subtype, "hijackedthread") == 0 && g_cfg.cooldownHijackedThreadMs) cooldown = g_cfg.cooldownHijackedThreadMs;
        else if (strcmp(subtype, "iathook") == 0 && g_cfg.cooldownIatHookMs) cooldown = g_cfg.cooldownIatHookMs;
        else if (strcmp(subtype, "integrity") == 0 && g_cfg.cooldownIntegrityMs) cooldown = g_cfg.cooldownIntegrityMs;
        else if (strcmp(subtype, "memsig") == 0 && g_cfg.cooldownMemsigMs) cooldown = g_cfg.cooldownMemsigMs;
        else if (strcmp(subtype, "ce_behavior") == 0 && g_cfg.cooldownCEBehaviorMs) cooldown = g_cfg.cooldownCEBehaviorMs;
        else if (strcmp(subtype, "ce_registry") == 0 && g_cfg.cooldownCERegistryMs) cooldown = g_cfg.cooldownCERegistryMs;
        else if (strcmp(subtype, "ce_window") == 0 && g_cfg.cooldownCEWindowMs) cooldown = g_cfg.cooldownCEWindowMs;
        else if (strcmp(subtype, "speed_hack") == 0 && g_cfg.cooldownSpeedHackMs) cooldown = g_cfg.cooldownSpeedHackMs;
        else if (strcmp(subtype, "memory_scanning") == 0 && g_cfg.cooldownMemoryScanningMs) cooldown = g_cfg.cooldownMemoryScanningMs;
    }

    // Cap cooldown to 1 hour to avoid overflow and compute safe horizon window (x5)
    ULONGLONG capped = (cooldown > 3600000ULL ? 3600000ULL : cooldown);
    ULONGLONG window = capped * 5ULL;
    ULONGLONG horizon = (now > window) ? (now - window) : 0ULL;

    std::string key(subtype ? subtype : "");
    key += "|";
    key += WToUtf8(result.reason);

    auto it = s_lastSeen.find(key);
    if (it != s_lastSeen.end() && (now - it->second) < cooldown) {
        return true;
    }
    s_lastSeen[key] = now;

    // Periodic pruning to cap memory: remove entries older than horizon
    if ((++s_calls & 0x3F) == 0) { // every 64 calls
        for (auto itr = s_lastSeen.begin(); itr != s_lastSeen.end(); ) {
            if (itr->second < horizon) itr = s_lastSeen.erase(itr); else ++itr;
        }
    }

    return false;
}

static BOOL CALLBACK EnumCloseWindowsProc(HWND hWnd, LPARAM lParam)
{
    DWORD targetPid = static_cast<DWORD>(lParam);
    DWORD wndPid = 0; GetWindowThreadProcessId(hWnd, &wndPid);
    if ( wndPid == targetPid && IsWindowVisible(hWnd)) {
        PostMessageW(hWnd, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

static bool TryGracefulShutdownRRO(DWORD pid, DWORD timeoutMs)
{
    EnumWindows(EnumCloseWindowsProc, static_cast<LPARAM>(pid));

    UniqueHandle hProc(OpenProcess(SYNCHRONIZE, FALSE, pid));
    if (!hProc) return false;
    DWORD wait = WaitForSingleObject(hProc.get(), timeoutMs);
    return wait == WAIT_OBJECT_0;
}

static void HandleDetection(const DetectionResult& result)
{
    wchar_t messageBuffer[512];
    const wchar_t* msgFmt = g_cfg.detectionMessage.c_str();
    swprintf_s(messageBuffer, 512, msgFmt, result.processName.c_str());
    MessageBoxW(nullptr, messageBuffer, L"Oblivion AntiCheat", MB_OK | MB_ICONWARNING | MB_TOPMOST);

    UniqueHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot) {
        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot.get(), &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                if (processName == L"rro.exe") {
                    DWORD pid = pe32.th32ProcessID;
                    bool closed = TryGracefulShutdownRRO(pid, 5000);
                    if (!closed) {
                        UniqueHandle hProcess(OpenProcess(PROCESS_TERMINATE, FALSE, pid));
                        if (hProcess) {
                            TerminateProcess(hProcess.get(), 1);
                        }
                    }
                    break;
                }
            } while (Process32NextW(hSnapshot.get(), &pe32));
        }
    }
}

// ===== PRIORITY 4.1.5: ML Evaluation Helper =====
static void EvaluateWithML(DetectionResult& result, const char* subtype)
{
    // Only evaluate if ML integration is enabled and components are available
    if (!g_cfg.enableMLIntegration || !g_pMLAnomalyDetector || !g_pMLFeatureExtractor || !g_pTelemetryCollector) {
        return;
    }
    
    // Skip if ML model is not trained yet (check statistics)
    auto stats = g_pMLAnomalyDetector->GetStatistics();
    if (!stats.isolationForestTrained && !stats.oneClassTrained) {
        return;
    }
    
    try {
        // Extract features from current telemetry
        ULONGLONG currentTime = GetTickCount64();
        FeatureVector features = g_pMLFeatureExtractor->ExtractFeatures(currentTime);
        
        // Get ML anomaly detection result
        AnomalyDetectionResult mlResult = g_pMLAnomalyDetector->DetectAnomaly(features);
        
        // Store ML results in detection result
        result.mlEvaluated = true;
        result.mlAnomalyScore = mlResult.anomalyScore;
        result.mlConfidence = mlResult.confidence;
        result.mlFlagged = (mlResult.anomalyScore >= g_cfg.mlDetectionThreshold && 
                            mlResult.confidence >= g_cfg.mlConfidenceThreshold);
        
        // Hybrid mode: boost indicators based on ML score
        if (g_cfg.mlHybridMode && g_cfg.mlBoostIndicators && result.mlFlagged) {
            int mlIndicators = static_cast<int>(mlResult.anomalyScore * g_cfg.mlIndicatorMultiplier);
            result.indicatorCount += mlIndicators;
            
            // Append ML info to reason
            wchar_t mlInfo[256];
            swprintf_s(mlInfo, L" [ML: score=%.2f, confidence=%.2f, +%d indicators]", 
                       mlResult.anomalyScore, mlResult.confidence, mlIndicators);
            result.reason += mlInfo;
        }
        
        // Log ML scores if enabled
        if (g_cfg.mlLogScores) {
            wchar_t logBuf[256];
            swprintf_s(logBuf, L"[Oblivion] ML Eval: type=%S, score=%.3f, conf=%.3f, flagged=%d\n",
                       subtype ? subtype : "unknown", 
                       mlResult.anomalyScore, 
                       mlResult.confidence,
                       result.mlFlagged ? 1 : 0);
            LogIfEnabled(logBuf);
        }
        
    } catch (...) {
        // ML evaluation failed - continue without ML
        LogIfEnabled(L"[Oblivion] ML evaluation failed\n");
    }
}

static void ProcessDetection(const DetectionResult& result, const char* subtype)
{
    // Make a mutable copy for ML evaluation
    DetectionResult evalResult = result;
    
    // ===== PRIORITY 4.1.5: ML Evaluation =====
    EvaluateWithML(evalResult, subtype);
    
    // ML Veto: If enabled, low ML scores can veto weak rule-based detections
    if (g_cfg.enableMLIntegration && g_cfg.mlEnableVeto && evalResult.mlEvaluated) {
        if (evalResult.mlAnomalyScore < g_cfg.mlVetoThreshold && evalResult.indicatorCount < 5) {
            wchar_t logBuf[256];
            swprintf_s(logBuf, L"[Oblivion] Detection vetoed by ML: score=%.3f < %.3f, indicators=%d\n",
                       evalResult.mlAnomalyScore, g_cfg.mlVetoThreshold, evalResult.indicatorCount);
            LogIfEnabled(logBuf);
            
            // Record vetoed detection in telemetry
            if (g_pTelemetryCollector) {
                DetectionTelemetry dt = {};
                dt.timestamp = GetTickCount64();
                dt.detectionType = subtype ? subtype : "unknown";
                dt.processName = evalResult.processName;
                dt.processId = evalResult.pid;
                dt.indicatorCount = evalResult.indicatorCount;
                dt.wasSuppressed = true;
                dt.userReportedFP = false;
                dt.reason = WToUtf8(evalResult.reason + L" [ML_VETO]");
                g_pTelemetryCollector->RecordDetection(dt);
            }
            return;
        }
    }
    
    if (ShouldSuppressDetection(evalResult, subtype)) {
        LogIfEnabled(L"[Oblivion] Duplicate detection suppressed\n");
        // Record suppressed detection in telemetry
        if (g_pTelemetryCollector) {
            DetectionTelemetry dt = {};
            dt.timestamp = GetTickCount64();
            dt.detectionType = subtype ? subtype : "unknown";
            dt.processName = evalResult.processName;
            dt.processId = evalResult.pid;
            dt.indicatorCount = evalResult.indicatorCount;
            dt.wasSuppressed = true;
            dt.userReportedFP = false;
            dt.reason = WToUtf8(evalResult.reason);
            g_pTelemetryCollector->RecordDetection(dt);
        }
        return;
    }
    SendDetectionJson(evalResult, subtype);
    HandleDetection(evalResult);
    
    // Record detection in telemetry
    if (g_pTelemetryCollector) {
        DetectionTelemetry dt = {};
        dt.timestamp = GetTickCount64();
        dt.detectionType = subtype ? subtype : "unknown";
        dt.processName = evalResult.processName;
        dt.processId = evalResult.pid;
        dt.indicatorCount = evalResult.indicatorCount;
        dt.wasSuppressed = false;
        dt.userReportedFP = false;
        dt.reason = WToUtf8(result.reason);
        g_pTelemetryCollector->RecordDetection(dt);
    }
}

static std::vector<std::wstring> ParseWhitelistPrefixes(const std::wstring& delimited)
{
    std::vector<std::wstring> out;
    std::wstring cur;
    for (wchar_t c : delimited) {
        if (c == L';') { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else { cur.push_back(c); }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string WToUtf8(const std::wstring& ws)
{
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

// Helper: identify RRO.exe by name or path (case-insensitive)
static bool IsRROExecutable(const std::wstring& s)
{
    if (s.empty()) return false;
    std::wstring t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::towlower);
    if (t == L"rro.exe") return true;
    // check tail after last path separator
    size_t pos = t.find_last_of(L"\\/");
    std::wstring base = (pos == std::wstring::npos) ? t : t.substr(pos + 1);
    return base == L"rro.exe";
}

static void AntiSuspendReportBridge(const DetectionResult& dr, const char* subtype)
{
    ProcessDetection(dr, subtype);
}

// Detect common Cheat Engine artifacts in other processes (module names like vehdebug/dbk/speedhack)
static bool CheckCheatEngineArtifactsInProcess(DWORD pid, std::wstring& outProcName, std::wstring& outReason)
{
    UniqueHandle hProcSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!hProcSnap) return false;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    bool foundName = false;
    if (Process32FirstW(hProcSnap.get(), &pe)) {
        do {
            if (pe.th32ProcessID == pid) { outProcName = pe.szExeFile; foundName = true; break; }
        } while (Process32NextW(hProcSnap.get(), &pe));
    }

    // Build token list from config (semicolon-delimited)
    std::vector<std::wstring> tokens;
    {
        std::wstring s = g_cfg.ceArtifactTokens; std::wstring cur;
        for (size_t i=0;i<=s.size();++i){ wchar_t c = (i<s.size()? s[i]:L';'); if (c==L';'){ if(!cur.empty()){ tokens.push_back(cur); cur.clear(); } } else cur.push_back(c);} 
        for (auto& t : tokens) { std::transform(t.begin(), t.end(), t.begin(), ::towlower); }
        if (tokens.empty()) {
            // fallback to defaults if somehow empty
            tokens = { L"vehdebug", L"speedhack", L"dbk", L"cheatengine", L"ceserver", L"celua", L"monohelper" };
        }
    }

    UniqueHandle hModSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!hModSnap) return false;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    bool hit = false;
    if (Module32FirstW(hModSnap.get(), &me)) {
        do {
            std::wstring base = me.szModule;
            std::wstring path = me.szExePath;
            // lowercase
            std::transform(base.begin(), base.end(), base.begin(), ::towlower);
            std::transform(path.begin(), path.end(), path.begin(), ::towlower);
            for (const auto& tok : tokens) {
                if (!tok.empty() && (base.find(tok) != std::wstring::npos || path.find(tok) != std::wstring::npos)) {
                    // Build reason string dynamically to avoid buffer truncation
                    outReason = L"Cheat Engine artifact: module '" + std::wstring(me.szModule) + L"' in '" + std::wstring(me.szExePath) + L"'";
                    if (!foundName) outProcName = me.szModule;
                    hit = true;
                    break;
                }
            }
            if (hit) break;
        } while (Module32NextW(hModSnap.get(), &me));
    }
    return hit;
}

// Detect CE kernel driver presence by enumerating loaded device drivers for dbk-like names
static bool DetectCheatEngineDriver(std::wstring& outName)
{
    LPVOID drivers[1024]; DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed) || needed == 0) return false;
    int count = (int)(needed / sizeof(drivers[0]));
    wchar_t name[MAX_PATH];
    for (int i = 0; i < count; ++i) {
        if (GetDeviceDriverBaseNameW(drivers[i], name, MAX_PATH)) {
            std::wstring base = name; std::transform(base.begin(), base.end(), base.begin(), ::towlower);
            if (base.find(L"dbk") != std::wstring::npos || base.find(L"cedriver") != std::wstring::npos) {
                outName = name; return true;
            }
        }
    }
    return false;
}

static std::vector<std::pair<std::wstring, std::string>> ParseIntegrityItems(const std::wstring& dllDir, const std::wstring& delimited)
{
    std::vector<std::pair<std::wstring, std::string>> items;
    std::wstring cur;
    for (size_t i = 0; i <= delimited.size(); ++i) {
        wchar_t c = (i < delimited.size() ? delimited[i] : L';');
        if (c == L';') {
            if (!cur.empty()) {
                size_t eq = cur.find(L'=');
                std::wstring path = (eq == std::wstring::npos ? cur : cur.substr(0, eq));
                std::string expected;
                if (eq != std::wstring::npos) {
                    std::wstring expectW = cur.substr(eq + 1);
                    expected = WToUtf8(expectW);
                }
                if (!(path.size() >= 2 && path[1] == L':')) {
                    path = dllDir + L"\\" + path; // resolve relative to dll dir
                }
                items.emplace_back(path, expected);
            }
            cur.clear();
        }
        else {
            cur.push_back(c);
        }
    }
    return items;
}

// Periodic scanner setup
static void SchedulePeriodicScans()
{
 if (!g_cfg.enablePeriodicScans) return;
 if (g_pPeriodic) { g_pPeriodic->Stop(); delete g_pPeriodic; g_pPeriodic = nullptr; }
 try {
 g_pPeriodic = new PeriodicScanner(g_pNetClient);
 } catch (...) {
 g_pPeriodic = nullptr;
 return;
 }
 // Bind periodic scanner to AdaptivePollingManager if present
 if (g_pAdaptivePollingManager) {
     g_pAdaptivePollingManager->Initialize(g_pTelemetryCollector, g_pPeriodic);
 }
 g_pPeriodic->Tick = []() -> bool {
 bool fired = false;
 ULONGLONG t0;

 // Early: system-wide CE artifact sweep (renamed or fast-renamed executables)
 {
 t0 = GetTickCount64();
 UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
 if (hSnap) {
 PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
 if (Process32FirstW(hSnap.get(), &pe)) {
 do {
 // skip system/idle/self
 if (pe.th32ProcessID ==0 || pe.th32ProcessID ==4 || pe.th32ProcessID == GetCurrentProcessId()) continue;
 std::wstring pname, reason;
 if (CheckCheatEngineArtifactsInProcess(pe.th32ProcessID, pname, reason)) {
 DetectionResult dr{}; dr.detected = true; dr.pid = pe.th32ProcessID; dr.processName = pname; dr.reason = reason; dr.indicatorCount =5; // strong
 ProcessDetection(dr, "process"); fired = true;
 break; // one hit per tick is enough
 }
 } while (Process32NextW(hSnap.get(), &pe));
 }
 }
 LogPerf(L"Periodic.CEArtifactSweep", GetTickCount64() - t0);
 }

 // Optional: CE driver presence (dbk*)
 {
 std::wstring drvName;
 if (DetectCheatEngineDriver(drvName)) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId(); dr.processName = L"<system>"; dr.reason = L"Cheat Engine driver loaded: " + drvName; dr.indicatorCount =5;
 ProcessDetection(dr, "process"); fired = true;
 }
 }

 // New: SCM driver service presence (dbk/cedriver)
 {
 std::wstring svc, path;
 if (CE_ScanDriverService(svc, path)) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId(); dr.processName = L"<system>"; dr.reason = L"Cheat Engine driver service present: name='" + svc + L"' path='" + path + L"'"; dr.indicatorCount =5;
 ProcessDetection(dr, "process"); fired = true;
 }
 }

 // New: Remote handle access to our process (replacement for HandleAccessScanner)
 {
 std::wstring offenderExe, reason;
 DWORD offenderPid =0;
 if (ScanRemoteHandleToSelf(offenderExe, offenderPid, reason)) {
 DetectionResult dr{}; dr.detected = true; dr.pid = offenderPid; dr.processName = offenderExe.empty()? L"<unknown>" : offenderExe; dr.reason = reason; dr.indicatorCount =4;
 ProcessDetection(dr, "process"); fired = true;
 }
 }

 // New: CE Behavior Monitor - detect excessive memory scanning (scheduled)
 if (g_pCEBehavior && g_pScanPrioritizer) {
     g_pScanPrioritizer->ScheduleTask("CEBehaviorMonitor", []() -> bool {
         ULONGLONG t0 = GetTickCount64();
         CEBehaviorMonitor::BehaviorFinding bf{};
         bool firedLocal = false;
         if (g_pCEBehavior->CheckSuspiciousBehavior(bf)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = bf.pid; dr.processName = bf.processName;
             dr.reason = L"Cheat Engine behavior detected: " + bf.reason;
             dr.indicatorCount = bf.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 const char* subtype = bf.likelySequential ? "memory_scanning" : "ce_behavior";
                 ProcessDetection(dr, subtype); firedLocal = true;
             }
         }
         LogPerf(L"Periodic.CEBehaviorMonitor", GetTickCount64() - t0);
         return firedLocal;
     });
 }

 // New: CE Registry Scanner - detect CE installation artifacts (scheduled)
 if (g_pCERegistry && g_pScanPrioritizer) {
     g_pScanPrioritizer->ScheduleTask("CERegistryScanner", []() -> bool {
         ULONGLONG t0 = GetTickCount64();
         CERegistryScanner::RegistryFinding rf{};
         bool firedLocal = false;
         if (g_pCERegistry->RunOnceScan(rf)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
             dr.processName = L"<registry>";
             dr.reason = L"Cheat Engine registry artifacts: " + rf.reason;
             dr.indicatorCount = rf.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 ProcessDetection(dr, "ce_registry"); firedLocal = true;
             }
         }
         LogPerf(L"Periodic.CERegistryScanner", GetTickCount64() - t0);
         return firedLocal;
     });
 }

 // New: CE Window Scanner - detect CE UI presence (scheduled)
 if (g_pCEWindow && g_pScanPrioritizer) {
     g_pScanPrioritizer->ScheduleTask("CEWindowScanner", []() -> bool {
         ULONGLONG t0 = GetTickCount64();
         CEWindowScanner::WindowFinding wf{};
         bool firedLocal = false;
         if (g_pCEWindow->ScanForCEWindows(wf)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = wf.pid;
             dr.processName = wf.windowTitle;
             dr.reason = L"Cheat Engine window detected: title='" + wf.windowTitle + L"' class='" + wf.className + L"'";
             dr.indicatorCount = wf.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 ProcessDetection(dr, "ce_window"); firedLocal = true;
             }
         }
         LogPerf(L"Periodic.CEWindowScanner", GetTickCount64() - t0);
         return firedLocal;
     });
 }

 // New: Speed Hack Detector - detect timing manipulation (scheduled)
 if (g_pSpeedHack && g_pScanPrioritizer) {
     g_pScanPrioritizer->ScheduleTask("SpeedHackDetector", []() -> bool {
         ULONGLONG t0 = GetTickCount64();
         SpeedHackDetector::SpeedHackFinding sf{};
         bool firedLocal = false;
         if (g_pSpeedHack->CheckSpeedHack(sf)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
             dr.processName = L"<speed_hack>";
             dr.reason = sf.reason;
             dr.indicatorCount = sf.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 ProcessDetection(dr, "speed_hack"); firedLocal = true;
             }
         }
         // ===== PRIORITY 2.3.2: Network timing speedhack detection =====
         if (g_pSpeedHack->DetectNetworkTimingAnomaly(sf)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
             dr.processName = L"<network_speed_hack>";
             dr.reason = sf.reason;
             dr.indicatorCount = sf.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 ProcessDetection(dr, "network_speed_hack"); firedLocal = true;
             }
         }
         LogPerf(L"Periodic.SpeedHackDetector", GetTickCount64() - t0);
         return firedLocal;
     });
 }

 // ===== PRIORITY 2.2: Device Object Scanner - DBK/CE driver detection (scheduled)
 if (g_pDeviceScanner && g_pScanPrioritizer) {
     g_pScanPrioritizer->ScheduleTask("DeviceObjectScanner", []() -> bool {
         ULONGLONG t0 = GetTickCount64();
         DeviceObjectFinding dof{};
         bool firedLocal = false;
         if (g_pDeviceScanner->DetectDBKIoctlPattern(dof)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
             dr.processName = L"<dbk_driver>";
             dr.reason = dof.reason;
             dr.indicatorCount = dof.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 ProcessDetection(dr, "dbk_driver"); firedLocal = true;
             }
         }
         LogPerf(L"Periodic.DeviceObjectScanner", GetTickCount64() - t0);
         return firedLocal;
     });
 }

 // ===== PRIORITY 2.3.1: Network Artifact Scanner - CE server detection (scheduled)
 if (g_pNetArtifact && g_pScanPrioritizer) {
     g_pScanPrioritizer->ScheduleTask("NetworkArtifactScanner", []() -> bool {
         ULONGLONG t0 = GetTickCount64();
         NetworkArtifactFinding naf{};
         bool firedLocal = false;
         if (g_pNetArtifact->ScanForCEServerPort(naf)) {
             DetectionResult dr{}; dr.detected = true; dr.pid = naf.processId;
             dr.processName = naf.processName.empty() ? L"<unknown>" : naf.processName;
             dr.reason = naf.reason;
             dr.indicatorCount = naf.indicators;
             if (dr.indicatorCount >= g_cfg.closeThreshold) {
                 ProcessDetection(dr, "ce_network"); firedLocal = true;
             }
         }
         LogPerf(L"Periodic.NetworkArtifactScanner", GetTickCount64() - t0);
         return firedLocal;
     });
 }

 if (g_cfg.enableOverlayScanner) {
 t0 = GetTickCount64();
 OverlayScanner overlay; overlay.SetCloseThreshold(max(g_cfg.overlayThreshold, g_cfg.closeThreshold));
 OverlayFinding of{}; if (overlay.RunOnceScan(of)) {
 DetectionResult od{}; od.detected=true; od.pid=of.pid; od.processName = of.windowTitle.empty()? of.className : of.windowTitle; od.reason = L"Suspicious overlay detected: title='" + od.processName + L"' class='" + of.className + L"'"; od.indicatorCount = of.indicators;
 if (od.indicatorCount >= max(g_cfg.overlayThreshold, g_cfg.closeThreshold)) { ProcessDetection(od, "overlay"); fired=true; }
 }
 LogPerf(L"Periodic.OverlayScanner", GetTickCount64()-t0);
 }
 if (g_cfg.enableAntiDebug) {
 t0 = GetTickCount64();
 AntiDebug ad; ad.SetThreshold(g_cfg.antiDebugThreshold); DetectionResult dbg{}; if (ad.RunScan(dbg)) { ProcessDetection(dbg, "antidebug"); fired=true; }
 LogPerf(L"Periodic.AntiDebug", GetTickCount64()-t0);
 }
 if (g_cfg.enableInjectionScanner) {
 t0 = GetTickCount64();
 InjectionScanner inj; inj.SetThreshold(g_cfg.injectionThreshold); inj.SetWhitelistPrefixes(ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes)); InjectionFinding inf{}; if (inj.RunOnceScan(inf)) { DetectionResult rd{}; rd.detected=true; rd.pid=GetCurrentProcessId(); rd.processName=inf.moduleName; rd.reason=L"Suspicious module injected: " + inf.modulePath; rd.indicatorCount=inf.indicators; if (rd.indicatorCount >= g_cfg.injectionThreshold) { ProcessDetection(rd, "injection"); fired=true; } }
 LogPerf(L"Periodic.InjectionScanner", GetTickCount64()-t0);
 }
 if (g_cfg.enableSignatureValidator) {
 t0 = GetTickCount64();
 DigitalSignatureValidator dsv; dsv.SetThreshold(g_cfg.signatureThreshold); dsv.SetWhitelistPrefixes(ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes));
 // configure skip names from config
 dsv.SetSkipModuleNames(ParseWhitelistPrefixes(g_cfg.signatureSkipNames));
 SignatureFinding sf{}; if (dsv.RunOnceScan(sf)) {
 // Skip sigcheck for RRO.exe (hard guard) in addition to configured skip list
 if (!(IsRROExecutable(sf.moduleName) || IsRROExecutable(sf.modulePath))) {
 DetectionResult sd{}; sd.detected=true; sd.pid=GetCurrentProcessId(); sd.processName=sf.moduleName; sd.reason=L"Untrusted signature or suspicious module: " + sf.modulePath; sd.indicatorCount=sf.indicators; if (sd.indicatorCount >= g_cfg.signatureThreshold) { ProcessDetection(sd, "sigcheck"); fired=true; }
 }
 }
 LogPerf(L"Periodic.SignatureValidator", GetTickCount64()-t0);
 }
 if (g_cfg.enableHijackedThreadScanner) {
 t0 = GetTickCount64();
 HijackedThreadScanner hts; hts.SetThreshold(g_cfg.hijackedThreadThreshold); hts.SetWhitelistPrefixes(ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes)); HijackedThreadFinding hf{}; if (hts.RunOnceScan(hf)) { DetectionResult td{}; td.detected=true; td.pid=GetCurrentProcessId(); wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", hf.startAddress); td.processName = hf.moduleName.empty()? L"<unknown>" : hf.moduleName; td.reason = std::wstring(L"Suspicious thread start: TID=") + std::to_wstring(hf.tid) + L", start=" + addrbuf + L", module=" + (hf.moduleName.empty()? L"<unknown>" : hf.moduleName); td.indicatorCount=hf.indicators; if (td.indicatorCount >= g_cfg.hijackedThreadThreshold) { ProcessDetection(td, "hijackedthread"); fired=true; } }
 LogPerf(L"Periodic.HijackedThread", GetTickCount64()-t0);
 }
 if (g_cfg.enableIATHookScanner) {
 t0 = GetTickCount64();
 IATHookScanner iat; iat.SetThreshold(g_cfg.iatHookThreshold); iat.SetWhitelistModules(ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes)); IATHookFinding f{}; if (iat.RunOnceScan(f)) { DetectionResult id{}; id.detected=true; id.pid=GetCurrentProcessId(); id.processName=f.moduleName.empty()? L"<unknown>" : f.moduleName; wchar_t iatbuf[32]; swprintf_s(iatbuf, L"0x%p", f.iatAddress); wchar_t tgtbuf[32]; swprintf_s(tgtbuf, L"0x%p", f.targetAddress); id.reason = std::wstring(L"IAT hook: module=") + id.processName + L", import='" + std::wstring(f.importName.begin(), f.importName.end()) + L"', iat=" + iatbuf + L", target=" + tgtbuf + L", targetModule=" + (f.targetModule.empty()? L"<unknown>" : f.targetModule); id.indicatorCount=f.indicators; if (id.indicatorCount >= g_cfg.iatHookThreshold) { ProcessDetection(id, "iathook"); fired=true; } }
 LogPerf(L"Periodic.IATHook", GetTickCount64()-t0);
 }
 if (g_cfg.enableFileIntegrityCheck && !g_cfg.integrityItems.empty()) {
 t0 = GetTickCount64();
 auto items = ParseIntegrityItems(GetDllDirectory(g_hModule), g_cfg.integrityItems); FileIntegrityChecker fic; fic.SetItems(items); IntegrityFinding fi{}; if (fic.RunOnceScan(fi)) { DetectionResult ir{}; ir.detected=true; ir.pid=GetCurrentProcessId(); ir.processName=fi.path; std::wstring exp = fi.expectedHex.empty()? L"<none>" : std::wstring(fi.expectedHex.begin(), fi.expectedHex.end()); std::wstring act = fi.actualHex.empty()? L"<none>" : std::wstring(fi.actualHex.begin(), fi.actualHex.end()); ir.reason = L"Integrity mismatch: path='" + fi.path + L"' expected=" + exp + L" actual=" + act; ir.indicatorCount=fi.indicators; if (ir.indicatorCount >= 1) { ProcessDetection(ir, "integrity"); fired=true; } }
 LogPerf(L"Periodic.FileIntegrity", GetTickCount64()-t0);
 }
 if (g_cfg.enableMemorySignatureScanner && !g_cfg.memorySignatures.empty()) {
 t0 = GetTickCount64();
 std::vector<MemSigPattern> pats;
 std::wstring s = g_cfg.memorySignatures; std::wstring cur;
 auto flush = [&](const std::wstring& entry) {
 if (entry.empty()) return;
 size_t eq = entry.find(L'='); if (eq == std::wstring::npos) return;
 std::wstring nameW(entry.begin(), entry.begin() + eq);
 // extract optional weight suffix in name: name@3
 int weight = 1;
 size_t at = nameW.find(L'@');
 if (at != std::wstring::npos) {
 std::wstring wstr = nameW.substr(at + 1);
 try { weight = std::stoi(wstr); } catch(...) { weight = 1; }
 nameW = nameW.substr(0, at);
 }
 std::string name = WToUtf8(nameW);
 std::wstring bytesStr = entry.substr(eq + 1);
 std::vector<unsigned char> bytes; std::vector<unsigned char> mask;
 std::wstring token;
 auto hexNibble = [](wchar_t c) -> int {
 if (c >= L'0' && c <= L'9') return c - L'0';
 if (c >= L'a' && c <= L'f') return 10 + (c - L'a');
 if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
 return -1;
 };
 auto pushTok = [&](){
 if (token.empty()) return;
 if (token.size() ==2) {
 wchar_t a = token[0];
 wchar_t b = token[1];
 if (a == L'?' && b == L'?') {
 bytes.push_back(0);
 mask.push_back(0x00);
 } else if (a == L'?') {
 int lb = hexNibble(b);
 if (lb >=0) {
 bytes.push_back((unsigned char)lb);
 mask.push_back(0x0F);
 }
 } else if (b == L'?') {
 int hb = hexNibble(a);
 if (hb >=0) {
 bytes.push_back((unsigned char)(hb <<4));
 mask.push_back(0xF0);
 }
 } else {
 int hb = hexNibble(a);
 int lb = hexNibble(b);
 if (hb >=0 && lb >=0) {
 bytes.push_back((unsigned char)((hb <<4) | lb));
 mask.push_back(0xFF);
 }
 }
 } else if (token.size() ==1 && token[0] == L'?') {
 bytes.push_back(0);
 mask.push_back(0x00);
 }
 token.clear();
 };
 for (size_t i = 0; i <= bytesStr.size(); ++i){ wchar_t c = (i < bytesStr.size()? bytesStr[i] : L' '); if (c == L' ' || c == L'\t' || c == L',' ) { pushTok(); } else token.push_back(c); }
 if (!bytes.empty()) { MemSigPattern p{}; p.name=name; p.bytes=std::move(bytes); p.mask=std::move(mask); p.weight = weight; pats.push_back(std::move(p)); }
 };
 for (size_t i = 0; i <= s.size(); ++i){ wchar_t c = (i < s.size()? s[i] : L';'); if (c == L';'){ flush(cur); cur.clear(); } else cur.push_back(c);}            
            MemorySignatureScanner mss; mss.SetThreshold(g_cfg.memorySignatureThreshold); mss.SetPatterns(pats); mss.SetEnableSIMD(g_cfg.enableSimdAcceleration);
 auto memPrefixes = g_cfg.memoryModuleWhitelistPrefixes.empty()? g_cfg.moduleWhitelistPrefixes : g_cfg.memoryModuleWhitelistPrefixes;
 mss.SetModuleWhitelistPrefixes(ParseWhitelistPrefixes(memPrefixes));
 mss.SetImagesOnly(g_cfg.memoryImagesOnly);
 MemorySignatureFinding mf{}; if (mss.RunOnceScan(mf)) {
 DetectionResult md{}; md.detected=true; md.pid=GetCurrentProcessId(); md.processName = mf.moduleName.empty()? L"<current>" : mf.moduleName; wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", mf.address); md.reason = std::wstring(L"Memory signature hit: pattern='") + std::wstring(mf.patternName.begin(), mf.patternName.end()) + L"' at=" + addrbuf; md.indicatorCount=mf.indicators; if (md.indicatorCount >= g_cfg.memorySignatureThreshold) { ProcessDetection(md, "memsig"); fired=true; }
 }
 LogPerf(L"Periodic.MemorySignatureScanner", GetTickCount64()-t0);
 }

 // ===== PRIORITY 3.1.1: PEB Manipulation Detector =====
 if (g_pPEBDetector) {
 t0 = GetTickCount64();
 if (g_pPEBDetector->ScanForPEBManipulation()) {
 auto hiddenModules = g_pPEBDetector->GetHiddenModules();
 if (!hiddenModules.empty()) {
 for (const auto& hm : hiddenModules) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 dr.processName = hm.moduleName;
 wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", hm.baseAddress);
 dr.reason = std::wstring(L"Hidden module detected: method=") + std::wstring(hm.detectionMethod.begin(), hm.detectionMethod.end()) + L", module=" + hm.moduleName + L", addr=" + addrbuf;
 dr.indicatorCount = 5; // High severity
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "peb_manipulation"); fired = true;
 break; // One detection per tick
 }
 }
 }
 }
 LogPerf(L"Periodic.PEBManipulationDetector", GetTickCount64() - t0);
 }

 // ===== PRIORITY 3.2: Hardware Breakpoint Monitor =====
 if (g_pHWBPMonitor) {
 t0 = GetTickCount64();
 if (g_pHWBPMonitor->ScanAllThreads()) {
 auto anomalies = g_pHWBPMonitor->GetAnomalies();
 if (!anomalies.empty()) {
 for (const auto& anomaly : anomalies) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 dr.processName = L"<thread_" + std::to_wstring(anomaly.threadId) + L">";
 dr.reason = std::wstring(L"Hardware breakpoint anomaly: type=") + std::wstring(anomaly.anomalyType.begin(), anomaly.anomalyType.end()) + L", desc=" + std::wstring(anomaly.description.begin(), anomaly.description.end());
 dr.indicatorCount = (anomaly.anomalyType == "HIDDEN_DEBUGGER") ? 5 : 4;
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "hardware_breakpoint"); fired = true;
 break;
 }
 }
 }
 }
 LogPerf(L"Periodic.HardwareBreakpointMonitor", GetTickCount64() - t0);
 }

 // ===== PRIORITY 3.3.2: Suspicious Memory Scanner =====
 if (g_pMemScanner) {
 t0 = GetTickCount64();
 if (g_pMemScanner->ScanMemory()) {
 auto suspiciousRegions = g_pMemScanner->GetSuspiciousRegions();
 if (!suspiciousRegions.empty()) {
 for (const auto& region : suspiciousRegions) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", region.baseAddress);
 dr.processName = L"<memory_" + std::wstring(addrbuf) + L">";
 dr.reason = std::wstring(L"Suspicious memory region: reason=") + std::wstring(region.suspiciousReason.begin(), region.suspiciousReason.end()) + L", size=" + std::to_wstring(region.size);
 dr.indicatorCount = (region.hasShellcodePattern || region.hasNOPSled) ? 5 : 3;
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "suspicious_memory"); fired = true;
 break;
 }
 }
 }
 }
 LogPerf(L"Periodic.SuspiciousMemoryScanner", GetTickCount64() - t0);
 }

 // ===== PRIORITY 3.3.3: Heap Spray Analyzer =====
 if (g_pHeapSpray) {
 t0 = GetTickCount64();
 if (g_pHeapSpray->AnalyzeHeaps()) {
 auto detections = g_pHeapSpray->GetDetections();
 if (!detections.empty()) {
 for (const auto& detection : detections) {
 if (detection.likelyExploit) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", detection.baseAddress);
 dr.processName = L"<heap_spray_" + std::wstring(addrbuf) + L">";
 dr.reason = std::wstring(L"Heap spray detected: ") + std::wstring(detection.patternDescription.begin(), detection.patternDescription.end()) + L", risk=" + std::to_wstring(detection.riskScore);
 dr.indicatorCount = 5; // High severity for likely exploits
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "heap_spray"); fired = true;
 break;
 }
 }
 }
 }
 }
 LogPerf(L"Periodic.HeapSprayAnalyzer", GetTickCount64() - t0);
 }

 // ===== PRIORITY 3.1.2: ETHREAD Manipulation Detector =====
 if (g_pETHREADDetector) {
 static ULONGLONG lastETHREADScan = 0;
 ULONGLONG now = GetTickCount64();
 if (now - lastETHREADScan >= g_cfg.cooldownETHREADMs) {
 lastETHREADScan = now;
 t0 = GetTickCount64();
 DWORD hiddenCount = g_pETHREADDetector->ScanForHiddenThreads();
 if (hiddenCount > 0) {
 auto hiddenThreads = g_pETHREADDetector->GetHiddenThreads();
 for (const auto& thread : hiddenThreads) {
 if (thread.IsHidden || thread.IsSuspicious) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 dr.processName = L"<hidden_thread_" + std::to_wstring(thread.ThreadId) + L">";
 dr.reason = std::wstring(L"Hidden/suspicious thread detected: ") + std::wstring(thread.DetectionReason.begin(), thread.DetectionReason.end());
 dr.indicatorCount = thread.IsHidden ? 5 : 3;
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "hidden_thread"); fired = true;
 break;
 }
 }
 }
 }
 LogPerf(L"Periodic.ETHREADDetector", GetTickCount64() - t0);
 }
 }

 // ===== PRIORITY 3.2.2: Kernel Callback Scanner =====
 if (g_pCallbackScanner) {
 static ULONGLONG lastCallbackScan = 0;
 ULONGLONG now = GetTickCount64();
 if (now - lastCallbackScan >= g_cfg.cooldownCallbackMs) {
 lastCallbackScan = now;
 t0 = GetTickCount64();
 DWORD anomalyCount = g_pCallbackScanner->ScanAllCallbacks();
 if (anomalyCount > 0) {
 auto anomalies = g_pCallbackScanner->GetAnomalies();
 for (const auto& anomaly : anomalies) {
 if (anomaly.IsUnhooked || anomaly.IsSuspicious) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 std::wstring driverName(anomaly.DriverName.begin(), anomaly.DriverName.end());
 dr.processName = L"<callback_anomaly_" + driverName + L">";
 dr.reason = std::wstring(L"Kernel callback anomaly: ") + std::wstring(anomaly.AnomalyReason.begin(), anomaly.AnomalyReason.end());
 dr.indicatorCount = anomaly.IsUnhooked ? 5 : 3;
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "callback_unhook"); fired = true;
 break;
 }
 }
 }
 }
 LogPerf(L"Periodic.CallbackScanner", GetTickCount64() - t0);
 }
 }

 // ===== PRIORITY 3.3.1: VAD Manipulation Detector =====
 if (g_pVADDetector) {
 static ULONGLONG lastVADScan = 0;
 ULONGLONG now = GetTickCount64();
 if (now - lastVADScan >= g_cfg.cooldownVADMs) {
 lastVADScan = now;
 t0 = GetTickCount64();
 DWORD anomalyCount = g_pVADDetector->ScanForVADManipulation();
 if (anomalyCount > 0) {
 auto anomalies = g_pVADDetector->GetAnomalies();
 for (const auto& anomaly : anomalies) {
 if (anomaly.IsSuspicious) {
 DetectionResult dr{}; dr.detected = true; dr.pid = GetCurrentProcessId();
 wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", (void*)anomaly.StartingAddress);
 dr.processName = L"<vad_anomaly_" + std::wstring(addrbuf) + L">";
 dr.reason = std::wstring(L"VAD manipulation detected: ") + std::wstring(anomaly.DetectionReason.begin(), anomaly.DetectionReason.end());
 dr.indicatorCount = 4; // High severity for VAD tampering
 if (dr.indicatorCount >= g_cfg.closeThreshold) {
 ProcessDetection(dr, "vad_manipulation"); fired = true;
 break;
 }
 }
 }
 }
    LogPerf(L"Periodic.VADDetector", GetTickCount64() - t0);
    }
    }

    // ===== PRIORITY 4.3.1/4.3.2: Update CPU usage, adaptive polling, and execute scheduled prioritized tasks =====
    if (g_pScanPrioritizer) {
        // Update CPU usage for load balancing and adaptive polling
        float cpuUsage = GetCurrentCpuUsage();
        g_pScanPrioritizer->UpdateCpuUsage(cpuUsage);
        if (g_pAdaptivePollingManager) {
            g_pAdaptivePollingManager->Update(cpuUsage);
        }
        
        // Execute pending tasks with configured budget
        DWORD budget = g_cfg.scanPrioritizationBudgetMs;
        g_pScanPrioritizer->ExecutePendingTasks(budget);
        
        // Update dynamic priorities based on detection rates
        if (g_cfg.enableDynamicPriorityAdjustment) {
            static ULONGLONG lastPriorityUpdate = 0;
            ULONGLONG now = GetTickCount64();
            if (now - lastPriorityUpdate >= g_cfg.statisticsUpdateIntervalMs) {
                g_pScanPrioritizer->UpdateDynamicPriorities();
                lastPriorityUpdate = now;
            }
        }
        
        // Debug info if logging enabled
        if (g_cfg.enableLogging) {
            static ULONGLONG lastDebugPrint = 0;
            ULONGLONG now = GetTickCount64();
            if (now - lastDebugPrint >= 60000) { // Print every 60 seconds
                g_pScanPrioritizer->PrintDebugInfo();
                lastDebugPrint = now;
            }
        }
    }
    else if (g_pAdaptivePollingManager) {
        // Even if prioritizer disabled, still update adaptive polling with CPU
        float cpuUsage = GetCurrentCpuUsage();
        g_pAdaptivePollingManager->Update(cpuUsage);
    }

    return fired;
 };
 DWORD interval = g_cfg.periodicScanIntervalMs;
 if (g_cfg.aggressiveDetection && interval > 5000) interval = 5000; // faster periodic scans
 g_pPeriodic->Start(interval);
}

static DWORD WINAPI InitThreadProc(LPVOID)
{
    LoadClientConfig(g_cfg, GetDllDirectory(g_hModule));
    ClampConfig();
    LogIfEnabled(L"[Oblivion] Init thread started\n");

    // ===== PRIORITY 4.1.1: Initialize Telemetry Collector =====
    if (g_cfg.enableTelemetry) {
        try {
            g_pTelemetryCollector = new TelemetryCollector();
            g_pTelemetry = g_pTelemetryCollector; // Set global instance
            g_pTelemetryCollector->SetEnabled(true);
            g_pTelemetryCollector->SetCollectionIntervalMs(g_cfg.telemetryCollectionIntervalMs);
            g_pTelemetryCollector->SetAggregationPeriodMs(g_cfg.telemetryAggregationPeriodMs);
            g_pTelemetryCollector->Start();
            LogIfEnabled(L"[Oblivion] Telemetry collector started\n");
        } catch (...) {
            g_pTelemetryCollector = nullptr;
            g_pTelemetry = nullptr;
            LogIfEnabled(L"[Oblivion] Telemetry collector failed to start\n");
        }
    }

    // ===== PRIORITY 4.1.2: Initialize ML Feature Extractor =====
    if (g_cfg.enableTelemetry && g_pTelemetryCollector) {
        try {
            g_pMLFeatureExtractor = new MLFeatureExtractor();
            FeatureExtractionConfig feConfig;
            // Use default config or customize from client_config later
            g_pMLFeatureExtractor->SetConfig(feConfig);
            LogIfEnabled(L"[Oblivion] ML Feature Extractor initialized\n");
        } catch (...) {
            g_pMLFeatureExtractor = nullptr;
            LogIfEnabled(L"[Oblivion] ML Feature Extractor failed to initialize\n");
        }
    }

    // ===== PRIORITY 4.1.3: Initialize ML Anomaly Detector =====
    if (g_cfg.enableMLAnomalyDetection && g_pMLFeatureExtractor && g_pTelemetryCollector) {
        try {
            MLAnomalyDetectorConfig mlConfig;
            mlConfig.enableIsolationForest = g_cfg.mlUseIsolationForest;
            mlConfig.enableOneClass = g_cfg.mlUseOneClass;
            mlConfig.useEnsemble = g_cfg.mlUseEnsemble;
            mlConfig.ensembleWeight = g_cfg.mlEnsembleWeight;
            mlConfig.isolationForestTrees = g_cfg.mlIsolationForestTrees;
            mlConfig.isolationForestSubsampleSize = g_cfg.mlIsolationForestSubsampleSize;
            mlConfig.isolationForestMaxDepth = g_cfg.mlIsolationForestMaxDepth;
            mlConfig.oneClassNu = g_cfg.mlOneClassNu;
            mlConfig.anomalyThreshold = g_cfg.mlAnomalyThreshold;
            mlConfig.minTrainingSamples = g_cfg.mlMinTrainingSamples;
            mlConfig.maxTrainingSamples = g_cfg.mlMaxTrainingSamples;
            mlConfig.enableOnlineLearning = g_cfg.mlEnableOnlineLearning;
            mlConfig.onlineUpdateInterval = g_cfg.mlOnlineUpdateInterval;
            mlConfig.onlineLearningRate = g_cfg.mlOnlineLearningRate;
            mlConfig.enableModelPersistence = g_cfg.mlEnableModelPersistence;
            mlConfig.modelSavePath = g_cfg.mlModelSavePath;

            g_pMLAnomalyDetector = new MLAnomalyDetector(mlConfig);
            g_pMLAnomalyDetector->Initialize(g_pMLFeatureExtractor, g_pTelemetryCollector);
            g_pMLAnomalyDetector = g_pMLAnomalyDetector; // Set global instance
            
            LogIfEnabled(L"[Oblivion] ML Anomaly Detector initialized\n");
            
            // Start warm-up period: collect initial normal behavior samples
            // The model will train after collecting enough samples (min_training_samples)
        } catch (...) {
            g_pMLAnomalyDetector = nullptr;
            LogIfEnabled(L"[Oblivion] ML Anomaly Detector failed to initialize\n");
        }
    }

    // ===== PRIORITY 4.1.4: Initialize Adaptive Threshold Manager =====
    if (g_cfg.enableAdaptiveThresholds && g_pTelemetryCollector) {
        try {
            AdaptiveThresholdConfig adaptiveConfig;
            adaptiveConfig.enableAdaptiveThresholds = g_cfg.enableAdaptiveThresholds;
            adaptiveConfig.usePerPlayerProfiles = g_cfg.usePerPlayerProfiles;
            adaptiveConfig.useGlobalBaseline = g_cfg.useGlobalBaseline;
            adaptiveConfig.defaultSigmaMultiplier = g_cfg.defaultSigmaMultiplier;
            adaptiveConfig.minBaselineSamples = g_cfg.minBaselineSamples;
            adaptiveConfig.maxProfileAge = g_cfg.maxProfileAgeHours;
            adaptiveConfig.globalMinThreshold = g_cfg.adaptiveMinThreshold;
            adaptiveConfig.globalMaxThreshold = g_cfg.adaptiveMaxThreshold;
            adaptiveConfig.decayRate = g_cfg.adaptiveDecayRate;
            adaptiveConfig.trustScoreInitial = g_cfg.trustScoreInitial;
            adaptiveConfig.trustScoreIncrement = g_cfg.trustScoreIncrement;
            adaptiveConfig.trustScoreDecrement = g_cfg.trustScoreDecrement;

            g_pAdaptiveThresholdManager = new AdaptiveThresholdManager(adaptiveConfig);
            g_pAdaptiveThresholdManager->Initialize(g_pTelemetryCollector, g_pMLAnomalyDetector);
            
            // Set HWID as player ID for this session
            std::string playerID = "HWID_" + GetHWID();
            g_pAdaptiveThresholdManager->SetActivePlayer(playerID);
            
            LogIfEnabled(L"[Oblivion] Adaptive Threshold Manager initialized\n");
        } catch (...) {
            g_pAdaptiveThresholdManager = nullptr;
            LogIfEnabled(L"[Oblivion] Adaptive Threshold Manager failed to initialize\n");
        }
    }

    // ===== PRIORITY 4.3.1: Initialize Scan Prioritization Manager =====
    if (g_cfg.enableScanPrioritization) {
        try {
            ScanPrioritizationConfig spcfg;
            spcfg.enablePrioritization = g_cfg.enableScanPrioritization;
            spcfg.enableDynamicAdjustment = g_cfg.enableDynamicPriorityAdjustment;
            spcfg.enableLoadBalancing = g_cfg.enableLoadBalancing;
            spcfg.cpuThresholdPercent = g_cfg.cpuThresholdPercent;
            spcfg.criticalScanMaxDelayMs = g_cfg.criticalScanMaxDelayMs;
            spcfg.highScanMaxDelayMs = g_cfg.highScanMaxDelayMs;
            spcfg.recentDetectionBoostWeight = g_cfg.recentDetectionBoostWeight;
            spcfg.detectionRateBoostWeight = g_cfg.detectionRateBoostWeight;
            spcfg.falsePositivePenaltyWeight = g_cfg.falsePositivePenaltyWeight;
            spcfg.recentDetectionWindowMs = g_cfg.recentDetectionWindowMs;
            spcfg.statisticsUpdateIntervalMs = g_cfg.statisticsUpdateIntervalMs;
            
            g_pScanPrioritizer = new ScanPrioritizationManager(spcfg);
            if (g_pScanPrioritizer->Initialize()) {
                g_pScanPrioritizer->SetTelemetryCollector(g_pTelemetryCollector);
                // Register a few key scanners with metadata
                ScannerInfo si;
                si.name = "CEBehaviorMonitor"; si.displayName = "CE Behavior Monitor"; si.priority = ScanPriority::HIGH; si.pathType = ScanPathType::HOT_PATH; si.minIntervalMs = 1000; si.canBeSkipped = false;
                g_pScanPrioritizer->RegisterScanner(si.name, si);

                si.name = "CERegistryScanner"; si.displayName = "CE Registry Scanner"; si.priority = ScanPriority::NORMAL; si.pathType = ScanPathType::WARM_PATH; si.minIntervalMs = 5000; si.canBeSkipped = true;
                g_pScanPrioritizer->RegisterScanner(si.name, si);

                si.name = "CEWindowScanner"; si.displayName = "CE Window Scanner"; si.priority = ScanPriority::NORMAL; si.pathType = ScanPathType::WARM_PATH; si.minIntervalMs = 5000; si.canBeSkipped = true;
                g_pScanPrioritizer->RegisterScanner(si.name, si);

                si.name = "SpeedHackDetector"; si.displayName = "Speed Hack Detector"; si.priority = ScanPriority::HIGH; si.pathType = ScanPathType::HOT_PATH; si.minIntervalMs = 1000; si.canBeSkipped = false;
                g_pScanPrioritizer->RegisterScanner(si.name, si);

                si.name = "DeviceObjectScanner"; si.displayName = "Device Object Scanner"; si.priority = ScanPriority::HIGH; si.pathType = ScanPathType::HOT_PATH; si.minIntervalMs = 2000; si.canBeSkipped = false;
                g_pScanPrioritizer->RegisterScanner(si.name, si);

            si.name = "NetworkArtifactScanner"; si.displayName = "Network Artifact Scanner"; si.priority = ScanPriority::NORMAL; si.pathType = ScanPathType::WARM_PATH; si.minIntervalMs = 5000; si.canBeSkipped = true;
            g_pScanPrioritizer->RegisterScanner(si.name, si);
            }
            LogIfEnabled(L"[Oblivion] Scan Prioritization Manager initialized\n");
        } catch (...) {
            g_pScanPrioritizer = nullptr;
            LogIfEnabled(L"[Oblivion] Scan Prioritization Manager failed to initialize\n");
        }
    }

    // ===== PRIORITY 4.3.2: Initialize Adaptive Polling Manager =====
    if (g_cfg.enableAdaptivePolling) {
        try {
            AdaptivePollingConfig apCfg;
            apCfg.enableAdaptivePolling = g_cfg.enableAdaptivePolling;
            apCfg.baseIntervalMs = g_cfg.periodicScanIntervalMs;
            apCfg.minIntervalMs = g_cfg.adaptiveMinIntervalMs;
            apCfg.maxIntervalMs = g_cfg.adaptiveMaxIntervalMs;
            apCfg.minChangeCooldownMs = g_cfg.adaptiveChangeCooldownMs;
            apCfg.minChangePercent = g_cfg.adaptiveMinChangePercent;
            apCfg.mediumRateThreshold = g_cfg.adaptiveMediumRateThreshold;
            apCfg.highRateThreshold = g_cfg.adaptiveHighRateThreshold;
            apCfg.criticalRateThreshold = g_cfg.adaptiveCriticalRateThreshold;
            apCfg.cpuLowPercent = g_cfg.adaptiveCpuLowPercent;
            apCfg.cpuHighPercent = g_cfg.adaptiveCpuHighPercent;

            g_pAdaptivePollingManager = new AdaptivePollingManager(apCfg);
            // Note: PeriodicScanner not yet created; bind it inside SchedulePeriodicScans after g_pPeriodic exists
            g_pAdaptivePolling = g_pAdaptivePollingManager; // set global alias
            LogIfEnabled(L"[Oblivion] Adaptive Polling Manager initialized\n");
        } catch (...) {
            g_pAdaptivePollingManager = nullptr;
            LogIfEnabled(L"[Oblivion] Adaptive Polling Manager failed to initialize\n");
        }
    }

    try {
        g_pNetClient = new NetworkClient();
        if (!g_pNetClient->Initialize(g_cfg.serverIp, g_cfg.serverPort)) {
            LogIfEnabled(L"[Oblivion] Network init failed\n");
        }
    } catch (...) {
        LogIfEnabled(L"[Oblivion] Exception during NetworkClient init\n");
        if (g_pNetClient) { delete g_pNetClient; g_pNetClient = nullptr; }
    }

    if (g_cfg.enableHmacAuth && !g_cfg.hmacSecret.empty()) {
        g_pNetClient->SetHmacSecret(g_cfg.hmacSecret);
    }

    if (g_cfg.enableHeartbeat) {
        try {
            g_pHeartbeat = new Heartbeat(g_pNetClient);
            g_pHeartbeat->Start(g_cfg.heartbeatIntervalMs);
        } catch (...) {
            g_pHeartbeat = nullptr;
        }
    }

    // Start kernel bridge (best-effort; will no-op if driver not present)
    if (g_cfg.enableKernelBridge) {
        KernelBridge_Start(g_pNetClient);
    }

    // ===== PRIORITY 4.2.1: Initialize Signature Database =====
    try {
        g_pSignatureDB = new SignatureDatabase();
        std::wstring sigPath = GetDllDirectory(g_hModule) + L"\\signatures\\ce_signatures.json";
        if (g_pSignatureDB->LoadFromJson(sigPath)) {
            LogIfEnabled(L"[Oblivion] Signature database loaded\n");
            wchar_t buf[256];
            swprintf_s(buf, L"[Oblivion] Loaded %d signatures (%d enabled)\n", 
                       g_pSignatureDB->GetTotalSignatureCount(),
                       g_pSignatureDB->GetEnabledSignatureCount());
            LogIfEnabled(buf);
        } else {
            LogIfEnabled(L"[Oblivion] Warning: Failed to load signature database\n");
            // Continue execution - signature DB is optional
        }
    } catch (...) {
        g_pSignatureDB = nullptr;
        LogIfEnabled(L"[Oblivion] Exception during SignatureDatabase init\n");
    }

    // Signature pack poller for fast YARA-like rollout (best-effort)
    try {
        g_pSigMgr = new SignaturePackManager(g_cfg.serverIp, g_cfg.serverPort, &g_cfg);
        g_pSigMgr->Start(60000); // poll every 60s
    } catch (...) {
        g_pSigMgr = nullptr;
    }

    // Start ETW-based heuristics with configurable thresholds
    try {
        int etwThr = g_cfg.etwBurstThreshold > 0 ? g_cfg.etwBurstThreshold : g_cfg.antiDebugThreshold;
        DWORD etwWindow = g_cfg.etwWindowMs ? g_cfg.etwWindowMs : (g_cfg.detectionCooldownMs ? g_cfg.detectionCooldownMs/2 : 3000);
        if (g_cfg.aggressiveDetection) {
            if (etwThr > 5) etwThr = 5;
            if (etwWindow > 2000) etwWindow = 2000;
        }
        if (etwWindow < 500) etwWindow = 500; // clamp min
        g_pEtw = new EtwHeuristics(g_pNetClient, etwThr, etwWindow);
        g_pEtw->SetMemscanMinStreak(g_cfg.aggressiveDetection ? min(g_cfg.etwMemscanMinStreak, 3) : g_cfg.etwMemscanMinStreak);
        g_pEtw->Start();
    } catch (...) {
        g_pEtw = nullptr;
    }

    // ===== PRIORITY 4.2.4: Optional Signature Testing (background, best-effort) =====
    if (g_cfg.enableSignatureTesting) {
        try {
            std::wstring dllDir = GetDllDirectory(g_hModule);
            std::wstring rulesPath = g_cfg.signatureYaraRulesPath.empty() ? (dllDir + L"\\signatures\\yara_rules.txt") : g_cfg.signatureYaraRulesPath;
            std::wstring testsCsv = g_cfg.signatureTestsCsvPath;
            // Run tests on a worker thread to avoid blocking init
            auto hThread = CreateThread(nullptr, 0, [](LPVOID ctx)->DWORD{
                std::wstring* params = reinterpret_cast<std::wstring*>(ctx);
                std::wstring rules = params[0];
                std::wstring tests = params[1];
                delete[] params;
                std::vector<SigTestCase> cases;
                SigTestReport report;
                if (SignatureTestFramework::LoadTestsFromCsv(tests, cases)) {
                    if (SignatureTestFramework::RunYaraTests(rules, cases, report)) {
                        std::wstring outCsv = L"Debug\\reports_signature_tests.csv";
                        std::wstring outJson = L"Debug\\reports_signature_tests.json";
                        SignatureTestFramework::SaveReportCsv(outCsv, report);
                        SignatureTestFramework::SaveReportJson(outJson, report);
                    }
                }
                return 0;
            }, new std::wstring[2]{ rulesPath, testsCsv }, 0, nullptr);
            if (hThread) CloseHandle(hThread);
        } catch (...) {
            // ignore - testing is optional
        }
    }

    // Start CE Behavior Monitor for detecting memory scanning patterns
    if (g_cfg.enableCEBehaviorMonitor) {
        try {
            g_pCEBehavior = new CEBehaviorMonitor();
            int thr = g_cfg.ceBehaviorThreshold;
            DWORD win = g_cfg.ceBehaviorWindowMs;
            DWORD poll = g_cfg.ceBehaviorPollMs;
            if (g_cfg.aggressiveDetection) {
                if (thr > 3) thr = 3;
                if (win > 3000) win = 3000;
                if (poll > 300) poll = 300;
            }
            g_pCEBehavior->SetThreshold(thr);
            g_pCEBehavior->SetMonitorWindowMs(win);
            g_pCEBehavior->SetPollingIntervalMs(poll);
            g_pCEBehavior->Start();
        } catch (...) {
            g_pCEBehavior = nullptr;
        }
    }

    // Start CE Registry Scanner
    if (g_cfg.enableCERegistryScanner) {
        try {
            g_pCERegistry = new CERegistryScanner();
            // Registry scanner is passive, scanned on-demand in periodic scans
        } catch (...) {
            g_pCERegistry = nullptr;
        }
    }

    // Start CE Window Scanner
    if (g_cfg.enableCEWindowScanner) {
        try {
            g_pCEWindow = new CEWindowScanner();
            // Window scanner is passive, scanned on-demand in periodic scans
        } catch (...) {
            g_pCEWindow = nullptr;
        }
    }

    // Start Speed Hack Detector
    if (g_cfg.enableSpeedHackDetector) {
        try {
            g_pSpeedHack = new SpeedHackDetector();
            int sens = g_cfg.speedHackSensitivity;
            DWORD sInt = g_cfg.speedHackMonitorIntervalMs;
            if (g_cfg.aggressiveDetection) {
                if (sInt > 500) sInt = 500;
            }
            g_pSpeedHack->SetSensitivity(sens);
            g_pSpeedHack->SetMonitorIntervalMs(sInt);
            g_pSpeedHack->Start();
            // Wire NetworkClient packet hook to feed network packet timings
            NetworkClient_SetPacketHook([](unsigned long long ts, size_t sz, bool outgoing){
                if (g_pSpeedHack) g_pSpeedHack->RecordNetworkPacket(ts, sz, outgoing);
            });
        } catch (...) {
            g_pSpeedHack = nullptr;
        }
    }

    // ===== PRIORITY 2.2: Initialize Device Object Scanner =====
    try {
        g_pDeviceScanner = new DeviceObjectScanner();
        g_pDeviceScanner->SetThreshold(2); // Moderate threshold for DBK detection
    } catch (...) {
        g_pDeviceScanner = nullptr;
    }

    // ===== PRIORITY 2.3.1: Initialize Network Artifact Scanner =====
    try {
        g_pNetArtifact = new NetworkArtifactScanner();
        g_pNetArtifact->SetThreshold(2); // Moderate threshold for CE server detection
    } catch (...) {
        g_pNetArtifact = nullptr;
    }

    // ===== PRIORITY 3: Initialize Stealth & Evasion Detection Modules =====
    
    // Priority 3.1.1: PEB Manipulation Detector
    if (g_cfg.enablePEBManipulationDetector) {
        try {
            g_pPEBDetector = new PEBManipulationDetector();
            HANDLE hSelf = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
            g_pPEBDetector->SetTargetProcess(hSelf, GetCurrentProcessId());
            g_pPEBDetector->SetEnableMemoryScan(g_cfg.pebEnableMemoryScan);
            g_pPEBDetector->SetEnableToolHelpValidation(g_cfg.pebEnableToolHelpValidation);
        } catch (...) {
            g_pPEBDetector = nullptr;
        }
    }

    // Priority 3.2: Hardware Breakpoint Monitor
    if (g_cfg.enableHardwareBreakpointMonitor) {
        try {
            g_pHWBPMonitor = new HardwareBreakpointMonitor();
            g_pHWBPMonitor->SetTargetProcess(GetCurrentProcessId());
            g_pHWBPMonitor->SetMaxBreakpointsThreshold(g_cfg.hwbpMaxThreshold);
            g_pHWBPMonitor->SetEnableAnomalyDetection(g_cfg.hwbpEnableAnomalyDetection);
            g_pHWBPMonitor->SetTrackHistory(g_cfg.hwbpTrackHistory);
        } catch (...) {
            g_pHWBPMonitor = nullptr;
        }
    }

    // Priority 3.3.2: Suspicious Memory Scanner
    if (g_cfg.enableSuspiciousMemoryScanner) {
        try {
            g_pMemScanner = new SuspiciousMemoryScanner();
            HANDLE hSelf = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
            g_pMemScanner->SetTargetProcess(hSelf, GetCurrentProcessId());
            g_pMemScanner->SetMinRegionSize(g_cfg.suspMemMinRegionSize);
            g_pMemScanner->SetEnablePatternAnalysis(g_cfg.suspMemEnablePatternAnalysis);
            g_pMemScanner->SetEnableEntropyCheck(g_cfg.suspMemEnableEntropyCheck);
            g_pMemScanner->SetEnableSIMD(g_cfg.enableSimdAcceleration);
            g_pMemScanner->SetFlagRWX(g_cfg.suspMemFlagRWX);
            g_pMemScanner->SetFlagPrivateExecutable(g_cfg.suspMemFlagPrivateExecutable);
        } catch (...) {
            g_pMemScanner = nullptr;
        }
    }

    // Priority 3.3.3: Heap Spray Analyzer
    if (g_cfg.enableHeapSprayAnalyzer) {
        try {
            g_pHeapSpray = new HeapSprayAnalyzer();
            HANDLE hSelf = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
            g_pHeapSpray->SetTargetProcess(hSelf, GetCurrentProcessId());
            g_pHeapSpray->SetMinSpraySize(g_cfg.heapSprayMinSize);
            g_pHeapSpray->SetMinRepeatCount(g_cfg.heapSprayMinRepeatCount);
            g_pHeapSpray->SetMinPatternDensity(g_cfg.heapSprayMinDensity);
            g_pHeapSpray->SetEnableNOPDetection(g_cfg.heapSprayEnableNOPDetection);
            g_pHeapSpray->SetEnableAddressSprayDetection(g_cfg.heapSprayEnableAddressSpray);
        } catch (...) {
            g_pHeapSpray = nullptr;
        }
    }

    // Priority 3.1.2: ETHREAD Manipulation Detector (requires kernel driver)
    if (g_cfg.enableETHREADDetector && KernelBridge_IsDriverAvailable()) {
        try {
            g_pETHREADDetector = new ETHREADManipulationDetector();
            g_pETHREADDetector->Initialize(KernelBridge_GetDriverHandle());
        } catch (...) {
            g_pETHREADDetector = nullptr;
        }
    }

    // Priority 3.2.2: Kernel Callback Scanner (requires kernel driver)
    if (g_cfg.enableCallbackScanner && KernelBridge_IsDriverAvailable()) {
        try {
            g_pCallbackScanner = new KernelCallbackScanner();
            g_pCallbackScanner->Initialize(KernelBridge_GetDriverHandle());
        } catch (...) {
            g_pCallbackScanner = nullptr;
        }
    }

    // Priority 3.3.1: VAD Manipulation Detector (requires kernel driver)
    if (g_cfg.enableVADDetector && KernelBridge_IsDriverAvailable()) {
        try {
            g_pVADDetector = new VADManipulationDetector();
            g_pVADDetector->Initialize(KernelBridge_GetDriverHandle());
            g_pVADDetector->SetSizeThreshold(g_cfg.vadSizeThreshold);
        } catch (...) {
            g_pVADDetector = nullptr;
        }
    }

    SchedulePeriodicScans();

    // ===== PRIORITY 4.3.3: SIMD Benchmark (optional) =====
    if (g_cfg.enableSimdBenchmark) {
        LogIfEnabled(L"[Oblivion] Running SIMD benchmark...\n");
        RunSimdBenchmark(g_cfg.simdBenchmarkIterations);
    }

    try {
        g_pWatcher = new ProcessThreadWatcher();
    } catch (...) {
        g_pWatcher = nullptr;
    }
    if (g_pWatcher && g_pWatcher->Initialize()) {
        g_pWatcher->SetCloseThreshold(g_cfg.closeThreshold);
        g_pWatcher->SetPollingIntervalMs(g_cfg.pollingIntervalMs);

        ULONGLONG t0 = GetTickCount64();
        DetectionResult result = g_pWatcher->RunOnceScan();
        LogPerf(L"ProcessThreadWatcher.FirstScan", GetTickCount64() - t0);
        if (result.detected && result.indicatorCount >= g_cfg.closeThreshold) {
            ProcessDetection(result, "process");
            CleanupGlobals();
            return 0;
        }

        if (g_cfg.enableOverlayScanner) {
            t0 = GetTickCount64();
            OverlayScanner overlay;
            int overlayThreshold = g_cfg.overlayThreshold > 0 ? g_cfg.overlayThreshold : 3;
            if (overlayThreshold < g_cfg.closeThreshold) overlayThreshold = g_cfg.closeThreshold;
            overlay.SetCloseThreshold(overlayThreshold);

            OverlayFinding of{};
            bool hit = overlay.RunOnceScan(of);
            LogPerf(L"OverlayScanner.RunOnceScan", GetTickCount64() - t0);
            if (hit) {
                DetectionResult od{};
                od.detected = true;
                od.pid = of.pid;
                od.processName = of.windowTitle.empty() ? of.className : of.windowTitle;
                od.reason = L"Suspicious overlay detected: title='" + od.processName + L"' class='" + of.className + L"'";
                od.indicatorCount = of.indicators;

                if (od.indicatorCount >= overlayThreshold) {
                    ProcessDetection(od, "overlay");
                    CleanupGlobals();
                    return 0;
                }
            }
        }

        if (g_cfg.enableAntiDebug) {
            t0 = GetTickCount64();
            AntiDebug ad; ad.SetThreshold(g_cfg.antiDebugThreshold);
            DetectionResult dbg{};
            bool hit = ad.RunScan(dbg);
            LogPerf(L"AntiDebug.RunScan", GetTickCount64() - t0);
            if (hit) {
                ProcessDetection(dbg, "antidebug");
                CleanupGlobals();
                return 0;
            }
        }

        if (g_cfg.enableInjectionScanner) {
            t0 = GetTickCount64();
            InjectionScanner inj; inj.SetThreshold(g_cfg.injectionThreshold);
            auto prefixes = ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes);
            inj.SetWhitelistPrefixes(prefixes);
            InjectionFinding inf{};
            bool hit = inj.RunOnceScan(inf);
            LogPerf(L"InjectionScanner.RunOnceScan", GetTickCount64() - t0);
            if (hit) {
                DetectionResult rd{};
                rd.detected = true;
                rd.pid = GetCurrentProcessId();
                rd.processName = inf.moduleName;
                rd.reason = L"Suspicious module injected: " + inf.modulePath;
                rd.indicatorCount = inf.indicators;

                if (rd.indicatorCount >= g_cfg.injectionThreshold) {
                    ProcessDetection(rd, "injection");
                    CleanupGlobals();
                    return 0;
                }
            }
        }

        if (g_cfg.enableSignatureValidator) {
            t0 = GetTickCount64();
            DigitalSignatureValidator dsv; dsv.SetThreshold(g_cfg.signatureThreshold);
            auto prefixes = ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes);
            dsv.SetWhitelistPrefixes(prefixes);
            dsv.SetSkipModuleNames(ParseWhitelistPrefixes(g_cfg.signatureSkipNames));
            SignatureFinding sf{};
            bool hit = dsv.RunOnceScan(sf);
            LogPerf(L"DigitalSignatureValidator.RunOnceScan", GetTickCount64() - t0);
            if (hit) {
                // Skip sigcheck for RRO.exe (hard guard) in addition to configured skip list
                if (!(IsRROExecutable(sf.moduleName) || IsRROExecutable(sf.modulePath))) {
                    DetectionResult sd{};
                    sd.detected = true;
                    sd.pid = GetCurrentProcessId();
                    sd.processName = sf.moduleName;
                    sd.reason = L"Untrusted signature or suspicious module: " + sf.modulePath;
                    sd.indicatorCount = sf.indicators;
                    if (sd.indicatorCount >= g_cfg.signatureThreshold) {
                        ProcessDetection(sd, "sigcheck");
                        CleanupGlobals();
                        return 0;
                    }
                }
            }
        }

        if (g_cfg.enableHijackedThreadScanner) {
            t0 = GetTickCount64();
            HijackedThreadScanner hts; hts.SetThreshold(g_cfg.hijackedThreadThreshold);
            auto prefixes = ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes);
            hts.SetWhitelistPrefixes(prefixes);
            HijackedThreadFinding hf{};
            bool hit = hts.RunOnceScan(hf);
            LogPerf(L"HijackedThreadScanner.RunOnceScan", GetTickCount64() - t0);
            if (hit) {
                DetectionResult td{};
                td.detected = true;
                td.pid = GetCurrentProcessId();
                wchar_t addrbuf[32]; swprintf_s(addrbuf, L"0x%p", hf.startAddress);
                td.processName = hf.moduleName.empty() ? L"<unknown>" : hf.moduleName;
                td.reason = std::wstring(L"Suspicious thread start: TID=") + std::to_wstring(hf.tid) + L", start=" + addrbuf + L", module=" + (hf.moduleName.empty() ? L"<unknown>" : hf.moduleName);
                td.indicatorCount = hf.indicators;
                if (td.indicatorCount >= g_cfg.hijackedThreadThreshold) {
                    ProcessDetection(td, "hijackedthread");
                    CleanupGlobals();
                    return 0;
                }
            }
        }

        if (g_cfg.enableIATHookScanner) {
            t0 = GetTickCount64();
            IATHookScanner iat; iat.SetThreshold(g_cfg.iatHookThreshold);
            auto prefixes = ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes);
            iat.SetWhitelistModules(prefixes);
            IATHookFinding f{};
            bool hit = iat.RunOnceScan(f);
            LogPerf(L"IATHookScanner.RunOnceScan", GetTickCount64() - t0);
            if (hit) {
                DetectionResult id{};
                id.detected = true;
                id.pid = GetCurrentProcessId();
                id.processName = f.moduleName.empty() ? L"<unknown>" : f.moduleName;
                wchar_t iatbuf[32]; swprintf_s(iatbuf, L"0x%p", f.iatAddress);
                wchar_t tgtbuf[32]; swprintf_s(tgtbuf, L"0x%p", f.targetAddress);
                id.reason = std::wstring(L"IAT hook: module=") + id.processName + L", import='" + std::wstring(f.importName.begin(), f.importName.end()) + L"', iat=" + iatbuf + L", target=" + tgtbuf + L", targetModule=" + (f.targetModule.empty() ? L"<unknown>" : f.targetModule);
                id.indicatorCount = f.indicators;
                if (id.indicatorCount >= g_cfg.iatHookThreshold) {
                    ProcessDetection(id, "iathook");
                    CleanupGlobals();
                    return 0;
                }
            }
        }

        // New: Code integrity scan (inline hook, RX/RWX regions, .text drift)
        {
            t0 = GetTickCount64();
            CodeIntegrityScanner cis; cis.SetThreshold(g_cfg.signatureThreshold); // reuse threshold
            cis.SetWhitelistPrefixes(ParseWhitelistPrefixes(g_cfg.moduleWhitelistPrefixes));
            DetectionResult ci{}; if (cis.RunOnceScan(ci)) { ProcessDetection(ci, "codeint"); CleanupGlobals(); return 0; }
            LogPerf(L"CodeIntegrityScanner.RunOnceScan", GetTickCount64() - t0);
        }

        if (g_cfg.enableFileIntegrityCheck && !g_cfg.integrityItems.empty()) {
            t0 = GetTickCount64();
            auto items = ParseIntegrityItems(GetDllDirectory(g_hModule), g_cfg.integrityItems);
            FileIntegrityChecker fic; fic.SetItems(items);
            IntegrityFinding fi{};
            bool hit = fic.RunOnceScan(fi);
            LogPerf(L"FileIntegrityChecker.RunOnceScan", GetTickCount64() - t0);
            if (hit) {
                DetectionResult ir{};
                ir.detected = true;
                ir.pid = GetCurrentProcessId();
                ir.processName = fi.path;
                std::wstring exp = fi.expectedHex.empty() ? L"<none>" : std::wstring(fi.expectedHex.begin(), fi.expectedHex.end());
                std::wstring act = fi.actualHex.empty() ? L"<none>" : std::wstring(fi.actualHex.begin(), fi.actualHex.end());
                ir.reason = L"Integrity mismatch: path='" + fi.path + L"' expected=" + exp + L" actual=" + act;
                ir.indicatorCount = fi.indicators;
                if (ir.indicatorCount >= 1) {
                    ProcessDetection(ir, "integrity");
                    CleanupGlobals();
                    return 0;
                }
            }
        }

        // Feature #6: Anti-Suspend heartbeat/watchdog
        if (g_cfg.enableAntiSuspend) {
            try {
                g_pAntiSuspend = new AntiSuspend();
                g_pAntiSuspend->Start(g_cfg.antiSuspendHeartbeatMs,
                                       g_cfg.antiSuspendStallWindowMs,
                                       g_cfg.antiSuspendMissesThreshold,
                                       AntiSuspendReportBridge);
            } catch (...) {
                g_pAntiSuspend = nullptr;
            }
        }

        if (g_cfg.enableBackgroundWatcher) {
            LogIfEnabled(L"[Oblivion] Starting background watcher\n");
            g_pWatcher->StartBackgroundWatcher();
        }
    }

    return 0;
}

static void CleanupGlobals()
{
    std::lock_guard<std::mutex> lock(g_cleanupMutex);
    
    // ===== PRIORITY 4: Export telemetry before cleanup =====
    if (g_pTelemetryCollector && g_cfg.telemetryExportOnExit) {
        std::wstring exportPath = g_cfg.telemetryExportPath;
        if (exportPath.empty()) {
            exportPath = L"telemetry_export.json";
        }
        // Make path relative to DLL directory
        std::wstring fullPath = GetDllDirectory(g_hModule) + L"\\" + exportPath;
        g_pTelemetryCollector->ExportToFile(fullPath, true);
        LogIfEnabled(L"[Oblivion] Telemetry exported\n");
    }
    
    // Stop background/periodic/etw/heartbeat before deleting
    if (g_pWatcher) { g_pWatcher->StopBackgroundWatcher(); delete g_pWatcher; g_pWatcher = nullptr; }
    if (g_pPeriodic) { g_pPeriodic->Stop(); delete g_pPeriodic; g_pPeriodic = nullptr; }
    if (g_pAntiSuspend) { g_pAntiSuspend->Stop(); delete g_pAntiSuspend; g_pAntiSuspend = nullptr; }
    if (g_pEtw) { g_pEtw->Stop(); delete g_pEtw; g_pEtw = nullptr; }
    if (g_pHeartbeat) { g_pHeartbeat->Stop(); delete g_pHeartbeat; g_pHeartbeat = nullptr; }
    if (g_pSigMgr) { g_pSigMgr->Stop(); delete g_pSigMgr; g_pSigMgr = nullptr; }
    if (g_pSignatureDB) { delete g_pSignatureDB; g_pSignatureDB = nullptr; }
    // ===== PRIORITY 4: Cleanup Infrastructure Modules =====
    if (g_pScanPrioritizer) { g_pScanPrioritizer->Shutdown(); delete g_pScanPrioritizer; g_pScanPrioritizer = nullptr; }
    if (g_pAdaptiveThresholdManager) { delete g_pAdaptiveThresholdManager; g_pAdaptiveThresholdManager = nullptr; }
    if (g_pAdaptivePollingManager) { delete g_pAdaptivePollingManager; g_pAdaptivePollingManager = nullptr; g_pAdaptivePolling = nullptr; }
    if (g_pMLAnomalyDetector) { delete g_pMLAnomalyDetector; g_pMLAnomalyDetector = nullptr; }
    if (g_pMLFeatureExtractor) { delete g_pMLFeatureExtractor; g_pMLFeatureExtractor = nullptr; }
    if (g_pTelemetryCollector) { g_pTelemetryCollector->Stop(); delete g_pTelemetryCollector; g_pTelemetryCollector = nullptr; g_pTelemetry = nullptr; }
    // Cleanup CE detection modules
    if (g_pCEBehavior) { g_pCEBehavior->Stop(); delete g_pCEBehavior; g_pCEBehavior = nullptr; }
    if (g_pCERegistry) { delete g_pCERegistry; g_pCERegistry = nullptr; }
    if (g_pCEWindow) { delete g_pCEWindow; g_pCEWindow = nullptr; }
    if (g_pSpeedHack) { g_pSpeedHack->Stop(); delete g_pSpeedHack; g_pSpeedHack = nullptr; }
    // ===== PRIORITY 2: Cleanup Advanced Detection Modules =====
    if (g_pDeviceScanner) { delete g_pDeviceScanner; g_pDeviceScanner = nullptr; }
    if (g_pNetArtifact) { delete g_pNetArtifact; g_pNetArtifact = nullptr; }
    // ===== PRIORITY 3: Cleanup Stealth & Evasion Detection Modules =====
    if (g_pPEBDetector) { delete g_pPEBDetector; g_pPEBDetector = nullptr; }
    if (g_pETHREADDetector) { g_pETHREADDetector->Cleanup(); delete g_pETHREADDetector; g_pETHREADDetector = nullptr; }
    if (g_pCallbackScanner) { g_pCallbackScanner->Cleanup(); delete g_pCallbackScanner; g_pCallbackScanner = nullptr; }
    if (g_pVADDetector) { g_pVADDetector->Cleanup(); delete g_pVADDetector; g_pVADDetector = nullptr; }
    if (g_pHWBPMonitor) { delete g_pHWBPMonitor; g_pHWBPMonitor = nullptr; }
    if (g_pMemScanner) { delete g_pMemScanner; g_pMemScanner = nullptr; }
    if (g_pHeapSpray) { delete g_pHeapSpray; g_pHeapSpray = nullptr; }
    if (g_cfg.enableKernelBridge) { KernelBridge_Stop(); }
    if (g_pNetClient) { delete g_pNetClient; g_pNetClient = nullptr; }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID /*lpReserved*/
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        // Spawn lightweight init thread and return immediately to avoid loader-lock
        HANDLE hThread = CreateThread(nullptr, 0, InitThreadProc, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
 {
 LogIfEnabled(L"[Oblivion] DLL_PROCESS_DETACH\n");
 CleanupGlobals();
 break;
 }
    }
    return TRUE;
}














































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































