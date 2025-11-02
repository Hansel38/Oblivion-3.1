#pragma once
#include <windows.h>
#include <string>
#include <vector>

// Structure to hold detection result
struct DetectionResult {
    bool detected;
    DWORD pid;
    std::wstring processName;
    std::wstring reason;
    int indicatorCount; // Multi-indicator count for threshold
    
    // ===== PRIORITY 4.1.5: ML Integration Fields =====
    bool mlEvaluated;           // Whether ML model was used for this detection
    double mlAnomalyScore;      // ML anomaly score (0.0-1.0, higher = more anomalous)
    double mlConfidence;        // ML confidence in the prediction (0.0-1.0)
    bool mlFlagged;             // Whether ML model flagged this as anomalous
    
    DetectionResult() 
        : detected(false)
        , pid(0)
        , indicatorCount(0)
        , mlEvaluated(false)
        , mlAnomalyScore(0.0)
        , mlConfidence(0.0)
        , mlFlagged(false)
    {}
};

// Process & Thread Watcher module
class ProcessThreadWatcher {
public:
    ProcessThreadWatcher();
    ~ProcessThreadWatcher();

    // Initialize the watcher (setup monitoring structures)
    bool Initialize();

    // Perform one full scan of all processes and threads
    DetectionResult RunOnceScan();

    // Start background monitoring thread (optional, polls for new processes)
    void StartBackgroundWatcher();

    // Stop background monitoring
    void StopBackgroundWatcher();

    // Check if a specific process is suspicious
    bool IsSuspiciousProcess(DWORD pid, std::wstring& reason);

    // Check if a specific thread is suspicious
    bool IsSuspiciousThread(DWORD tid, std::wstring& reason);

    // Config setters
    void SetCloseThreshold(int v) { m_closeThreshold = v; }
    void SetPollingIntervalMs(DWORD v) { m_pollingIntervalMs = v; }

private:
    // Blacklist of process names
    std::vector<std::wstring> m_processBlacklist;
    
    // Background monitoring
    HANDLE m_watcherThread;
    bool m_stopWatcher;
    DWORD m_pollingIntervalMs;

    // Configuration
    int m_closeThreshold;

    // Helper: convert string to lowercase
    std::wstring ToLower(const std::wstring& str);

    // Helper: check if process name matches blacklist
    bool IsBlacklisted(const std::wstring& processName);

    // Helper: get process path from PID
    std::wstring GetProcessPath(DWORD pid);

    // Helper: check if path is suspicious
    bool IsSuspiciousPath(const std::wstring& path);

    // Helper: get parent process ID
    DWORD GetParentProcessId(DWORD pid);

    // Helper: check thread start address
    bool IsThreadStartAddressSuspicious(DWORD tid, DWORD ownerPid, std::wstring& reason);

    // Background watcher thread function
    static DWORD WINAPI WatcherThreadProc(LPVOID lpParam);

    // Snapshot-based process enumeration
    std::vector<DWORD> GetCurrentProcessList();

    // Previous snapshot for diff detection
    std::vector<DWORD> m_previousProcessList;
};
