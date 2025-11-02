#pragma once
#include <Windows.h>
#include <vector>
#include <unordered_map>
#include <string>

// Debug register information
struct DebugRegisterInfo {
    DWORD threadId;
    DWORD_PTR dr0;
    DWORD_PTR dr1;
    DWORD_PTR dr2;
    DWORD_PTR dr3;
    DWORD_PTR dr6;  // Debug status register
    DWORD_PTR dr7;  // Debug control register
    DWORD timestamp;
    bool isActive;
};

// Breakpoint type enum
enum class BreakpointType {
    EXECUTE = 0,
    WRITE = 1,
    IO = 2,
    READ_WRITE = 3
};

// Breakpoint size enum
enum class BreakpointSize {
    ONE_BYTE = 0,
    TWO_BYTES = 1,
    EIGHT_BYTES = 2,
    FOUR_BYTES = 3
};

// Parsed hardware breakpoint
struct HardwareBreakpoint {
    int registerIndex;      // 0-3 (DR0-DR3)
    DWORD_PTR address;
    BreakpointType type;
    BreakpointSize size;
    bool enabled;
    bool local;
    bool global;
};

// Anomaly detection result
struct HardwareBreakpointAnomaly {
    DWORD threadId;
    std::string anomalyType;  // "EXCESSIVE_USE", "HIDDEN_DEBUGGER", "SUSPICIOUS_PATTERN", "CONTEXT_SWITCH_ANOMALY"
    std::string description;
    int breakpointCount;
    DWORD timestamp;
    std::vector<HardwareBreakpoint> breakpoints;
};

class HardwareBreakpointMonitor {
public:
    HardwareBreakpointMonitor();
    ~HardwareBreakpointMonitor();

    // Main scanning function
    bool ScanAllThreads();
    
    // Scan specific thread
    bool ScanThread(DWORD threadId);

    // Get results
    std::vector<DebugRegisterInfo> GetDebugRegisterData() const { return m_debugRegData; }
    std::vector<HardwareBreakpointAnomaly> GetAnomalies() const { return m_anomalies; }

    // Clear previous results
    void ClearResults();

    // Configuration
    void SetTargetProcess(DWORD pid);
    void SetMaxBreakpointsThreshold(int threshold) { m_maxBpThreshold = threshold; }
    void SetEnableAnomalyDetection(bool enable) { m_enableAnomalyDetection = enable; }
    void SetTrackHistory(bool enable) { m_trackHistory = enable; }

    // Analysis functions
    int GetTotalActiveBreakpoints() const;
    int GetThreadsWithBreakpoints() const;
    bool HasSuspiciousPatterns() const;

private:
    // Thread enumeration
    std::vector<DWORD> EnumerateThreads();
    
    // Debug register reading
    bool ReadThreadDebugRegisters(DWORD threadId, DebugRegisterInfo& info);
    bool GetThreadContext(HANDLE hThread, CONTEXT& ctx);
    
    // DR7 parsing
    std::vector<HardwareBreakpoint> ParseDR7(DWORD_PTR dr7, DWORD_PTR dr0, DWORD_PTR dr1, DWORD_PTR dr2, DWORD_PTR dr3);
    BreakpointType GetBreakpointType(DWORD_PTR dr7, int index);
    BreakpointSize GetBreakpointSize(DWORD_PTR dr7, int index);
    bool IsBreakpointEnabled(DWORD_PTR dr7, int index);
    bool IsBreakpointLocal(DWORD_PTR dr7, int index);
    bool IsBreakpointGlobal(DWORD_PTR dr7, int index);

    // Anomaly detection
    void DetectAnomalies(const DebugRegisterInfo& info);
    void DetectExcessiveUsage(const DebugRegisterInfo& info);
    void DetectSuspiciousPatterns(const DebugRegisterInfo& info);
    void DetectContextSwitchAnomalies(DWORD threadId);

    // History tracking
    void UpdateHistory(const DebugRegisterInfo& info);
    bool HasHistoryChanged(DWORD threadId, const DebugRegisterInfo& info);

private:
    DWORD m_targetPid;
    std::vector<DebugRegisterInfo> m_debugRegData;
    std::vector<HardwareBreakpointAnomaly> m_anomalies;
    
    // Configuration
    int m_maxBpThreshold;           // Max allowed hardware breakpoints per thread
    bool m_enableAnomalyDetection;
    bool m_trackHistory;
    bool m_isInitialized;

    // History tracking (for detecting changes)
    std::unordered_map<DWORD, DebugRegisterInfo> m_previousState;
    std::unordered_map<DWORD, int> m_changeFrequency;  // How often DR values change per thread
    
    // Statistics
    DWORD m_lastScanTime;
    int m_totalScans;
};
