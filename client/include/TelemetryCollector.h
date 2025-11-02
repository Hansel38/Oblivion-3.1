#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <windows.h>

// Undefine Windows macros that conflict with our enums
#ifdef ERROR
#undef ERROR
#endif
#ifdef DETECTED
#undef DETECTED
#endif
#ifdef PROCESS_BEHAVIOR
#undef PROCESS_BEHAVIOR
#endif

// =====================================================================
// TelemetryCollector.h
// Priority 4.1.1 - Telemetry Collection System
// 
// Collects behavior telemetry for ML training and adaptive thresholds:
// - Scan frequencies and detection rates
// - System performance metrics (CPU, memory usage)
// - Process behavior patterns (memory access, thread creation)
// - Privacy-safe data aggregation
// =====================================================================

// Event types for telemetry tracking
enum class TelemetryEventType {
    SCAN_EXECUTED = 0,      // A scan was executed
    DETECTION_TRIGGERED,    // A detection was triggered
    FALSE_POSITIVE,         // User-reported false positive
    SYSTEM_METRIC,          // System performance metric snapshot
    PROCESS_BEHAVIOR,       // Process behavior observation
    SCAN_PERFORMANCE        // Scan execution time/performance
};

// Scan result for telemetry
enum class ScanResultType {
    CLEAN = 0,
    SUSPICIOUS,
    DETECTED,
    SCAN_ERROR
};

// System metric snapshot
struct SystemMetric {
    ULONGLONG timestamp;
    float cpuUsagePercent;      // CPU usage percentage
    SIZE_T memoryUsageMB;       // Memory usage in MB
    SIZE_T workingSetMB;        // Working set size in MB
    DWORD threadCount;          // Number of threads
    DWORD handleCount;          // Number of handles
};

// Process behavior event
struct ProcessBehaviorEvent {
    ULONGLONG timestamp;
    DWORD processId;
    std::wstring processName;
    
    // Behavior metrics
    DWORD memoryReadCount;      // Number of ReadProcessMemory calls observed
    DWORD memoryWriteCount;     // Number of WriteProcessMemory calls observed
    DWORD threadCreateCount;    // Number of threads created
    DWORD moduleLoadCount;      // Number of modules loaded
    DWORD suspiciousAPICalls;   // Count of suspicious API calls
};

// Scan execution telemetry
struct ScanTelemetry {
    ULONGLONG timestamp;
    std::string scannerName;    // e.g., "InjectionScanner", "MemorySignatureScanner"
    ScanResultType result;
    ULONGLONG executionTimeMs;  // How long the scan took
    DWORD indicatorCount;       // Number of indicators found
    bool wasThrottled;          // Whether scan was delayed due to CPU budget
    
    // Resource usage during scan
    float cpuUsageDelta;        // CPU usage change during scan
    SIZE_T memoryUsageDelta;    // Memory usage change during scan
};

// Detection telemetry
struct DetectionTelemetry {
    ULONGLONG timestamp;
    std::string detectionType;  // e.g., "injection", "overlay", "antidebug"
    std::wstring processName;
    DWORD processId;
    DWORD indicatorCount;
    bool wasSuppressed;         // Whether detection was suppressed by cooldown
    bool userReportedFP;        // Whether user reported this as false positive
    
    // Context
    std::string reason;         // Detection reason (anonymized)
    std::vector<std::string> contributingScans; // Which scans contributed
};

// Aggregated statistics (for privacy-safe reporting)
struct AggregatedStats {
    ULONGLONG periodStartTime;
    ULONGLONG periodEndTime;
    
    // Scan statistics
    DWORD totalScans;
    DWORD cleanScans;
    DWORD suspiciousScans;
    DWORD detectedScans;
    DWORD errorScans;
    
    // Detection statistics
    DWORD totalDetections;
    DWORD suppressedDetections;
    DWORD falsePositives;
    
    // Performance statistics
    double avgScanTimeMs;
    double maxScanTimeMs;
    double avgCPUUsage;
    double avgMemoryUsageMB;
    
    // Per-scanner breakdown
    std::unordered_map<std::string, DWORD> scanCountByType;
    std::unordered_map<std::string, double> avgTimeByScanner;
};

class TelemetryCollector {
public:
    TelemetryCollector();
    ~TelemetryCollector();

    // Configuration
    void SetEnabled(bool enabled);
    void SetCollectionIntervalMs(DWORD intervalMs);
    void SetMaxEventsInMemory(size_t maxEvents);
    void SetAggregationPeriodMs(ULONGLONG periodMs);
    
    // Event recording
    void RecordScanExecution(const ScanTelemetry& scan);
    void RecordDetection(const DetectionTelemetry& detection);
    void RecordSystemMetric(const SystemMetric& metric);
    void RecordProcessBehavior(const ProcessBehaviorEvent& behavior);
    void RecordFalsePositive(const std::string& detectionType, const std::wstring& processName);
    
    // Convenience methods for common events
    void RecordScanStart(const std::string& scannerName);
    void RecordScanEnd(const std::string& scannerName, ScanResultType result, DWORD indicators);
    
    // Query methods
    AggregatedStats GetCurrentPeriodStats() const;
    AggregatedStats GetLastPeriodStats() const;
    std::vector<ScanTelemetry> GetRecentScans(size_t count) const;
    std::vector<DetectionTelemetry> GetRecentDetections(size_t count) const;
    
    // Export telemetry data
    std::string ExportToJSON(bool includeRawEvents = false) const;
    bool ExportToFile(const std::wstring& filepath, bool includeRawEvents = false) const;
    
    // Statistics
    double GetDetectionRate() const; // detections / scans
    double GetFalsePositiveRate() const; // FPs / detections
    double GetAvgScanTime(const std::string& scannerName = "") const;
    
    // Background thread management
    void Start();
    void Stop();

private:
    // Internal methods
    void CollectionThread();
    void CollectSystemMetrics();
    void AggregateCurrentPeriod();
    void PruneOldEvents();
    std::string AnonymizeReason(const std::string& reason) const;
    
    // System metric collection
    float GetCPUUsage();
    SIZE_T GetMemoryUsage();
    DWORD GetThreadCount();
    DWORD GetHandleCount();
    
    // Data storage
    mutable std::mutex m_mutex;
    std::vector<ScanTelemetry> m_scanEvents;
    std::vector<DetectionTelemetry> m_detectionEvents;
    std::vector<SystemMetric> m_systemMetrics;
    std::vector<ProcessBehaviorEvent> m_behaviorEvents;
    
    // Aggregated statistics
    AggregatedStats m_currentPeriod;
    AggregatedStats m_lastPeriod;
    ULONGLONG m_currentPeriodStart;
    
    // Active scan tracking (for timing)
    std::unordered_map<std::string, ULONGLONG> m_activeScanStartTimes;
    
    // Configuration
    bool m_enabled;
    DWORD m_collectionIntervalMs;
    size_t m_maxEventsInMemory;
    ULONGLONG m_aggregationPeriodMs;
    
    // Background thread
    HANDLE m_thread;
    HANDLE m_stopEvent;
    bool m_running;
    
    // CPU usage tracking (for delta calculation)
    ULONGLONG m_lastCPUCheckTime;
    ULONGLONG m_lastCPUKernelTime;
    ULONGLONG m_lastCPUUserTime;
    
    // Privacy settings
    bool m_anonymizeData;
    bool m_collectRawEvents;
};

// Global telemetry instance (optional - can be integrated into main flow)
extern TelemetryCollector* g_pTelemetry;

// Helper macros for easy telemetry recording
#define TELEMETRY_RECORD_SCAN_START(scanner) \
    if (g_pTelemetry) g_pTelemetry->RecordScanStart(scanner)

#define TELEMETRY_RECORD_SCAN_END(scanner, result, indicators) \
    if (g_pTelemetry) g_pTelemetry->RecordScanEnd(scanner, result, indicators)

#define TELEMETRY_RECORD_DETECTION(detection) \
    if (g_pTelemetry) g_pTelemetry->RecordDetection(detection)

#define TELEMETRY_RECORD_FP(type, process) \
    if (g_pTelemetry) g_pTelemetry->RecordFalsePositive(type, process)
