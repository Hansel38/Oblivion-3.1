// ===== PRIORITY 4.3.1: Scan Prioritization Manager =====
// Hot Path vs Cold Path scan scheduling system
// Optimizes scan execution based on criticality and detection rate
// Version: 1.0
// Author: Oblivion AntiCheat Team
// Date: 2025-11-02

#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <functional>

// Forward declarations
class TelemetryCollector;

// ===== Scan Priority Levels =====
enum class ScanPriority {
    CRITICAL = 0,   // Must run every cycle (anti-debug, kernel callbacks)
    HIGH = 1,       // Important, run frequently (memory injection, IAT hooks)
    NORMAL = 2,     // Standard priority (signature scanning, file integrity)
    LOW = 3,        // Background tasks (telemetry, statistics)
    DEFERRED = 4    // Can be skipped under high load (optimization scans)
};

// ===== Scan Path Classification =====
enum class ScanPathType {
    HOT_PATH,       // Frequently executed, performance-critical
    WARM_PATH,      // Moderately frequent
    COLD_PATH       // Rarely executed, low priority
};

// ===== Scanner Metadata =====
struct ScannerInfo {
    std::string name;                       // Scanner unique identifier
    std::string displayName;                // Human-readable name
    ScanPriority priority;                  // Base priority level
    ScanPathType pathType;                  // Hot/warm/cold classification
    
    // Execution statistics
    ULONGLONG lastExecutionTime;            // Timestamp of last run
    ULONGLONG avgExecutionTimeMs;           // Average execution time
    ULONGLONG maxExecutionTimeMs;           // Worst-case execution time
    
    // Detection statistics
    DWORD totalExecutions;                  // Total number of runs
    DWORD totalDetections;                  // Total detections triggered
    DWORD falsePositives;                   // User-reported false positives
    float detectionRate;                    // Detections / Executions
    
    // Dynamic priority adjustment
    int priorityBoost;                      // Temporary priority boost (-2 to +2)
    ULONGLONG lastDetectionTime;            // Last time this scanner detected something
    
    // Scheduling constraints
    DWORD minIntervalMs;                    // Minimum time between runs
    DWORD maxIntervalMs;                    // Maximum time between runs
    bool canBeSkipped;                      // Can skip if system under load
    
    ScannerInfo()
        : priority(ScanPriority::NORMAL), pathType(ScanPathType::WARM_PATH),
          lastExecutionTime(0), avgExecutionTimeMs(0), maxExecutionTimeMs(0),
          totalExecutions(0), totalDetections(0), falsePositives(0), detectionRate(0.0f),
          priorityBoost(0), lastDetectionTime(0),
          minIntervalMs(1000), maxIntervalMs(60000), canBeSkipped(false) {}
};

// ===== Scan Task (for priority queue) =====
struct ScanTask {
    std::string scannerName;                // Scanner to execute
    ScanPriority effectivePriority;         // Priority after adjustments
    ULONGLONG scheduledTime;                // When this task should run
    ULONGLONG deadline;                     // Latest time to run (for CRITICAL scans)
    std::function<bool()> callback;         // Scanner execution function
    
    // For priority queue ordering (higher priority = lower value)
    bool operator>(const ScanTask& other) const {
        if (effectivePriority != other.effectivePriority) {
            return static_cast<int>(effectivePriority) > static_cast<int>(other.effectivePriority);
        }
        return scheduledTime > other.scheduledTime;
    }
    
    ScanTask() : effectivePriority(ScanPriority::NORMAL), scheduledTime(0), deadline(0) {}
};

// ===== Configuration =====
struct ScanPrioritizationConfig {
    bool enablePrioritization;              // Master switch
    bool enableDynamicAdjustment;           // Auto-adjust priorities based on detections
    bool enableLoadBalancing;               // Skip low-priority scans under high CPU
    
    float cpuThresholdPercent;              // CPU % threshold for load balancing
    DWORD criticalScanMaxDelayMs;           // Max acceptable delay for CRITICAL scans
    DWORD highScanMaxDelayMs;               // Max acceptable delay for HIGH scans
    
    // Dynamic priority adjustment weights
    float recentDetectionBoostWeight;       // Weight for recent detection boost
    float detectionRateBoostWeight;         // Weight for detection rate boost
    float falsePositivePenaltyWeight;       // Weight for FP penalty
    
    // Time windows for statistics
    DWORD recentDetectionWindowMs;          // Time window to consider "recent" (default: 5 min)
    DWORD statisticsUpdateIntervalMs;       // How often to recalculate stats (default: 30s)
    
    ScanPrioritizationConfig()
        : enablePrioritization(true), enableDynamicAdjustment(true), enableLoadBalancing(true),
          cpuThresholdPercent(80.0f), criticalScanMaxDelayMs(1000), highScanMaxDelayMs(5000),
          recentDetectionBoostWeight(2.0f), detectionRateBoostWeight(1.5f), falsePositivePenaltyWeight(1.0f),
          recentDetectionWindowMs(300000), statisticsUpdateIntervalMs(30000) {}
};

// ===== Performance Statistics =====
struct ScanPrioritizationStats {
    DWORD totalTasksScheduled;              // Total tasks scheduled
    DWORD totalTasksExecuted;               // Total tasks executed
    DWORD totalTasksSkipped;                // Tasks skipped due to load
    DWORD totalTasksDeferred;               // Tasks deferred to next cycle
    
    DWORD criticalTasksExecuted;            // CRITICAL priority executed
    DWORD highTasksExecuted;                // HIGH priority executed
    DWORD normalTasksExecuted;              // NORMAL priority executed
    DWORD lowTasksExecuted;                 // LOW priority executed
    
    ULONGLONG avgSchedulingDelayMs;         // Avg time between schedule and execution
    ULONGLONG maxSchedulingDelayMs;         // Max scheduling delay observed
    
    float currentCpuUsage;                  // Current CPU usage %
    bool isLoadBalancingActive;             // Load balancing currently active
    
    ScanPrioritizationStats()
        : totalTasksScheduled(0), totalTasksExecuted(0), totalTasksSkipped(0), totalTasksDeferred(0),
          criticalTasksExecuted(0), highTasksExecuted(0), normalTasksExecuted(0), lowTasksExecuted(0),
          avgSchedulingDelayMs(0), maxSchedulingDelayMs(0),
          currentCpuUsage(0.0f), isLoadBalancingActive(false) {}
};

// ===== Main Scan Prioritization Manager =====
class ScanPrioritizationManager {
public:
    explicit ScanPrioritizationManager(const ScanPrioritizationConfig& config = ScanPrioritizationConfig());
    ~ScanPrioritizationManager();

    // Initialization and configuration
    bool Initialize();
    void Shutdown();
    void SetConfig(const ScanPrioritizationConfig& config);
    void SetTelemetryCollector(TelemetryCollector* pTelemetry);

    // Scanner registration
    bool RegisterScanner(const std::string& name, const ScannerInfo& info);
    bool UnregisterScanner(const std::string& name);
    bool UpdateScannerInfo(const std::string& name, const ScannerInfo& info);
    ScannerInfo* GetScannerInfo(const std::string& name);

    // Task scheduling
    bool ScheduleTask(const std::string& scannerName, std::function<bool()> callback);
    bool ScheduleTaskWithDelay(const std::string& scannerName, std::function<bool()> callback, DWORD delayMs);
    
    // Task execution
    bool ExecuteNextTask();                 // Execute highest priority task
    size_t ExecutePendingTasks(DWORD maxExecutionTimeMs = 100); // Execute tasks for up to X ms
    void ExecuteCriticalTasks();            // Execute all CRITICAL tasks immediately
    
    // Dynamic priority adjustment
    void OnScanExecuted(const std::string& scannerName, ULONGLONG executionTimeMs, bool detected);
    void OnFalsePositive(const std::string& scannerName);
    void UpdateDynamicPriorities();         // Recalculate all priority adjustments
    
    // Statistics and monitoring
    ScanPrioritizationStats GetStatistics() const;
    void ResetStatistics();
    size_t GetPendingTaskCount() const;
    size_t GetPendingTaskCount(ScanPriority priority) const;
    
    // Load balancing
    void UpdateCpuUsage(float cpuPercent);
    bool ShouldSkipLowPriorityScans() const;
    
    // Utility
    std::vector<std::string> GetRegisteredScanners() const;
    void PrintDebugInfo() const;

private:
    // Internal methods
    ScanPriority CalculateEffectivePriority(const std::string& scannerName);
    bool CanExecuteNow(const ScannerInfo& info) const;
    int CalculatePriorityBoost(const ScannerInfo& info) const;
    void CleanupExpiredTasks();
    
    // Configuration
    ScanPrioritizationConfig m_config;
    
    // Scanner registry
    std::unordered_map<std::string, ScannerInfo> m_scanners;
    mutable std::mutex m_scannerMutex;
    
    // Task queue (priority queue with custom comparator)
    std::priority_queue<ScanTask, std::vector<ScanTask>, std::greater<ScanTask>> m_taskQueue;
    mutable std::mutex m_queueMutex;
    
    // Statistics
    ScanPrioritizationStats m_stats;
    mutable std::mutex m_statsMutex;
    
    // External dependencies
    TelemetryCollector* m_pTelemetry;
    
    // State
    bool m_initialized;
    ULONGLONG m_lastStatisticsUpdate;
    float m_currentCpuUsage;
};

// ===== Global instance (optional) =====
extern ScanPrioritizationManager* g_pScanPrioritizer;
