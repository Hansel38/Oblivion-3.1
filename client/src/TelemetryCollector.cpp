#include "../pch.h"
#include "TelemetryCollector.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <Psapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "psapi.lib")

TelemetryCollector::TelemetryCollector()
    : m_enabled(true)
    , m_collectionIntervalMs(5000) // Collect system metrics every 5 seconds
    , m_maxEventsInMemory(10000) // Keep max 10k events in memory
    , m_aggregationPeriodMs(300000) // Aggregate every 5 minutes
    , m_thread(nullptr)
    , m_stopEvent(nullptr)
    , m_running(false)
    , m_lastCPUCheckTime(0)
    , m_lastCPUKernelTime(0)
    , m_lastCPUUserTime(0)
    , m_anonymizeData(true)
    , m_collectRawEvents(true)
    , m_currentPeriodStart(GetTickCount64())
{
    m_currentPeriod = {};
    m_currentPeriod.periodStartTime = m_currentPeriodStart;
    m_lastPeriod = {};
    
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

TelemetryCollector::~TelemetryCollector()
{
    Stop();
    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }
}

void TelemetryCollector::SetEnabled(bool enabled)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_enabled = enabled;
}

void TelemetryCollector::SetCollectionIntervalMs(DWORD intervalMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_collectionIntervalMs = max(1000, intervalMs); // Min 1 second
}

void TelemetryCollector::SetMaxEventsInMemory(size_t maxEvents)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxEventsInMemory = max((size_t)100, maxEvents); // Min 100 events
}

void TelemetryCollector::SetAggregationPeriodMs(ULONGLONG periodMs)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_aggregationPeriodMs = max(60000ULL, periodMs); // Min 1 minute
}

void TelemetryCollector::RecordScanExecution(const ScanTelemetry& scan)
{
    if (!m_enabled) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Add to raw events (if enabled)
    if (m_collectRawEvents) {
        m_scanEvents.push_back(scan);
    }
    
    // Update aggregated stats
    m_currentPeriod.totalScans++;
    
    switch (scan.result) {
        case ScanResultType::CLEAN:
            m_currentPeriod.cleanScans++;
            break;
        case ScanResultType::SUSPICIOUS:
            m_currentPeriod.suspiciousScans++;
            break;
        case ScanResultType::DETECTED:
            m_currentPeriod.detectedScans++;
            break;
        case ScanResultType::SCAN_ERROR:
            m_currentPeriod.errorScans++;
            break;
    }
    
    // Update per-scanner stats
    m_currentPeriod.scanCountByType[scan.scannerName]++;
    
    // Update timing stats
    if (m_currentPeriod.totalScans == 1) {
        m_currentPeriod.avgScanTimeMs = static_cast<double>(scan.executionTimeMs);
        m_currentPeriod.maxScanTimeMs = static_cast<double>(scan.executionTimeMs);
    } else {
        // Running average
        m_currentPeriod.avgScanTimeMs = 
            (m_currentPeriod.avgScanTimeMs * (m_currentPeriod.totalScans - 1) + static_cast<double>(scan.executionTimeMs)) 
            / m_currentPeriod.totalScans;
        
        if (scan.executionTimeMs > m_currentPeriod.maxScanTimeMs) {
            m_currentPeriod.maxScanTimeMs = static_cast<double>(scan.executionTimeMs);
        }
    }
    
    // Update per-scanner timing
    auto& scannerTime = m_currentPeriod.avgTimeByScanner[scan.scannerName];
    DWORD scanCount = m_currentPeriod.scanCountByType[scan.scannerName];
    if (scanCount == 1) {
        scannerTime = static_cast<double>(scan.executionTimeMs);
    } else {
        scannerTime = (scannerTime * (scanCount - 1) + static_cast<double>(scan.executionTimeMs)) / scanCount;
    }
    
    PruneOldEvents();
}

void TelemetryCollector::RecordDetection(const DetectionTelemetry& detection)
{
    if (!m_enabled) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Add to raw events
    if (m_collectRawEvents) {
        DetectionTelemetry anonymized = detection;
        if (m_anonymizeData) {
            anonymized.reason = AnonymizeReason(detection.reason);
        }
        m_detectionEvents.push_back(anonymized);
    }
    
    // Update aggregated stats
    m_currentPeriod.totalDetections++;
    
    if (detection.wasSuppressed) {
        m_currentPeriod.suppressedDetections++;
    }
    
    if (detection.userReportedFP) {
        m_currentPeriod.falsePositives++;
    }
    
    PruneOldEvents();
}

void TelemetryCollector::RecordSystemMetric(const SystemMetric& metric)
{
    if (!m_enabled) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_collectRawEvents) {
        m_systemMetrics.push_back(metric);
    }
    
    // Update running averages
    if (m_currentPeriod.totalScans > 0) {
        m_currentPeriod.avgCPUUsage = 
            (m_currentPeriod.avgCPUUsage * 0.9 + metric.cpuUsagePercent * 0.1);
        m_currentPeriod.avgMemoryUsageMB = 
            (m_currentPeriod.avgMemoryUsageMB * 0.9 + metric.memoryUsageMB * 0.1);
    } else {
        m_currentPeriod.avgCPUUsage = metric.cpuUsagePercent;
        m_currentPeriod.avgMemoryUsageMB = metric.memoryUsageMB;
    }
    
    PruneOldEvents();
}

void TelemetryCollector::RecordProcessBehavior(const ProcessBehaviorEvent& behavior)
{
    if (!m_enabled) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_collectRawEvents) {
        m_behaviorEvents.push_back(behavior);
    }
    
    PruneOldEvents();
}

void TelemetryCollector::RecordFalsePositive(const std::string& detectionType, const std::wstring& processName)
{
    if (!m_enabled) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_currentPeriod.falsePositives++;
    
    // Try to mark recent detection as FP
    for (auto it = m_detectionEvents.rbegin(); it != m_detectionEvents.rend(); ++it) {
        if (it->detectionType == detectionType && it->processName == processName) {
            it->userReportedFP = true;
            break; // Only mark the most recent one
        }
    }
}

void TelemetryCollector::RecordScanStart(const std::string& scannerName)
{
    if (!m_enabled) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activeScanStartTimes[scannerName] = GetTickCount64();
}

void TelemetryCollector::RecordScanEnd(const std::string& scannerName, ScanResultType result, DWORD indicators)
{
    if (!m_enabled) return;
    
    ULONGLONG endTime = GetTickCount64();
    ULONGLONG startTime = 0;
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_activeScanStartTimes.find(scannerName);
        if (it != m_activeScanStartTimes.end()) {
            startTime = it->second;
            m_activeScanStartTimes.erase(it);
        }
    }
    
    ScanTelemetry scan = {};
    scan.timestamp = endTime;
    scan.scannerName = scannerName;
    scan.result = result;
    scan.executionTimeMs = startTime > 0 ? (endTime - startTime) : 0;
    scan.indicatorCount = indicators;
    scan.wasThrottled = false; // TODO: integrate with scan prioritizer
    scan.cpuUsageDelta = 0.0f; // TODO: measure CPU delta
    scan.memoryUsageDelta = 0;
    
    RecordScanExecution(scan);
}

AggregatedStats TelemetryCollector::GetCurrentPeriodStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    AggregatedStats stats = m_currentPeriod;
    stats.periodEndTime = GetTickCount64();
    return stats;
}

AggregatedStats TelemetryCollector::GetLastPeriodStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastPeriod;
}

std::vector<ScanTelemetry> TelemetryCollector::GetRecentScans(size_t count) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<ScanTelemetry> result;
    size_t start = m_scanEvents.size() > count ? m_scanEvents.size() - count : 0;
    
    for (size_t i = start; i < m_scanEvents.size(); ++i) {
        result.push_back(m_scanEvents[i]);
    }
    
    return result;
}

std::vector<DetectionTelemetry> TelemetryCollector::GetRecentDetections(size_t count) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<DetectionTelemetry> result;
    size_t start = m_detectionEvents.size() > count ? m_detectionEvents.size() - count : 0;
    
    for (size_t i = start; i < m_detectionEvents.size(); ++i) {
        result.push_back(m_detectionEvents[i]);
    }
    
    return result;
}

std::string TelemetryCollector::ExportToJSON(bool includeRawEvents) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ostringstream json;
    json << "{\n";
    json << "  \"telemetry_version\": \"1.0\",\n";
    json << "  \"timestamp\": " << GetTickCount64() << ",\n";
    
    // Current period stats
    json << "  \"current_period\": {\n";
    json << "    \"start_time\": " << m_currentPeriod.periodStartTime << ",\n";
    json << "    \"end_time\": " << GetTickCount64() << ",\n";
    json << "    \"total_scans\": " << m_currentPeriod.totalScans << ",\n";
    json << "    \"clean_scans\": " << m_currentPeriod.cleanScans << ",\n";
    json << "    \"suspicious_scans\": " << m_currentPeriod.suspiciousScans << ",\n";
    json << "    \"detected_scans\": " << m_currentPeriod.detectedScans << ",\n";
    json << "    \"error_scans\": " << m_currentPeriod.errorScans << ",\n";
    json << "    \"total_detections\": " << m_currentPeriod.totalDetections << ",\n";
    json << "    \"suppressed_detections\": " << m_currentPeriod.suppressedDetections << ",\n";
    json << "    \"false_positives\": " << m_currentPeriod.falsePositives << ",\n";
    json << "    \"avg_scan_time_ms\": " << m_currentPeriod.avgScanTimeMs << ",\n";
    json << "    \"max_scan_time_ms\": " << m_currentPeriod.maxScanTimeMs << ",\n";
    json << "    \"avg_cpu_usage\": " << m_currentPeriod.avgCPUUsage << ",\n";
    json << "    \"avg_memory_mb\": " << m_currentPeriod.avgMemoryUsageMB << ",\n";
    
    // Per-scanner breakdown
    json << "    \"scanner_breakdown\": {\n";
    bool first = true;
    for (const auto& kv : m_currentPeriod.scanCountByType) {
        if (!first) json << ",\n";
        json << "      \"" << kv.first << "\": {\n";
        json << "        \"count\": " << kv.second << ",\n";
        json << "        \"avg_time_ms\": " << m_currentPeriod.avgTimeByScanner.at(kv.first) << "\n";
        json << "      }";
        first = false;
    }
    json << "\n    }\n";
    json << "  },\n";
    
    // Last period stats
    json << "  \"last_period\": {\n";
    json << "    \"start_time\": " << m_lastPeriod.periodStartTime << ",\n";
    json << "    \"end_time\": " << m_lastPeriod.periodEndTime << ",\n";
    json << "    \"total_scans\": " << m_lastPeriod.totalScans << "\n";
    json << "  }";
    
    // Include raw events if requested
    if (includeRawEvents) {
        json << ",\n  \"raw_events\": {\n";
        json << "    \"scan_count\": " << m_scanEvents.size() << ",\n";
        json << "    \"detection_count\": " << m_detectionEvents.size() << ",\n";
        json << "    \"system_metric_count\": " << m_systemMetrics.size() << ",\n";
        json << "    \"behavior_event_count\": " << m_behaviorEvents.size() << "\n";
        json << "  }";
    }
    
    json << "\n}\n";
    
    return json.str();
}

bool TelemetryCollector::ExportToFile(const std::wstring& filepath, bool includeRawEvents) const
{
    try {
        std::ofstream file(filepath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) return false;
        
        std::string json = ExportToJSON(includeRawEvents);
        file << json;
        file.close();
        
        return true;
    } catch (...) {
        return false;
    }
}

double TelemetryCollector::GetDetectionRate() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_currentPeriod.totalScans == 0) return 0.0;
    return (double)m_currentPeriod.totalDetections / (double)m_currentPeriod.totalScans;
}

double TelemetryCollector::GetFalsePositiveRate() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_currentPeriod.totalDetections == 0) return 0.0;
    return (double)m_currentPeriod.falsePositives / (double)m_currentPeriod.totalDetections;
}

double TelemetryCollector::GetAvgScanTime(const std::string& scannerName) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (scannerName.empty()) {
        return m_currentPeriod.avgScanTimeMs;
    }
    
    auto it = m_currentPeriod.avgTimeByScanner.find(scannerName);
    if (it != m_currentPeriod.avgTimeByScanner.end()) {
        return it->second;
    }
    
    return 0.0;
}

void TelemetryCollector::Start()
{
    if (m_running) return;
    
    m_running = true;
    ResetEvent(m_stopEvent);
    
    m_thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        TelemetryCollector* pThis = static_cast<TelemetryCollector*>(param);
        pThis->CollectionThread();
        return 0;
    }, this, 0, nullptr);
}

void TelemetryCollector::Stop()
{
    if (!m_running) return;
    
    m_running = false;
    SetEvent(m_stopEvent);
    
    if (m_thread) {
        WaitForSingleObject(m_thread, 5000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
}

void TelemetryCollector::CollectionThread()
{
    ULONGLONG lastMetricCollection = 0;
    ULONGLONG lastAggregation = GetTickCount64();
    
    while (m_running) {
        ULONGLONG now = GetTickCount64();
        
        // Collect system metrics periodically
        if (now - lastMetricCollection >= m_collectionIntervalMs) {
            CollectSystemMetrics();
            lastMetricCollection = now;
        }
        
        // Aggregate current period
        if (now - lastAggregation >= m_aggregationPeriodMs) {
            AggregateCurrentPeriod();
            lastAggregation = now;
        }
        
        // Wait for stop event or next interval
        DWORD waitTime = min(m_collectionIntervalMs, 1000);
        if (WaitForSingleObject(m_stopEvent, waitTime) == WAIT_OBJECT_0) {
            break;
        }
    }
}

void TelemetryCollector::CollectSystemMetrics()
{
    SystemMetric metric = {};
    metric.timestamp = GetTickCount64();
    metric.cpuUsagePercent = GetCPUUsage();
    metric.memoryUsageMB = GetMemoryUsage();
    metric.threadCount = GetThreadCount();
    metric.handleCount = GetHandleCount();
    
    RecordSystemMetric(metric);
}

void TelemetryCollector::AggregateCurrentPeriod()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Save current period to last period
    m_lastPeriod = m_currentPeriod;
    m_lastPeriod.periodEndTime = GetTickCount64();
    
    // Reset current period
    m_currentPeriod = {};
    m_currentPeriod.periodStartTime = GetTickCount64();
}

void TelemetryCollector::PruneOldEvents()
{
    // Prune scan events
    if (m_scanEvents.size() > m_maxEventsInMemory) {
        size_t toRemove = m_scanEvents.size() - m_maxEventsInMemory;
        m_scanEvents.erase(m_scanEvents.begin(), m_scanEvents.begin() + toRemove);
    }
    
    // Prune detection events
    if (m_detectionEvents.size() > m_maxEventsInMemory) {
        size_t toRemove = m_detectionEvents.size() - m_maxEventsInMemory;
        m_detectionEvents.erase(m_detectionEvents.begin(), m_detectionEvents.begin() + toRemove);
    }
    
    // Prune system metrics
    if (m_systemMetrics.size() > m_maxEventsInMemory) {
        size_t toRemove = m_systemMetrics.size() - m_maxEventsInMemory;
        m_systemMetrics.erase(m_systemMetrics.begin(), m_systemMetrics.begin() + toRemove);
    }
    
    // Prune behavior events
    if (m_behaviorEvents.size() > m_maxEventsInMemory) {
        size_t toRemove = m_behaviorEvents.size() - m_maxEventsInMemory;
        m_behaviorEvents.erase(m_behaviorEvents.begin(), m_behaviorEvents.begin() + toRemove);
    }
}

std::string TelemetryCollector::AnonymizeReason(const std::string& reason) const
{
    // Simple anonymization: remove specific addresses and paths
    std::string anonymized = reason;
    
    // Remove hex addresses (0x...)
    size_t pos = 0;
    while ((pos = anonymized.find("0x", pos)) != std::string::npos) {
        size_t end = pos + 2;
        while (end < anonymized.size() && isxdigit(anonymized[end])) {
            end++;
        }
        anonymized.replace(pos, end - pos, "0x[ADDR]");
        pos += 8;
    }
    
    return anonymized;
}

float TelemetryCollector::GetCPUUsage()
{
    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return 0.0f;
    }
    
    ULONGLONG now = GetTickCount64();
    ULONGLONG kernel = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
    ULONGLONG user = ((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;
    
    if (m_lastCPUCheckTime == 0) {
        m_lastCPUCheckTime = now;
        m_lastCPUKernelTime = kernel;
        m_lastCPUUserTime = user;
        return 0.0f;
    }
    
    ULONGLONG kernelDelta = kernel - m_lastCPUKernelTime;
    ULONGLONG userDelta = user - m_lastCPUUserTime;
    ULONGLONG timeDelta = now - m_lastCPUCheckTime;
    
    m_lastCPUCheckTime = now;
    m_lastCPUKernelTime = kernel;
    m_lastCPUUserTime = user;
    
    if (timeDelta == 0) return 0.0f;
    
    // CPU time is in 100-nanosecond units, convert to percentage
    float cpuPercent = ((float)(kernelDelta + userDelta) / (float)(timeDelta * 10000)) * 100.0f;
    
    return min(100.0f, cpuPercent);
}

SIZE_T TelemetryCollector::GetMemoryUsage()
{
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
    pmc.cb = sizeof(pmc);
    
    HANDLE hProcess = GetCurrentProcess();
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024); // Convert to MB
    }
    
    return 0;
}

DWORD TelemetryCollector::GetThreadCount()
{
    DWORD threadCount = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        DWORD currentPid = GetCurrentProcessId();
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == currentPid) {
                    threadCount++;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
    }
    
    return threadCount;
}

DWORD TelemetryCollector::GetHandleCount()
{
    DWORD handleCount = 0;
    HANDLE hProcess = GetCurrentProcess();
    GetProcessHandleCount(hProcess, &handleCount);
    return handleCount;
}
