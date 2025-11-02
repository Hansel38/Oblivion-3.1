#include "../pch.h"
#include "ScanPrioritizationManager.h"
#include "TelemetryCollector.h"
#include <algorithm>

// Global instance
ScanPrioritizationManager* g_pScanPrioritizer = nullptr;

ScanPrioritizationManager::ScanPrioritizationManager(const ScanPrioritizationConfig& config)
    : m_config(config), m_pTelemetry(nullptr), m_initialized(false), m_lastStatisticsUpdate(0), m_currentCpuUsage(0.0f)
{
}

ScanPrioritizationManager::~ScanPrioritizationManager()
{
    Shutdown();
}

bool ScanPrioritizationManager::Initialize()
{
    std::lock_guard<std::mutex> l(m_queueMutex);
    m_initialized = true;
    m_lastStatisticsUpdate = GetTickCount64();
    return true;
}

void ScanPrioritizationManager::Shutdown()
{
    std::lock_guard<std::mutex> l(m_queueMutex);
    while (!m_taskQueue.empty()) m_taskQueue.pop();
    m_initialized = false;
}

void ScanPrioritizationManager::SetConfig(const ScanPrioritizationConfig& config)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    m_config = config;
}

void ScanPrioritizationManager::SetTelemetryCollector(TelemetryCollector* pTelemetry)
{
    m_pTelemetry = pTelemetry;
}

bool ScanPrioritizationManager::RegisterScanner(const std::string& name, const ScannerInfo& info)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    m_scanners[name] = info;
    return true;
}

bool ScanPrioritizationManager::UnregisterScanner(const std::string& name)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    return m_scanners.erase(name) > 0;
}

bool ScanPrioritizationManager::UpdateScannerInfo(const std::string& name, const ScannerInfo& info)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    auto it = m_scanners.find(name);
    if (it == m_scanners.end()) return false;
    it->second = info;
    return true;
}

ScannerInfo* ScanPrioritizationManager::GetScannerInfo(const std::string& name)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    auto it = m_scanners.find(name);
    if (it == m_scanners.end()) return nullptr;
    return &it->second;
}

bool ScanPrioritizationManager::ScheduleTask(const std::string& scannerName, std::function<bool()> callback)
{
    return ScheduleTaskWithDelay(scannerName, callback, 0);
}

bool ScanPrioritizationManager::ScheduleTaskWithDelay(const std::string& scannerName, std::function<bool()> callback, DWORD delayMs)
{
    ULONGLONG now = GetTickCount64();
    ScannerInfo info;
    {
        std::lock_guard<std::mutex> l(m_scannerMutex);
        auto it = m_scanners.find(scannerName);
        if (it != m_scanners.end()) info = it->second;
        else {
            // Unknown scanner, create default entry
            info.name = scannerName;
            info.priority = ScanPriority::NORMAL;
            info.pathType = ScanPathType::WARM_PATH;
        }
    }

    ScanTask task;
    task.scannerName = scannerName;
    task.callback = callback;
    task.scheduledTime = now + delayMs;
    task.deadline = task.scheduledTime + info.maxIntervalMs;
    task.effectivePriority = CalculateEffectivePriority(scannerName);

    {
        std::lock_guard<std::mutex> l(m_queueMutex);
        m_taskQueue.push(task);
    }

    {
        std::lock_guard<std::mutex> l(m_statsMutex);
        m_stats.totalTasksScheduled++;
    }

    return true;
}

ScanPriority ScanPrioritizationManager::CalculateEffectivePriority(const std::string& scannerName)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    auto it = m_scanners.find(scannerName);
    if (it == m_scanners.end()) return ScanPriority::NORMAL;
    const ScannerInfo& info = it->second;
    int base = static_cast<int>(info.priority);
    int boost = CalculatePriorityBoost(info);
    int eff = base + boost;
    if (eff < static_cast<int>(ScanPriority::CRITICAL)) eff = static_cast<int>(ScanPriority::CRITICAL);
    if (eff > static_cast<int>(ScanPriority::DEFERRED)) eff = static_cast<int>(ScanPriority::DEFERRED);
    return static_cast<ScanPriority>(eff);
}

int ScanPrioritizationManager::CalculatePriorityBoost(const ScannerInfo& info) const
{
    int boost = 0;
    // recent detection boost
    ULONGLONG now = GetTickCount64();
    if (info.lastDetectionTime != 0 && (now - info.lastDetectionTime) <= m_config.recentDetectionWindowMs) {
        boost -= static_cast<int>(m_config.recentDetectionBoostWeight); // lower enum value => higher priority
    }
    // detection rate boost
    if (info.totalExecutions > 0) {
        float rate = (float)info.totalDetections / (float)info.totalExecutions;
        if (rate > 0.01f) {
            boost -= static_cast<int>(m_config.detectionRateBoostWeight);
        }
    }
    // false positive penalty
    if (info.falsePositives > 0) {
        boost += static_cast<int>(m_config.falsePositivePenaltyWeight);
    }
    // clamp
    if (boost < -2) boost = -2;
    if (boost > 2) boost = 2;
    return boost;
}

bool ScanPrioritizationManager::CanExecuteNow(const ScannerInfo& info) const
{
    if (!m_config.enableLoadBalancing) return true;
    if (m_currentCpuUsage > m_config.cpuThresholdPercent && info.canBeSkipped) return false;
    return true;
}

bool ScanPrioritizationManager::ExecuteNextTask()
{
    ScanTask task;
    {
        std::lock_guard<std::mutex> l(m_queueMutex);
        if (m_taskQueue.empty()) return false;
        task = m_taskQueue.top(); m_taskQueue.pop();
    }

    // Check if scanner exists
    ScannerInfo info;
    {
        std::lock_guard<std::mutex> l(m_scannerMutex);
        auto it = m_scanners.find(task.scannerName);
        if (it != m_scanners.end()) info = it->second;
        else info.name = task.scannerName;
    }

    if (!CanExecuteNow(info)) {
        // skip/mark
        std::lock_guard<std::mutex> l(m_statsMutex);
        m_stats.totalTasksSkipped++;
        return false;
    }

    ULONGLONG t0 = GetTickCount64();
    bool result = false;
    try { result = task.callback(); } catch (...) { result = false; }
    ULONGLONG took = GetTickCount64() - t0;

    // update stats
    {
        std::lock_guard<std::mutex> l(m_statsMutex);
        m_stats.totalTasksExecuted++;
        if (task.effectivePriority == ScanPriority::CRITICAL) m_stats.criticalTasksExecuted++;
        else if (task.effectivePriority == ScanPriority::HIGH) m_stats.highTasksExecuted++;
        else if (task.effectivePriority == ScanPriority::NORMAL) m_stats.normalTasksExecuted++;
        else if (task.effectivePriority == ScanPriority::LOW) m_stats.lowTasksExecuted++;
        // scheduling delay approximated
        ULONGLONG delay = (t0 > task.scheduledTime) ? (t0 - task.scheduledTime) : 0ULL;
        m_stats.avgSchedulingDelayMs = (m_stats.avgSchedulingDelayMs + delay) / 2;
        if (delay > m_stats.maxSchedulingDelayMs) m_stats.maxSchedulingDelayMs = delay;
    }

    // notify scanner info
    OnScanExecuted(task.scannerName, static_cast<ULONGLONG>(took), result);

    return result;
}

size_t ScanPrioritizationManager::ExecutePendingTasks(DWORD maxExecutionTimeMs)
{
    ULONGLONG deadline = GetTickCount64() + maxExecutionTimeMs;
    size_t executed = 0;
    while (GetTickCount64() < deadline) {
        if (!ExecuteNextTask()) break;
        executed++;
    }
    return executed;
}

void ScanPrioritizationManager::ExecuteCriticalTasks()
{
    // Execute tasks until no CRITICAL tasks remain
    std::vector<ScanTask> remaining;
    {
        std::lock_guard<std::mutex> l(m_queueMutex);
        while (!m_taskQueue.empty()) {
            ScanTask t = m_taskQueue.top(); m_taskQueue.pop();
            if (t.effectivePriority == ScanPriority::CRITICAL) {
                // execute
                m_queueMutex.unlock(); // careful: temporarily release
                ExecuteNextTask();
                m_queueMutex.lock();
            } else {
                remaining.push_back(t);
            }
        }
        for (auto &rt : remaining) m_taskQueue.push(rt);
    }
}

void ScanPrioritizationManager::OnScanExecuted(const std::string& scannerName, ULONGLONG executionTimeMs, bool detected)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    auto it = m_scanners.find(scannerName);
    if (it == m_scanners.end()) return;
    ScannerInfo &info = it->second;
    info.lastExecutionTime = GetTickCount64();
    info.totalExecutions++;
    info.avgExecutionTimeMs = (info.avgExecutionTimeMs + executionTimeMs) / 2;
    if (executionTimeMs > info.maxExecutionTimeMs) info.maxExecutionTimeMs = executionTimeMs;
    if (detected) { info.totalDetections++; info.lastDetectionTime = GetTickCount64(); }
}

void ScanPrioritizationManager::OnFalsePositive(const std::string& scannerName)
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    auto it = m_scanners.find(scannerName);
    if (it == m_scanners.end()) return;
    it->second.falsePositives++;
}

void ScanPrioritizationManager::UpdateDynamicPriorities()
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    for (auto &kv : m_scanners) {
        ScannerInfo &info = kv.second;
        info.priorityBoost = CalculatePriorityBoost(info);
    }
}

ScanPrioritizationStats ScanPrioritizationManager::GetStatistics() const
{
    std::lock_guard<std::mutex> l(m_statsMutex);
    return m_stats;
}

void ScanPrioritizationManager::ResetStatistics()
{
    std::lock_guard<std::mutex> l(m_statsMutex);
    m_stats = ScanPrioritizationStats();
}

size_t ScanPrioritizationManager::GetPendingTaskCount() const
{
    std::lock_guard<std::mutex> l(m_queueMutex);
    return m_taskQueue.size();
}

size_t ScanPrioritizationManager::GetPendingTaskCount(ScanPriority priority) const
{
    std::lock_guard<std::mutex> l(m_queueMutex);
    // slow path: iterate copy
    std::priority_queue<ScanTask, std::vector<ScanTask>, std::greater<ScanTask>> copy = m_taskQueue;
    size_t c = 0;
    while (!copy.empty()) { if (copy.top().effectivePriority == priority) c++; copy.pop(); }
    return c;
}

void ScanPrioritizationManager::UpdateCpuUsage(float cpuPercent)
{
    std::lock_guard<std::mutex> l(m_statsMutex);
    m_currentCpuUsage = cpuPercent;
    m_stats.currentCpuUsage = cpuPercent;
    m_stats.isLoadBalancingActive = (cpuPercent > m_config.cpuThresholdPercent);
}

bool ScanPrioritizationManager::ShouldSkipLowPriorityScans() const
{
    std::lock_guard<std::mutex> l(m_statsMutex);
    return m_stats.isLoadBalancingActive;
}

std::vector<std::string> ScanPrioritizationManager::GetRegisteredScanners() const
{
    std::lock_guard<std::mutex> l(m_scannerMutex);
    std::vector<std::string> keys; keys.reserve(m_scanners.size());
    for (auto &kv : m_scanners) keys.push_back(kv.first);
    return keys;
}

void ScanPrioritizationManager::PrintDebugInfo() const
{
    auto stats = GetStatistics();
    wchar_t buf[256];
    swprintf_s(buf, L"[ScanPri] pending=%zu executed=%u skipped=%u cpu=%.1f\n", GetPendingTaskCount(), stats.totalTasksExecuted, stats.totalTasksSkipped, stats.currentCpuUsage);
    OutputDebugStringW(buf);
}
