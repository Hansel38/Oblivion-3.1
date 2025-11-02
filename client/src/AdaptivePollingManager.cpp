#include "../pch.h"
#include "AdaptivePollingManager.h"
#include "TelemetryCollector.h"
#include "PeriodicScanner.h"

AdaptivePollingManager::AdaptivePollingManager(const AdaptivePollingConfig& cfg)
    : m_cfg(cfg)
{
    m_stats.currentIntervalMs = cfg.baseIntervalMs;
}

void AdaptivePollingManager::Initialize(TelemetryCollector* telemetry, PeriodicScanner* periodic)
{
    std::lock_guard<std::mutex> l(m_mutex);
    m_telemetry = telemetry;
    m_periodic = periodic;
    if (m_periodic && m_cfg.baseIntervalMs) {
        m_periodic->SetIntervalMs(m_cfg.baseIntervalMs);
        m_stats.currentIntervalMs = m_cfg.baseIntervalMs;
        m_stats.lastChangeTime = GetTickCount64();
    }
}

void AdaptivePollingManager::Update(float cpuPercentOptional)
{
    std::lock_guard<std::mutex> l(m_mutex);
    if (!m_cfg.enableAdaptivePolling || !m_periodic) return;

    double rate = 0.0;
    if (m_telemetry) {
        try { rate = m_telemetry->GetDetectionRate(); } catch (...) { rate = 0.0; }
    }

    float cpu = cpuPercentOptional;
    if (cpu < 0.0f) {
        // Fall back: derive from TelemetryCollector's system metrics if available later
        cpu = 0.0f; // neutral
    }

    m_stats.lastDetectionRate = rate;
    m_stats.lastCpuPercent = cpu;

    ThreatLevel tl = ComputeThreatLevel(rate);
    m_stats.currentThreat = tl;

    DWORD rec = ComputeRecommendedInterval(tl, cpu);
    MaybeApplyInterval(rec);
}

AdaptivePollingStats AdaptivePollingManager::GetStats() const
{
    std::lock_guard<std::mutex> l(m_mutex);
    return m_stats;
}

void AdaptivePollingManager::SetConfig(const AdaptivePollingConfig& cfg)
{
    std::lock_guard<std::mutex> l(m_mutex);
    m_cfg = cfg;
}

ThreatLevel AdaptivePollingManager::ComputeThreatLevel(double detectionRate) const
{
    if (detectionRate >= m_cfg.criticalRateThreshold) return ThreatLevel::CRITICAL;
    if (detectionRate >= m_cfg.highRateThreshold) return ThreatLevel::HIGH;
    if (detectionRate >= m_cfg.mediumRateThreshold) return ThreatLevel::MEDIUM;
    return ThreatLevel::LOW;
}

DWORD AdaptivePollingManager::ComputeRecommendedInterval(ThreatLevel tl, float cpuPercent) const
{
    double factor = 1.0;
    switch (tl) {
        case ThreatLevel::LOW: factor = 1.0; break;
        case ThreatLevel::MEDIUM: factor = 0.7; break;
        case ThreatLevel::HIGH: factor = 0.33; break;
        case ThreatLevel::CRITICAL: factor = 0.2; break;
    }

    // CPU load balancing: if CPU is high, back off (increase interval)
    if (cpuPercent >= m_cfg.cpuHighPercent) {
        factor *= 1.5; // slower when CPU is hot
    } else if (cpuPercent > 0.0f && cpuPercent <= m_cfg.cpuLowPercent && (tl == ThreatLevel::HIGH || tl == ThreatLevel::CRITICAL)) {
        factor *= 0.8; // even faster when CPU is free and threat is high
    }

    double d = static_cast<double>(m_cfg.baseIntervalMs) * factor;
    DWORD interval = static_cast<DWORD>(d);
    if (interval < m_cfg.minIntervalMs) interval = m_cfg.minIntervalMs;
    if (interval > m_cfg.maxIntervalMs) interval = m_cfg.maxIntervalMs;
    return interval;
}

void AdaptivePollingManager::MaybeApplyInterval(DWORD newIntervalMs)
{
    if (!m_periodic) return;
    ULONGLONG now = GetTickCount64();
    if (now - m_stats.lastChangeTime < m_cfg.minChangeCooldownMs) return;

    DWORD cur = m_stats.currentIntervalMs;
    if (!cur) cur = m_cfg.baseIntervalMs;

    // Only apply if relative change >= minChangePercent
    double delta = (cur > 0) ? (static_cast<double>( (cur > newIntervalMs) ? (cur - newIntervalMs) : (newIntervalMs - cur) ) / static_cast<double>(cur)) : 1.0;
    if (delta < m_cfg.minChangePercent) return;

    m_periodic->SetIntervalMs(newIntervalMs);
    m_stats.currentIntervalMs = newIntervalMs;
    m_stats.lastChangeTime = now;
}
