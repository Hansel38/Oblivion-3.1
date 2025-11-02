// ===== PRIORITY 4.3.2: Adaptive Polling Manager =====
// Dynamically adjusts periodic scan interval based on threat level and CPU usage
// Version: 1.0 | Date: 2025-11-02

#pragma once
#include <Windows.h>
#include <mutex>

class TelemetryCollector;
class PeriodicScanner;

// Threat levels for adaptive polling
enum class ThreatLevel {
	LOW = 0,
	MEDIUM = 1,
	HIGH = 2,
	CRITICAL = 3
};

// Configuration for adaptive polling behavior
struct AdaptivePollingConfig {
	bool enableAdaptivePolling = true;
	DWORD baseIntervalMs = 15000;        // Nominal periodic interval
	DWORD minIntervalMs = 1000;          // Minimum allowed interval
	DWORD maxIntervalMs = 60000;         // Maximum allowed interval

	// Detection rate thresholds (detections / scans)
	double mediumRateThreshold = 0.001;  // 0.1%
	double highRateThreshold = 0.005;    // 0.5%
	double criticalRateThreshold = 0.02; // 2.0%

	// CPU usage thresholds (percent of process CPU usage)
	float cpuLowPercent = 40.0f;
	float cpuHighPercent = 85.0f;

	// Smoothing / hysteresis
	DWORD minChangeCooldownMs = 5000;    // Minimum time between interval changes
	float minChangePercent = 0.15f;      // Only apply if change >= 15%
};

// Statistics for monitoring
struct AdaptivePollingStats {
	ThreatLevel currentThreat = ThreatLevel::LOW;
	DWORD currentIntervalMs = 15000;
	double lastDetectionRate = 0.0;
	float lastCpuPercent = 0.0f;
	ULONGLONG lastChangeTime = 0;
};

class AdaptivePollingManager {
public:
	explicit AdaptivePollingManager(const AdaptivePollingConfig& cfg = AdaptivePollingConfig());

	void Initialize(TelemetryCollector* telemetry, PeriodicScanner* periodic);

	// Call periodically (e.g., at the end of each periodic Tick)
	void Update(float cpuPercentOptional = -1.0f);

	// Accessors
	AdaptivePollingStats GetStats() const;
	void SetConfig(const AdaptivePollingConfig& cfg);

private:
	// Compute threat level based on detection rate
	ThreatLevel ComputeThreatLevel(double detectionRate) const;
	// Compute recommended interval given threat and CPU
	DWORD ComputeRecommendedInterval(ThreatLevel tl, float cpuPercent) const;
	// Apply new interval to PeriodicScanner if change is significant and cooldown passed
	void MaybeApplyInterval(DWORD newIntervalMs);

	// Dependencies
	TelemetryCollector* m_telemetry = nullptr;
	PeriodicScanner* m_periodic = nullptr;

	// State
	AdaptivePollingConfig m_cfg;
	mutable std::mutex m_mutex;
	AdaptivePollingStats m_stats;
};

// Global instance (optional)
extern AdaptivePollingManager* g_pAdaptivePolling;

