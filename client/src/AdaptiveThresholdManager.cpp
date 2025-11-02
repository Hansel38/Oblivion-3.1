// ===== PRIORITY 4.1.4: Adaptive Threshold Manager Implementation =====
#include "../pch.h"
#include "AdaptiveThresholdManager.h"
#include "TelemetryCollector.h"
#include "MLAnomalyDetector.h"
#include <algorithm>
#include <cmath>
#include <fstream>

// Global instance
AdaptiveThresholdManager* g_pAdaptiveThresholdManager = nullptr;

// Module name mapping
static const char* MODULE_NAMES[] = {
    "ProcessThreadWatcher",
    "OverlayScanner",
    "AntiDebug",
    "InjectionScanner",
    "SignatureValidator",
    "HijackedThread",
    "IATHook",
    "FileIntegrity",
    "MemorySignature",
    "PEBManipulation",
    "HardwareBreakpoint",
    "SuspiciousMemory",
    "HeapSpray",
    "ETHREADManipulation",
    "KernelCallback",
    "VADManipulation",
    "CEBehavior",
    "CERegistry",
    "CEWindow",
    "SpeedHack",
    "DeviceObject",
    "NetworkArtifact",
    "MLAnomaly"
};

// ===== AdaptiveThresholdManager Implementation =====
AdaptiveThresholdManager::AdaptiveThresholdManager(const AdaptiveThresholdConfig& config)
    : m_config(config), m_telemetry(nullptr), m_mlDetector(nullptr),
      m_lastDecayCheck(0), m_lastProfileSave(0), m_autoDecayEnabled(false),
      m_decayThread(nullptr), m_stopDecay(false) {
    
    // Initialize global thresholds with defaults
    for (int i = 0; i < static_cast<int>(DetectionModule::COUNT); ++i) {
        DetectionModule module = static_cast<DetectionModule>(i);
        AdaptiveThreshold threshold;
        threshold.module = module;
        threshold.baseThreshold = 2;  // Default
        threshold.currentThreshold = 2;
        threshold.sigmaMultiplier = m_config.defaultSigmaMultiplier;
        threshold.minThreshold = m_config.globalMinThreshold;
        threshold.maxThreshold = m_config.globalMaxThreshold;
        threshold.decayRate = m_config.decayRate;
        m_globalThresholds[module] = threshold;
    }
    
    // Initialize statistics
    memset(&m_stats, 0, sizeof(m_stats));
    m_stats.averageTrustScore = m_config.trustScoreInitial;
}

AdaptiveThresholdManager::~AdaptiveThresholdManager() {
    // Stop auto-decay thread
    if (m_decayThread) {
        m_stopDecay = true;
        WaitForSingleObject(m_decayThread, 5000);
        CloseHandle(m_decayThread);
    }
    
    // Save profiles if persistence enabled
    if (m_config.enableProfilePersistence) {
        SaveAllProfiles();
    }
}

bool AdaptiveThresholdManager::Initialize(TelemetryCollector* telemetry, MLAnomalyDetector* mlDetector) {
    if (!telemetry) return false;
    
    m_telemetry = telemetry;
    m_mlDetector = mlDetector;
    
    // Load existing profiles if available
    if (m_config.enableProfilePersistence) {
        LoadAllProfiles();
    }
    
    // Start auto-decay thread if enabled
    if (m_config.decayInterval > 0) {
        m_autoDecayEnabled = true;
        m_stopDecay = false;
        m_decayThread = CreateThread(nullptr, 0, DecayThreadProc, this, 0, nullptr);
    }
    
    return true;
}

DWORD WINAPI AdaptiveThresholdManager::DecayThreadProc(LPVOID param) {
    AdaptiveThresholdManager* manager = static_cast<AdaptiveThresholdManager*>(param);
    
    while (!manager->m_stopDecay) {
        Sleep(static_cast<DWORD>(manager->m_config.decayInterval));
        
        if (!manager->m_stopDecay && manager->m_autoDecayEnabled) {
            manager->ApplyDecay();
        }
    }
    
    return 0;
}

bool AdaptiveThresholdManager::CreatePlayerProfile(const std::string& playerID) {
    if (playerID.empty()) return false;
    
    std::lock_guard<std::mutex> lock(m_profileMutex);
    
    // Check if profile already exists
    if (m_playerProfiles.find(playerID) != m_playerProfiles.end()) {
        return false;  // Already exists
    }
    
    PlayerProfile profile;
    profile.playerID = playerID;
    profile.trustScore = m_config.trustScoreInitial;
    profile.profileCreated = GetTickCount64();
    profile.lastSeen = profile.profileCreated;
    
    // Initialize thresholds for all modules
    for (int i = 0; i < static_cast<int>(DetectionModule::COUNT); ++i) {
        DetectionModule module = static_cast<DetectionModule>(i);
        AdaptiveThreshold threshold = m_globalThresholds[module];
        profile.thresholds[module] = threshold;
    }
    
    m_playerProfiles[playerID] = profile;
    m_stats.totalProfiles++;
    
    return true;
}

bool AdaptiveThresholdManager::LoadPlayerProfile(const std::string& playerID) {
    // Simplified - would load from persistent storage
    return m_playerProfiles.find(playerID) != m_playerProfiles.end();
}

bool AdaptiveThresholdManager::SavePlayerProfile(const std::string& playerID) {
    // Simplified - would save to persistent storage
    std::lock_guard<std::mutex> lock(m_profileMutex);
    return m_playerProfiles.find(playerID) != m_playerProfiles.end();
}

void AdaptiveThresholdManager::DeletePlayerProfile(const std::string& playerID) {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    auto it = m_playerProfiles.find(playerID);
    if (it != m_playerProfiles.end()) {
        m_playerProfiles.erase(it);
        m_stats.totalProfiles--;
    }
}

void AdaptiveThresholdManager::SetActivePlayer(const std::string& playerID) {
    m_activePlayerID = playerID;
    
    // Create profile if doesn't exist
    if (!playerID.empty() && m_playerProfiles.find(playerID) == m_playerProfiles.end()) {
        CreatePlayerProfile(playerID);
    }
    
    // Update last seen
    std::lock_guard<std::mutex> lock(m_profileMutex);
    auto* profile = GetProfile(playerID);
    if (profile) {
        profile->lastSeen = GetTickCount64();
    }
}

void AdaptiveThresholdManager::UpdateBaseline(const std::string& playerID) {
    if (!m_telemetry || playerID.empty()) return;
    
    std::lock_guard<std::mutex> lock(m_profileMutex);
    auto* profile = GetProfile(playerID);
    if (!profile) return;
    
    UpdateStatistics(profile->stats, m_telemetry);
    
    // Update thresholds based on new baseline
    for (auto& pair : profile->thresholds) {
        CalculateAdaptiveThreshold(pair.second, profile->stats);
    }
}

void AdaptiveThresholdManager::UpdateGlobalBaseline() {
    if (!m_telemetry) return;
    
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    UpdateStatistics(m_globalBaseline, m_telemetry);
    
    // Update global thresholds
    for (auto& pair : m_globalThresholds) {
        CalculateAdaptiveThreshold(pair.second, m_globalBaseline);
    }
    
    m_stats.lastBaselineUpdate = GetTickCount64();
}

BehaviorStatistics AdaptiveThresholdManager::GetBaseline(const std::string& playerID) const {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    const auto* profile = GetProfile(playerID);
    return profile ? profile->stats : BehaviorStatistics();
}

BehaviorStatistics AdaptiveThresholdManager::GetGlobalBaseline() const {
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    return m_globalBaseline;
}

int AdaptiveThresholdManager::GetAdaptiveThreshold(DetectionModule module) const {
    return GetAdaptiveThreshold(module, m_activePlayerID);
}

int AdaptiveThresholdManager::GetAdaptiveThreshold(DetectionModule module, const std::string& playerID) const {
    if (!m_config.enableAdaptiveThresholds) {
        // Return base threshold if adaptive is disabled
        auto it = m_globalThresholds.find(module);
        return it != m_globalThresholds.end() ? it->second.baseThreshold : 2;
    }
    
    // Try per-player threshold first
    if (m_config.usePerPlayerProfiles && !playerID.empty()) {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        const auto* profile = GetProfile(playerID);
        if (profile) {
            auto it = profile->thresholds.find(module);
            if (it != profile->thresholds.end()) {
                return it->second.currentThreshold;
            }
        }
    }
    
    // Fall back to global threshold
    if (m_config.useGlobalBaseline) {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        auto it = m_globalThresholds.find(module);
        if (it != m_globalThresholds.end()) {
            return it->second.currentThreshold;
        }
    }
    
    // Ultimate fallback
    return 2;
}

void AdaptiveThresholdManager::SetBaseThreshold(DetectionModule module, int threshold) {
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    auto it = m_globalThresholds.find(module);
    if (it != m_globalThresholds.end()) {
        it->second.baseThreshold = threshold;
        it->second.currentThreshold = threshold;
    }
}

void AdaptiveThresholdManager::AdjustThreshold(DetectionModule module, int delta) {
    // Adjust for active player
    if (!m_activePlayerID.empty() && m_config.usePerPlayerProfiles) {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        auto* profile = GetProfile(m_activePlayerID);
        if (profile) {
            auto it = profile->thresholds.find(module);
            if (it != profile->thresholds.end()) {
                AdjustThresholdInternal(it->second, delta);
                m_stats.adjustmentsMade++;
            }
        }
    } else {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        auto it = m_globalThresholds.find(module);
        if (it != m_globalThresholds.end()) {
            AdjustThresholdInternal(it->second, delta);
            m_stats.adjustmentsMade++;
        }
    }
}

void AdaptiveThresholdManager::ResetThreshold(DetectionModule module) {
    if (!m_activePlayerID.empty() && m_config.usePerPlayerProfiles) {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        auto* profile = GetProfile(m_activePlayerID);
        if (profile) {
            auto it = profile->thresholds.find(module);
            if (it != profile->thresholds.end()) {
                it->second.currentThreshold = it->second.baseThreshold;
                it->second.lastAdjustment = GetTickCount64();
            }
        }
    } else {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        auto it = m_globalThresholds.find(module);
        if (it != m_globalThresholds.end()) {
            it->second.currentThreshold = it->second.baseThreshold;
            it->second.lastAdjustment = GetTickCount64();
        }
    }
}

void AdaptiveThresholdManager::ResetAllThresholds() {
    for (int i = 0; i < static_cast<int>(DetectionModule::COUNT); ++i) {
        ResetThreshold(static_cast<DetectionModule>(i));
    }
}

void AdaptiveThresholdManager::RecordDetection(DetectionModule module, bool isTruePositive) {
    ULONGLONG now = GetTickCount64();
    
    if (!m_activePlayerID.empty() && m_config.usePerPlayerProfiles) {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        auto* profile = GetProfile(m_activePlayerID);
        if (profile) {
            profile->stats.totalDetections++;
            if (!isTruePositive) {
                profile->stats.falsePositives++;
            }
            
            auto it = profile->thresholds.find(module);
            if (it != profile->thresholds.end()) {
                it->second.lastDetection = now;
            }
            
            // Update trust score
            if (isTruePositive) {
                profile->trustScore = max(0.0, profile->trustScore - m_config.trustScoreDecrement);
                if (profile->trustScore < 0.3) {
                    profile->isSuspicious = true;
                }
            }
        }
    }
    
    // Update global stats
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    m_globalBaseline.totalDetections++;
    if (!isTruePositive) {
        m_globalBaseline.falsePositives++;
    }
}

void AdaptiveThresholdManager::RecordFalsePositive(DetectionModule module) {
    RecordDetection(module, false);
    
    // Increase threshold to reduce false positives
    AdjustThreshold(module, 1);
}

void AdaptiveThresholdManager::RecordCleanScan(DetectionModule module) {
    if (!m_activePlayerID.empty() && m_config.usePerPlayerProfiles) {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        auto* profile = GetProfile(m_activePlayerID);
        if (profile) {
            profile->stats.totalScans++;
            
            // Reward clean scans with trust score increment
            profile->trustScore = min(1.0, profile->trustScore + m_config.trustScoreIncrement);
            if (profile->trustScore > 0.8) {
                profile->isLegitimate = true;
                profile->isSuspicious = false;
            }
        }
    }
    
    std::lock_guard<std::mutex> lock(m_baselineMutex);
    m_globalBaseline.totalScans++;
}

void AdaptiveThresholdManager::ApplyDecay() {
    ULONGLONG now = GetTickCount64();
    
    // Check if enough time has passed
    if (now - m_lastDecayCheck < m_config.decayInterval) {
        return;
    }
    
    m_lastDecayCheck = now;
    
    // Decay global thresholds
    {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        for (auto& pair : m_globalThresholds) {
            DecayThreshold(pair.second);
        }
    }
    
    // Decay per-player thresholds
    if (m_config.usePerPlayerProfiles) {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        for (auto& profilePair : m_playerProfiles) {
            for (auto& thresholdPair : profilePair.second.thresholds) {
                DecayThreshold(thresholdPair.second);
            }
        }
    }
    
    // Prune old profiles
    PruneOldProfiles();
}

double AdaptiveThresholdManager::GetTrustScore(const std::string& playerID) const {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    const auto* profile = GetProfile(playerID);
    return profile ? profile->trustScore : m_config.trustScoreInitial;
}

void AdaptiveThresholdManager::UpdateTrustScore(const std::string& playerID, double delta) {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    auto* profile = GetProfile(playerID);
    if (profile) {
        profile->trustScore = max(0.0, min(1.0, profile->trustScore + delta));
    }
}

bool AdaptiveThresholdManager::IsPlayerTrusted(const std::string& playerID) const {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    const auto* profile = GetProfile(playerID);
    return profile && profile->trustScore >= 0.8;
}

bool AdaptiveThresholdManager::IsPlayerSuspicious(const std::string& playerID) const {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    const auto* profile = GetProfile(playerID);
    return profile && profile->isSuspicious;
}

AdaptiveThresholdManager::ThresholdStatistics AdaptiveThresholdManager::GetStatistics() const {
    ThresholdStatistics stats = m_stats;
    
    // Count active profiles
    std::lock_guard<std::mutex> lock(m_profileMutex);
    ULONGLONG now = GetTickCount64();
    int activeCount = 0;
    double totalTrust = 0.0;
    int trustCount = 0;
    
    for (const auto& pair : m_playerProfiles) {
        if (now - pair.second.lastSeen < 3600000) {  // Active in last hour
            activeCount++;
        }
        totalTrust += pair.second.trustScore;
        trustCount++;
    }
    
    stats.activeProfiles = activeCount;
    stats.averageTrustScore = trustCount > 0 ? totalTrust / trustCount : m_config.trustScoreInitial;
    
    // Current thresholds
    for (const auto& pair : m_globalThresholds) {
        stats.currentThresholds[pair.first] = pair.second.currentThreshold;
        stats.confidenceLevels[pair.first] = pair.second.confidenceLevel;
    }
    
    return stats;
}

std::vector<std::pair<std::string, PlayerProfile>> AdaptiveThresholdManager::GetTopPlayers(int count) const {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    
    std::vector<std::pair<std::string, PlayerProfile>> players;
    for (const auto& pair : m_playerProfiles) {
        players.push_back(pair);
    }
    
    // Sort by trust score descending
    std::sort(players.begin(), players.end(),
        [](const auto& a, const auto& b) {
            return a.second.trustScore > b.second.trustScore;
        });
    
    if (static_cast<int>(players.size()) > count) {
        players.resize(count);
    }
    
    return players;
}

std::vector<std::pair<std::string, PlayerProfile>> AdaptiveThresholdManager::GetSuspiciousPlayers() const {
    std::lock_guard<std::mutex> lock(m_profileMutex);
    
    std::vector<std::pair<std::string, PlayerProfile>> suspicious;
    for (const auto& pair : m_playerProfiles) {
        if (pair.second.isSuspicious) {
            suspicious.push_back(pair);
        }
    }
    
    return suspicious;
}

void AdaptiveThresholdManager::SetConfig(const AdaptiveThresholdConfig& config) {
    m_config = config;
}

bool AdaptiveThresholdManager::SaveAllProfiles() {
    // Simplified - would save to binary/JSON file
    m_lastProfileSave = GetTickCount64();
    return true;
}

bool AdaptiveThresholdManager::LoadAllProfiles() {
    // Simplified - would load from binary/JSON file
    return true;
}

bool AdaptiveThresholdManager::ExportProfilesToJSON(const std::wstring& path) {
    // Simplified JSON export
    std::ofstream ofs(path);
    if (!ofs) return false;
    
    ofs << "{\n";
    ofs << "  \"profiles\": [\n";
    
    std::lock_guard<std::mutex> lock(m_profileMutex);
    bool first = true;
    for (const auto& pair : m_playerProfiles) {
        if (!first) ofs << ",\n";
        first = false;
        
        ofs << "    {\n";
        ofs << "      \"playerID\": \"" << pair.first << "\",\n";
        ofs << "      \"trustScore\": " << pair.second.trustScore << ",\n";
        ofs << "      \"totalScans\": " << pair.second.stats.totalScans << ",\n";
        ofs << "      \"totalDetections\": " << pair.second.stats.totalDetections << "\n";
        ofs << "    }";
    }
    
    ofs << "\n  ]\n";
    ofs << "}\n";
    ofs.close();
    
    return true;
}

// ===== Private Methods =====

void AdaptiveThresholdManager::CalculateAdaptiveThreshold(AdaptiveThreshold& threshold, const BehaviorStatistics& stats) {
    if (stats.sampleCount < m_config.minBaselineSamples) {
        // Not enough samples, use base threshold
        threshold.currentThreshold = threshold.baseThreshold;
        threshold.confidenceLevel = 0.0;
        return;
    }
    
    // Calculate threshold: mean + sigma * stddev
    double calculated = stats.detectionRateMean + 
                       threshold.sigmaMultiplier * stats.detectionRateStdDev;
    
    // Round and clamp
    int newThreshold = static_cast<int>(ceil(calculated));
    newThreshold = max(threshold.minThreshold, min(threshold.maxThreshold, newThreshold));
    
    threshold.currentThreshold = newThreshold;
    threshold.confidenceLevel = CalculateConfidence(stats);
    threshold.lastAdjustment = GetTickCount64();
    threshold.adjustmentCount++;
}

double AdaptiveThresholdManager::CalculateConfidence(const BehaviorStatistics& stats) const {
    if (stats.sampleCount == 0) return 0.0;
    
    // Confidence increases with sample count (logarithmic)
    double sampleConfidence = log10(static_cast<double>(stats.sampleCount + 1)) / 3.0;  // Max at 1000 samples
    sampleConfidence = min(1.0, sampleConfidence);
    
    // Decrease confidence if high variance
    double varianceConfidence = 1.0;
    if (stats.detectionRateMean > 0.0) {
        double cv = stats.detectionRateStdDev / stats.detectionRateMean;  // Coefficient of variation
        varianceConfidence = 1.0 / (1.0 + cv);
    }
    
    return sampleConfidence * varianceConfidence;
}

void AdaptiveThresholdManager::UpdateStatistics(BehaviorStatistics& stats, const TelemetryCollector* telemetry) {
    if (!telemetry) return;
    
    ULONGLONG now = GetTickCount64();
    
    // Update sample count
    stats.sampleCount++;
    
    // Get current metrics from telemetry
    auto aggregated = telemetry->GetCurrentPeriodStats();
    
    // Update scan frequency (online mean/variance)
    if (aggregated.totalScans > 0) {
        double scanFreq = static_cast<double>(aggregated.totalScans) / 
                         (stats.sessionDuration > 0 ? stats.sessionDuration / 60000.0 : 1.0);
        double variance = stats.scanFrequencyStdDev * stats.scanFrequencyStdDev;
        UpdateOnlineStatistics(stats.scanFrequencyMean, variance, scanFreq, stats.sampleCount);
        stats.scanFrequencyStdDev = sqrt(variance);
        stats.totalScans += aggregated.totalScans;
    }
    
    // Update detection rate
    if (aggregated.totalDetections > 0) {
        double detectionRate = static_cast<double>(aggregated.totalDetections);
        double variance = stats.detectionRateStdDev * stats.detectionRateStdDev;
        UpdateOnlineStatistics(stats.detectionRateMean, variance, detectionRate, stats.sampleCount);
        stats.detectionRateStdDev = sqrt(variance);
        stats.totalDetections += aggregated.totalDetections;
    }
    
    // Update resource usage
    double cpuUsage = aggregated.avgCPUUsage;
    double memUsage = aggregated.avgMemoryUsageMB;
    
    double cpuVar = stats.cpuUsageStdDev * stats.cpuUsageStdDev;
    double memVar = stats.memoryUsageStdDev * stats.memoryUsageStdDev;
    
    UpdateOnlineStatistics(stats.cpuUsageMean, cpuVar, cpuUsage, stats.sampleCount);
    UpdateOnlineStatistics(stats.memoryUsageMean, memVar, memUsage, stats.sampleCount);
    
    stats.cpuUsageStdDev = sqrt(cpuVar);
    stats.memoryUsageStdDev = sqrt(memVar);
    
    // Update timestamps
    if (stats.firstSeen == 0) {
        stats.firstSeen = now;
    }
    stats.lastUpdated = now;
    stats.sessionDuration = now - stats.firstSeen;
}

void AdaptiveThresholdManager::UpdateOnlineStatistics(double& mean, double& variance, double newValue, int sampleCount) {
    // Welford's online algorithm for mean and variance
    if (sampleCount == 1) {
        mean = newValue;
        variance = 0.0;
    } else {
        double delta = newValue - mean;
        mean += delta / sampleCount;
        double delta2 = newValue - mean;
        variance += (delta * delta2 - variance) / sampleCount;
    }
}

PlayerProfile* AdaptiveThresholdManager::GetProfile(const std::string& playerID) {
    auto it = m_playerProfiles.find(playerID);
    return it != m_playerProfiles.end() ? &it->second : nullptr;
}

const PlayerProfile* AdaptiveThresholdManager::GetProfile(const std::string& playerID) const {
    auto it = m_playerProfiles.find(playerID);
    return it != m_playerProfiles.end() ? &it->second : nullptr;
}

void AdaptiveThresholdManager::PruneOldProfiles() {
    ULONGLONG now = GetTickCount64();
    ULONGLONG maxAge = static_cast<ULONGLONG>(m_config.maxProfileAge) * 3600000;  // hours to ms
    
    std::vector<std::string> toDelete;
    for (const auto& pair : m_playerProfiles) {
        if (now - pair.second.lastSeen > maxAge) {
            toDelete.push_back(pair.first);
        }
    }
    
    for (const auto& id : toDelete) {
        m_playerProfiles.erase(id);
        m_stats.totalProfiles--;
    }
}

void AdaptiveThresholdManager::AdjustThresholdInternal(AdaptiveThreshold& threshold, int delta) {
    int newThreshold = threshold.currentThreshold + delta;
    newThreshold = max(threshold.minThreshold, min(threshold.maxThreshold, newThreshold));
    threshold.currentThreshold = newThreshold;
    threshold.lastAdjustment = GetTickCount64();
    threshold.adjustmentCount++;
}

void AdaptiveThresholdManager::DecayThreshold(AdaptiveThreshold& threshold) {
    // Gradually move current threshold back towards base threshold
    if (threshold.currentThreshold == threshold.baseThreshold) {
        return;  // Already at base
    }
    
    int diff = threshold.currentThreshold - threshold.baseThreshold;
    int decayed = static_cast<int>(diff * threshold.decayRate);
    
    if (abs(decayed) < 1) {
        // Close enough, snap to base
        threshold.currentThreshold = threshold.baseThreshold;
    } else {
        threshold.currentThreshold = threshold.baseThreshold + decayed;
    }
}

const char* AdaptiveThresholdManager::GetModuleName(DetectionModule module) {
    int idx = static_cast<int>(module);
    if (idx >= 0 && idx < static_cast<int>(DetectionModule::COUNT)) {
        return MODULE_NAMES[idx];
    }
    return "Unknown";
}

// ===== Utility Functions =====
namespace AdaptiveThresholdUtils {
    std::string ModuleToString(DetectionModule module) {
        return AdaptiveThresholdManager::GetModuleName(module);
    }
    
    DetectionModule StringToModule(const std::string& str) {
        for (int i = 0; i < static_cast<int>(DetectionModule::COUNT); ++i) {
            if (str == MODULE_NAMES[i]) {
                return static_cast<DetectionModule>(i);
            }
        }
        return DetectionModule::PROCESS_THREAD_WATCHER;  // Default fallback
    }
    
    double CalculateOptimalSigma(int sampleCount) {
        // More samples = tighter threshold (lower sigma)
        // Fewer samples = looser threshold (higher sigma)
        if (sampleCount < 10) return 4.0;
        if (sampleCount < 50) return 3.5;
        if (sampleCount < 100) return 3.0;
        if (sampleCount < 500) return 2.5;
        return 2.0;  // High confidence
    }
    
    std::pair<double, double> CalculateConfidenceInterval(double mean, double stdDev, int sampleCount, double confidence) {
        // Z-score for 95% confidence ≈ 1.96
        double z = (confidence >= 0.99) ? 2.576 : 
                   (confidence >= 0.95) ? 1.96 : 1.645;
        
        double margin = z * stdDev / sqrt(static_cast<double>(sampleCount));
        return {mean - margin, mean + margin};
    }
}
