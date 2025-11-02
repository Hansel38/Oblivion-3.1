// ===== PRIORITY 4.1.4: Adaptive Threshold Manager =====
// Dynamic threshold adjustment system based on player behavior baseline
// Implements statistical threshold calculation and per-player profiles
// Version: 1.0
// Author: Oblivion AntiCheat Team
// Date: 2025-11-02

#pragma once
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

// Forward declarations
class TelemetryCollector;
class MLAnomalyDetector;

// ===== Threshold Profile Types =====
enum class ThresholdProfileType {
    GLOBAL,         // Server-wide baseline for all players
    PER_PLAYER,     // Individual player behavior profile
    SESSION         // Current session only (temporary)
};

// ===== Detection Module Types =====
enum class DetectionModule {
    PROCESS_THREAD_WATCHER,
    OVERLAY_SCANNER,
    ANTI_DEBUG,
    INJECTION_SCANNER,
    SIGNATURE_VALIDATOR,
    HIJACKED_THREAD,
    IAT_HOOK,
    FILE_INTEGRITY,
    MEMORY_SIGNATURE,
    PEB_MANIPULATION,
    HARDWARE_BREAKPOINT,
    SUSPICIOUS_MEMORY,
    HEAP_SPRAY,
    ETHREAD_MANIPULATION,
    KERNEL_CALLBACK,
    VAD_MANIPULATION,
    CE_BEHAVIOR,
    CE_REGISTRY,
    CE_WINDOW,
    SPEED_HACK,
    DEVICE_OBJECT,
    NETWORK_ARTIFACT,
    ML_ANOMALY,
    COUNT  // Total number of modules
};

// ===== Behavior Statistics for Baseline =====
struct BehaviorStatistics {
    // Scan frequency statistics
    double scanFrequencyMean;           // Average scans per minute
    double scanFrequencyStdDev;         // Standard deviation
    ULONGLONG totalScans;               // Total number of scans
    
    // Detection statistics
    double detectionRateMean;           // Average detections per hour
    double detectionRateStdDev;         // Standard deviation
    ULONGLONG totalDetections;          // Total detections
    ULONGLONG falsePositives;           // Estimated false positives
    
    // Resource usage statistics
    double cpuUsageMean;                // Average CPU usage (%)
    double cpuUsageStdDev;              // Standard deviation
    double memoryUsageMean;             // Average memory usage (MB)
    double memoryUsageStdDev;           // Standard deviation
    
    // Temporal statistics
    ULONGLONG firstSeen;                // First data collection timestamp
    ULONGLONG lastUpdated;              // Last update timestamp
    ULONGLONG sessionDuration;          // Total session time (ms)
    
    // Sample count
    int sampleCount;                    // Number of samples collected
    
    BehaviorStatistics()
        : scanFrequencyMean(0.0), scanFrequencyStdDev(0.0), totalScans(0),
          detectionRateMean(0.0), detectionRateStdDev(0.0), totalDetections(0),
          falsePositives(0), cpuUsageMean(0.0), cpuUsageStdDev(0.0),
          memoryUsageMean(0.0), memoryUsageStdDev(0.0), firstSeen(0),
          lastUpdated(0), sessionDuration(0), sampleCount(0) {}
};

// ===== Adaptive Threshold for a Module =====
struct AdaptiveThreshold {
    DetectionModule module;
    int baseThreshold;                  // Original static threshold
    int currentThreshold;               // Current adaptive threshold
    double confidenceLevel;             // Confidence in threshold (0.0-1.0)
    
    // Statistical parameters
    double mean;                        // Mean indicator count from baseline
    double stdDev;                      // Standard deviation
    double sigmaMultiplier;             // N in (mean + N*stddev)
    
    // Adaptive parameters
    int minThreshold;                   // Minimum allowed threshold
    int maxThreshold;                   // Maximum allowed threshold
    double decayRate;                   // Decay rate for threshold reset
    
    // Temporal tracking
    ULONGLONG lastAdjustment;           // Last threshold adjustment time
    ULONGLONG lastDetection;            // Last detection timestamp
    int adjustmentCount;                // Number of adjustments made
    
    AdaptiveThreshold()
        : module(DetectionModule::PROCESS_THREAD_WATCHER), baseThreshold(2),
          currentThreshold(2), confidenceLevel(0.0), mean(0.0), stdDev(0.0),
          sigmaMultiplier(3.0), minThreshold(1), maxThreshold(10),
          decayRate(0.95), lastAdjustment(0), lastDetection(0),
          adjustmentCount(0) {}
};

// ===== Player Profile =====
struct PlayerProfile {
    std::string playerID;               // Unique player identifier (HWID or account ID)
    BehaviorStatistics stats;           // Behavior statistics
    std::unordered_map<DetectionModule, AdaptiveThreshold> thresholds;
    
    // Profile metadata
    bool isLegitimate;                  // Known legitimate player
    bool isSuspicious;                  // Flagged as suspicious
    double trustScore;                  // Trust score (0.0-1.0)
    ULONGLONG profileCreated;           // Profile creation time
    ULONGLONG lastSeen;                 // Last activity timestamp
    
    PlayerProfile()
        : playerID(""), isLegitimate(false), isSuspicious(false),
          trustScore(0.5), profileCreated(0), lastSeen(0) {}
};

// ===== Adaptive Threshold Manager Configuration =====
struct AdaptiveThresholdConfig {
    bool enableAdaptiveThresholds;      // Master switch
    bool usePerPlayerProfiles;          // Enable per-player profiling
    bool useGlobalBaseline;             // Use global baseline
    
    // Statistical parameters
    double defaultSigmaMultiplier;      // Default N for (mean + N*stddev)
    int minBaselineSamples;             // Minimum samples before adaptation
    int maxProfileAge;                  // Max age for profiles (hours)
    
    // Threshold bounds
    int globalMinThreshold;             // Global minimum threshold
    int globalMaxThreshold;             // Global maximum threshold
    
    // Decay and reset
    double decayRate;                   // Hourly decay rate (0.0-1.0)
    ULONGLONG decayInterval;            // Decay check interval (ms)
    bool enableAutoReset;               // Auto-reset to baseline
    ULONGLONG resetInterval;            // Reset interval (ms)
    
    // Trust scoring
    double trustScoreInitial;           // Initial trust score for new players
    double trustScoreIncrement;         // Increment per clean session
    double trustScoreDecrement;         // Decrement per detection
    
    // Persistence
    bool enableProfilePersistence;      // Save/load profiles
    std::wstring profileSavePath;       // Path to profile database
    ULONGLONG profileSaveInterval;      // Save interval (ms)
    
    AdaptiveThresholdConfig()
        : enableAdaptiveThresholds(true), usePerPlayerProfiles(true),
          useGlobalBaseline(true), defaultSigmaMultiplier(3.0),
          minBaselineSamples(100), maxProfileAge(720),  // 30 days
          globalMinThreshold(1), globalMaxThreshold(10),
          decayRate(0.95), decayInterval(3600000),  // 1 hour
          enableAutoReset(false), resetInterval(86400000),  // 24 hours
          trustScoreInitial(0.5), trustScoreIncrement(0.05),
          trustScoreDecrement(0.2), enableProfilePersistence(false),
          profileSavePath(L"player_profiles.dat"),
          profileSaveInterval(300000) {}  // 5 minutes
};

// ===== Main Adaptive Threshold Manager =====
class AdaptiveThresholdManager {
public:
    explicit AdaptiveThresholdManager(const AdaptiveThresholdConfig& config = AdaptiveThresholdConfig());
    ~AdaptiveThresholdManager();

    // Initialize with telemetry and ML detector
    bool Initialize(TelemetryCollector* telemetry, MLAnomalyDetector* mlDetector);

    // Player profile management
    bool CreatePlayerProfile(const std::string& playerID);
    bool LoadPlayerProfile(const std::string& playerID);
    bool SavePlayerProfile(const std::string& playerID);
    void DeletePlayerProfile(const std::string& playerID);
    
    // Set active player for session
    void SetActivePlayer(const std::string& playerID);
    std::string GetActivePlayer() const { return m_activePlayerID; }

    // Baseline establishment
    void UpdateBaseline(const std::string& playerID);
    void UpdateGlobalBaseline();
    BehaviorStatistics GetBaseline(const std::string& playerID) const;
    BehaviorStatistics GetGlobalBaseline() const;

    // Threshold calculation and retrieval
    int GetAdaptiveThreshold(DetectionModule module) const;
    int GetAdaptiveThreshold(DetectionModule module, const std::string& playerID) const;
    void SetBaseThreshold(DetectionModule module, int threshold);
    
    // Manual threshold adjustment
    void AdjustThreshold(DetectionModule module, int delta);
    void ResetThreshold(DetectionModule module);
    void ResetAllThresholds();

    // Detection feedback (for adaptive learning)
    void RecordDetection(DetectionModule module, bool isTruePositive);
    void RecordFalsePositive(DetectionModule module);
    void RecordCleanScan(DetectionModule module);

    // Threshold decay (gradual reset to baseline)
    void ApplyDecay();
    void EnableAutoDecay(bool enable) { m_autoDecayEnabled = enable; }

    // Trust scoring
    double GetTrustScore(const std::string& playerID) const;
    void UpdateTrustScore(const std::string& playerID, double delta);
    bool IsPlayerTrusted(const std::string& playerID) const;
    bool IsPlayerSuspicious(const std::string& playerID) const;

    // Statistics and reporting
    struct ThresholdStatistics {
        int totalProfiles;
        int activeProfiles;
        int adjustmentsMade;
        double averageTrustScore;
        ULONGLONG lastBaselineUpdate;
        std::unordered_map<DetectionModule, int> currentThresholds;
        std::unordered_map<DetectionModule, double> confidenceLevels;
    };
    
    ThresholdStatistics GetStatistics() const;
    std::vector<std::pair<std::string, PlayerProfile>> GetTopPlayers(int count) const;
    std::vector<std::pair<std::string, PlayerProfile>> GetSuspiciousPlayers() const;

    // Configuration
    void SetConfig(const AdaptiveThresholdConfig& config);
    AdaptiveThresholdConfig GetConfig() const { return m_config; }

    // Persistence
    bool SaveAllProfiles();
    bool LoadAllProfiles();
    bool ExportProfilesToJSON(const std::wstring& path);

private:
    // Statistical calculations
    void CalculateAdaptiveThreshold(AdaptiveThreshold& threshold, const BehaviorStatistics& stats);
    double CalculateConfidence(const BehaviorStatistics& stats) const;
    void UpdateStatistics(BehaviorStatistics& stats, const TelemetryCollector* telemetry);
    
    // Welford's online algorithm for mean/variance
    void UpdateOnlineStatistics(double& mean, double& variance, double newValue, int sampleCount);
    
    // Profile management internals
    PlayerProfile* GetProfile(const std::string& playerID);
    const PlayerProfile* GetProfile(const std::string& playerID) const;
    void PruneOldProfiles();
    
    // Threshold adjustment logic
    void AdjustThresholdInternal(AdaptiveThreshold& threshold, int delta);
    void DecayThreshold(AdaptiveThreshold& threshold);
    
public:
    // Helper: module name for logging
    static const char* GetModuleName(DetectionModule module);

private:
    AdaptiveThresholdConfig m_config;
    
    // Global baseline
    BehaviorStatistics m_globalBaseline;
    std::unordered_map<DetectionModule, AdaptiveThreshold> m_globalThresholds;
    
    // Per-player profiles
    std::unordered_map<std::string, PlayerProfile> m_playerProfiles;
    std::string m_activePlayerID;
    
    // External dependencies
    TelemetryCollector* m_telemetry;
    MLAnomalyDetector* m_mlDetector;
    
    // Thread safety
    mutable std::mutex m_profileMutex;
    mutable std::mutex m_baselineMutex;
    
    // Statistics tracking
    ThresholdStatistics m_stats;
    ULONGLONG m_lastDecayCheck;
    ULONGLONG m_lastProfileSave;
    
    // Auto-decay background task
    bool m_autoDecayEnabled;
    HANDLE m_decayThread;
    volatile bool m_stopDecay;
    static DWORD WINAPI DecayThreadProc(LPVOID param);
};

// ===== Utility Functions =====
namespace AdaptiveThresholdUtils {
    // Convert module enum to string
    std::string ModuleToString(DetectionModule module);
    
    // Convert string to module enum
    DetectionModule StringToModule(const std::string& str);
    
    // Calculate optimal sigma multiplier based on sample size
    double CalculateOptimalSigma(int sampleCount);
    
    // Confidence interval calculation
    std::pair<double, double> CalculateConfidenceInterval(double mean, double stdDev, int sampleCount, double confidence = 0.95);
}

// ===== Global Adaptive Threshold Manager Instance =====
extern AdaptiveThresholdManager* g_pAdaptiveThresholdManager;
