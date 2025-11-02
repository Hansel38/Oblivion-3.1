#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <windows.h>

// =====================================================================
// MLFeatureExtractor.h
// Priority 4.1.2 - ML Feature Extraction Pipeline
// 
// Extracts statistical features from telemetry data for ML models:
// - Time-series features (moving averages, variance, trends)
// - Behavioral patterns (scan frequencies, detection rates)
// - System resource patterns (CPU/memory usage trends)
// - Anomaly indicators (outliers, sudden changes)
// =====================================================================

// Forward declarations
struct AggregatedStats;
struct ScanTelemetry;
struct DetectionTelemetry;
struct SystemMetric;
class TelemetryCollector;

// Feature vector - normalized values ready for ML
struct FeatureVector {
    // Metadata
    ULONGLONG timestamp;
    std::string featureSetVersion;  // For schema versioning
    
    // === Scan Behavior Features (15 features) ===
    float scanFrequency;              // Scans per minute
    float detectionRate;              // Detections / scans
    float falsePositiveRate;          // FPs / detections
    float avgScanTime;                // Average scan duration (normalized)
    float maxScanTime;                // Max scan duration (normalized)
    float scanTimeVariance;           // Variance in scan times
    float cleanScanRatio;             // Clean scans / total scans
    float suspiciousScanRatio;        // Suspicious / total
    float errorScanRatio;             // Errors / total
    float scanBurstiness;             // Measure of scan clustering
    float scanDiversity;              // Number of unique scan types
    float scanRepetitionRate;         // Same scan repeated quickly
    float periodicScanCompliance;     // Adherence to expected intervals
    float throttledScanRatio;         // Throttled / total scans
    float scanTimeOutliers;           // Number of outlier scan times
    
    // === System Resource Features (10 features) ===
    float avgCPUUsage;                // Average CPU (normalized 0-1)
    float maxCPUUsage;                // Peak CPU usage
    float cpuVariance;                // CPU usage variance
    float cpuTrend;                   // CPU trend (increasing/decreasing)
    float avgMemoryUsage;             // Average memory (normalized)
    float maxMemoryUsage;             // Peak memory usage
    float memoryGrowthRate;           // Memory growth over time
    float threadCountAvg;             // Average thread count
    float handleCountAvg;             // Average handle count
    float resourceStability;          // Low variance = stable
    
    // === Detection Pattern Features (10 features) ===
    float detectionBurstiness;        // Clustering of detections
    float detectionDiversity;         // Variety of detection types
    float suppressionRate;            // Suppressed / total detections
    float avgIndicatorCount;          // Average indicators per detection
    float maxIndicatorCount;          // Max indicators
    float indicatorVariance;          // Variance in indicator counts
    float recentDetectionRate;        // Detections in last N minutes
    float detectionTrend;             // Increasing/decreasing trend
    float contributingScanDiversity;  // Variety of contributing scans
    float detectionTimePattern;       // Temporal pattern score
    
    // === Temporal Features (8 features) ===
    float timeSinceLastDetection;     // Minutes since last detection (normalized)
    float timeSinceLastScan;          // Minutes since last scan
    float sessionDuration;            // Total runtime (normalized)
    float hourOfDay;                  // 0-23 normalized to 0-1
    float dayOfWeek;                  // 0-6 normalized to 0-1
    float scanRateChange;             // Recent vs historical scan rate
    float detectionRateChange;        // Recent vs historical detection rate
    float activityLevel;              // Overall activity intensity
    
    // === Anomaly Indicators (7 features) ===
    float outlierScoreScans;          // Statistical outlier score for scans
    float outlierScoreDetections;     // Statistical outlier for detections
    float outlierScoreCPU;            // Outlier for CPU usage
    float outlierScoreMemory;         // Outlier for memory usage
    float suddenChangeScore;          // Magnitude of sudden changes
    float abnormalPatternScore;       // Pattern anomaly score
    float overallAnomalyScore;        // Combined anomaly indicator
    
    // Total: 50 features
};

// Configuration for feature extraction
struct FeatureExtractionConfig {
    // Window sizes for statistics
    ULONGLONG shortWindowMs = 60000;      // 1 minute
    ULONGLONG mediumWindowMs = 300000;    // 5 minutes
    ULONGLONG longWindowMs = 1800000;     // 30 minutes
    
    // Normalization bounds
    float maxExpectedScanTime = 1000.0f;  // 1 second max expected
    float maxExpectedCPU = 100.0f;        // 100% CPU
    float maxExpectedMemoryMB = 512.0f;   // 512MB max expected
    float maxSessionDurationMs = 14400000.0f; // 4 hours
    
    // Anomaly detection thresholds
    float outlierThresholdStdDev = 3.0f;  // 3 standard deviations
    float burstinessThreshold = 2.0f;     // Burst detection sensitivity
    float trendSmoothingFactor = 0.3f;    // EMA smoothing (0-1)
    
    // Feature selection
    bool includeTemporalFeatures = true;
    bool includeAnomalyFeatures = true;
    bool includeResourceFeatures = true;
    bool includeDetectionFeatures = true;
};

// Statistics for normalization and outlier detection
struct FeatureStatistics {
    float mean;
    float stdDev;
    float min;
    float max;
    DWORD sampleCount;
};

class MLFeatureExtractor {
public:
    MLFeatureExtractor();
    ~MLFeatureExtractor();
    
    // Configuration
    void SetConfig(const FeatureExtractionConfig& config);
    void SetTelemetryCollector(TelemetryCollector* pCollector);
    
    // Feature extraction
    FeatureVector ExtractFeatures(ULONGLONG currentTime);
    FeatureVector ExtractFeaturesFromStats(const AggregatedStats& stats, ULONGLONG currentTime);
    
    // Normalization
    void UpdateStatistics(const FeatureVector& features);
    FeatureVector NormalizeFeatures(const FeatureVector& rawFeatures);
    
    // Feature selection
    std::vector<float> GetSelectedFeatures(const FeatureVector& features, const std::vector<int>& indices);
    std::vector<int> SelectTopKFeatures(int k);  // Select K most important features
    
    // Serialization
    std::string SerializeFeatures(const FeatureVector& features) const;
    bool DeserializeFeatures(const std::string& data, FeatureVector& outFeatures) const;
    
    // Export for training
    bool ExportFeaturesToCSV(const std::wstring& filepath, const std::vector<FeatureVector>& features) const;
    std::string GetFeatureCSVHeader() const;
    std::string FeatureToCSVRow(const FeatureVector& features) const;
    
    // Statistics access
    FeatureStatistics GetFeatureStatistics(const std::string& featureName) const;
    void ResetStatistics();
    
private:
    // Internal computation methods
    
    // Scan behavior features
    float ComputeScanFrequency(const std::vector<ScanTelemetry>& scans, ULONGLONG windowMs) const;
    float ComputeScanBurstiness(const std::vector<ScanTelemetry>& scans) const;
    float ComputeScanDiversity(const std::vector<ScanTelemetry>& scans) const;
    float ComputeScanRepetitionRate(const std::vector<ScanTelemetry>& scans) const;
    float ComputePeriodicCompliance(const std::vector<ScanTelemetry>& scans, ULONGLONG expectedInterval) const;
    
    // Detection pattern features
    float ComputeDetectionBurstiness(const std::vector<DetectionTelemetry>& detections) const;
    float ComputeDetectionDiversity(const std::vector<DetectionTelemetry>& detections) const;
    float ComputeDetectionTimePattern(const std::vector<DetectionTelemetry>& detections) const;
    
    // Resource features
    float ComputeResourceTrend(const std::vector<SystemMetric>& metrics, 
                               float (MLFeatureExtractor::*extractor)(const SystemMetric&) const) const;
    float ComputeResourceStability(const std::vector<SystemMetric>& metrics) const;
    float ExtractCPU(const SystemMetric& metric) const;
    float ExtractMemory(const SystemMetric& metric) const;
    
    // Temporal features
    float ComputeActivityLevel(const std::vector<ScanTelemetry>& scans, 
                               const std::vector<DetectionTelemetry>& detections,
                               ULONGLONG windowMs) const;
    float ComputeRateChange(float recentRate, float historicalRate) const;
    
    // Anomaly detection
    float ComputeOutlierScore(float value, const FeatureStatistics& stats) const;
    float ComputeSuddenChangeScore(const std::vector<float>& timeSeries) const;
    float ComputeAbnormalPatternScore(const FeatureVector& features) const;
    
    // Statistical helpers
    float ComputeMean(const std::vector<float>& values) const;
    float ComputeStdDev(const std::vector<float>& values, float mean) const;
    float ComputeVariance(const std::vector<float>& values, float mean) const;
    float ComputeTrend(const std::vector<float>& timeSeries) const;
    float ComputeEMA(float newValue, float oldEMA, float alpha) const;
    
    // Normalization helpers
    float NormalizeValue(float value, float min, float max) const;
    float NormalizeZScore(float value, float mean, float stdDev) const;
    
    // Data
    TelemetryCollector* m_pTelemetry;
    FeatureExtractionConfig m_config;
    
    // Feature statistics for normalization
    std::unordered_map<std::string, FeatureStatistics> m_featureStats;
    
    // Historical data for trend computation
    std::vector<FeatureVector> m_recentFeatures;  // Keep last N feature vectors
    size_t m_maxRecentFeatures = 100;
    
    // EMA trackers for smoothing
    std::unordered_map<std::string, float> m_emaValues;
    
    // Feature importance scores (for feature selection)
    std::unordered_map<std::string, float> m_featureImportance;
};

// Helper functions
namespace FeatureUtils {
    // Convert feature vector to flat array (for ML libraries)
    std::vector<float> FeatureVectorToArray(const FeatureVector& features);
    
    // Compute correlation between two feature time series
    float ComputeCorrelation(const std::vector<float>& x, const std::vector<float>& y);
    
    // Detect outliers using IQR method
    std::vector<int> DetectOutliersIQR(const std::vector<float>& values, float multiplier = 1.5f);
    
    // Detect outliers using Z-score method
    std::vector<int> DetectOutliersZScore(const std::vector<float>& values, float threshold = 3.0f);
    
    // Sliding window statistics
    struct WindowStats {
        float mean;
        float stdDev;
        float min;
        float max;
        float median;
    };
    WindowStats ComputeWindowStats(const std::vector<float>& values, size_t windowSize);
}
