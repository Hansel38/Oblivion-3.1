#include "../pch.h"
#include "MLFeatureExtractor.h"
#include "TelemetryCollector.h"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <fstream>
#include <numeric>
#include <unordered_set>

// =====================================================================
// MLFeatureExtractor.cpp
// Implementation of ML feature extraction pipeline
// =====================================================================

MLFeatureExtractor::MLFeatureExtractor()
    : m_pTelemetry(nullptr)
{
    m_config = FeatureExtractionConfig();
}

MLFeatureExtractor::~MLFeatureExtractor()
{
}

void MLFeatureExtractor::SetConfig(const FeatureExtractionConfig& config)
{
    m_config = config;
}

void MLFeatureExtractor::SetTelemetryCollector(TelemetryCollector* pCollector)
{
    m_pTelemetry = pCollector;
}

FeatureVector MLFeatureExtractor::ExtractFeatures(ULONGLONG currentTime)
{
    if (!m_pTelemetry) {
        return FeatureVector();  // Return empty vector
    }
    
    // Get aggregated stats from telemetry
    AggregatedStats stats = m_pTelemetry->GetCurrentPeriodStats();
    
    return ExtractFeaturesFromStats(stats, currentTime);
}

FeatureVector MLFeatureExtractor::ExtractFeaturesFromStats(const AggregatedStats& stats, ULONGLONG currentTime)
{
    FeatureVector features = {};
    features.timestamp = currentTime;
    features.featureSetVersion = "1.0";
    
    if (!m_pTelemetry) {
        return features;
    }
    
    // Get raw telemetry data
    auto recentScans = m_pTelemetry->GetRecentScans(1000);  // Last 1000 scans
    auto recentDetections = m_pTelemetry->GetRecentDetections(100);  // Last 100 detections
    
    // === Scan Behavior Features ===
    if (m_config.includeDetectionFeatures && !recentScans.empty()) {
        ULONGLONG periodDuration = (stats.periodEndTime > stats.periodStartTime) 
            ? (stats.periodEndTime - stats.periodStartTime) : 1;
        
        features.scanFrequency = ComputeScanFrequency(recentScans, m_config.mediumWindowMs);
        features.detectionRate = stats.totalScans > 0 
            ? (float)stats.totalDetections / (float)stats.totalScans : 0.0f;
        features.falsePositiveRate = stats.totalDetections > 0 
            ? (float)stats.falsePositives / (float)stats.totalDetections : 0.0f;
        features.avgScanTime = (float)stats.avgScanTimeMs;
        features.maxScanTime = (float)stats.maxScanTimeMs;
        
        // Compute scan time variance
        std::vector<float> scanTimes;
        for (const auto& scan : recentScans) {
            scanTimes.push_back((float)scan.executionTimeMs);
        }
        float meanTime = ComputeMean(scanTimes);
        features.scanTimeVariance = ComputeVariance(scanTimes, meanTime);
        
        features.cleanScanRatio = stats.totalScans > 0 
            ? (float)stats.cleanScans / (float)stats.totalScans : 1.0f;
        features.suspiciousScanRatio = stats.totalScans > 0 
            ? (float)stats.suspiciousScans / (float)stats.totalScans : 0.0f;
        features.errorScanRatio = stats.totalScans > 0 
            ? (float)stats.errorScans / (float)stats.totalScans : 0.0f;
        
        features.scanBurstiness = ComputeScanBurstiness(recentScans);
        features.scanDiversity = ComputeScanDiversity(recentScans);
        features.scanRepetitionRate = ComputeScanRepetitionRate(recentScans);
        features.periodicScanCompliance = ComputePeriodicCompliance(recentScans, 15000); // 15s expected
        
        // Count throttled scans
        DWORD throttledCount = 0;
        for (const auto& scan : recentScans) {
            if (scan.wasThrottled) throttledCount++;
        }
        features.throttledScanRatio = !recentScans.empty() 
            ? (float)throttledCount / (float)recentScans.size() : 0.0f;
        
        // Outlier detection for scan times
        auto outliers = FeatureUtils::DetectOutliersZScore(scanTimes, m_config.outlierThresholdStdDev);
        features.scanTimeOutliers = (float)outliers.size();
    }
    
    // === System Resource Features ===
    if (m_config.includeResourceFeatures) {
        features.avgCPUUsage = (float)stats.avgCPUUsage / 100.0f;  // Normalize to 0-1
        features.maxCPUUsage = features.avgCPUUsage;  // Use avg as proxy (max not in stats)
        features.cpuVariance = 0.0f;  // TODO: compute from SystemMetric history
        features.cpuTrend = 0.0f;     // TODO: compute trend
        
        features.avgMemoryUsage = (float)stats.avgMemoryUsageMB / m_config.maxExpectedMemoryMB;
        features.maxMemoryUsage = features.avgMemoryUsage;  // Use avg as proxy
        features.memoryGrowthRate = 0.0f;  // TODO: compute growth rate
        
        features.threadCountAvg = 0.0f;   // TODO: from SystemMetric
        features.handleCountAvg = 0.0f;   // TODO: from SystemMetric
        features.resourceStability = 1.0f - features.cpuVariance;  // High stability = low variance
    }
    
    // === Detection Pattern Features ===
    if (m_config.includeDetectionFeatures && !recentDetections.empty()) {
        features.detectionBurstiness = ComputeDetectionBurstiness(recentDetections);
        features.detectionDiversity = ComputeDetectionDiversity(recentDetections);
        features.suppressionRate = stats.totalDetections > 0 
            ? (float)stats.suppressedDetections / (float)stats.totalDetections : 0.0f;
        
        // Indicator statistics
        std::vector<float> indicatorCounts;
        for (const auto& det : recentDetections) {
            indicatorCounts.push_back((float)det.indicatorCount);
        }
        if (!indicatorCounts.empty()) {
            features.avgIndicatorCount = ComputeMean(indicatorCounts);
            features.maxIndicatorCount = *std::max_element(indicatorCounts.begin(), indicatorCounts.end());
            features.indicatorVariance = ComputeVariance(indicatorCounts, features.avgIndicatorCount);
        }
        
        // Recent detection rate (last 5 minutes)
        DWORD recentDetCount = 0;
        ULONGLONG cutoff = currentTime - m_config.mediumWindowMs;
        for (const auto& det : recentDetections) {
            if (det.timestamp >= cutoff) recentDetCount++;
        }
        features.recentDetectionRate = (float)recentDetCount / (m_config.mediumWindowMs / 60000.0f);
        
        // Detection trend
        std::vector<float> detectionRates;
        // TODO: compute historical detection rates for trend
        features.detectionTrend = 0.0f;
        
        // Contributing scan diversity
        std::unordered_set<std::string> contributingScans;
        for (const auto& det : recentDetections) {
            for (const auto& scan : det.contributingScans) {
                contributingScans.insert(scan);
            }
        }
        features.contributingScanDiversity = (float)contributingScans.size();
        
        features.detectionTimePattern = ComputeDetectionTimePattern(recentDetections);
    }
    
    // === Temporal Features ===
    if (m_config.includeTemporalFeatures) {
        // Time since last detection
        if (!recentDetections.empty()) {
            ULONGLONG lastDetTime = recentDetections.back().timestamp;
            features.timeSinceLastDetection = (float)(currentTime - lastDetTime) / 60000.0f; // Minutes
        } else {
            features.timeSinceLastDetection = 999.0f;  // Large value = no recent detections
        }
        
        // Time since last scan
        if (!recentScans.empty()) {
            ULONGLONG lastScanTime = recentScans.back().timestamp;
            features.timeSinceLastScan = (float)(currentTime - lastScanTime) / 1000.0f; // Seconds
        } else {
            features.timeSinceLastScan = 999.0f;
        }
        
        // Session duration
        ULONGLONG sessionStart = stats.periodStartTime;
        features.sessionDuration = (float)(currentTime - sessionStart) / m_config.maxSessionDurationMs;
        
        // Time of day features
        SYSTEMTIME st;
        GetLocalTime(&st);
        features.hourOfDay = (float)st.wHour / 24.0f;
        features.dayOfWeek = (float)st.wDayOfWeek / 7.0f;
        
        // Rate changes (TODO: compare with historical)
        features.scanRateChange = 0.0f;
        features.detectionRateChange = 0.0f;
        
        features.activityLevel = ComputeActivityLevel(recentScans, recentDetections, m_config.mediumWindowMs);
    }
    
    // === Anomaly Indicators ===
    if (m_config.includeAnomalyFeatures) {
        // Compute outlier scores if we have statistics
        auto scanTimeStats = GetFeatureStatistics("avgScanTime");
        if (scanTimeStats.sampleCount > 10) {
            features.outlierScoreScans = ComputeOutlierScore(features.avgScanTime, scanTimeStats);
        } else {
            features.outlierScoreScans = 0.0f;
        }
        
        auto detRateStats = GetFeatureStatistics("detectionRate");
        if (detRateStats.sampleCount > 10) {
            features.outlierScoreDetections = ComputeOutlierScore(features.detectionRate, detRateStats);
        } else {
            features.outlierScoreDetections = 0.0f;
        }
        
        auto cpuStats = GetFeatureStatistics("avgCPUUsage");
        if (cpuStats.sampleCount > 10) {
            features.outlierScoreCPU = ComputeOutlierScore(features.avgCPUUsage, cpuStats);
        } else {
            features.outlierScoreCPU = 0.0f;
        }
        
        auto memStats = GetFeatureStatistics("avgMemoryUsage");
        if (memStats.sampleCount > 10) {
            features.outlierScoreMemory = ComputeOutlierScore(features.avgMemoryUsage, memStats);
        } else {
            features.outlierScoreMemory = 0.0f;
        }
        
        // Sudden change score (requires history)
        std::vector<float> recentDetRates;
        for (const auto& fv : m_recentFeatures) {
            recentDetRates.push_back(fv.detectionRate);
        }
        features.suddenChangeScore = ComputeSuddenChangeScore(recentDetRates);
        
        // Abnormal pattern score
        features.abnormalPatternScore = ComputeAbnormalPatternScore(features);
        
        // Overall anomaly score (weighted combination)
        features.overallAnomalyScore = 
            0.3f * features.outlierScoreScans +
            0.3f * features.outlierScoreDetections +
            0.1f * features.outlierScoreCPU +
            0.1f * features.outlierScoreMemory +
            0.2f * features.suddenChangeScore;
    }
    
    // Store this feature vector for history
    m_recentFeatures.push_back(features);
    if (m_recentFeatures.size() > m_maxRecentFeatures) {
        m_recentFeatures.erase(m_recentFeatures.begin());
    }
    
    return features;
}

void MLFeatureExtractor::UpdateStatistics(const FeatureVector& features)
{
    // Update statistics for each feature (for normalization and outlier detection)
    auto updateStat = [this](const std::string& name, float value) {
        auto& stat = m_featureStats[name];
        if (stat.sampleCount == 0) {
            stat.mean = value;
            stat.min = value;
            stat.max = value;
            stat.stdDev = 0.0f;
            stat.sampleCount = 1;
        } else {
            // Update min/max
            if (value < stat.min) stat.min = value;
            if (value > stat.max) stat.max = value;
            
            // Update mean and std dev using online algorithm
            float oldMean = stat.mean;
            stat.sampleCount++;
            stat.mean = oldMean + (value - oldMean) / stat.sampleCount;
            
            // Welford's online algorithm for variance
            float delta = value - oldMean;
            float delta2 = value - stat.mean;
            float M2 = stat.stdDev * stat.stdDev * (stat.sampleCount - 1);
            M2 += delta * delta2;
            stat.stdDev = sqrtf(M2 / stat.sampleCount);
        }
    };
    
    // Update all feature statistics
    updateStat("scanFrequency", features.scanFrequency);
    updateStat("detectionRate", features.detectionRate);
    updateStat("avgScanTime", features.avgScanTime);
    updateStat("avgCPUUsage", features.avgCPUUsage);
    updateStat("avgMemoryUsage", features.avgMemoryUsage);
    // ... update more as needed
}

FeatureVector MLFeatureExtractor::NormalizeFeatures(const FeatureVector& rawFeatures)
{
    FeatureVector normalized = rawFeatures;
    
    // Normalize features using min-max or z-score normalization
    auto normalizeStat = [this](const std::string& name, float value) -> float {
        auto it = m_featureStats.find(name);
        if (it == m_featureStats.end() || it->second.sampleCount < 2) {
            return value;  // Not enough data to normalize
        }
        
        const auto& stat = it->second;
        
        // Use min-max normalization for bounded features
        if (stat.max > stat.min) {
            return (value - stat.min) / (stat.max - stat.min);
        }
        
        return value;
    };
    
    // Normalize selected features
    normalized.scanFrequency = normalizeStat("scanFrequency", rawFeatures.scanFrequency);
    normalized.avgScanTime = normalizeStat("avgScanTime", rawFeatures.avgScanTime);
    // ... normalize more as needed
    
    return normalized;
}

std::vector<float> MLFeatureExtractor::GetSelectedFeatures(const FeatureVector& features, const std::vector<int>& indices)
{
    std::vector<float> allFeatures = FeatureUtils::FeatureVectorToArray(features);
    std::vector<float> selected;
    
    for (int idx : indices) {
        if (idx >= 0 && idx < (int)allFeatures.size()) {
            selected.push_back(allFeatures[idx]);
        }
    }
    
    return selected;
}

std::vector<int> MLFeatureExtractor::SelectTopKFeatures(int k)
{
    // Simple feature selection based on importance scores
    std::vector<std::pair<std::string, float>> importance;
    for (const auto& kv : m_featureImportance) {
        importance.push_back(kv);
    }
    
    // Sort by importance (descending)
    std::sort(importance.begin(), importance.end(), 
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Return indices of top K
    std::vector<int> indices;
    int maxK = (k < static_cast<int>(importance.size())) ? k : static_cast<int>(importance.size());
    for (int i = 0; i < maxK; ++i) {
        // TODO: map feature name to index
        indices.push_back(i);
    }
    
    return indices;
}

std::string MLFeatureExtractor::SerializeFeatures(const FeatureVector& features) const
{
    std::ostringstream oss;
    
    // Simple JSON serialization
    oss << "{";
    oss << "\"timestamp\":" << features.timestamp << ",";
    oss << "\"version\":\"" << features.featureSetVersion << "\",";
    oss << "\"scanFrequency\":" << features.scanFrequency << ",";
    oss << "\"detectionRate\":" << features.detectionRate << ",";
    oss << "\"avgCPUUsage\":" << features.avgCPUUsage << ",";
    oss << "\"avgMemoryUsage\":" << features.avgMemoryUsage << ",";
    oss << "\"overallAnomalyScore\":" << features.overallAnomalyScore;
    // ... add more fields as needed
    oss << "}";
    
    return oss.str();
}

bool MLFeatureExtractor::DeserializeFeatures(const std::string& data, FeatureVector& outFeatures) const
{
    // TODO: Implement JSON parsing
    // For now, return false
    return false;
}

bool MLFeatureExtractor::ExportFeaturesToCSV(const std::wstring& filepath, const std::vector<FeatureVector>& features) const
{
    try {
        std::ofstream file(filepath);
        if (!file.is_open()) return false;
        
        // Write header
        file << GetFeatureCSVHeader() << "\n";
        
        // Write rows
        for (const auto& fv : features) {
            file << FeatureToCSVRow(fv) << "\n";
        }
        
        file.close();
        return true;
    } catch (...) {
        return false;
    }
}

std::string MLFeatureExtractor::GetFeatureCSVHeader() const
{
    return "timestamp,scanFrequency,detectionRate,falsePositiveRate,avgScanTime,maxScanTime,"
           "scanTimeVariance,cleanScanRatio,suspiciousScanRatio,errorScanRatio,scanBurstiness,"
           "scanDiversity,scanRepetitionRate,periodicScanCompliance,throttledScanRatio,"
           "scanTimeOutliers,avgCPUUsage,maxCPUUsage,cpuVariance,cpuTrend,avgMemoryUsage,"
           "maxMemoryUsage,memoryGrowthRate,threadCountAvg,handleCountAvg,resourceStability,"
           "detectionBurstiness,detectionDiversity,suppressionRate,avgIndicatorCount,"
           "maxIndicatorCount,indicatorVariance,recentDetectionRate,detectionTrend,"
           "contributingScanDiversity,detectionTimePattern,timeSinceLastDetection,"
           "timeSinceLastScan,sessionDuration,hourOfDay,dayOfWeek,scanRateChange,"
           "detectionRateChange,activityLevel,outlierScoreScans,outlierScoreDetections,"
           "outlierScoreCPU,outlierScoreMemory,suddenChangeScore,abnormalPatternScore,"
           "overallAnomalyScore";
}

std::string MLFeatureExtractor::FeatureToCSVRow(const FeatureVector& features) const
{
    std::ostringstream oss;
    oss << features.timestamp << ","
        << features.scanFrequency << "," << features.detectionRate << ","
        << features.falsePositiveRate << "," << features.avgScanTime << ","
        << features.maxScanTime << "," << features.scanTimeVariance << ","
        << features.cleanScanRatio << "," << features.suspiciousScanRatio << ","
        << features.errorScanRatio << "," << features.scanBurstiness << ","
        << features.scanDiversity << "," << features.scanRepetitionRate << ","
        << features.periodicScanCompliance << "," << features.throttledScanRatio << ","
        << features.scanTimeOutliers << "," << features.avgCPUUsage << ","
        << features.maxCPUUsage << "," << features.cpuVariance << ","
        << features.cpuTrend << "," << features.avgMemoryUsage << ","
        << features.maxMemoryUsage << "," << features.memoryGrowthRate << ","
        << features.threadCountAvg << "," << features.handleCountAvg << ","
        << features.resourceStability << "," << features.detectionBurstiness << ","
        << features.detectionDiversity << "," << features.suppressionRate << ","
        << features.avgIndicatorCount << "," << features.maxIndicatorCount << ","
        << features.indicatorVariance << "," << features.recentDetectionRate << ","
        << features.detectionTrend << "," << features.contributingScanDiversity << ","
        << features.detectionTimePattern << "," << features.timeSinceLastDetection << ","
        << features.timeSinceLastScan << "," << features.sessionDuration << ","
        << features.hourOfDay << "," << features.dayOfWeek << ","
        << features.scanRateChange << "," << features.detectionRateChange << ","
        << features.activityLevel << "," << features.outlierScoreScans << ","
        << features.outlierScoreDetections << "," << features.outlierScoreCPU << ","
        << features.outlierScoreMemory << "," << features.suddenChangeScore << ","
        << features.abnormalPatternScore << "," << features.overallAnomalyScore;
    return oss.str();
}

FeatureStatistics MLFeatureExtractor::GetFeatureStatistics(const std::string& featureName) const
{
    auto it = m_featureStats.find(featureName);
    if (it != m_featureStats.end()) {
        return it->second;
    }
    return FeatureStatistics{};
}

void MLFeatureExtractor::ResetStatistics()
{
    m_featureStats.clear();
    m_recentFeatures.clear();
    m_emaValues.clear();
}

// ===== Internal Computation Methods =====

float MLFeatureExtractor::ComputeScanFrequency(const std::vector<ScanTelemetry>& scans, ULONGLONG windowMs) const
{
    if (scans.empty()) return 0.0f;
    
    ULONGLONG now = GetTickCount64();
    ULONGLONG cutoff = now - windowMs;
    
    DWORD count = 0;
    for (const auto& scan : scans) {
        if (scan.timestamp >= cutoff) count++;
    }
    
    // Scans per minute
    return (float)count / (windowMs / 60000.0f);
}

float MLFeatureExtractor::ComputeScanBurstiness(const std::vector<ScanTelemetry>& scans) const
{
    if (scans.size() < 3) return 0.0f;
    
    // Compute coefficient of variation for inter-arrival times
    std::vector<float> intervals;
    for (size_t i = 1; i < scans.size(); ++i) {
        float interval = (float)(scans[i].timestamp - scans[i-1].timestamp);
        intervals.push_back(interval);
    }
    
    float mean = ComputeMean(intervals);
    float stdDev = ComputeStdDev(intervals, mean);
    
    // Coefficient of variation: higher = more bursty
    return (mean > 0.0f) ? (stdDev / mean) : 0.0f;
}

float MLFeatureExtractor::ComputeScanDiversity(const std::vector<ScanTelemetry>& scans) const
{
    std::unordered_set<std::string> uniqueScans;
    for (const auto& scan : scans) {
        uniqueScans.insert(scan.scannerName);
    }
    return (float)uniqueScans.size();
}

float MLFeatureExtractor::ComputeScanRepetitionRate(const std::vector<ScanTelemetry>& scans) const
{
    if (scans.size() < 2) return 0.0f;
    
    DWORD repetitions = 0;
    for (size_t i = 1; i < scans.size(); ++i) {
        if (scans[i].scannerName == scans[i-1].scannerName) {
            // Check if time gap is short (< 1 second)
            if ((scans[i].timestamp - scans[i-1].timestamp) < 1000) {
                repetitions++;
            }
        }
    }
    
    return (float)repetitions / (float)scans.size();
}

float MLFeatureExtractor::ComputePeriodicCompliance(const std::vector<ScanTelemetry>& scans, ULONGLONG expectedInterval) const
{
    if (scans.size() < 2) return 1.0f;  // Perfect compliance with no data
    
    float totalDeviation = 0.0f;
    int count = 0;
    
    for (size_t i = 1; i < scans.size(); ++i) {
        ULONGLONG interval = scans[i].timestamp - scans[i-1].timestamp;
        float deviation = fabsf((float)interval - (float)expectedInterval) / (float)expectedInterval;
        totalDeviation += deviation;
        count++;
    }
    
    float avgDeviation = count > 0 ? (totalDeviation / count) : 0.0f;
    
    // Return compliance (1.0 = perfect, 0.0 = poor)
    return max(0.0f, 1.0f - avgDeviation);
}

float MLFeatureExtractor::ComputeDetectionBurstiness(const std::vector<DetectionTelemetry>& detections) const
{
    if (detections.size() < 3) return 0.0f;
    
    std::vector<float> intervals;
    for (size_t i = 1; i < detections.size(); ++i) {
        float interval = (float)(detections[i].timestamp - detections[i-1].timestamp);
        intervals.push_back(interval);
    }
    
    float mean = ComputeMean(intervals);
    float stdDev = ComputeStdDev(intervals, mean);
    
    return (mean > 0.0f) ? (stdDev / mean) : 0.0f;
}

float MLFeatureExtractor::ComputeDetectionDiversity(const std::vector<DetectionTelemetry>& detections) const
{
    std::unordered_set<std::string> uniqueTypes;
    for (const auto& det : detections) {
        uniqueTypes.insert(det.detectionType);
    }
    return (float)uniqueTypes.size();
}

float MLFeatureExtractor::ComputeDetectionTimePattern(const std::vector<DetectionTelemetry>& detections) const
{
    // Compute entropy of detection times (hour of day)
    if (detections.empty()) return 0.0f;
    
    int hourCounts[24] = {0};
    for (const auto& det : detections) {
        // Extract hour from timestamp (simplified)
        ULONGLONG ms = det.timestamp;
        int hour = (int)((ms / 3600000) % 24);
        hourCounts[hour]++;
    }
    
    // Compute Shannon entropy
    float entropy = 0.0f;
    for (int i = 0; i < 24; ++i) {
        if (hourCounts[i] > 0) {
            float p = (float)hourCounts[i] / (float)detections.size();
            entropy -= p * log2f(p);
        }
    }
    
    // Normalize by max entropy (log2(24))
    return entropy / log2f(24.0f);
}

float MLFeatureExtractor::ComputeResourceTrend(const std::vector<SystemMetric>& metrics, 
                                               float (MLFeatureExtractor::*extractor)(const SystemMetric&) const) const
{
    if (metrics.size() < 2) return 0.0f;
    
    std::vector<float> values;
    for (const auto& m : metrics) {
        values.push_back((this->*extractor)(m));
    }
    
    return ComputeTrend(values);
}

float MLFeatureExtractor::ComputeResourceStability(const std::vector<SystemMetric>& metrics) const
{
    if (metrics.empty()) return 1.0f;
    
    // Compute variance of CPU and memory
    std::vector<float> cpuValues, memValues;
    for (const auto& m : metrics) {
        cpuValues.push_back(m.cpuUsagePercent);
        memValues.push_back((float)m.memoryUsageMB);
    }
    
    float cpuMean = ComputeMean(cpuValues);
    float memMean = ComputeMean(memValues);
    
    float cpuVar = ComputeVariance(cpuValues, cpuMean);
    float memVar = ComputeVariance(memValues, memMean);
    
    // Normalize and invert (high variance = low stability)
    float normalizedVar = (cpuVar / 100.0f + memVar / 100.0f) / 2.0f;
    return max(0.0f, 1.0f - normalizedVar);
}

float MLFeatureExtractor::ExtractCPU(const SystemMetric& metric) const
{
    return metric.cpuUsagePercent;
}

float MLFeatureExtractor::ExtractMemory(const SystemMetric& metric) const
{
    return (float)metric.memoryUsageMB;
}

float MLFeatureExtractor::ComputeActivityLevel(const std::vector<ScanTelemetry>& scans, 
                                               const std::vector<DetectionTelemetry>& detections,
                                               ULONGLONG windowMs) const
{
    ULONGLONG now = GetTickCount64();
    ULONGLONG cutoff = now - windowMs;
    
    int scanCount = 0;
    int detectionCount = 0;
    
    for (const auto& scan : scans) {
        if (scan.timestamp >= cutoff) scanCount++;
    }
    
    for (const auto& det : detections) {
        if (det.timestamp >= cutoff) detectionCount++;
    }
    
    // Activity score: combine scan and detection counts
    float scanActivity = (float)scanCount / (windowMs / 1000.0f);  // Per second
    float detectionActivity = (float)detectionCount / (windowMs / 60000.0f);  // Per minute
    
    // Normalize and combine
    return min(1.0f, scanActivity / 10.0f + detectionActivity / 5.0f);
}

float MLFeatureExtractor::ComputeRateChange(float recentRate, float historicalRate) const
{
    if (historicalRate == 0.0f) return 0.0f;
    return (recentRate - historicalRate) / historicalRate;
}

float MLFeatureExtractor::ComputeOutlierScore(float value, const FeatureStatistics& stats) const
{
    if (stats.stdDev == 0.0f) return 0.0f;
    
    // Z-score
    float z = fabsf(value - stats.mean) / stats.stdDev;
    
    // Normalize to 0-1 (3 std dev = 1.0)
    return min(1.0f, z / m_config.outlierThresholdStdDev);
}

float MLFeatureExtractor::ComputeSuddenChangeScore(const std::vector<float>& timeSeries) const
{
    if (timeSeries.size() < 3) return 0.0f;
    
    // Compute max absolute difference between consecutive values
    float maxChange = 0.0f;
    for (size_t i = 1; i < timeSeries.size(); ++i) {
        float change = fabsf(timeSeries[i] - timeSeries[i-1]);
        if (change > maxChange) maxChange = change;
    }
    
    return min(1.0f, maxChange);
}

float MLFeatureExtractor::ComputeAbnormalPatternScore(const FeatureVector& features) const
{
    // Combine multiple anomaly signals
    float score = 0.0f;
    int signals = 0;
    
    // High detection rate is abnormal
    if (features.detectionRate > 0.1f) {  // More than 10%
        score += features.detectionRate;
        signals++;
    }
    
    // High FP rate is abnormal
    if (features.falsePositiveRate > 0.2f) {  // More than 20%
        score += features.falsePositiveRate;
        signals++;
    }
    
    // High scan burstiness is abnormal
    if (features.scanBurstiness > 2.0f) {
        score += min(1.0f, features.scanBurstiness / 5.0f);
        signals++;
    }
    
    // High detection burstiness is abnormal
    if (features.detectionBurstiness > 2.0f) {
        score += min(1.0f, features.detectionBurstiness / 5.0f);
        signals++;
    }
    
    return signals > 0 ? (score / signals) : 0.0f;
}

// Statistical helpers

float MLFeatureExtractor::ComputeMean(const std::vector<float>& values) const
{
    if (values.empty()) return 0.0f;
    float sum = std::accumulate(values.begin(), values.end(), 0.0f);
    return sum / values.size();
}

float MLFeatureExtractor::ComputeStdDev(const std::vector<float>& values, float mean) const
{
    return sqrtf(ComputeVariance(values, mean));
}

float MLFeatureExtractor::ComputeVariance(const std::vector<float>& values, float mean) const
{
    if (values.size() < 2) return 0.0f;
    
    float sumSq = 0.0f;
    for (float v : values) {
        float diff = v - mean;
        sumSq += diff * diff;
    }
    
    return sumSq / (values.size() - 1);  // Sample variance
}

float MLFeatureExtractor::ComputeTrend(const std::vector<float>& timeSeries) const
{
    if (timeSeries.size() < 2) return 0.0f;
    
    // Simple linear regression slope
    float n = (float)timeSeries.size();
    float sumX = 0.0f, sumY = 0.0f, sumXY = 0.0f, sumX2 = 0.0f;
    
    for (size_t i = 0; i < timeSeries.size(); ++i) {
        float x = (float)i;
        float y = timeSeries[i];
        sumX += x;
        sumY += y;
        sumXY += x * y;
        sumX2 += x * x;
    }
    
    float slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return slope;
}

float MLFeatureExtractor::ComputeEMA(float newValue, float oldEMA, float alpha) const
{
    return alpha * newValue + (1.0f - alpha) * oldEMA;
}

float MLFeatureExtractor::NormalizeValue(float value, float min, float max) const
{
    if (max <= min) return 0.0f;
    return (value - min) / (max - min);
}

float MLFeatureExtractor::NormalizeZScore(float value, float mean, float stdDev) const
{
    if (stdDev == 0.0f) return 0.0f;
    return (value - mean) / stdDev;
}

// ===== FeatureUtils Namespace =====

namespace FeatureUtils {

std::vector<float> FeatureVectorToArray(const FeatureVector& features)
{
    std::vector<float> arr;
    arr.reserve(50);  // Total feature count
    
    // Add all features in order
    arr.push_back(features.scanFrequency);
    arr.push_back(features.detectionRate);
    arr.push_back(features.falsePositiveRate);
    arr.push_back(features.avgScanTime);
    arr.push_back(features.maxScanTime);
    arr.push_back(features.scanTimeVariance);
    arr.push_back(features.cleanScanRatio);
    arr.push_back(features.suspiciousScanRatio);
    arr.push_back(features.errorScanRatio);
    arr.push_back(features.scanBurstiness);
    arr.push_back(features.scanDiversity);
    arr.push_back(features.scanRepetitionRate);
    arr.push_back(features.periodicScanCompliance);
    arr.push_back(features.throttledScanRatio);
    arr.push_back(features.scanTimeOutliers);
    
    arr.push_back(features.avgCPUUsage);
    arr.push_back(features.maxCPUUsage);
    arr.push_back(features.cpuVariance);
    arr.push_back(features.cpuTrend);
    arr.push_back(features.avgMemoryUsage);
    arr.push_back(features.maxMemoryUsage);
    arr.push_back(features.memoryGrowthRate);
    arr.push_back(features.threadCountAvg);
    arr.push_back(features.handleCountAvg);
    arr.push_back(features.resourceStability);
    
    arr.push_back(features.detectionBurstiness);
    arr.push_back(features.detectionDiversity);
    arr.push_back(features.suppressionRate);
    arr.push_back(features.avgIndicatorCount);
    arr.push_back(features.maxIndicatorCount);
    arr.push_back(features.indicatorVariance);
    arr.push_back(features.recentDetectionRate);
    arr.push_back(features.detectionTrend);
    arr.push_back(features.contributingScanDiversity);
    arr.push_back(features.detectionTimePattern);
    
    arr.push_back(features.timeSinceLastDetection);
    arr.push_back(features.timeSinceLastScan);
    arr.push_back(features.sessionDuration);
    arr.push_back(features.hourOfDay);
    arr.push_back(features.dayOfWeek);
    arr.push_back(features.scanRateChange);
    arr.push_back(features.detectionRateChange);
    arr.push_back(features.activityLevel);
    
    arr.push_back(features.outlierScoreScans);
    arr.push_back(features.outlierScoreDetections);
    arr.push_back(features.outlierScoreCPU);
    arr.push_back(features.outlierScoreMemory);
    arr.push_back(features.suddenChangeScore);
    arr.push_back(features.abnormalPatternScore);
    arr.push_back(features.overallAnomalyScore);
    
    return arr;
}

float ComputeCorrelation(const std::vector<float>& x, const std::vector<float>& y)
{
    if (x.size() != y.size() || x.empty()) return 0.0f;
    
    float meanX = std::accumulate(x.begin(), x.end(), 0.0f) / x.size();
    float meanY = std::accumulate(y.begin(), y.end(), 0.0f) / y.size();
    
    float sumXY = 0.0f, sumX2 = 0.0f, sumY2 = 0.0f;
    for (size_t i = 0; i < x.size(); ++i) {
        float dx = x[i] - meanX;
        float dy = y[i] - meanY;
        sumXY += dx * dy;
        sumX2 += dx * dx;
        sumY2 += dy * dy;
    }
    
    float denom = sqrtf(sumX2 * sumY2);
    return (denom > 0.0f) ? (sumXY / denom) : 0.0f;
}

std::vector<int> DetectOutliersIQR(const std::vector<float>& values, float multiplier)
{
    if (values.size() < 4) return {};
    
    std::vector<float> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    
    size_t n = sorted.size();
    float q1 = sorted[n / 4];
    float q3 = sorted[3 * n / 4];
    float iqr = q3 - q1;
    
    float lowerBound = q1 - multiplier * iqr;
    float upperBound = q3 + multiplier * iqr;
    
    std::vector<int> outlierIndices;
    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i] < lowerBound || values[i] > upperBound) {
            outlierIndices.push_back((int)i);
        }
    }
    
    return outlierIndices;
}

std::vector<int> DetectOutliersZScore(const std::vector<float>& values, float threshold)
{
    if (values.size() < 2) return {};
    
    float mean = std::accumulate(values.begin(), values.end(), 0.0f) / values.size();
    
    float sumSq = 0.0f;
    for (float v : values) {
        float diff = v - mean;
        sumSq += diff * diff;
    }
    float stdDev = sqrtf(sumSq / (values.size() - 1));
    
    if (stdDev == 0.0f) return {};
    
    std::vector<int> outlierIndices;
    for (size_t i = 0; i < values.size(); ++i) {
        float z = fabsf(values[i] - mean) / stdDev;
        if (z > threshold) {
            outlierIndices.push_back((int)i);
        }
    }
    
    return outlierIndices;
}

WindowStats ComputeWindowStats(const std::vector<float>& values, size_t windowSize)
{
    WindowStats stats = {};
    
    if (values.empty()) return stats;
    
    size_t start = values.size() > windowSize ? values.size() - windowSize : 0;
    std::vector<float> window(values.begin() + start, values.end());
    
    if (window.empty()) return stats;
    
    // Mean
    stats.mean = std::accumulate(window.begin(), window.end(), 0.0f) / window.size();
    
    // Min/Max
    stats.min = *std::min_element(window.begin(), window.end());
    stats.max = *std::max_element(window.begin(), window.end());
    
    // Std dev
    float sumSq = 0.0f;
    for (float v : window) {
        float diff = v - stats.mean;
        sumSq += diff * diff;
    }
    stats.stdDev = sqrtf(sumSq / window.size());
    
    // Median
    std::vector<float> sorted = window;
    std::sort(sorted.begin(), sorted.end());
    size_t mid = sorted.size() / 2;
    if (sorted.size() % 2 == 0) {
        stats.median = (sorted[mid-1] + sorted[mid]) / 2.0f;
    } else {
        stats.median = sorted[mid];
    }
    
    return stats;
}

} // namespace FeatureUtils
