// ===== PRIORITY 4.1.3: ML Anomaly Detector =====
// Simple machine learning-based anomaly detection system
// Uses lightweight algorithms: Isolation Forest and One-Class classification
// Supports online learning for model adaptation to player behavior
// Version: 1.0
// Author: Oblivion AntiCheat Team
// Date: 2025-11-02

#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <random>
#include <unordered_map>

// Forward declarations
struct FeatureVector;
class TelemetryCollector;
class MLFeatureExtractor;

// ===== Anomaly Detection Result =====
struct AnomalyDetectionResult {
    bool isAnomaly;                     // True if behavior is anomalous
    float anomalyScore;                 // Score in [0.0, 1.0], higher = more anomalous
    float confidence;                   // Model confidence in [0.0, 1.0]
    std::string detectionMethod;        // "IsolationForest", "OneClass", "Ensemble"
    std::vector<int> topFeatureIndices; // Indices of most anomalous features
    std::vector<float> featureContributions; // Contribution of each feature to anomaly score
    ULONGLONG timestamp;                // Detection timestamp

    AnomalyDetectionResult()
        : isAnomaly(false), anomalyScore(0.0f), confidence(0.0f),
          detectionMethod("None"), timestamp(0) {}
};

// ===== Isolation Tree Node (for Isolation Forest) =====
struct IsolationTreeNode {
    int splitFeatureIndex;              // Feature to split on (-1 for leaf)
    float splitValue;                   // Threshold value for split
    std::unique_ptr<IsolationTreeNode> left;
    std::unique_ptr<IsolationTreeNode> right;
    int pathLength;                     // Depth in tree (for leaf nodes)
    int sampleSize;                     // Number of samples at this node

    IsolationTreeNode()
        : splitFeatureIndex(-1), splitValue(0.0f),
          pathLength(0), sampleSize(0) {}

    bool IsLeaf() const { return splitFeatureIndex == -1; }
};

// ===== Isolation Tree =====
class IsolationTree {
public:
    IsolationTree(int maxDepth = 10, int minSamplesSplit = 2);
    ~IsolationTree() = default;

    // Build tree from training data
    void Build(const std::vector<std::vector<float>>& samples, int subsampleSize, std::mt19937& rng);

    // Compute path length for a sample
    float ComputePathLength(const std::vector<float>& sample) const;

private:
    std::unique_ptr<IsolationTreeNode> BuildNode(
        const std::vector<std::vector<float>>& samples,
        const std::vector<int>& indices,
        int depth,
        std::mt19937& rng);

    float ComputePathLengthRecursive(const std::vector<float>& sample, const IsolationTreeNode* node, int depth) const;

public:
    static float AveragePathLength(int n);

private:
    int m_maxDepth;
    int m_minSamplesSplit;
    std::unique_ptr<IsolationTreeNode> m_root;
};

// ===== Isolation Forest Detector =====
class IsolationForest {
public:
    IsolationForest(int numTrees = 100, int subsampleSize = 256, int maxDepth = 10);
    ~IsolationForest() = default;

    // Train the model on normal behavior samples
    void Train(const std::vector<std::vector<float>>& normalSamples);

    // Predict anomaly score for a sample (0.0 = normal, 1.0 = highly anomalous)
    float PredictAnomalyScore(const std::vector<float>& sample) const;

    // Check if sample is anomalous based on threshold
    bool IsAnomaly(const std::vector<float>& sample, float threshold = 0.6f) const;

    // Get model metadata
    int GetNumTrees() const { return m_numTrees; }
    int GetSubsampleSize() const { return m_subsampleSize; }
    bool IsTrained() const { return m_trained; }

private:
    int m_numTrees;
    int m_subsampleSize;
    int m_maxDepth;
    bool m_trained;
    std::vector<std::unique_ptr<IsolationTree>> m_trees;
    mutable std::mt19937 m_rng;
};

// ===== One-Class Classifier (simplified SVM-like approach) =====
// Uses statistical distance from learned centroid with adaptive boundaries
class OneClassClassifier {
public:
    OneClassClassifier(float nu = 0.1f); // nu: outlier fraction (0.0 to 1.0)
    ~OneClassClassifier() = default;

    // Train on normal behavior samples
    void Train(const std::vector<std::vector<float>>& normalSamples);

    // Predict anomaly score (Mahalanobis distance normalized)
    float PredictAnomalyScore(const std::vector<float>& sample) const;

    // Check if anomalous
    bool IsAnomaly(const std::vector<float>& sample, float threshold = 0.6f) const;

    // Online update (incremental learning)
    void UpdateWithSample(const std::vector<float>& sample, bool isNormal);

    // Get model state
    bool IsTrained() const { return m_trained; }
    int GetFeatureDimension() const { return static_cast<int>(m_centroid.size()); }

private:
    float ComputeMahalanobisDistance(const std::vector<float>& sample) const;
    void UpdateCovarianceMatrix(const std::vector<float>& sample, bool isNormal);

    float m_nu;                                  // Outlier fraction
    bool m_trained;
    std::vector<float> m_centroid;               // Mean of normal samples
    std::vector<std::vector<float>> m_covariance; // Covariance matrix (simplified diagonal)
    float m_boundary;                             // Decision boundary (distance threshold)
    int m_sampleCount;                            // Number of training samples
};

// ===== ML Anomaly Detector Configuration =====
struct MLAnomalyDetectorConfig {
    bool enableIsolationForest;     // Use Isolation Forest
    bool enableOneClass;            // Use One-Class classifier
    bool useEnsemble;               // Combine both methods
    float ensembleWeight;           // Weight for ensemble (0.0 = only OneClass, 1.0 = only IsoForest)
    
    int isolationForestTrees;       // Number of trees in Isolation Forest
    int isolationForestSubsampleSize; // Subsample size for each tree
    int isolationForestMaxDepth;    // Max tree depth
    
    float oneClassNu;               // One-Class outlier fraction
    
    float anomalyThreshold;         // Global threshold for anomaly detection (0.0-1.0)
    int minTrainingSamples;         // Min samples before model is considered trained
    int maxTrainingSamples;         // Max samples to keep in training set
    
    bool enableOnlineLearning;      // Enable incremental learning
    int onlineUpdateInterval;       // Update model every N samples
    float onlineLearningRate;       // Learning rate for online updates (0.0-1.0)
    
    bool enableModelPersistence;    // Save/load model to/from disk
    std::wstring modelSavePath;     // Path to save model

    MLAnomalyDetectorConfig()
        : enableIsolationForest(true), enableOneClass(true), useEnsemble(true),
          ensembleWeight(0.5f), isolationForestTrees(100), isolationForestSubsampleSize(256),
          isolationForestMaxDepth(10), oneClassNu(0.1f), anomalyThreshold(0.65f),
          minTrainingSamples(50), maxTrainingSamples(5000), enableOnlineLearning(true),
          onlineUpdateInterval(100), onlineLearningRate(0.1f), enableModelPersistence(false),
          modelSavePath(L"ml_anomaly_model.bin") {}
};

// ===== Main ML Anomaly Detector =====
class MLAnomalyDetector {
public:
    explicit MLAnomalyDetector(const MLAnomalyDetectorConfig& config = MLAnomalyDetectorConfig());
    ~MLAnomalyDetector();

    // Initialize with feature extractor and telemetry
    bool Initialize(MLFeatureExtractor* featureExtractor, TelemetryCollector* telemetry);

    // Train models on historical normal behavior
    bool TrainModels(const std::vector<FeatureVector>& normalBehaviorSamples);

    // Detect anomalies in current behavior
    AnomalyDetectionResult DetectAnomaly(const FeatureVector& features);

    // Online learning: update model with new sample
    void UpdateWithSample(const FeatureVector& features, bool isNormal);

    // Model management
    bool SaveModel(const std::wstring& path);
    bool LoadModel(const std::wstring& path);
    void ResetModel();

    // Statistics
    struct ModelStatistics {
        int totalSamplesProcessed;
        int anomaliesDetected;
        int onlineUpdates;
        float averageAnomalyScore;
        float maxAnomalyScore;
        ULONGLONG lastTrainingTime;
        ULONGLONG lastDetectionTime;
        bool isolationForestTrained;
        bool oneClassTrained;
    };

    ModelStatistics GetStatistics() const;

    // Configuration
    void SetConfig(const MLAnomalyDetectorConfig& config);
    MLAnomalyDetectorConfig GetConfig() const { return m_config; }
    
    // Feature importance analysis
    std::vector<std::pair<int, float>> GetTopAnomalousFeatures(const FeatureVector& features, int topK = 5);

private:
    // Convert FeatureVector to float array
    std::vector<float> FeatureVectorToArray(const FeatureVector& fv) const;

    // Ensemble prediction
    float ComputeEnsembleScore(const std::vector<float>& sample) const;

    // Feature contribution analysis
    std::vector<float> ComputeFeatureContributions(const std::vector<float>& sample) const;

    // Training data management
    void AddTrainingSample(const std::vector<float>& sample);
    void PruneTrainingData();

    MLAnomalyDetectorConfig m_config;
    
    // ML Models
    std::unique_ptr<IsolationForest> m_isolationForest;
    std::unique_ptr<OneClassClassifier> m_oneClassClassifier;

    // Training data buffer
    std::vector<std::vector<float>> m_trainingData;
    mutable std::mutex m_trainingMutex;

    // Statistics
    ModelStatistics m_stats;
    mutable std::mutex m_statsMutex;

    // Online learning state
    int m_samplesSinceUpdate;
    std::vector<std::vector<float>> m_onlineBuffer;

    // External dependencies
    MLFeatureExtractor* m_featureExtractor;
    TelemetryCollector* m_telemetry;

    // Random number generator
    std::mt19937 m_rng;
};

// ===== Utility Functions =====
namespace MLAnomalyUtils {
    // Compute mean of samples
    std::vector<float> ComputeMean(const std::vector<std::vector<float>>& samples);

    // Compute standard deviation
    std::vector<float> ComputeStdDev(const std::vector<std::vector<float>>& samples, const std::vector<float>& mean);

    // Normalize sample using z-score
    std::vector<float> NormalizeSample(const std::vector<float>& sample, const std::vector<float>& mean, const std::vector<float>& stddev);

    // Compute Euclidean distance
    float EuclideanDistance(const std::vector<float>& a, const std::vector<float>& b);

    // Compute cosine similarity
    float CosineSimilarity(const std::vector<float>& a, const std::vector<float>& b);

    // Feature variance for importance ranking
    float ComputeVariance(const std::vector<float>& values, float mean);
}

// ===== Global Anomaly Detector Instance (optional) =====
extern MLAnomalyDetector* g_pMLAnomalyDetector;
