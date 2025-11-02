// ===== PRIORITY 4.1.3: ML Anomaly Detector Implementation =====
#include "../pch.h"
#include "MLAnomalyDetector.h"
#include "MLFeatureExtractor.h"
#include "TelemetryCollector.h"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <fstream>

// Global instance
MLAnomalyDetector* g_pMLAnomalyDetector = nullptr;

// ===== Isolation Tree Implementation =====
IsolationTree::IsolationTree(int maxDepth, int minSamplesSplit)
    : m_maxDepth(maxDepth), m_minSamplesSplit(minSamplesSplit) {}

void IsolationTree::Build(const std::vector<std::vector<float>>& samples, int subsampleSize, std::mt19937& rng) {
    if (samples.empty()) return;

    // Random subsample
    std::vector<int> indices;
    int actualSize = min(subsampleSize, static_cast<int>(samples.size()));
    indices.reserve(actualSize);
    
    std::uniform_int_distribution<int> dist(0, static_cast<int>(samples.size()) - 1);
    for (int i = 0; i < actualSize; ++i) {
        indices.push_back(dist(rng));
    }

    m_root = BuildNode(samples, indices, 0, rng);
}

std::unique_ptr<IsolationTreeNode> IsolationTree::BuildNode(
    const std::vector<std::vector<float>>& samples,
    const std::vector<int>& indices,
    int depth,
    std::mt19937& rng) {
    
    auto node = std::make_unique<IsolationTreeNode>();
    node->sampleSize = static_cast<int>(indices.size());

    // Leaf conditions: max depth reached or too few samples
    if (depth >= m_maxDepth || static_cast<int>(indices.size()) <= m_minSamplesSplit) {
        node->splitFeatureIndex = -1; // Mark as leaf
        node->pathLength = depth;
        return node;
    }

    // Random feature selection
    int numFeatures = static_cast<int>(samples[0].size());
    std::uniform_int_distribution<int> featureDist(0, numFeatures - 1);
    int splitFeature = featureDist(rng);

    // Find min/max of selected feature
    float minVal = FLT_MAX, maxVal = -FLT_MAX;
    for (int idx : indices) {
        float val = samples[idx][splitFeature];
        minVal = min(minVal, val);
        maxVal = max(maxVal, val);
    }

    // Random split value between min and max
    if (maxVal - minVal < 1e-6f) {
        // All values are the same, make leaf
        node->splitFeatureIndex = -1;
        node->pathLength = depth;
        return node;
    }

    std::uniform_real_distribution<float> valueDist(minVal, maxVal);
    float splitValue = valueDist(rng);

    node->splitFeatureIndex = splitFeature;
    node->splitValue = splitValue;

    // Split indices
    std::vector<int> leftIndices, rightIndices;
    for (int idx : indices) {
        if (samples[idx][splitFeature] < splitValue) {
            leftIndices.push_back(idx);
        } else {
            rightIndices.push_back(idx);
        }
    }

    // Build children
    if (!leftIndices.empty()) {
        node->left = BuildNode(samples, leftIndices, depth + 1, rng);
    }
    if (!rightIndices.empty()) {
        node->right = BuildNode(samples, rightIndices, depth + 1, rng);
    }

    return node;
}

float IsolationTree::ComputePathLength(const std::vector<float>& sample) const {
    if (!m_root) return 0.0f;
    return ComputePathLengthRecursive(sample, m_root.get(), 0);
}

float IsolationTree::ComputePathLengthRecursive(const std::vector<float>& sample, const IsolationTreeNode* node, int depth) const {
    if (node->IsLeaf()) {
        // Adjust path length by average path length for remaining samples
        return static_cast<float>(depth) + AveragePathLength(node->sampleSize);
    }

    if (sample[node->splitFeatureIndex] < node->splitValue) {
        if (node->left) {
            return ComputePathLengthRecursive(sample, node->left.get(), depth + 1);
        }
    } else {
        if (node->right) {
            return ComputePathLengthRecursive(sample, node->right.get(), depth + 1);
        }
    }

    // Shouldn't reach here, but return current depth as fallback
    return static_cast<float>(depth);
}

float IsolationTree::AveragePathLength(int n) {
    if (n <= 1) return 0.0f;
    // H(n-1) approximation: 2*ln(n-1) + Euler constant - 2*(n-1)/n
    float hn = 2.0f * logf(static_cast<float>(n - 1)) + 0.5772156649f - 2.0f * (n - 1) / n;
    return hn;
}

// ===== Isolation Forest Implementation =====
IsolationForest::IsolationForest(int numTrees, int subsampleSize, int maxDepth)
    : m_numTrees(numTrees), m_subsampleSize(subsampleSize), m_maxDepth(maxDepth), m_trained(false) {
    m_rng.seed(static_cast<unsigned int>(GetTickCount64()));
}

void IsolationForest::Train(const std::vector<std::vector<float>>& normalSamples) {
    if (normalSamples.empty()) return;

    m_trees.clear();
    m_trees.reserve(m_numTrees);

    for (int i = 0; i < m_numTrees; ++i) {
        auto tree = std::make_unique<IsolationTree>(m_maxDepth);
        tree->Build(normalSamples, m_subsampleSize, m_rng);
        m_trees.push_back(std::move(tree));
    }

    m_trained = true;
}

float IsolationForest::PredictAnomalyScore(const std::vector<float>& sample) const {
    if (!m_trained || m_trees.empty()) return 0.0f;

    // Average path length across all trees
    float avgPathLength = 0.0f;
    for (const auto& tree : m_trees) {
        avgPathLength += tree->ComputePathLength(sample);
    }
    avgPathLength /= static_cast<float>(m_trees.size());

    // Expected average path length for dataset of size m_subsampleSize
    float c = IsolationTree::AveragePathLength(m_subsampleSize);
    
    // Anomaly score: 2^(-avgPathLength / c)
    // Score close to 1.0 = anomaly, close to 0.0 = normal
    float score = powf(2.0f, -avgPathLength / c);
    
    return score;
}

bool IsolationForest::IsAnomaly(const std::vector<float>& sample, float threshold) const {
    return PredictAnomalyScore(sample) >= threshold;
}

// ===== One-Class Classifier Implementation =====
OneClassClassifier::OneClassClassifier(float nu)
    : m_nu(nu), m_trained(false), m_boundary(0.0f), m_sampleCount(0) {}

void OneClassClassifier::Train(const std::vector<std::vector<float>>& normalSamples) {
    if (normalSamples.empty()) return;

    int numFeatures = static_cast<int>(normalSamples[0].size());
    m_centroid.resize(numFeatures, 0.0f);
    m_covariance.resize(numFeatures, std::vector<float>(numFeatures, 0.0f));

    // Compute centroid (mean)
    for (const auto& sample : normalSamples) {
        for (int i = 0; i < numFeatures; ++i) {
            m_centroid[i] += sample[i];
        }
    }
    for (float& val : m_centroid) {
        val /= static_cast<float>(normalSamples.size());
    }

    // Compute diagonal covariance (simplified for performance)
    for (const auto& sample : normalSamples) {
        for (int i = 0; i < numFeatures; ++i) {
            float diff = sample[i] - m_centroid[i];
            m_covariance[i][i] += diff * diff;
        }
    }
    for (int i = 0; i < numFeatures; ++i) {
        m_covariance[i][i] /= static_cast<float>(normalSamples.size());
        // Add small epsilon to avoid division by zero
        if (m_covariance[i][i] < 1e-6f) {
            m_covariance[i][i] = 1e-6f;
        }
    }

    // Compute boundary based on nu (outlier fraction)
    // Use percentile of distances from training samples
    std::vector<float> distances;
    distances.reserve(normalSamples.size());
    for (const auto& sample : normalSamples) {
        distances.push_back(ComputeMahalanobisDistance(sample));
    }
    
    std::sort(distances.begin(), distances.end());
    int boundaryIndex = static_cast<int>((1.0f - m_nu) * distances.size());
    if (boundaryIndex >= static_cast<int>(distances.size())) {
        boundaryIndex = static_cast<int>(distances.size()) - 1;
    }
    m_boundary = distances[boundaryIndex];

    m_sampleCount = static_cast<int>(normalSamples.size());
    m_trained = true;
}

float OneClassClassifier::PredictAnomalyScore(const std::vector<float>& sample) const {
    if (!m_trained) return 0.0f;

    float distance = ComputeMahalanobisDistance(sample);
    
    // Normalize by boundary (distance > boundary = anomaly)
    float score = distance / (m_boundary + 1e-6f);
    
    // Clamp to [0, 1] and apply sigmoid for smooth transition
    score = 1.0f / (1.0f + expf(-2.0f * (score - 1.0f)));
    
    return score;
}

bool OneClassClassifier::IsAnomaly(const std::vector<float>& sample, float threshold) const {
    return PredictAnomalyScore(sample) >= threshold;
}

void OneClassClassifier::UpdateWithSample(const std::vector<float>& sample, bool isNormal) {
    if (!m_trained) return;

    // Simple online update using exponential moving average
    float alpha = 0.01f; // Learning rate
    
    if (isNormal) {
        // Update centroid
        for (size_t i = 0; i < m_centroid.size(); ++i) {
            m_centroid[i] = (1.0f - alpha) * m_centroid[i] + alpha * sample[i];
        }

        // Update covariance
        for (size_t i = 0; i < m_centroid.size(); ++i) {
            float diff = sample[i] - m_centroid[i];
            m_covariance[i][i] = (1.0f - alpha) * m_covariance[i][i] + alpha * (diff * diff);
        }

        m_sampleCount++;
    }
    // If anomalous, don't update (to avoid poisoning the model)
}

float OneClassClassifier::ComputeMahalanobisDistance(const std::vector<float>& sample) const {
    float distance = 0.0f;
    
    // Simplified Mahalanobis distance (diagonal covariance only)
    for (size_t i = 0; i < sample.size(); ++i) {
        float diff = sample[i] - m_centroid[i];
        distance += (diff * diff) / m_covariance[i][i];
    }

    return sqrtf(distance);
}

// ===== ML Anomaly Detector Implementation =====
MLAnomalyDetector::MLAnomalyDetector(const MLAnomalyDetectorConfig& config)
    : m_config(config), m_samplesSinceUpdate(0), m_featureExtractor(nullptr), m_telemetry(nullptr) {
    
    m_rng.seed(static_cast<unsigned int>(GetTickCount64()));

    // Initialize models based on config
    if (m_config.enableIsolationForest) {
        m_isolationForest = std::make_unique<IsolationForest>(
            m_config.isolationForestTrees,
            m_config.isolationForestSubsampleSize,
            m_config.isolationForestMaxDepth
        );
    }

    if (m_config.enableOneClass) {
        m_oneClassClassifier = std::make_unique<OneClassClassifier>(m_config.oneClassNu);
    }

    // Initialize statistics
    memset(&m_stats, 0, sizeof(m_stats));
}

MLAnomalyDetector::~MLAnomalyDetector() {
    // Save model if persistence is enabled
    if (m_config.enableModelPersistence && !m_config.modelSavePath.empty()) {
        SaveModel(m_config.modelSavePath);
    }
}

bool MLAnomalyDetector::Initialize(MLFeatureExtractor* featureExtractor, TelemetryCollector* telemetry) {
    if (!featureExtractor || !telemetry) return false;

    m_featureExtractor = featureExtractor;
    m_telemetry = telemetry;

    // Load existing model if available
    if (m_config.enableModelPersistence && !m_config.modelSavePath.empty()) {
        LoadModel(m_config.modelSavePath);
    }

    return true;
}

bool MLAnomalyDetector::TrainModels(const std::vector<FeatureVector>& normalBehaviorSamples) {
    if (normalBehaviorSamples.size() < static_cast<size_t>(m_config.minTrainingSamples)) {
        return false; // Not enough samples
    }

    // Convert feature vectors to float arrays
    std::vector<std::vector<float>> samples;
    samples.reserve(normalBehaviorSamples.size());
    for (const auto& fv : normalBehaviorSamples) {
        samples.push_back(FeatureVectorToArray(fv));
    }

    std::lock_guard<std::mutex> lock(m_trainingMutex);

    // Train Isolation Forest
    if (m_isolationForest && m_config.enableIsolationForest) {
        m_isolationForest->Train(samples);
        m_stats.isolationForestTrained = m_isolationForest->IsTrained();
    }

    // Train One-Class Classifier
    if (m_oneClassClassifier && m_config.enableOneClass) {
        m_oneClassClassifier->Train(samples);
        m_stats.oneClassTrained = m_oneClassClassifier->IsTrained();
    }

    // Store training data for future updates
    m_trainingData = samples;
    PruneTrainingData();

    m_stats.lastTrainingTime = GetTickCount64();

    return m_stats.isolationForestTrained || m_stats.oneClassTrained;
}

AnomalyDetectionResult MLAnomalyDetector::DetectAnomaly(const FeatureVector& features) {
    AnomalyDetectionResult result;
    result.timestamp = GetTickCount64();

    std::vector<float> sample = FeatureVectorToArray(features);

    float isoScore = 0.0f, oneClassScore = 0.0f;
    int methodCount = 0;

    // Isolation Forest detection
    if (m_isolationForest && m_config.enableIsolationForest && m_isolationForest->IsTrained()) {
        isoScore = m_isolationForest->PredictAnomalyScore(sample);
        methodCount++;
    }

    // One-Class detection
    if (m_oneClassClassifier && m_config.enableOneClass && m_oneClassClassifier->IsTrained()) {
        oneClassScore = m_oneClassClassifier->PredictAnomalyScore(sample);
        methodCount++;
    }

    if (methodCount == 0) {
        // No trained models
        result.isAnomaly = false;
        result.anomalyScore = 0.0f;
        result.confidence = 0.0f;
        result.detectionMethod = "None (not trained)";
        return result;
    }

    // Ensemble scoring
    if (m_config.useEnsemble && methodCount > 1) {
        result.anomalyScore = m_config.ensembleWeight * isoScore + (1.0f - m_config.ensembleWeight) * oneClassScore;
        result.detectionMethod = "Ensemble";
        result.confidence = 1.0f - fabsf(isoScore - oneClassScore); // Agreement measure
    } else if (isoScore > 0.0f) {
        result.anomalyScore = isoScore;
        result.detectionMethod = "IsolationForest";
        result.confidence = 0.8f; // Fixed confidence for single method
    } else {
        result.anomalyScore = oneClassScore;
        result.detectionMethod = "OneClass";
        result.confidence = 0.8f;
    }

    result.isAnomaly = result.anomalyScore >= m_config.anomalyThreshold;

    // Feature contribution analysis
    result.featureContributions = ComputeFeatureContributions(sample);
    
    // Top anomalous features
    std::vector<std::pair<int, float>> indexedContribs;
    for (size_t i = 0; i < result.featureContributions.size(); ++i) {
        indexedContribs.push_back({static_cast<int>(i), result.featureContributions[i]});
    }
    std::sort(indexedContribs.begin(), indexedContribs.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    int topK = min(5, static_cast<int>(indexedContribs.size()));
    for (int i = 0; i < topK; ++i) {
        result.topFeatureIndices.push_back(indexedContribs[i].first);
    }

    // Update statistics
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.totalSamplesProcessed++;
        if (result.isAnomaly) {
            m_stats.anomaliesDetected++;
        }
        m_stats.averageAnomalyScore = 
            (m_stats.averageAnomalyScore * (m_stats.totalSamplesProcessed - 1) + result.anomalyScore) 
            / m_stats.totalSamplesProcessed;
        m_stats.maxAnomalyScore = max(m_stats.maxAnomalyScore, result.anomalyScore);
        m_stats.lastDetectionTime = result.timestamp;
    }

    return result;
}

void MLAnomalyDetector::UpdateWithSample(const FeatureVector& features, bool isNormal) {
    if (!m_config.enableOnlineLearning) return;

    std::vector<float> sample = FeatureVectorToArray(features);

    // Add to online buffer
    m_onlineBuffer.push_back(sample);
    m_samplesSinceUpdate++;

    // Update models when buffer is full
    if (m_samplesSinceUpdate >= m_config.onlineUpdateInterval) {
        std::lock_guard<std::mutex> lock(m_trainingMutex);

        // Update One-Class classifier (supports online learning)
        if (m_oneClassClassifier && m_config.enableOneClass && m_oneClassClassifier->IsTrained()) {
            for (const auto& s : m_onlineBuffer) {
                m_oneClassClassifier->UpdateWithSample(s, isNormal);
            }
        }

        // For Isolation Forest, accumulate samples and retrain periodically
        if (isNormal) {
            for (const auto& s : m_onlineBuffer) {
                AddTrainingSample(s);
            }

            // Retrain if enough new samples accumulated
            if (m_trainingData.size() >= static_cast<size_t>(m_config.minTrainingSamples * 2)) {
                if (m_isolationForest && m_config.enableIsolationForest) {
                    m_isolationForest->Train(m_trainingData);
                }
                PruneTrainingData();
            }
        }

        m_onlineBuffer.clear();
        m_samplesSinceUpdate = 0;
        m_stats.onlineUpdates++;
    }
}

bool MLAnomalyDetector::SaveModel(const std::wstring& path) {
    // Simplified model persistence (binary format)
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;

    // Write metadata
    ofs.write("OBML", 4); // Magic header
    int version = 1;
    ofs.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Write config
    ofs.write(reinterpret_cast<const char*>(&m_config), sizeof(m_config));

    // Write One-Class model state
    if (m_oneClassClassifier && m_oneClassClassifier->IsTrained()) {
        int trained = 1;
        ofs.write(reinterpret_cast<const char*>(&trained), sizeof(trained));
        
        // Save centroid and covariance (simplified - would need proper serialization in production)
        // For now, just mark as saved
    } else {
        int trained = 0;
        ofs.write(reinterpret_cast<const char*>(&trained), sizeof(trained));
    }

    ofs.close();
    return true;
}

bool MLAnomalyDetector::LoadModel(const std::wstring& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    // Read magic header
    char magic[4];
    ifs.read(magic, 4);
    if (memcmp(magic, "OBML", 4) != 0) return false;

    int version;
    ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) return false;

    // Read config
    ifs.read(reinterpret_cast<char*>(&m_config), sizeof(m_config));

    // Read One-Class model state
    int trained;
    ifs.read(reinterpret_cast<char*>(&trained), sizeof(trained));
    
    // In production, would deserialize full model state here

    ifs.close();
    return true;
}

void MLAnomalyDetector::ResetModel() {
    std::lock_guard<std::mutex> lock(m_trainingMutex);
    
    if (m_isolationForest) {
        m_isolationForest = std::make_unique<IsolationForest>(
            m_config.isolationForestTrees,
            m_config.isolationForestSubsampleSize,
            m_config.isolationForestMaxDepth
        );
    }

    if (m_oneClassClassifier) {
        m_oneClassClassifier = std::make_unique<OneClassClassifier>(m_config.oneClassNu);
    }

    m_trainingData.clear();
    m_onlineBuffer.clear();
    m_samplesSinceUpdate = 0;

    memset(&m_stats, 0, sizeof(m_stats));
}

MLAnomalyDetector::ModelStatistics MLAnomalyDetector::GetStatistics() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

void MLAnomalyDetector::SetConfig(const MLAnomalyDetectorConfig& config) {
    m_config = config;
}

std::vector<std::pair<int, float>> MLAnomalyDetector::GetTopAnomalousFeatures(const FeatureVector& features, int topK) {
    std::vector<float> sample = FeatureVectorToArray(features);
    std::vector<float> contributions = ComputeFeatureContributions(sample);

    std::vector<std::pair<int, float>> indexed;
    for (size_t i = 0; i < contributions.size(); ++i) {
        indexed.push_back({static_cast<int>(i), contributions[i]});
    }

    std::sort(indexed.begin(), indexed.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    int k = min(topK, static_cast<int>(indexed.size()));
    return std::vector<std::pair<int, float>>(indexed.begin(), indexed.begin() + k);
}

std::vector<float> MLAnomalyDetector::FeatureVectorToArray(const FeatureVector& fv) const {
    // Use the utility from MLFeatureExtractor
    return FeatureUtils::FeatureVectorToArray(fv);
}

float MLAnomalyDetector::ComputeEnsembleScore(const std::vector<float>& sample) const {
    float isoScore = 0.0f, oneClassScore = 0.0f;
    int count = 0;

    if (m_isolationForest && m_isolationForest->IsTrained()) {
        isoScore = m_isolationForest->PredictAnomalyScore(sample);
        count++;
    }

    if (m_oneClassClassifier && m_oneClassClassifier->IsTrained()) {
        oneClassScore = m_oneClassClassifier->PredictAnomalyScore(sample);
        count++;
    }

    if (count == 0) return 0.0f;
    if (count == 1) return isoScore > 0.0f ? isoScore : oneClassScore;

    return m_config.ensembleWeight * isoScore + (1.0f - m_config.ensembleWeight) * oneClassScore;
}

std::vector<float> MLAnomalyDetector::ComputeFeatureContributions(const std::vector<float>& sample) const {
    std::vector<float> contributions(sample.size(), 0.0f);

    if (!m_oneClassClassifier || !m_oneClassClassifier->IsTrained()) {
        return contributions;
    }

    // Compute contribution of each feature to anomaly score
    // Using simple deviation from centroid as proxy
    std::lock_guard<std::mutex> lock(m_trainingMutex);
    
    std::vector<float> mean = MLAnomalyUtils::ComputeMean(m_trainingData);
    std::vector<float> stddev = MLAnomalyUtils::ComputeStdDev(m_trainingData, mean);

    for (size_t i = 0; i < sample.size(); ++i) {
        if (stddev[i] > 1e-6f) {
            contributions[i] = fabsf(sample[i] - mean[i]) / stddev[i]; // Z-score magnitude
        }
    }

    return contributions;
}

void MLAnomalyDetector::AddTrainingSample(const std::vector<float>& sample) {
    m_trainingData.push_back(sample);
}

void MLAnomalyDetector::PruneTrainingData() {
    if (m_trainingData.size() > static_cast<size_t>(m_config.maxTrainingSamples)) {
        // Remove oldest samples (FIFO)
        int toRemove = static_cast<int>(m_trainingData.size()) - m_config.maxTrainingSamples;
        m_trainingData.erase(m_trainingData.begin(), m_trainingData.begin() + toRemove);
    }
}

// ===== Utility Functions Implementation =====
namespace MLAnomalyUtils {
    std::vector<float> ComputeMean(const std::vector<std::vector<float>>& samples) {
        if (samples.empty()) return {};

        std::vector<float> mean(samples[0].size(), 0.0f);
        for (const auto& sample : samples) {
            for (size_t i = 0; i < mean.size(); ++i) {
                mean[i] += sample[i];
            }
        }
        for (float& val : mean) {
            val /= static_cast<float>(samples.size());
        }
        return mean;
    }

    std::vector<float> ComputeStdDev(const std::vector<std::vector<float>>& samples, const std::vector<float>& mean) {
        if (samples.empty()) return {};

        std::vector<float> variance(mean.size(), 0.0f);
        for (const auto& sample : samples) {
            for (size_t i = 0; i < mean.size(); ++i) {
                float diff = sample[i] - mean[i];
                variance[i] += diff * diff;
            }
        }
        
        std::vector<float> stddev(mean.size());
        for (size_t i = 0; i < variance.size(); ++i) {
            stddev[i] = sqrtf(variance[i] / static_cast<float>(samples.size()));
        }
        return stddev;
    }

    std::vector<float> NormalizeSample(const std::vector<float>& sample, const std::vector<float>& mean, const std::vector<float>& stddev) {
        std::vector<float> normalized(sample.size());
        for (size_t i = 0; i < sample.size(); ++i) {
            if (stddev[i] > 1e-6f) {
                normalized[i] = (sample[i] - mean[i]) / stddev[i];
            } else {
                normalized[i] = 0.0f;
            }
        }
        return normalized;
    }

    float EuclideanDistance(const std::vector<float>& a, const std::vector<float>& b) {
        float sum = 0.0f;
        for (size_t i = 0; i < a.size(); ++i) {
            float diff = a[i] - b[i];
            sum += diff * diff;
        }
        return sqrtf(sum);
    }

    float CosineSimilarity(const std::vector<float>& a, const std::vector<float>& b) {
        float dotProduct = 0.0f, normA = 0.0f, normB = 0.0f;
        for (size_t i = 0; i < a.size(); ++i) {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        normA = sqrtf(normA);
        normB = sqrtf(normB);
        if (normA < 1e-6f || normB < 1e-6f) return 0.0f;
        return dotProduct / (normA * normB);
    }

    float ComputeVariance(const std::vector<float>& values, float mean) {
        if (values.empty()) return 0.0f;
        float variance = 0.0f;
        for (float val : values) {
            float diff = val - mean;
            variance += diff * diff;
        }
        return variance / static_cast<float>(values.size());
    }
}
