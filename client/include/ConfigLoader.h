#pragma once
#include <windows.h>
#include <string>

// Configuration for the client module. Keep this header simple ASCII to avoid
// IntelliSense parsing issues. Only add fields; do not remove/rename existing ones
// without updating all call sites.
struct ClientConfig {
    // Networking
    std::string serverIp = "127.0.0.1";
    int serverPort = 4000;

    // Runtime
    DWORD pollingIntervalMs = 2000;
    int closeThreshold = 2;
    std::wstring detectionMessage = L"Oblivion AntiCheat: Suspicious software detected (%s). The game will close to protect integrity.";
    bool enableBackgroundWatcher = true;
    bool enableLogging = false;

    // TLS (optional)
    bool enableTlsClient = false;
    std::string tlsServerName;

    // Overlay Scanner
    bool enableOverlayScanner = true;
    int overlayThreshold = 3;

    // Anti-Debug
    bool enableAntiDebug = true;
    int antiDebugThreshold = 2;

    // Injection Scanner
    bool enableInjectionScanner = true;
    int injectionThreshold = 2;
    std::wstring moduleWhitelistPrefixes;

    // Digital Signature Validator
    bool enableSignatureValidator = true;
    int signatureThreshold = 2;
    std::wstring signatureSkipNames;

    // Anti-Suspend Threads
    bool enableAntiSuspend = true;
    DWORD antiSuspendHeartbeatMs = 200;
    DWORD antiSuspendStallWindowMs = 3000;
    int antiSuspendMissesThreshold = 2;

    // Hijacked Thread Scanner
    bool enableHijackedThreadScanner = true;
    int hijackedThreadThreshold = 2;

    // IAT Hook Scanner
    bool enableIATHookScanner = true;
    int iatHookThreshold = 2;

    // File Integrity Check
    bool enableFileIntegrityCheck = true;
    std::wstring integrityItems; // path[=expectedhex]; semicolon-delimited

    // Memory Signature Scanner
    bool enableMemorySignatureScanner = true;
    int memorySignatureThreshold = 1;
    std::wstring memorySignatures; // name=AA BB ?? CC;name2=...
    std::wstring memoryModuleWhitelistPrefixes;
    bool memoryImagesOnly = true;

    // Cheat Engine artifact tokens (semicolon-delimited)
    std::wstring ceArtifactTokens =
        L"cheatengine;cheat engine;dark byte;ce.exe;cetrainer;speedhack;vehdebug;dbk;cedriver;ceserver;celua;monohelper;"
        L"memscan;symbolhandler;tmainform;frmmemoryviewer;found:;first scan;next scan";

    // CE Behavior Monitor
    bool enableCEBehaviorMonitor = true;
    int ceBehaviorThreshold = 4;
    DWORD ceBehaviorWindowMs = 5000;
    DWORD ceBehaviorPollMs = 500;

    // CE Registry Scanner
    bool enableCERegistryScanner = true;

    // CE Window Scanner
    bool enableCEWindowScanner = true;

    // Speed Hack Detector
    bool enableSpeedHackDetector = true;
    int speedHackSensitivity = 3;
    DWORD speedHackMonitorIntervalMs = 1000;

    // Aggressive detection profile
    bool aggressiveDetection = false;

    // ETW tuning
    int etwBurstThreshold = 6;
    DWORD etwWindowMs = 3000;
    int etwMemscanMinStreak = 4;

    // HMAC auth
    bool enableHmacAuth = false;
    std::string hmacSecret;

    // Heartbeat
    bool enableHeartbeat = true;
    DWORD heartbeatIntervalMs = 30000;

    // Periodic scans
    bool enablePeriodicScans = true;
    DWORD periodicScanIntervalMs = 15000;

    // Global cooldown
    DWORD detectionCooldownMs = 10000;

    // Per-subtype cooldowns
    DWORD cooldownProcessMs = 10000;
    DWORD cooldownOverlayMs = 10000;
    DWORD cooldownAntiDebugMs = 10000;
    DWORD cooldownInjectionMs = 30000;
    DWORD cooldownSigcheckMs = 30000;
    DWORD cooldownHijackedThreadMs = 20000;
    DWORD cooldownIatHookMs = 30000;
    DWORD cooldownIntegrityMs = 60000;
    DWORD cooldownMemsigMs = 30000;

    // New detector cooldowns
    DWORD cooldownCEBehaviorMs = 15000;
    DWORD cooldownCERegistryMs = 20000;
    DWORD cooldownCEWindowMs = 10000;
    DWORD cooldownSpeedHackMs = 15000;
    // Memory scanning (behavioral) cooldown
    DWORD cooldownMemoryScanningMs = 15000;

    // ===== PRIORITY 3: Stealth & Evasion Detection =====
    
    // PEB Manipulation Detector
    bool enablePEBManipulationDetector = true;
    bool pebEnableMemoryScan = true;
    bool pebEnableToolHelpValidation = true;
    DWORD cooldownPEBManipulationMs = 20000;

    // Hardware Breakpoint Monitor
    bool enableHardwareBreakpointMonitor = true;
    int hwbpMaxThreshold = 2;  // Max hardware breakpoints per thread
    bool hwbpEnableAnomalyDetection = true;
    bool hwbpTrackHistory = true;
    DWORD cooldownHardwareBreakpointMs = 15000;

    // Suspicious Memory Scanner
    bool enableSuspiciousMemoryScanner = true;
    SIZE_T suspMemMinRegionSize = 4096;  // 4KB minimum
    bool suspMemEnablePatternAnalysis = true;
    bool suspMemEnableEntropyCheck = true;
    bool suspMemFlagRWX = true;
    bool suspMemFlagPrivateExecutable = true;
    DWORD cooldownSuspiciousMemoryMs = 20000;

    // Heap Spray Analyzer
    bool enableHeapSprayAnalyzer = true;
    SIZE_T heapSprayMinSize = 0x10000;  // 64KB minimum
    int heapSprayMinRepeatCount = 100;
    double heapSprayMinDensity = 0.8;  // 80% pattern density
    bool heapSprayEnableNOPDetection = true;
    bool heapSprayEnableAddressSpray = true;
    DWORD cooldownHeapSprayMs = 25000;

    // ETHREAD Manipulation Detector
    bool enableETHREADDetector = true;
    DWORD cooldownETHREADMs = 30000;

    // Kernel Callback Scanner
    bool enableCallbackScanner = true;
    DWORD cooldownCallbackMs = 60000;  // 1 minute cooldown (expensive operation)

    // VAD Manipulation Detector
    bool enableVADDetector = true;
    SIZE_T vadSizeThreshold = 100 * 1024 * 1024;  // 100MB threshold for suspicious regions
    DWORD cooldownVADMs = 30000;

    // Kernel bridge (driver)
    bool enableKernelBridge = false;

    // ===== PRIORITY 4: Infrastructure & Optimization =====
    
    // Telemetry Collection
    bool enableTelemetry = true;
    DWORD telemetryCollectionIntervalMs = 5000;  // Collect system metrics every 5 seconds
    ULONGLONG telemetryAggregationPeriodMs = 300000;  // Aggregate every 5 minutes
    bool telemetryExportOnExit = true;
    std::wstring telemetryExportPath = L"telemetry_export.json";

    // ML Anomaly Detection
    bool enableMLAnomalyDetection = true;
    bool mlUseIsolationForest = true;
    bool mlUseOneClass = true;
    bool mlUseEnsemble = true;
    float mlEnsembleWeight = 0.5f;  // Balance between IsolationForest and OneClass
    int mlIsolationForestTrees = 100;
    int mlIsolationForestSubsampleSize = 256;
    int mlIsolationForestMaxDepth = 10;
    float mlOneClassNu = 0.1f;  // Expected outlier fraction
    float mlAnomalyThreshold = 0.65f;  // Threshold for anomaly detection (0.0-1.0)
    int mlMinTrainingSamples = 50;
    int mlMaxTrainingSamples = 5000;
    bool mlEnableOnlineLearning = true;
    int mlOnlineUpdateInterval = 100;  // Update model every 100 samples
    float mlOnlineLearningRate = 0.1f;
    bool mlEnableModelPersistence = false;
    std::wstring mlModelSavePath = L"ml_anomaly_model.bin";

    // ===== PRIORITY 4.1.5: ML Integration with Detection Pipeline =====
    bool enableMLIntegration = true;  // Use ML scoring in detection pipeline
    bool mlHybridMode = true;  // Combine rule-based + ML (false = ML only)
    float mlDetectionThreshold = 0.7f;  // ML score threshold for standalone detection
    float mlConfidenceThreshold = 0.6f;  // Minimum ML confidence to trust prediction
    bool mlBoostIndicators = true;  // Add ML score as additional indicators
    float mlIndicatorMultiplier = 2.0f;  // Multiply ML score by this to get indicator count
    bool mlEnableVeto = false;  // Allow ML to veto low-confidence rule-based detections
    float mlVetoThreshold = 0.3f;  // ML score below this can veto detections
    bool mlLogScores = true;  // Log ML scores in detection JSON

    // Adaptive Threshold Manager
    bool enableAdaptiveThresholds = true;
    bool usePerPlayerProfiles = true;
    bool useGlobalBaseline = true;
    double defaultSigmaMultiplier = 3.0;  // N in (mean + N*stddev)
    int minBaselineSamples = 100;
    int maxProfileAgeHours = 720;  // 30 days
    int adaptiveMinThreshold = 1;
    int adaptiveMaxThreshold = 10;
    double adaptiveDecayRate = 0.95;
    bool enableAutoDecay = true;
    double trustScoreInitial = 0.5;
    double trustScoreIncrement = 0.05;
    double trustScoreDecrement = 0.2;

    // ===== PRIORITY 4.2.4: Signature Testing Framework =====
    bool enableSignatureTesting = false;                 // Run signature test suite on startup
    std::wstring signatureTestsCsvPath = L"signatures\\tests\\tests.csv"; // CSV path for test cases
    std::wstring signatureYaraRulesPath = L"signatures\\yara_rules.txt";   // YARA rules path
    int signatureBenchmarkIterations = 3;                // Repetitions for throughput benchmark

    // ===== PRIORITY 4.3.1: Scan Prioritization Manager =====
    bool enableScanPrioritization = true;                // Enable scan prioritization system
    bool enableDynamicPriorityAdjustment = true;         // Auto-adjust priorities based on detection rate
    bool enableLoadBalancing = true;                     // Skip low-priority scans under high CPU load
    float cpuThresholdPercent = 80.0f;                   // CPU % threshold for load balancing
    DWORD criticalScanMaxDelayMs = 1000;                 // Max delay for CRITICAL priority scans
    DWORD highScanMaxDelayMs = 5000;                     // Max delay for HIGH priority scans
    DWORD scanPrioritizationBudgetMs = 100;              // Max time per tick for executing scheduled scans
    float recentDetectionBoostWeight = 2.0f;             // Priority boost for recent detections
    float detectionRateBoostWeight = 1.5f;               // Priority boost based on detection rate
    float falsePositivePenaltyWeight = 1.0f;             // Priority penalty for false positives
    DWORD recentDetectionWindowMs = 300000;              // Time window for "recent" detection (5 min)
    DWORD statisticsUpdateIntervalMs = 30000;            // How often to recalculate priority stats

    // ===== PRIORITY 4.3.2: Adaptive Polling Interval =====
    bool enableAdaptivePolling = true;                   // Enable adaptive interval for periodic scans
    DWORD adaptiveMinIntervalMs = 1000;                  // Minimum periodic scan interval
    DWORD adaptiveMaxIntervalMs = 60000;                 // Maximum periodic scan interval
    DWORD adaptiveChangeCooldownMs = 5000;               // Minimum time between interval changes
    float adaptiveMinChangePercent = 0.15f;              // Apply only if change >= 15%
    double adaptiveMediumRateThreshold = 0.001;          // Detection rate thresholds
    double adaptiveHighRateThreshold = 0.005;
    double adaptiveCriticalRateThreshold = 0.02;
    float adaptiveCpuLowPercent = 40.0f;                 // CPU thresholds for scaling
    float adaptiveCpuHighPercent = 85.0f;

    // ===== PRIORITY 4.3.3: SIMD Acceleration =====
    bool enableSimdAcceleration = true;                  // Use SSE2/AVX2 accelerated paths when available
    bool enableSimdBenchmark = false;                    // Run SIMD benchmark on startup and log results
    int simdBenchmarkIterations = 5;                     // Number of iterations for benchmark averaging
};


// Load client_config.json from DLL directory (preferred) or current directory
bool LoadClientConfig(ClientConfig& outCfg, const std::wstring& dllDirectory);
