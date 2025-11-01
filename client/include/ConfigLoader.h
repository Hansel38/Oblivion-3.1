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

    // Kernel bridge (driver)
    bool enableKernelBridge = false;
};

// Load client_config.json from DLL directory (preferred) or current directory
bool LoadClientConfig(ClientConfig& outCfg, const std::wstring& dllDirectory);
