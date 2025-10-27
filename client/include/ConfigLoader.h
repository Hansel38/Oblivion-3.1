#pragma once
#include <windows.h>
#include <string>

struct ClientConfig {
    std::string serverIp = "127.0.0.1";
    int serverPort = 4000;
    DWORD pollingIntervalMs = 2000;
    int closeThreshold = 2;
    std::wstring detectionMessage = L"Oblivion AntiCheat: Suspicious software detected (%s). The game will close to protect integrity.";
    bool enableBackgroundWatcher = true; // enable by default for proactive monitoring
    bool enableLogging = false;           // OutputDebugString logging

    // Optional TLS for client->server
    bool enableTlsClient = false;
    std::string tlsServerName; // SNI/hostname for server cert validation

    // Overlay Scanner
    bool enableOverlayScanner = true;
    int overlayThreshold = 3;

    // Anti-Debug
    bool enableAntiDebug = true;
    int antiDebugThreshold = 2;

    // Injection Scanner
    bool enableInjectionScanner = true;
    int injectionThreshold = 2;
    // Semicolon-separated whitelist prefixes, e.g. "C:\\Windows\\;C:\\Program Files\\RRO\\"
    std::wstring moduleWhitelistPrefixes;

    // Digital Signature Validator
    bool enableSignatureValidator = true;
    int signatureThreshold = 2;
    // Semicolon-separated module names to skip sigcheck, e.g. "rro.exe;myclient.exe"
    std::wstring signatureSkipNames; // names to skip in signature validator (semicolon-delimited)

    // Anti-Suspend Threads
    bool enableAntiSuspend = true;
    DWORD antiSuspendHeartbeatMs = 200;        // beat interval
    DWORD antiSuspendStallWindowMs = 3000;   // window to consider stalled
    int antiSuspendMissesThreshold = 2;      // consecutive misses to trigger

    // Hijacked Thread Scanner
    bool enableHijackedThreadScanner = true;
    int hijackedThreadThreshold = 2;

    // IAT Hook Scanner
    bool enableIATHookScanner = true;
    int iatHookThreshold = 2;

    // File Integrity Check
    bool enableFileIntegrityCheck = true;
    // Semicolon-separated list of items: "path[=expectedhex]"; relative paths are resolved to DLL directory
    std::wstring integrityItems;

    // Memory Signature Scanner
    bool enableMemorySignatureScanner = true; // enabled by default
    int memorySignatureThreshold = 1;
    std::wstring memorySignatures; // format: name@w=AA BB ?? CC;name2@w=DE AD BE EF
    std::wstring memoryModuleWhitelistPrefixes; // optional, override generic module whitelist for memsig
    bool memoryImagesOnly = true; // scan only MEM_IMAGE regions

    // Cheat Engine artifact tokens (semicolon-delimited), case-insensitive contains match
    // Expanded to cover common CE UI/classes/driver names
    std::wstring ceArtifactTokens =
        L"cheatengine;cheat engine;dark byte;ce.exe;cetrainer;speedhack;vehdebug;dbk;cedriver;ceserver;celua;monohelper;"
        L"memscan;symbolhandler;tmainform;frmmemoryviewer;found:;first scan;next scan";

    // HMAC auth for client->server messages
    bool enableHmacAuth = false;
    std::string hmacSecret; // keep ASCII/UTF-8

    // Heartbeat telemetry
    bool enableHeartbeat = true;
    DWORD heartbeatIntervalMs = 30000; // 30s

    // Periodic scans for all features
    bool enablePeriodicScans = true;
    DWORD periodicScanIntervalMs = 15000; // 15s

    // Cooldown for duplicate detections (global fallback)
    DWORD detectionCooldownMs = 10000; // 10s

    // Per-subtype cooldowns (override global if non-zero)
    DWORD cooldownProcessMs = 10000;
    DWORD cooldownOverlayMs = 10000;
    DWORD cooldownAntiDebugMs = 10000;
    DWORD cooldownInjectionMs = 30000;
    DWORD cooldownSigcheckMs = 30000;
    DWORD cooldownHijackedThreadMs = 20000;
    DWORD cooldownIatHookMs = 30000;
    DWORD cooldownIntegrityMs = 60000;
    DWORD cooldownMemsigMs = 30000;

    // Kernel bridge (driver) toggle. Default false for safe user-mode only.
    bool enableKernelBridge = false;
};

// Load client_config.json from DLL directory (preferred) or current directory as fallback
// Returns true if file found and at least one field parsed; otherwise false and defaults remain
bool LoadClientConfig(ClientConfig& outCfg, const std::wstring& dllDirectory);
