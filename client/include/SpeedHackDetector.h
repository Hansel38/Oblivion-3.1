#pragma once
#include <Windows.h>
#include <vector>
#include <mutex>
#include <atomic>

// Speed hack detection via timing anomalies
// Detects manipulation of QueryPerformanceCounter, GetTickCount, and system time
// Identifies speed hacks used to accelerate or decelerate game time
class SpeedHackDetector
{
public:
    SpeedHackDetector();
    ~SpeedHackDetector();

    struct SpeedHackFinding {
        bool detected = false;
        int indicators = 0;
        std::wstring reason;
        double timeRatio = 1.0; // Detected speed multiplier
        ULONGLONG suspiciousTimestamp = 0;
    };

    // Start monitoring timing
    bool Start();
    
    // Stop monitoring
    void Stop();

    // Check for speed hack detection
    bool CheckSpeedHack(SpeedHackFinding& outFinding);

    // Configure sensitivity (1-5, higher = more sensitive)
    void SetSensitivity(int sensitivity) { m_sensitivity = sensitivity; }
    
    // Configure monitoring interval in milliseconds
    void SetMonitorIntervalMs(DWORD intervalMs) { m_monitorIntervalMs = intervalMs; }

private:
    struct TimingSample {
        ULONGLONG tickCount;           // GetTickCount64()
        LARGE_INTEGER perfCounter;     // QueryPerformanceCounter()
        LARGE_INTEGER perfFrequency;   // QueryPerformanceFrequency()
        ULONGLONG timestamp;           // Sample collection time
        double calculatedDelta;        // Time delta in milliseconds
    };

    std::atomic<bool> m_running{ false };
    int m_sensitivity = 3; // Default medium sensitivity
    DWORD m_monitorIntervalMs = 1000; // Sample every 1 second
    
    std::mutex m_samplesMutex;
    std::vector<TimingSample> m_samples;
    ULONGLONG m_lastSampleTime = 0;
    
    // Analysis thresholds
    static constexpr double SPEED_TOLERANCE = 0.15; // 15% tolerance for normal variation
    static constexpr double CRITICAL_SPEED_DIFF = 0.30; // 30% difference is critical
    static constexpr int MIN_SAMPLES_FOR_DETECTION = 5;
    
    // Monitoring thread
    static DWORD WINAPI MonitorThreadProc(LPVOID lpParam);
    void MonitorLoop();
    HANDLE m_hMonitorThread = nullptr;
    
    // Analysis methods
    void CollectTimingSample();
    bool AnalyzeTimingConsistency(SpeedHackFinding& outFinding);
    bool DetectQueryPerformanceCounterManipulation();
    bool DetectTickCountJump();
    bool DetectTimeInconsistency();
    
    // Calculate expected vs actual time ratio
    double CalculateTimeRatio(const TimingSample& older, const TimingSample& newer);
    
    // Check if QPC is behaving normally
    bool IsQPCConsistent();
};
