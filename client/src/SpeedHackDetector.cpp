#include "../pch.h"
#include "SpeedHackDetector.h"
#include <algorithm>
#include <cmath>

SpeedHackDetector::SpeedHackDetector()
{
}

SpeedHackDetector::~SpeedHackDetector()
{
    Stop();
}

bool SpeedHackDetector::Start()
{
    if (m_running.load()) return true;

    m_running.store(true);
    
    // Collect initial sample
    CollectTimingSample();
    m_lastSampleTime = GetTickCount64();
    
    // Start monitoring thread
    m_hMonitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
    
    return m_hMonitorThread != nullptr;
}

void SpeedHackDetector::Stop()
{
    if (!m_running.load()) return;

    m_running.store(false);

    if (m_hMonitorThread) {
        WaitForSingleObject(m_hMonitorThread, 2000);
        CloseHandle(m_hMonitorThread);
        m_hMonitorThread = nullptr;
    }
}

bool SpeedHackDetector::CheckSpeedHack(SpeedHackFinding& outFinding)
{
    // Analyze collected timing samples for anomalies
    return AnalyzeTimingConsistency(outFinding);
}

DWORD WINAPI SpeedHackDetector::MonitorThreadProc(LPVOID lpParam)
{
    auto* detector = reinterpret_cast<SpeedHackDetector*>(lpParam);
    if (detector) {
        detector->MonitorLoop();
    }
    return 0;
}

void SpeedHackDetector::MonitorLoop()
{
    while (m_running.load()) {
        Sleep(m_monitorIntervalMs);
        
        // Collect timing sample
        CollectTimingSample();
    }
}

void SpeedHackDetector::CollectTimingSample()
{
    std::lock_guard<std::mutex> lock(m_samplesMutex);

    TimingSample sample;
    sample.tickCount = GetTickCount64();
    QueryPerformanceCounter(&sample.perfCounter);
    QueryPerformanceFrequency(&sample.perfFrequency);
    sample.timestamp = GetTickCount64();
    
    // Calculate delta from previous sample if exists
    if (!m_samples.empty()) {
        const TimingSample& prev = m_samples.back();
        
        // Calculate time delta using QPC
        LONGLONG counterDelta = sample.perfCounter.QuadPart - prev.perfCounter.QuadPart;
        double freqDouble = static_cast<double>(sample.perfFrequency.QuadPart);
        sample.calculatedDelta = (static_cast<double>(counterDelta) / freqDouble) * 1000.0;
    }
    else {
        sample.calculatedDelta = 0.0;
    }
    
    m_samples.push_back(sample);
    
    // Keep only last 60 samples (1 minute at 1 sample/sec)
    if (m_samples.size() > 60) {
        m_samples.erase(m_samples.begin());
    }
}

bool SpeedHackDetector::AnalyzeTimingConsistency(SpeedHackFinding& outFinding)
{
    std::lock_guard<std::mutex> lock(m_samplesMutex);

    if (m_samples.size() < MIN_SAMPLES_FOR_DETECTION) {
        return false; // Not enough data yet
    }

    // Detection 1: Check for QPC manipulation
    if (DetectQueryPerformanceCounterManipulation()) {
        outFinding.detected = true;
        outFinding.indicators = 5;
        outFinding.reason = L"QueryPerformanceCounter manipulation detected (likely speed hack)";
        return true;
    }

    // Detection 2: Check for large time jumps in GetTickCount
    if (DetectTickCountJump()) {
        outFinding.detected = true;
        outFinding.indicators = 4;
        outFinding.reason = L"Abnormal time jump detected in GetTickCount (speed manipulation)";
        return true;
    }

    // Detection 3: Check for inconsistency between timing sources
    if (DetectTimeInconsistency()) {
        outFinding.detected = true;
        outFinding.indicators = 4;
        outFinding.reason = L"Timing inconsistency detected between QPC and GetTickCount";
        return true;
    }

    // Detection 4: Statistical analysis of timing ratios
    std::vector<double> ratios;
    for (size_t i = 1; i < m_samples.size(); ++i) {
        double ratio = CalculateTimeRatio(m_samples[i - 1], m_samples[i]);
        if (ratio > 0.0 && ratio < 10.0) { // Ignore extreme outliers
            ratios.push_back(ratio);
        }
    }

    if (ratios.size() >= MIN_SAMPLES_FOR_DETECTION) {
        // Calculate mean and standard deviation
        double sum = 0.0;
        for (double r : ratios) sum += r;
        double mean = sum / static_cast<double>(ratios.size());

        double variance = 0.0;
        for (double r : ratios) {
            double diff = r - mean;
            variance += diff * diff;
        }
        variance /= static_cast<double>(ratios.size());
        double stddev = std::sqrt(variance);

        // Expected mean should be close to 1.0 (no speed modification)
        double deviation = std::abs(mean - 1.0);

        // Adjust threshold based on sensitivity
        double threshold = SPEED_TOLERANCE;
        if (m_sensitivity >= 4) threshold = 0.10; // 10% for high sensitivity
        else if (m_sensitivity <= 2) threshold = 0.20; // 20% for low sensitivity

        if (deviation > threshold) {
            outFinding.detected = true;
            outFinding.timeRatio = mean;
            outFinding.indicators = (deviation > CRITICAL_SPEED_DIFF) ? 5 : 3;
            
            wchar_t buf[256];
            swprintf_s(buf, L"Speed hack detected: time ratio %.2fx (expected 1.0x, deviation: %.1f%%)",
                mean, deviation * 100.0);
            outFinding.reason = buf;
            
            return true;
        }

        // High variance can also indicate timing manipulation
        if (stddev > 0.3 && m_sensitivity >= 4) {
            outFinding.detected = true;
            outFinding.indicators = 3;
            outFinding.reason = L"Unstable timing pattern detected (possible speed hack)";
            return true;
        }
    }

    return false;
}

bool SpeedHackDetector::DetectQueryPerformanceCounterManipulation()
{
    // Check if QueryPerformanceFrequency changes (should be constant)
    if (m_samples.size() < 2) return false;

    LONGLONG firstFreq = m_samples[0].perfFrequency.QuadPart;
    
    for (size_t i = 1; i < m_samples.size(); ++i) {
        if (m_samples[i].perfFrequency.QuadPart != firstFreq) {
            // Frequency changed - this is highly suspicious
            return true;
        }
    }

    // Check for QPC going backwards (should never happen)
    for (size_t i = 1; i < m_samples.size(); ++i) {
        if (m_samples[i].perfCounter.QuadPart < m_samples[i - 1].perfCounter.QuadPart) {
            // Counter went backwards - definite manipulation
            return true;
        }
    }

    // Check for QPC not advancing (frozen time)
    int frozenCount = 0;
    for (size_t i = 1; i < m_samples.size(); ++i) {
        if (m_samples[i].perfCounter.QuadPart == m_samples[i - 1].perfCounter.QuadPart) {
            frozenCount++;
        }
    }
    
    // If more than 3 consecutive samples show frozen QPC, it's manipulated
    if (frozenCount >= 3) {
        return true;
    }

    return false;
}

bool SpeedHackDetector::DetectTickCountJump()
{
    if (m_samples.size() < 2) return false;

    for (size_t i = 1; i < m_samples.size(); ++i) {
        ULONGLONG delta = m_samples[i].tickCount - m_samples[i - 1].tickCount;
        ULONGLONG expectedDelta = m_monitorIntervalMs;
        
        // Allow some tolerance for system jitter
        ULONGLONG minExpected = static_cast<ULONGLONG>(expectedDelta * 0.7);
        ULONGLONG maxExpected = static_cast<ULONGLONG>(expectedDelta * 1.5);
        
        // Extreme deviation indicates manipulation
        if (delta < minExpected / 2 || delta > maxExpected * 2) {
            return true;
        }
    }

    return false;
}

bool SpeedHackDetector::DetectTimeInconsistency()
{
    if (m_samples.size() < 2) return false;

    // Compare QPC-based time with GetTickCount-based time
    for (size_t i = 1; i < m_samples.size(); ++i) {
        const TimingSample& prev = m_samples[i - 1];
        const TimingSample& curr = m_samples[i];
        
        // Calculate delta using GetTickCount
        ULONGLONG tickDelta = curr.tickCount - prev.tickCount;
        
        // Calculate delta using QPC
        LONGLONG counterDelta = curr.perfCounter.QuadPart - prev.perfCounter.QuadPart;
        double qpcDeltaMs = (static_cast<double>(counterDelta) / 
                            static_cast<double>(curr.perfFrequency.QuadPart)) * 1000.0;
        
        // These should be very close (within a few ms)
        double diff = std::abs(static_cast<double>(tickDelta) - qpcDeltaMs);
        double ratio = diff / static_cast<double>(tickDelta);
        
        // If difference is more than 20%, it's suspicious
        if (ratio > 0.20 && tickDelta > 100) {
            return true;
        }
    }

    return false;
}

double SpeedHackDetector::CalculateTimeRatio(const TimingSample& older, const TimingSample& newer)
{
    // Calculate actual time elapsed using QPC
    LONGLONG counterDelta = newer.perfCounter.QuadPart - older.perfCounter.QuadPart;
    if (counterDelta <= 0) return 1.0;
    
    double actualMs = (static_cast<double>(counterDelta) / 
                      static_cast<double>(newer.perfFrequency.QuadPart)) * 1000.0;
    
    // Expected time is the monitoring interval
    double expectedMs = static_cast<double>(m_monitorIntervalMs);
    
    if (expectedMs <= 0.0) return 1.0;
    
    // Ratio > 1.0 means time is passing faster (speed hack acceleration)
    // Ratio < 1.0 means time is passing slower (speed hack deceleration)
    return actualMs / expectedMs;
}

bool SpeedHackDetector::IsQPCConsistent()
{
    std::lock_guard<std::mutex> lock(m_samplesMutex);
    
    if (m_samples.size() < 2) return true;
    
    // Basic consistency checks
    LONGLONG freq = m_samples[0].perfFrequency.QuadPart;
    
    for (const auto& sample : m_samples) {
        // Frequency should be constant
        if (sample.perfFrequency.QuadPart != freq) {
            return false;
        }
        
        // Counter should always increase
        if (&sample != &m_samples[0]) {
            size_t idx = &sample - &m_samples[0];
            if (sample.perfCounter.QuadPart <= m_samples[idx - 1].perfCounter.QuadPart) {
                return false;
            }
        }
    }
    
    return true;
}
