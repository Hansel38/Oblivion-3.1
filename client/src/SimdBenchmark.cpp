#include "../pch.h"
#include "../include/SimdBenchmark.h"
#include "../include/SimdUtils.h"
#include <vector>
#include <algorithm>
#include <sstream>

static std::wstring WFormat(const wchar_t* fmt, ...) {
    wchar_t buf[512];
    va_list args;
    va_start(args, fmt);
    vswprintf_s(buf, fmt, args);
    va_end(args);
    return std::wstring(buf);
}

static void LogBench(const std::wstring& msg) {
    OutputDebugStringW((L"[SIMD Benchmark] " + msg + L"\n").c_str());
}

// Benchmark masked pattern compare
static void BenchmarkMaskedCompare(int iterations) {
    LogBench(L"=== Masked Pattern Compare Benchmark ===");
    
    // Test pattern sizes: 16, 32, 64, 128 bytes
    const size_t sizes[] = { 16, 32, 64, 128 };
    
    for (size_t sz : sizes) {
        std::vector<BYTE> data(sz);
        std::vector<BYTE> pattern(sz);
        std::vector<BYTE> mask(sz);
        
        // Fill with pseudo-random data
        for (size_t i = 0; i < sz; ++i) {
            data[i] = (BYTE)(i * 13 + 37);
            pattern[i] = (BYTE)(i * 13 + 37);
            mask[i] = (i % 4 == 0) ? 0x00 : 0xFF; // 25% wildcards
        }
        
        // Warmup
        for (int w = 0; w < 10; ++w) {
            SimdMaskedCompare(data.data(), pattern.data(), mask.data(), sz);
        }
        
        // Benchmark SIMD path
        ULONGLONG startSimd = GetTickCount64();
        for (int i = 0; i < iterations * 1000; ++i) {
            SimdMaskedCompare(data.data(), pattern.data(), mask.data(), sz);
        }
        ULONGLONG elapsedSimd = GetTickCount64() - startSimd;
        
        // Benchmark scalar path (disable SIMD internally by calling with data that forces scalar)
        // For comparison, manually do scalar loop
        auto scalarCompare = [](const BYTE* d, const BYTE* p, const BYTE* m, size_t len) -> bool {
            for (size_t i = 0; i < len; ++i) {
                BYTE mv = m[i];
                if (mv == 0x00) continue;
                if (mv == 0xFF) { if (d[i] != p[i]) return false; }
                else { if ((d[i] & mv) != (p[i] & mv)) return false; }
            }
            return true;
        };
        
        ULONGLONG startScalar = GetTickCount64();
        for (int i = 0; i < iterations * 1000; ++i) {
            scalarCompare(data.data(), pattern.data(), mask.data(), sz);
        }
        ULONGLONG elapsedScalar = GetTickCount64() - startScalar;
        
        double speedup = (elapsedScalar > 0) ? ((double)elapsedScalar / (double)elapsedSimd) : 1.0;
        LogBench(WFormat(L"  Pattern size %zu bytes: SIMD=%llums, Scalar=%llums, Speedup=%.2fx",
                         sz, elapsedSimd, elapsedScalar, speedup));
    }
}

// Benchmark entropy calculation
static void BenchmarkEntropy(int iterations) {
    LogBench(L"=== Entropy Calculation Benchmark ===");
    
    // Test buffer sizes: 4KB, 64KB, 1MB
    const size_t sizes[] = { 4096, 65536, 1048576 };
    
    for (size_t sz : sizes) {
        std::vector<BYTE> data(sz);
        
        // Fill with pseudo-random data (high entropy)
        for (size_t i = 0; i < sz; ++i) {
            data[i] = (BYTE)((i * 7 + i / 256) ^ (i >> 3));
        }
        
        // Warmup
        for (int w = 0; w < 5; ++w) {
            ComputeEntropyShannon(data.data(), sz, true);
        }
        
        // Benchmark optimized path
        ULONGLONG startOpt = GetTickCount64();
        for (int i = 0; i < iterations * 10; ++i) {
            ComputeEntropyShannon(data.data(), sz, true);
        }
        ULONGLONG elapsedOpt = GetTickCount64() - startOpt;
        
        // Benchmark with SIMD disabled (falls back to scalar)
        ULONGLONG startScalar = GetTickCount64();
        for (int i = 0; i < iterations * 10; ++i) {
            ComputeEntropyShannon(data.data(), sz, false);
        }
        ULONGLONG elapsedScalar = GetTickCount64() - startScalar;
        
        double speedup = (elapsedScalar > 0) ? ((double)elapsedScalar / (double)elapsedOpt) : 1.0;
        
        std::wstring szStr;
        if (sz >= 1048576) szStr = WFormat(L"%zuMB", sz / 1048576);
        else if (sz >= 1024) szStr = WFormat(L"%zuKB", sz / 1024);
        else szStr = WFormat(L"%zuB", sz);
        
        LogBench(WFormat(L"  Buffer size %s: Optimized=%llums, Scalar=%llums, Speedup=%.2fx",
                         szStr.c_str(), elapsedOpt, elapsedScalar, speedup));
    }
}

void RunSimdBenchmark(int iterations) {
    if (iterations < 1) iterations = 1;
    
    LogBench(L"Starting SIMD performance benchmark...");
    
    // Report CPU features
    const CpuFeatures& feats = GetCpuFeatures();
    LogBench(WFormat(L"CPU Features: SSE2=%s, AVX2=%s",
                     feats.sse2 ? L"YES" : L"NO",
                     feats.avx2 ? L"YES" : L"NO"));
    
    BenchmarkMaskedCompare(iterations);
    BenchmarkEntropy(iterations);
    
    LogBench(L"SIMD benchmark complete.");
}
