#pragma once
#include <windows.h>

// Run SIMD performance benchmarks and log results
// Compares scalar vs SIMD paths for pattern matching and entropy
void RunSimdBenchmark(int iterations);
