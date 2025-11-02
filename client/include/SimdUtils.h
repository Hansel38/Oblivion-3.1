#pragma once
#include <windows.h>
#include <cstddef>

struct CpuFeatures {
    bool sse2 = false;
    bool avx2 = false;
};

// Returns cached CPU feature flags
const CpuFeatures& GetCpuFeatures();

// Compare (data & mask) == (pattern & mask) for len bytes
// Uses AVX2/SSE2 when available; falls back to scalar otherwise.
bool SimdMaskedCompare(const BYTE* data, const BYTE* pattern, const BYTE* mask, size_t len);

// Compute Shannon entropy (0..8). If enableSimd is true, may use vector assists when available.
float ComputeEntropyShannon(const BYTE* data, size_t len, bool enableSimd);
