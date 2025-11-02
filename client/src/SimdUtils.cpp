#include "../pch.h"
#include "../include/SimdUtils.h"
#include <intrin.h>
#ifdef __AVX2__
#include <immintrin.h>
#endif

static CpuFeatures g_feats{};
static bool g_featsInit = false;

static void InitCpuFeatures() {
    if (g_featsInit) return;
    g_feats.sse2 = IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE) != 0;
    // PF_AVX2_INSTRUCTIONS_AVAILABLE is available on Windows 8.1+; guard via try/catch not needed here
#ifdef PF_AVX2_INSTRUCTIONS_AVAILABLE
    g_feats.avx2 = IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE) != 0;
#else
    g_feats.avx2 = false;
#endif
    g_featsInit = true;
}

const CpuFeatures& GetCpuFeatures() {
    InitCpuFeatures();
    return g_feats;
}

static inline bool ScalarMaskedCompare(const BYTE* data, const BYTE* pattern, const BYTE* mask, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        BYTE m = mask[i];
        if (m == 0x00) continue; // wildcard
        BYTE dv = data[i];
        BYTE pv = pattern[i];
        if (m == 0xFF) { if (dv != pv) return false; }
        else {
            if ( (dv & m) != (pv & m) ) return false;
        }
    }
    return true;
}

bool SimdMaskedCompare(const BYTE* data, const BYTE* pattern, const BYTE* mask, size_t len) {
    InitCpuFeatures();
#ifdef __AVX2__
    if (g_feats.avx2 && len >= 32) {
        size_t i = 0;
        for (; i + 32 <= len; i += 32) {
            __m256i vData = _mm256_loadu_si256((const __m256i*)(data + i));
            __m256i vPat  = _mm256_loadu_si256((const __m256i*)(pattern + i));
            __m256i vMask = _mm256_loadu_si256((const __m256i*)(mask + i));
            __m256i dMasked = _mm256_and_si256(vData, vMask);
            __m256i pMasked = _mm256_and_si256(vPat,  vMask);
            __m256i cmp = _mm256_cmpeq_epi8(dMasked, pMasked);
            unsigned int bits = (unsigned int)_mm256_movemask_epi8(cmp);
            if (bits != 0xFFFFFFFFu) {
                // Need to handle possible wildcard bytes (mask==0) separately
                // Compute mismatches only where mask != 0
                __m256i ones = _mm256_set1_epi8((char)0xFF);
                __m256i maskZero = _mm256_cmpeq_epi8(vMask, _mm256_setzero_si256()); // 0xFF where mask==0
                __m256i cmpOrWildcard = _mm256_or_si256(cmp, maskZero);
                unsigned int bits2 = (unsigned int)_mm256_movemask_epi8(cmpOrWildcard);
                if (bits2 != 0xFFFFFFFFu) return false;
            }
        }
        // tail
        if (i < len) return ScalarMaskedCompare(data + i, pattern + i, mask + i, len - i);
        return true;
    }
#endif
#if defined(_M_X64) || defined(_M_IX86)
    if (g_feats.sse2 && len >= 16) {
        size_t i = 0;
        for (; i + 16 <= len; i += 16) {
            __m128i vData = _mm_loadu_si128((const __m128i*)(data + i));
            __m128i vPat  = _mm_loadu_si128((const __m128i*)(pattern + i));
            __m128i vMask = _mm_loadu_si128((const __m128i*)(mask + i));
            __m128i dMasked = _mm_and_si128(vData, vMask);
            __m128i pMasked = _mm_and_si128(vPat,  vMask);
            __m128i cmp = _mm_cmpeq_epi8(dMasked, pMasked);
            int bits = _mm_movemask_epi8(cmp);
            if (bits != 0xFFFF) {
                __m128i maskZero = _mm_cmpeq_epi8(vMask, _mm_setzero_si128()); // 0xFF where mask==0
                __m128i cmpOrWildcard = _mm_or_si128(cmp, maskZero);
                int bits2 = _mm_movemask_epi8(cmpOrWildcard);
                if (bits2 != 0xFFFF) return false;
            }
        }
        if (i < len) return ScalarMaskedCompare(data + i, pattern + i, mask + i, len - i);
        return true;
    }
#endif
    return ScalarMaskedCompare(data, pattern, mask, len);
}

float ComputeEntropyShannon(const BYTE* data, size_t len, bool /*enableSimd*/) {
    if (!data || len == 0) return 0.0f;
    // Optimized scalar 256-bin histogram
    unsigned int freq[256] = {0};
    const BYTE* p = data;
    const BYTE* end = data + len;
    // Unroll by 4 for better throughput
    for (; p + 4 <= end; p += 4) {
        ++freq[p[0]];
        ++freq[p[1]];
        ++freq[p[2]];
        ++freq[p[3]];
    }
    for (; p < end; ++p) ++freq[*p];

    // Shannon entropy in bits per byte (0..8)
    double H = 0.0;
    const double invLen = 1.0 / static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        unsigned int c = freq[i];
        if (c == 0) continue;
        double p_i = static_cast<double>(c) * invLen;
        H -= p_i * log2(p_i);
    }
    return static_cast<float>(H);
}
