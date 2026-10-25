// x86 feature macros: without machine flags, the x86-64 baseline (MMX, SSE,
// SSE2) as GCC defines it, and nothing beyond (code picks its SIMD path by
// these, and sic implements the intrinsics behind them).
#include <emmintrin.h>

int main(void)
{
#if !defined(__MMX__) || !defined(__SSE__) || !defined(__SSE2__) || !defined(__SSE2_MATH__)
    return 1;
#endif
#if defined(__SSE3__) || defined(__SSE4_1__) || defined(__AVX__) || defined(__AVX2__) || defined(__AVX512F__)
    return 2;
#endif
    __m128i a = _mm_set1_epi16(300);
    __m128i s = _mm_adds_epi16(a, _mm_set1_epi16(32700));
    return _mm_extract_epi16(s, 3) == 32767 ? 42 : 3;
}
