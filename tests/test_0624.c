// x86 feature macros follow -march and -m flags in order, with GCC's
// implications: x86-64-v3 brings AVX2/FMA/F16C and SSE3..SSE4.2, then -mno-fma
// takes FMA away. AVX-512 is never announced (sic stops at AVX2).
#include <immintrin.h>

int main(void)
{
#if !defined(__AVX2__) || !defined(__AVX__) || !defined(__SSE4_2__) || !defined(__SSSE3__) || !defined(__F16C__)
    return 1;
#endif
#if defined(__FMA__) || defined(__AVX512F__)
    return 2;
#endif
    __m256i v = _mm256_set1_epi32(21);
    __m256i d = _mm256_add_epi32(v, v);
    return _mm256_extract_epi32(d, 7);
}
