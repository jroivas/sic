// Vector slots split into 16-byte register parts (-O2 "vec-split"): values
// carried around a loop, copies between split and unsplit slots, a slot also
// read lane by lane (stays in memory), memcpy in and out, a vector in a struct.
#include <immintrin.h>
#include <string.h>

typedef struct { __m256 v; int tag; } Boxed;

static __m256 acc8(const float *p, int n)
{
    __m256 s = _mm256_setzero_ps(), t = _mm256_set1_ps(1.0f);
    for (int i = 0; i + 8 <= n; i += 8) {
        __m256 x = _mm256_loadu_ps(p + i);
        s = _mm256_add_ps(s, _mm256_mul_ps(x, t));
        t = _mm256_add_ps(t, t);
    }
    return s;
}

int main(void)
{
    float in[32];
    for (int i = 0; i < 32; i++) in[i] = (float)i;
    __m256 s = acc8(in, 32);
    float out[8];
    _mm256_storeu_ps(out, s);
    // lane k: k*1 + (8+k)*2 + (16+k)*4 + (24+k)*8 = 15k + 16 + 64 + 192
    for (int k = 0; k < 8; k++) if (out[k] != 15.0f * k + 272.0f) return 1;
    // A slot read lane by lane as well as whole.
    __m128i v = _mm_setr_epi32(1, 2, 3, 4);
    int *lanes = (int *)&v;
    lanes[2] = 30;
    __m128i w = _mm_add_epi32(v, v);
    if (_mm_extract_epi32(w, 2) != 60 || _mm_extract_epi32(w, 3) != 8) return 2;
    // memcpy in and out of a split slot.
    __m256i q;
    int src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, dst[8];
    memcpy(&q, src, sizeof q);
    q = _mm256_add_epi32(q, _mm256_set1_epi32(10));
    memcpy(dst, &q, sizeof dst);
    if (dst[0] != 11 || dst[7] != 18) return 3;
    // Copies through a struct (not split: the struct is 64 bytes with a tag).
    Boxed b = { s, 5 }, c = b;
    c.v = _mm256_sub_ps(c.v, b.v);
    _mm256_storeu_ps(out, c.v);
    if (out[3] != 0.0f || c.tag != 5) return 4;
    // Swaps through temporaries.
    __m128 x = _mm_set1_ps(1), y = _mm_set1_ps(2), tmp;
    for (int i = 0; i < 5; i++) { tmp = x; x = y; y = tmp; }
    if (_mm_cvtss_f32(x) != 2.0f || _mm_cvtss_f32(y) != 1.0f) return 5;
    return 42;
}
