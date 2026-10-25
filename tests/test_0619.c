// AVX2 gathers and AVX masked loads/stores. Gathers check against plain loops
// (32- and 64-bit indices, scales, masks, pass-through lanes). Masked-off lanes
// must not touch memory: the masked accesses here end at an inaccessible page.
#include <immintrin.h>
#include <sys/mman.h>
#include <unistd.h>

static float tf[64];
static double td[64];
static int ti[64];
static long long tq[64];

int main(void)
{
    for (int i = 0; i < 64; i++) { tf[i] = i * 1.5f; td[i] = i * 2.25; ti[i] = i * 7 - 100; tq[i] = (long long)i << 33; }
    int idx[8] = { 3, 0, 63, 17, 8, 8, 1, 40 };
    long long qidx[4] = { 5, 62, 0, 31 };
    __m256i vi = _mm256_loadu_si256((const __m256i *)idx);
    __m128i vi4 = _mm_loadu_si128((const __m128i *)idx);
    __m256i vq = _mm256_loadu_si256((const __m256i *)qidx);
    __m128i vq2 = _mm_loadu_si128((const __m128i *)qidx);

    float of[8]; _mm256_storeu_ps(of, _mm256_i32gather_ps(tf, vi, 4));
    for (int i = 0; i < 8; i++) if (of[i] != tf[idx[i]]) return 1;
    // Byte scale 1 on byte offsets, with a mask and pass-through.
    int boff[4] = { 0, 4, 8, 252 };
    __m128 src = _mm_set1_ps(-1.0f);
    __m128 mask = _mm_castsi128_ps(_mm_setr_epi32(-1, 0, -1, -1));
    float om[4]; _mm_storeu_ps(om, _mm_mask_i32gather_ps(src, tf, _mm_loadu_si128((const __m128i *)boff), mask, 1));
    if (om[0] != tf[0] || om[1] != -1.0f || om[2] != tf[2] || om[3] != tf[63]) return 2;
    double od[4]; _mm256_storeu_pd(od, _mm256_i32gather_pd(td, vi4, 8));
    for (int i = 0; i < 4; i++) if (od[i] != td[idx[i]]) return 3;
    _mm256_storeu_pd(od, _mm256_i64gather_pd(td, vq, 8));
    for (int i = 0; i < 4; i++) if (od[i] != td[qidx[i]]) return 4;
    // 64-bit indices into a 128-bit float result: two lanes, the rest zero.
    _mm_storeu_ps(om, _mm_i64gather_ps(tf, vq2, 4));
    if (om[0] != tf[5] || om[1] != tf[62] || om[2] != 0 || om[3] != 0) return 5;
    int oi[8]; _mm256_storeu_si256((__m256i *)oi, _mm256_i32gather_epi32(ti, vi, 4));
    for (int i = 0; i < 8; i++) if (oi[i] != ti[idx[i]]) return 6;
    long long oq[4]; _mm256_storeu_si256((__m256i *)oq, _mm256_i64gather_epi64(tq, vq, 8));
    for (int i = 0; i < 4; i++) if (oq[i] != tq[qidx[i]]) return 7;

    // Masked load/store whose masked-off lanes would fall past a page end.
    long pg = sysconf(_SC_PAGESIZE);
    char *m = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 8;
    if (mprotect(m + pg, pg, PROT_NONE)) return 9;
    int *end = (int *)(m + pg) - 2; // two ints before the guard page
    end[0] = 11; end[1] = 22;
    __m256i lo2 = _mm256_setr_epi32(-1, -1, 0, 0, 0, 0, 0, 0);
    int ol[8]; _mm256_storeu_si256((__m256i *)ol, _mm256_maskload_epi32(end, lo2));
    if (ol[0] != 11 || ol[1] != 22 || ol[2] != 0 || ol[7] != 0) return 10;
    _mm256_maskstore_epi32(end, _mm256_setr_epi32(0, -1, 0, 0, 0, 0, 0, 0), _mm256_set1_epi32(99));
    if (end[0] != 11 || end[1] != 99) return 11;
    double *dend = (double *)(m + pg) - 1;
    *dend = 4.5;
    __m128d dl = _mm_maskload_pd(dend, _mm_set_epi64x(0, -1));
    if (_mm_cvtsd_f64(dl) != 4.5) return 12;
    return 42;
}
