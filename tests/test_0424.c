/* GNU inline asm: sic used to SKIP every asm statement, so QEMU's host tick
 * counter `asm volatile("rdtsc" : "=a"(lo), "=d"(hi))` "returned" 0, the
 * emulated TSC never advanced and a guest divided by its zero CPU speed. The
 * recognised x86-64 templates (QEMU's rdtsc / cpuid / xgetbv / divq / shld /
 * shrd / vmovdqa, barriers) must compute what the CPU does. Returns 42. */
#include <stdint.h>
#include <cpuid.h>
static inline int64_t ticks(void) {
    uint32_t low, high; int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high; val <<= 32; val |= low; return val;
}
static inline uint64_t udiv_qrnnd(uint64_t *r, uint64_t n1, uint64_t n0, uint64_t d) {
    uint64_t q;
    asm("divq %4" : "=a"(q), "=d"(*r) : "0"(n0), "1"(n1), "rm"(d));
    return q;
}
static inline uint64_t shl_double(uint64_t l, uint64_t r, int c) {
    asm("shld %b2, %1, %0" : "+r"(l) : "r"(r), "ci"(c)); return l;
}
static inline uint64_t shr_double(uint64_t l, uint64_t r, int c) {
    asm("shrd %b2, %1, %0" : "+r"(r) : "r"(l), "ci"(c)); return r;
}
typedef long long v2di __attribute__((vector_size(16)));
typedef union { v2di v; __int128 s; uint64_t q[2]; } U;
int main(void) {
    int64_t a = ticks();
    for (volatile int i = 0; i < 1000; i++) asm volatile("rep; nop" ::: "memory");
    int64_t b = ticks();
    if (!(a > 0 && b > a)) return 1;
    uint64_t r, q = udiv_qrnnd(&r, 0x1234, 0x56789abcdef01234ull, 0x9876543210ull);
    unsigned __int128 n = ((unsigned __int128)0x1234 << 64) | 0x56789abcdef01234ull;
    if (q != (uint64_t)(n / 0x9876543210ull) || r != (uint64_t)(n % 0x9876543210ull)) return 2;
    uint64_t L = 0x0123456789abcdefull, R = 0xfedcba9876543210ull;
    for (int c = 0; c < 64; c++) {
        if (shl_double(L, R, c) != (c ? (L << c) | (R >> (64 - c)) : L)) return 3;
        if (shr_double(L, R, c) != (c ? (R >> c) | (L << (64 - c)) : R)) return 4;
    }
    unsigned ea, eb, ec, ed, ea2;
    __cpuid(0, ea, eb, ec, ed);
    if (ea == 0 || eb == 0) return 5;               /* max leaf, vendor string */
    uint32_t vec[4];
    asm volatile("cpuid" : "=a"(vec[0]), "=b"(vec[1]), "=c"(vec[2]), "=d"(vec[3]) : "0"(0), "c"(0) : "cc");
    if (vec[0] != ea || vec[1] != eb || vec[2] != ec || vec[3] != ed) return 6;
    __cpuid(1, ea2, eb, ec, ed);
    if ((ec & (1u << 27)) && (ec & (1u << 28))) {   /* OSXSAVE + AVX */
        unsigned xa, xd; asm("xgetbv" : "=a"(xa), "=d"(xd) : "c"(0));
        if ((xa & 6) == 6) {                        /* the OS saves SSE+AVX state */
            __int128 src __attribute__((aligned(16))) = ((__int128)0x1122334455667788ll << 64) | 0x99aabbccddeeff00ull;
            __int128 dst __attribute__((aligned(16))) = 0;
            U u; asm("vmovdqa %1, %0" : "=x" (u.v) : "m" (src));
            if (u.s != src) return 7;
            u.q[0] ^= 1; asm("vmovdqa %1, %0" : "=m"(dst) : "x" (u.v));
            if (dst != (src ^ 1)) return 8;
            U w; asm("vmovdqu %1, %0" : "=x" (w.v) : "m" (dst));
            if (w.s != dst) return 9;
        }
    }
    int x = 41, y; asm("" : "=r"(y) : "0"(x + 1));
    void *p = &x; asm volatile("" : "+rm"(p));
    asm volatile("" ::: "memory"); asm volatile("");
    if (y != 42 || p != (void *)&x) return 10;
    return 42;
}
