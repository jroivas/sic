// Real SIMD lowering for GCC `vector_size` types: element-wise operators on
// 128-bit vectors (one XMM) lower to a single hardware packed instruction
// (vpaddd/vpmulld/vpmullw/vpxor/vaddps/vmulps/vdivps…) instead of a lane-by-lane
// scalar loop, while unsupported shapes/ops fall back to emulation. Also pins the
// two ways a vector value reaches memory — a store through a pointer
// (`*(v*)p = a op b`) and a local initializer (`v s = a op b;`) — both of which
// must copy the whole vector, not just a pointer to it. Returns 0 on success.
#include <stdio.h>

typedef int          v4i __attribute__((vector_size(16)));
typedef unsigned int v4u __attribute__((vector_size(16)));
typedef short        v8s __attribute__((vector_size(16)));
typedef long long    v2l __attribute__((vector_size(16)));
typedef float        v4f __attribute__((vector_size(16)));
typedef double       v2d __attribute__((vector_size(16)));
typedef int          v8i __attribute__((vector_size(32)));   // 256-bit → emulated

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    int ok = 1;

    // --- i32x4: add/sub/mul/and/or/xor, stored through a pointer ---
    int a[4] = {1, 2, 3, 4}, b[4] = {10, 20, 30, 40}, out[4];
    *(v4i *)out = *(v4i *)a + *(v4i *)b;
    for (int i = 0; i < 4; i++) if (out[i] != a[i] + b[i]) ok = 0;
    *(v4i *)out = *(v4i *)b - *(v4i *)a;
    for (int i = 0; i < 4; i++) if (out[i] != b[i] - a[i]) ok = 0;
    *(v4i *)out = *(v4i *)a * *(v4i *)b;
    for (int i = 0; i < 4; i++) if (out[i] != a[i] * b[i]) ok = 0;
    *(v4i *)out = *(v4i *)a ^ *(v4i *)b;
    for (int i = 0; i < 4; i++) if (out[i] != (a[i] ^ b[i])) ok = 0;
    *(v4i *)out = *(v4i *)a & *(v4i *)b;
    for (int i = 0; i < 4; i++) if (out[i] != (a[i] & b[i])) ok = 0;
    *(v4i *)out = *(v4i *)a | *(v4i *)b;
    for (int i = 0; i < 4; i++) if (out[i] != (a[i] | b[i])) ok = 0;
    if (!ok) { printf("i32x4 fail\n"); return 1; }

    // --- vector local initializer must copy the whole vector, then subscript ---
    v4i s = *(v4i *)a + *(v4i *)b;
    for (int i = 0; i < 4; i++) if (s[i] != a[i] + b[i]) ok = 0;
    if (!ok) { printf("v4i local-init fail\n"); return 2; }

    // --- unsigned i32x4 (lane signedness must not change add/mul bits) ---
    unsigned ua[4] = {0xFFFFFFFFu, 2, 3, 0x80000000u}, ub[4] = {1, 2, 3, 4}, uo[4];
    *(v4u *)uo = *(v4u *)ua + *(v4u *)ub;
    for (int i = 0; i < 4; i++) if (uo[i] != ua[i] + ub[i]) ok = 0;
    if (!ok) { printf("u32x4 fail\n"); return 3; }

    // --- i16x8 multiply (packed word multiply keeps the low 16 bits) ---
    short pa[8] = {1, 2, 3, 4, 5, 6, 7, 8}, pb[8] = {2, 3, 4, 5, 6, 7, 8, 9}, po[8];
    *(v8s *)po = *(v8s *)pa * *(v8s *)pb;
    for (int i = 0; i < 8; i++) if (po[i] != (short)(pa[i] * pb[i])) ok = 0;
    if (!ok) { printf("i16x8 mul fail\n"); return 4; }

    // --- i64x2 add ---
    long long la[2] = {1000000000000LL, -5}, lb[2] = {2000000000000LL, 8}, lo[2];
    *(v2l *)lo = *(v2l *)la + *(v2l *)lb;
    for (int i = 0; i < 2; i++) if (lo[i] != la[i] + lb[i]) ok = 0;
    if (!ok) { printf("i64x2 fail\n"); return 5; }

    // --- f32x4: add/sub/mul/div ---
    float fa[4] = {1.5f, 2.5f, 3.5f, 4.5f}, fb[4] = {0.5f, 0.5f, 2.0f, 1.5f}, fo[4];
    *(v4f *)fo = *(v4f *)fa + *(v4f *)fb;
    for (int i = 0; i < 4; i++) if (fo[i] != fa[i] + fb[i]) ok = 0;
    *(v4f *)fo = *(v4f *)fa * *(v4f *)fb;
    for (int i = 0; i < 4; i++) if (fo[i] != fa[i] * fb[i]) ok = 0;
    *(v4f *)fo = *(v4f *)fa / *(v4f *)fb;
    for (int i = 0; i < 4; i++) if (fo[i] != fa[i] / fb[i]) ok = 0;
    if (!ok) { printf("f32x4 fail\n"); return 6; }

    // --- f64x2: add/mul ---
    double da[2] = {1.25, 2.5}, db[2] = {4.0, 0.5}, dob[2];
    *(v2d *)dob = *(v2d *)da * *(v2d *)db;
    for (int i = 0; i < 2; i++) if (dob[i] != da[i] * db[i]) ok = 0;
    if (!ok) { printf("f64x2 fail\n"); return 7; }

    // --- 256-bit vector (not one XMM) still works via scalar emulation ---
    int wa[8] = {1, 2, 3, 4, 5, 6, 7, 8}, wb[8] = {8, 7, 6, 5, 4, 3, 2, 1}, woo[8];
    *(v8i *)woo = *(v8i *)wa + *(v8i *)wb;
    for (int i = 0; i < 8; i++) if (woo[i] != 9) ok = 0;
    if (!ok) { printf("v8i emulation fail\n"); return 8; }

    printf("simd-vecops: OK\n");
    return 0;
}
