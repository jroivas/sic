/* Read-write SSE/AVX operands ("+x") on vector_size values: QEMU's
 * SSE_REASSOC_BARRIER in util/bufferiszero.c. With LLVM sic passed a vector's
 * value where its address was expected ("cannot convert <2 x i64> to ptr"),
 * ignored __attribute__((target("avx2"))), and gave a 256-bit operand a byte
 * array type ("couldn't allocate output register for constraint 'x'").
 * Returns 42. */
typedef long long v2 __attribute__((vector_size(16)));
typedef long long v4 __attribute__((vector_size(32)));

#define BARRIER(a, b) __asm__("" : "+x"(a), "+x"(b))

__attribute__((noinline)) static int zero_sse2(const v2 *p, int n) {
    v2 v = p[0], w = p[1];
    for (int i = 2; i + 1 < n; i += 2) {
        BARRIER(v, w);
        v |= p[i]; w |= p[i + 1];
    }
    v |= w;
    return v[0] == 0 && v[1] == 0;
}

__attribute__((noinline, target("avx2"))) static int zero_avx2(const v4 *p, int n) {
    v4 v = p[0], w = p[1];
    for (int i = 2; i + 1 < n; i += 2) {
        BARRIER(v, w);
        v |= p[i]; w |= p[i + 1];
    }
    v |= w;
    return v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0;
}

int main(void) {
    v2 b2[8] = { 0 };
    if (!zero_sse2(b2, 8)) return 1;
    b2[5][1] = 1;
    if (zero_sse2(b2, 8)) return 2;
    if (__builtin_cpu_supports("avx2")) {
        v4 b4[8] = { 0 };
        if (!zero_avx2(b4, 8)) return 3;
        b4[6][3] = 1;
        if (zero_avx2(b4, 8)) return 4;
    }
    return 42;
}
