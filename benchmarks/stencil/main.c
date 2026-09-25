/* 1-D 3-point blur (weighted [1 2 1]/4) over a large array, iterated many passes
   — a stencil with three *different* offsets into the same array (a[i-1], a[i],
   a[i+1]). LLVM auto-vectorizes it with shifted packed loads + vaddpd/vmulpd; a
   scalar back end pays 3 loads + 2 adds + 1 mul per element. The per-element blur
   is order-independent, and the checksum sums the TRUNCATED values as integers, so
   it is bit-stable across vectorized and scalar builds. Prints that checksum. */
#include <stdio.h>

#define N 100000
#define P 3000

static double a[N], b[N];

int main(void) {
    for (int i = 0; i < N; i++) a[i] = i % 251;
    for (int p = 0; p < P; p++) {
        for (int i = 1; i < N - 1; i++) b[i] = (a[i - 1] + 2.0 * a[i] + a[i + 1]) * 0.25;
        for (int i = 1; i < N - 1; i++) a[i] = b[i];
    }
    long sum = 0;
    for (int i = 0; i < N; i++) sum += (long)a[i];
    printf("%ld\n", sum);
    return 0;
}
