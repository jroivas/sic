// STREAM triad — standalone extracted C benchmark
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void bench_stream(void) {
    const size_t N = 16000000;
    const int R = 40;
    const uint32_t K = 3u;
    uint32_t *a = malloc(N * sizeof(uint32_t)), *b = malloc(N * sizeof(uint32_t)), *c = malloc(N * sizeof(uint32_t));
    uint32_t x = 11111;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u; b[i] = x;
        x = x * 1664525u + 1013904223u; c[i] = x;
        a[i] = 0;
    }
    for (int r = 0; r < R; r++)
        for (size_t i = 0; i < N; i++) a[i] = b[i] + K * c[i];
    uint32_t cs = 0;
    for (size_t i = 0; i < N; i++) cs = cs * 1000003u + a[i];
    printf("checksum %u\n", cs);
    free(a); free(b); free(c);
}

int main(void) {
    bench_stream();
    return 0;
}