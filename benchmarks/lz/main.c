/* LZ77 greedy compressor (sliding window) — a memory-bound pattern-match benchmark.
   Generates 4 MiB of synthetic data, compresses with a 512-byte sliding window,
   64-byte max match length, FNV-1a hash. Prints checksum so all versions agree. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void bench_lz(void) {
    const size_t N = 4000000;
    const size_t WIN = 512;
    const size_t MAXLEN = 64;
    uint8_t *buf = malloc(N);
    uint32_t x = 77771;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)((x / 65536u) % 8u);
    }
    uint32_t h = 2166136261u;
    size_t p = 0;
    while (p < N) {
        size_t lo = p > WIN ? p - WIN : 0;
        size_t bestlen = 0, bestoff = 0;
        for (size_t sidx = lo; sidx < p; sidx++) {
            size_t len = 0;
            while (p + len < N && len < MAXLEN && buf[sidx + len] == buf[p + len]) len++;
            if (len > bestlen) { bestlen = len; bestoff = p - sidx; }
        }
        if (bestlen >= 3) {
            h ^= (uint8_t)(bestoff & 0xFFu); h *= 16777619u;
            h ^= (uint8_t)((bestoff / 256u) & 0xFFu); h *= 16777619u;
            h ^= (uint8_t)(bestlen & 0xFFu); h *= 16777619u;
            p += bestlen;
        } else {
            h ^= buf[p]; h *= 16777619u;
            p += 1;
        }
    }
    printf("checksum %u\n", h);
    free(buf);
}

int main(void) {
    bench_lz();
    return 0;
}