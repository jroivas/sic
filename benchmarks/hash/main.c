/* FNV-1a hash — a pure arithmetic / memory-read benchmark. Fills 32M bytes with
   LCG values, then runs 4 rounds of FNV-1a hashing. Prints checksum so all
   language versions can be compared. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void bench_hash(void) {
    const size_t N = 32000000;
    const int R = 4;
    uint8_t *buf = malloc(N);
    uint32_t x = 12345;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(x & 0xFFu);
    }
    uint32_t h = 2166136261u;
    for (int r = 0; r < R; r++) {
        for (size_t i = 0; i < N; i++) {
            h ^= buf[i];
            h *= 16777619u;
        }
    }
    printf("checksum %u\n", h);
    free(buf);
}

int main(void) {
    bench_hash();
    return 0;
}