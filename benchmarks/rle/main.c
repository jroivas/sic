/* Run-length encoding benchmark — 40M byte buffer, 4 rounds.
   Uses malloc'd buffers, FNV hash per round. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    const size_t N = 40000000;
    const int R = 4;
    uint8_t *buf = malloc(N);
    uint8_t *out = malloc(2 * N);
    uint32_t x = 33333;
    size_t i = 0;
    while (i < N) {
        x = x * 1664525u + 1013904223u;
        uint8_t v = (uint8_t)(x & 0xFFu);
        uint32_t rl = ((x & 0x7FFFFFFFu) % 16u) + 1u;
        for (uint32_t c = 0; c < rl && i < N; c++) buf[i++] = v;
    }
    uint32_t h = 2166136261u;
    for (int r = 0; r < R; r++) {
        size_t o = 0;
        size_t p = 0;
        while (p < N) {
            uint8_t v = buf[p];
            size_t run = 1;
            while (p + run < N && buf[p + run] == v && run < 255) run++;
            out[o++] = (uint8_t)run;
            out[o++] = v;
            p += run;
        }
        for (size_t k = 0; k < o; k++) {
            h ^= out[k];
            h *= 16777619u;
        }
        h ^= (uint8_t)(o % 256);
        h *= 16777619u;
        h ^= (uint8_t)((o / 256) % 256);
        h *= 16777619u;
        h ^= (uint8_t)((o / 65536) % 256);
        h *= 16777619u;
        h ^= (uint8_t)((o / 16777216) % 256);
        h *= 16777619u;
    }
    printf("checksum %u\n", h);
    free(buf);
    free(out);
    return 0;
}