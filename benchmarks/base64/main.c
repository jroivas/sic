/* Base64 encoding benchmark — 24M bytes, 4 rounds.
   Uses malloc'd buffer and static B64 table. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(void) {
    const size_t N = 24000000;
    const int R = 4;
    uint8_t *buf = malloc(N);
    uint32_t x = 44444;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(x & 0xFFu);
    }
    uint32_t h = 2166136261u;
    for (int r = 0; r < R; r++) {
        for (size_t i = 0; i + 2 < N; i += 3) {
            uint32_t b0 = buf[i];
            uint32_t b1 = buf[i + 1];
            uint32_t b2 = buf[i + 2];
            uint32_t i0 = b0 / 4;
            uint32_t i1 = (b0 & 3) * 16 + b1 / 16;
            uint32_t i2 = (b1 & 15) * 4 + b2 / 64;
            uint32_t i3 = b2 & 63;
            h ^= (uint8_t)B64[i0];
            h *= 16777619u;
            h ^= (uint8_t)B64[i1];
            h *= 16777619u;
            h ^= (uint8_t)B64[i2];
            h *= 16777619u;
            h ^= (uint8_t)B64[i3];
            h *= 16777619u;
        }
    }
    printf("checksum %u\n", h);
    free(buf);
    return 0;
}