// Open-addressing hash map (linear probing), 8M insert + 16M lookup, 2^24 table.
// Fixed-width u32, calls calloc'd zero-initialised arrays.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    const size_t M = 8000000, Q = 16000000;
    const uint32_t SIZE = 1u << 24;
    const uint32_t MASK = SIZE - 1u;
    uint32_t *keys = calloc(SIZE, sizeof(uint32_t));
    uint32_t *vals = calloc(SIZE, sizeof(uint32_t));
    uint32_t x = 33331;
    for (size_t n = 0; n < M; n++) {
        x = x * 1664525u + 1013904223u;
        uint32_t key = (x & 0x7FFFFFFFu) | 1u;
        uint32_t idx = key & MASK;
        for (;;) {
            if (keys[idx] == 0) { keys[idx] = key; vals[idx] = x; break; }
            if (keys[idx] == key) { vals[idx] += x; break; }
            idx = (idx + 1u) & MASK;
        }
    }
    uint32_t y = 99989, acc = 0;
    for (size_t q = 0; q < Q; q++) {
        y = y * 1664525u + 1013904223u;
        uint32_t key = (y & 0x7FFFFFFFu) | 1u;
        uint32_t idx = key & MASK;
        uint32_t steps = 0;
        for (;;) {
            steps += 1;
            if (keys[idx] == 0) break;
            if (keys[idx] == key) { acc += vals[idx]; break; }
            idx = (idx + 1u) & MASK;
        }
        acc = acc * 1000003u + steps;
    }
    printf("checksum %u\n", acc);
    free(keys); free(vals);
    return 0;
}