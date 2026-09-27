/* Pointer-chasing (random memory latency) — a random permutation traversal
   benchmark. Creates a 16M-element random permutation via Fisher-Yates shuffle,
   then chases through it for 4M hops. Prints checksum so all language versions
   can be compared. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void bench_ptrchase(void) {
    const size_t N = 16000000;
    const uint64_t HOPS = 4000000;
    uint32_t *order = malloc(N * sizeof(uint32_t));
    uint32_t *next = malloc(N * sizeof(uint32_t));
    for (size_t i = 0; i < N; i++) order[i] = (uint32_t)i;
    uint32_t x = 1;
    for (size_t i = N - 1; i >= 1; i--) {
        x = x * 1664525u + 1013904223u;
        size_t j = (x & 0x7FFFFFFFu) % (i + 1);
        uint32_t t = order[i];
        order[i] = order[j];
        order[j] = t;
    }
    for (size_t k = 0; k < N; k++) next[order[k]] = order[(k + 1) % N];
    uint32_t sum = 0, p = 0;
    for (uint64_t h = 0; h < HOPS; h++) {
        p = next[p];
        sum += p;
    }
    printf("checksum %u\n", sum);
    free(order);
    free(next);
}

int main(void) {
    bench_ptrchase();
    return 0;
}