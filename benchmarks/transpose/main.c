// Naive out-of-place matrix transpose (4096x4096, 6 rounds). Two heap u32 arrays,
// pointer swap after each round. Prints checksum.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    const size_t Ndim = 4096;
    const int R = 6;
    uint32_t *src = malloc(Ndim * Ndim * sizeof(uint32_t));
    uint32_t *dst = malloc(Ndim * Ndim * sizeof(uint32_t));
    uint32_t x = 55551;
    for (size_t i = 0; i < Ndim * Ndim; i++) {
        x = x * 1664525u + 1013904223u; src[i] = x;
    }
    for (int r = 0; r < R; r++) {
        for (size_t i = 0; i < Ndim; i++)
            for (size_t j = 0; j < Ndim; j++)
                dst[j * Ndim + i] = src[i * Ndim + j];
        uint32_t *tmp = src; src = dst; dst = tmp;
    }
    uint32_t cs = 0;
    for (size_t i = 0; i < Ndim * Ndim; i++) cs = cs * 1000003u + src[i];
    printf("checksum %u\n", cs);
    free(src); free(dst);
    return 0;
}