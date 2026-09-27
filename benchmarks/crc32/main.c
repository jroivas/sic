/* CRC32 table-driven hashing — compute-bound / table-lookup benchmark.
   Generates 16 MiB of synthetic data, processes 8 rounds with CRC32 table
   (polynomial 0xEDB88320). Prints checksum so all versions agree. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void bench_crc32(void) {
    const size_t N = 16000000;
    const int R = 8;
    uint32_t table[256];
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        table[i] = c;
    }
    uint8_t *buf = malloc(N);
    uint32_t x = 88881;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)((x / 65536u) & 0xFFu);
    }
    uint32_t cs = 0;
    for (int r = 0; r < R; r++) {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < N; i++)
            crc = table[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
        crc ^= 0xFFFFFFFFu;
        cs = cs * 1000003u + crc;
    }
    printf("checksum %u\n", cs);
    free(buf);
}

int main(void) {
    bench_crc32();
    return 0;
}