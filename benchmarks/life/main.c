// Conway's Game of Life — standalone extracted C benchmark
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void bench_life(void) {
    const int W = 1024, H = 1024, T = 300;
    uint8_t *cur = malloc((size_t)W * H), *nxt = malloc((size_t)W * H);
    uint32_t x = 22221;
    for (int i = 0; i < W * H; i++) {
        x = x * 1664525u + 1013904223u;
        cur[i] = (uint8_t)((x / 65536u) & 1u);
    }
    for (int gen = 0; gen < T; gen++) {
        for (int y = 0; y < H; y++) {
            int ym = y == 0 ? H - 1 : y - 1;
            int yp = y == H - 1 ? 0 : y + 1;
            for (int xx = 0; xx < W; xx++) {
                int xm = xx == 0 ? W - 1 : xx - 1;
                int xp = xx == W - 1 ? 0 : xx + 1;
                int n = cur[ym * W + xm] + cur[ym * W + xx] + cur[ym * W + xp]
                      + cur[y * W + xm] + cur[y * W + xp]
                      + cur[yp * W + xm] + cur[yp * W + xx] + cur[yp * W + xp];
                uint8_t alive = cur[y * W + xx];
                nxt[y * W + xx] = (n == 3 || (alive && n == 2)) ? 1 : 0;
            }
        }
        uint8_t *tmp = cur; cur = nxt; nxt = tmp;
    }
    uint32_t cs = 0;
    for (int i = 0; i < W * H; i++) cs = cs * 1000003u + cur[i];
    printf("checksum %u\n", cs);
    free(cur); free(nxt);
}

int main(void) {
    bench_life();
    return 0;
}