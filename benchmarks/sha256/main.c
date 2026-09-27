// Full SHA-256 compression (4M buffer, 16 rounds), 32-bit crypto mixing.
// Uses rotr32 helper, SHA_K constants, and u32 w[64] message schedule.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static const uint32_t SHA_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

int main(void) {
    const size_t N = 4000000;
    const int R = 16;
    uint8_t *buf = malloc(N);
    uint32_t x = 44441;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)((x / 256u) & 0xFFu);
    }
    uint32_t cs = 0;
    for (int r = 0; r < R; r++) {
        uint32_t h0 = 0x6a09e667u, h1 = 0xbb67ae85u, h2 = 0x3c6ef372u, h3 = 0xa54ff53au;
        uint32_t h4 = 0x510e527fu, h5 = 0x9b05688cu, h6 = 0x1f83d9abu, h7 = 0x5be0cd19u;
        size_t nblocks = N / 64;
        uint32_t w[64];
        for (size_t blk = 0; blk < nblocks; blk++) {
            size_t base = blk * 64;
            for (int t = 0; t < 16; t++) {
                size_t o = base + (size_t)t * 4;
                w[t] = ((uint32_t)buf[o] << 24) | ((uint32_t)buf[o + 1] << 16) | ((uint32_t)buf[o + 2] << 8) | (uint32_t)buf[o + 3];
            }
            for (int t = 16; t < 64; t++) {
                uint32_t s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >> 3);
                uint32_t s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >> 10);
                w[t] = w[t - 16] + s0 + w[t - 7] + s1;
            }
            uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
            for (int t = 0; t < 64; t++) {
                uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t t1 = hh + S1 + ch + SHA_K[t] + w[t];
                uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t t2 = S0 + maj;
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += hh;
        }
        cs = cs * 1000003u + (h0 ^ h1 ^ h2 ^ h3 ^ h4 ^ h5 ^ h6 ^ h7);
    }
    printf("checksum %u\n", cs);
    free(buf);
    return 0;
}