/* Indirect dispatch benchmark — 4M ops, 32 rounds.
   Uses malloc'd code/operand buffers and function pointer table. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static uint32_t op_add(uint32_t a, uint32_t b) { return a + b; }
static uint32_t op_xor(uint32_t a, uint32_t b) { return a ^ b; }
static uint32_t op_mul(uint32_t a, uint32_t b) { return a * (b | 1u); }
static uint32_t op_sub(uint32_t a, uint32_t b) { return a - b; }

int main(void) {
    const size_t N = 4000000;
    const int R = 32;
    uint8_t *code = malloc(N);
    uint32_t *operand = malloc(N * sizeof(uint32_t));
    uint32_t x = 55555;
    for (size_t i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        code[i] = (uint8_t)((x & 0x7FFFFFFFu) % 4u);
        operand[i] = x;
    }
    uint32_t (*fns[4])(uint32_t, uint32_t) = {op_add, op_xor, op_mul, op_sub};
    uint32_t acc = 2166136261u;
    for (int r = 0; r < R; r++) {
        for (size_t i = 0; i < N; i++) {
            acc = fns[code[i]](acc, operand[i]);
        }
    }
    printf("checksum %u\n", acc);
    free(code);
    free(operand);
    return 0;
}