/* -O2 licm must not hoist a read of an array declared INSIDE the loop body
   (QEMU target/riscv/vcrypto_helper.c: `static const uint32_t rcon[]` in a
   loop) — the hoisted read named it before its declaration ("undefined name"). */
#include <stdint.h>
static uint32_t f(uint32_t uimm, int n) {
    uint32_t r = 0;
    for (int i = 0; i < n; i++) {
        static const uint32_t rcon[] = { 1, 2, 4, 8 };
        r ^= rcon[uimm - 1];
        uint32_t loc[2] = { (uint32_t)i, 40 };
        r += loc[1];
    }
    return r;
}
int main(void) { return f(3, 1) == 44 && f(2, 2) == 80 ? 42 : 1; }
