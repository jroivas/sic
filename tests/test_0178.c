/* __builtin_mul_overflow on a 128-bit operand emits a division (result/a) to
 * check the product — which on i128 must route through the __udivti3/__divti3
 * libcall like any other i128 divide (cranelift's x64 backend can't lower
 * udiv.i128). QEMU's util/host-utils.c mulu128() and libdecnumber use this. */
#include <stdint.h>

int main(void)
{
    __uint128_t res;

    /* (1<<70) * 4 = 1<<72, no overflow */
    if (__builtin_mul_overflow(((__uint128_t)1 << 70), (__uint128_t)4, &res)) return 1;
    if (res != ((__uint128_t)1 << 72)) return 2;

    /* (1<<120) * 1000 overflows 128 bits */
    if (!__builtin_mul_overflow(((__uint128_t)1 << 120), (__uint128_t)1000, &res)) return 3;

    /* signed variant */
    __int128 sres;
    if (__builtin_mul_overflow((__int128)1000000, (__int128)-2000000, &sres)) return 4;
    if (sres != (__int128)-2000000000000LL) return 5;

    return 0;
}
