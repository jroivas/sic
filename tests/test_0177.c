/* 128-bit integers (__int128) must be real 128-bit values. sic's backend mapped
 * them to Cranelift I64, so all upper-64-bit behaviour was lost: `x >> 64`
 * became `x >> 0`. QEMU builds Int128 as native __int128; int128_gethi(size) =
 * (int64_t)(size >> 64) then wrongly returned the low bits, so section_covers_addr
 * treated every RAM section as covering the whole address space and an MSI write
 * to the LAPIC (0xFEE00000) was mis-routed to RAM, asserting at machine reset. */
#include <stdint.h>

static uint64_t hi(__int128 a) { return (uint64_t)(a >> 64); }
static uint64_t lo(__int128 a) { return (uint64_t)a; }

int main(void)
{
    if (sizeof(__int128) != 16) return 1;

    /* the exact section_covers_addr pattern: a "small" size has hi == 0 */
    __int128 size = (__int128)0x8000000;          /* 128 MiB */
    if (hi(size) != 0) return 2;                   /* was 0x8000000 (the low bits) */
    if (lo(size) != 0x8000000ULL) return 3;

    /* cross-boundary shifts */
    __int128 v = ((__int128)1) << 100;
    if (hi(v) != 0x1000000000ULL || lo(v) != 0) return 4;

    /* arithmetic that overflows 64 bits */
    __int128 m = (__int128)0x123456789AULL * (__int128)0x100000000ULL;
    if (hi(m) != 0x12ULL || lo(m) != 0x3456789a00000000ULL) return 5;

    /* division (routed through a libcall) */
    __int128 d = (__int128)1000000000000000LL * 1000;
    if ((uint64_t)(d / 7) != 142857142857142857ULL) return 6;

    /* signed comparison across the boundary */
    __int128 neg = -((__int128)1 << 70);
    if (!(neg < 0) || neg > 0) return 7;

    return 0;
}
