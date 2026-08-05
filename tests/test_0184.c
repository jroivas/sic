/* sizeof/_Alignof yield size_t (unsigned, pointer-width). sic materialized them
 * as a bare integer constant, which defaults to 32-bit when the value fits, so
 * `sizeof(long) * n` (size_t * unsigned) computed at 32 bits. QEMU's ROUND_UP
 * masks a 64-bit pointer with `-(sizeof(tcg_target_ulong) * p->nlong)`; a 32-bit
 * mask truncated the high 32 bits of the TB code-buffer address, so codegen
 * wrote to a bad address and faulted while translating the first guest TB. */
#include <stddef.h>
#include <stdint.h>

#define ROUND_DOWN(n, d) ((n) & -(0 ? (n) : (d)))
#define ROUND_UP(n, d)   ROUND_DOWN((n) + (d) - 1, (d))

int main(void)
{
    unsigned nlong = 1;

    /* size_t * unsigned must be computed at 64-bit width */
    unsigned long neg = -(sizeof(unsigned long) * nlong);
    if (neg != 0xFFFFFFFFFFFFFFF8UL) return 2;

    /* the exact ROUND_UP pattern on a high pointer */
    uintptr_t p = 0x7fffac000141UL;
    uintptr_t a = ROUND_UP(p, sizeof(unsigned long) * nlong);
    if (a != 0x7fffac000148UL) return 3;    /* was 0xac000148 (truncated) */

    /* _Alignof also size_t-typed */
    if (-(_Alignof(long) * nlong) != 0xFFFFFFFFFFFFFFF8UL) return 4;

    return 0;
}
