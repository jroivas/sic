// Regression: a `_Generic(...)` selection is a primary expression and may be
// followed by postfix operators — in particular a call. QEMU's byte-swap macro
// expands to `(*(p) = _Generic(*(p), uint16_t: __builtin_bswap16, ...)(*(p)))`.
// The `_Generic` parser returned without applying postfix ops, so the trailing
// `(...)` call failed to parse ("expected RParen but got LParen") when
// parenthesized. And a builtin selected by `_Generic` and then called wasn't
// recognized (it was only handled in direct-call position).

#include <stdint.h>

#define bswap_(p) _Generic(*(p), \
    uint16_t: __builtin_bswap16, uint32_t: __builtin_bswap32, uint64_t: __builtin_bswap64)
#define bswaps(p) (*(p) = bswap_(p)(*(p)))

int main(void)
{
    uint16_t a = 0x1234;
    bswaps(&a);
    if (a != 0x3412) return 1;

    uint32_t b = 0x11223344;
    bswaps(&b);
    if (b != 0x44332211) return 2;

    uint64_t c = 0x0102030405060708ULL;
    bswaps(&c);
    if (c != 0x0807060504030201ULL) return 3;

    // _Generic call in other syntactic positions.
    uint16_t d = 0xABCD;
    uint16_t e = _Generic(d, uint16_t: __builtin_bswap16, default: __builtin_bswap32)(d);
    if (e != 0xCDAB) return 4;

    return 0;
}
