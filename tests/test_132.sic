/*
 * Language-mode detection: in C source, sic's Rust-style primitive aliases
 * (`isize`, `usize`, `i32`, `u64`, ...) are ordinary identifiers, so C code may
 * use them as variable names. QEMU util/cacheflush.c does exactly this:
 *   int isize = 0, dsize = 0;
 *   assert((isize & (isize - 1)) == 0);
 *
 * The identical source as `.sic` (test_132.sic) must FAIL, because in sic-lang
 * those names are reserved type keywords.
 */
#include <stdio.h>

static int pow2ish(int isize)
{
    /* `isize` used as a value inside a parenthesized expression: this is the
       construct that used to be mis-parsed as a cast in C. */
    return (isize & (isize - 1)) == 0;
}

int main(void)
{
    setvbuf(stdout, 0, 2 /*_IONBF*/, 0);
    int isize = 16, usize = 7;
    long i64 = 100, u32 = 3;

    int ok = 1;
    if (!pow2ish(isize)) ok = 0;      /* 16 is a power of two */
    if (pow2ish(usize)) ok = 0;       /* 7 is not */
    if ((i64 + u32) != 103) ok = 0;   /* aliases as ordinary locals */

    printf("lang-c-aliases: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
