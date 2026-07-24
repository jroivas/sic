/*
 * A typedef name shadowed by a local variable — legal C, very common in QEMU
 * (`typedef uint64_t vaddr;` then locals/params named `vaddr`). Because sic's
 * lexer pre-classifies `vaddr` as a type, the parser must recognize from context
 * (an assignment/member operator, a binary operator inside parens) that it's a
 * value here. This is a C-mode behavior; the sic-lang keeps such names reserved
 * (see test_132.sic).
 */
#include <stdio.h>

typedef unsigned long vaddr;
typedef unsigned long entry_t;

/* parameter named exactly the same as the typedef */
static unsigned long masklow(vaddr vaddr)
{
    vaddr &= 0xFFFFF000UL;     /* statement: TypeName shadow + compound assign */
    vaddr |= 0xABC;
    vaddr += 0x10;
    return vaddr;
}

static unsigned long combine(vaddr a, unsigned long mask)
{
    entry_t entry = 0xF0;                 /* local shadows typedef entry_t */
    return (entry & mask) | (a & ~mask);  /* (entry & ...) is AND, not a cast */
}

int main(void)
{
    setvbuf(stdout, 0, 2 /*_IONBF*/, 0);
    int ok = 1;

    if (masklow(0x12345678) != (((0x12345000UL) | 0xABC) + 0x10)) ok = 0;
    if (combine(0x0F, 0xF0) != ((0xF0UL & 0xF0) | (0x0F & ~0xF0UL))) ok = 0;

    printf("typedef-shadow: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
