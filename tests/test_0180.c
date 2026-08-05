/* Conversion to _Bool is `x != 0`, not a bit-truncation. A wide value whose low
 * byte is zero (e.g. 0x100) must become true. sic truncated to the bool's
 * storage width on the RETURN path, so `bool cpu_is_bsp() { return apic_base &
 * (1<<8); }` returned 0x100 -> read as false -> QEMU marked the x86 boot CPU
 * halted (cs->halted = !cpu_is_bsp(cpu)) and the vCPU never executed. */
#include <stdint.h>

static uint64_t apic_base = 0xfee00900;

__attribute__((noinline)) static _Bool is_bsp(void)
{
    return apic_base & 0x100;      /* 0x100, low byte 0 — must be true */
}

__attribute__((noinline)) static _Bool low_zero(void)
{
    return 0x300;                  /* also true */
}

int main(void)
{
    if (!is_bsp()) return 1;               /* return-path bool normalize */
    if (is_bsp() != 1) return 2;
    if ((int)!is_bsp() != 0) return 3;     /* the exact `!cpu_is_bsp()` use */
    if (!low_zero()) return 4;

    /* also exercise assignment / init / struct-field bool coercion */
    uint64_t x = 0x200;
    _Bool a = x;                    /* true */
    _Bool b = (x & 0xff);           /* 0 -> false */
    struct S { _Bool f; } s = { .f = 0x500 };
    if (a != 1 || b != 0 || s.f != 1) return 5;

    return 0;
}
