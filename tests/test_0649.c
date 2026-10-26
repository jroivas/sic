// A unit with inline-asm helpers is assembled with the C driver ($SIC_CC or
// cc), never $LD: Linux's Kbuild exports LD=ld, which read the assembler
// source as a linker script ("unrecognised keyword in MRI style script").
// test_0649.c.env sets LD=ld. The helper also names a static symbol.
static long counter = 40;

int main(void) {
    long v;
    asm("movq %a1, %0" : "=r"(v) : "i"(&counter));
    return (int)v + 2;
}
