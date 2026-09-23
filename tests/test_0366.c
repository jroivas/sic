// Regression: C integer promotions also apply to the unary `-` and `~`
// operators. sic computed them in the operand's narrow width, so
// `~(unsigned char)0` gave 0xFF instead of the promoted `int` value -1, and
// `-(unsigned char)1` gave 255 instead of -1. Returns 42.
#include <stdio.h>

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);

    // ~ promotes to int.
    unsigned char uc = 0;
    if (~uc != -1) return 1;
    if (~(unsigned char)0x0F != -16) return 2;
    unsigned short us = 0;
    if (~us != -1) return 3;
    if (~(unsigned short)0xFFFF != -65536) return 4;

    // Unary - promotes to int (no narrow wrap).
    unsigned char u1 = 1;
    if (-u1 != -1) return 5;
    signed char smin = -128;
    if (-smin != 128) return 6;               // 8-bit negate would wrap to -128
    unsigned short u5 = 5;
    if (-u5 != -5) return 7;

    // Result feeding a wider computation stays correct.
    unsigned char b = 0x0F;
    unsigned mask = ~b;                        // int -16 -> unsigned 0xFFFFFFF0
    if (mask != 0xFFFFFFF0u) return 8;

    // A promoted result assigned back to a narrow lvalue still truncates.
    unsigned char t = ~(unsigned char)0;       // int -1 -> uchar 0xFF
    if (t != 0xFF) return 9;

    // Sanity: wide types are unaffected (runtime operands, not folded literals).
    volatile int z = 0;
    volatile unsigned zu = 0;
    if (~z != -1 || ~zu != 0xFFFFFFFFu) return 10;
    volatile long long five = 5;
    if (-five != -5LL) return 11;

    return 42;
}
