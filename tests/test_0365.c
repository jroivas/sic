// Regression: C integer promotions must run before arithmetic — an operand
// narrower than `int` (char/short/bool, signed or unsigned) is promoted to `int`,
// so the operation evaluates in (at least) 32 bits, not the narrow width. sic was
// computing `(unsigned char)200 + (unsigned char)100` in 8 bits (== 44) instead of
// promoting to int (== 300); same for shorts and signed narrow types. Returns 42.
#include <stdio.h>

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);

    unsigned char a = 200, b = 100;
    if (a + b != 300) return 1;           // promote to int
    if (a * b != 20000) return 2;
    if ((a + b) & 0xFF) { /* low byte is 44 */ if (((a + b) & 0xFF) != 44) return 3; }

    unsigned short s = 60000, t = 60000;
    if (s + t != 120000) return 4;
    if ((unsigned)(s * s) != 3600000000u) return 5;  // 60000*60000 in int overflows; take unsigned

    signed char x = 100, y = 100;
    if (x + y != 200) return 6;           // no 8-bit wrap
    signed char n = -1;
    if (n + 0 != -1) return 7;            // sign-preserving promotion
    if ((unsigned)n != 0xFFFFFFFFu) return 8;

    // Narrow result truncates only on assignment back to a narrow type.
    unsigned char c = a + b;              // 300 -> 44
    if (c != 44) return 9;

    // char in a comparison promotes (so (char)-1 != 255).
    char ch = -1;
    if (ch == 255) return 10;             // -1 (promoted) != 255
    if ((unsigned char)ch != 255) return 11;

    // Mixed narrow + int.
    unsigned short u16 = 5;
    if (u16 - 10 != -5) return 12;        // promotes to int → signed -5, not 65531

    // bool promotes to int.
    _Bool flag = 1;
    if (flag + 41 != 42) return 13;

    return 42;
}
