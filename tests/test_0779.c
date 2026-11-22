/* An `int` constant expression that overflows wraps as the same operation at
   run time does: sic's constant folding made it a `long` (2147483647 * 2 was
   4294967294, 65536 * 65536 was not 0), so a result depended on whether its
   operands were constants. Returns 42. */
int main(void) {
    volatile int a = 2147483647, b = 2;
    int r = 0;
    long y = 2147483647 * 2;
    if (y == -2 && y == (long)(a * b)) r++;
    if (65536 * 65536 == 0) r++;
    long w = -2147483647 - 2;
    if (w == 2147483647) r++;
    if (-(-2147483647 - 1) == -2147483647 - 1) r++;
    if (0xFFFFFFFFu + 1u == 0) r++;
    if (2147483647 + 1 < 0) r++;
    return r == 6 ? 42 : r;
}
