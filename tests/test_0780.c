/* A floating value converts to an unsigned type in all of its range: a
   32-bit or 64-bit unsigned result went through a signed conversion of its
   own width, which clamped (unsigned)3e9 to 2147483647 and
   (unsigned long)1e19 to 9223372036854775807 (constants folded the same
   way). Returns 42. */
int main(void) {
    volatile double a = 3e9, b = 1e19, c = 255.0, d = 65535.0;
    volatile float f = 4e9f;
    int r = 0;
    if ((unsigned)a == 3000000000u) r++;
    if ((unsigned long)b == 10000000000000000000ul) r++;
    if ((unsigned char)c == 255 && (unsigned short)d == 65535) r++;
    if ((unsigned)f == 4000000000u) r++;
    unsigned ka = (unsigned)3e9;
    unsigned long kb = (unsigned long)1e19;
    if (ka == 3000000000u && kb == 10000000000000000000ul) r++;
    if ((long)-2.5 == -2 && (int)2.9 == 2) r++;
    return r == 6 ? 42 : r;
}
