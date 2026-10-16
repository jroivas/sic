/* long double keeps the x87 80-bit format in memory and at C boundaries:
   global/array images, struct fields, libc (printf %Lf, strtold, sqrtl),
   stack arguments needing 16-byte alignment pads, varargs, st(0) returns. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
struct P { int tag; long double v; };
long double g = 1.0L;
long double arr[2] = {-2.0L, 0.5};
struct P gp = {7, 4.75L};
static long double mix(int a, int b, int c, int d, int e, int f, int h, long double x, int i, long double y) {
    return a + b + c + d + e + f + h + x + i + y;
}
static long double sumv(int n, ...) {
    va_list ap; va_start(ap, n);
    for (int i = 0; i < 7; i++) (void)va_arg(ap, int);
    long double s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, long double);
    va_end(ap);
    return s;
}
static long double (*fp)(int, int, int, int, int, int, int, long double, int, long double) = mix;
int main(void) {
    static const unsigned char one[10] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f};
    static const unsigned char m2[10] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0x00, 0xc0};
    if (memcmp(&g, one, 10)) return 1;
    if (memcmp(&arr[0], m2, 10)) return 2;
    long double x = 1.0;
    if (memcmp(&x, one, 10)) return 3;
    if (gp.v != 4.75L || sizeof(1.0L) != 16) return 4;
    char buf[64];
    snprintf(buf, sizeof buf, "%.2Lf %Lg %.1Lf", gp.v, 1.5L, sqrtl(16.0L));
    if (strcmp(buf, "4.75 1.5 4.0")) { puts(buf); return 5; }
    if (strtold("2.5", NULL) != 2.5L) return 6;
    if (mix(1, 2, 3, 4, 5, 6, 7, 0.5L, 8, 0.25L) != 36.75L) return 7;
    if (fp(1, 2, 3, 4, 5, 6, 7, 0.5L, 8, 0.25L) != 36.75L) return 8;
    if (sumv(3, 1, 2, 3, 4, 5, 6, 7, 1.5L, 2.0L, 0.5L) != 4.0L) return 9;
    return 42;
}
