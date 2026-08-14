/* System V by-value aggregate ARGUMENT passing (structs/unions in registers, and
 * large aggregates by value on the stack). Before the ABI fix sic passed every
 * aggregate by pointer, which corrupted interop with gcc/glibc. This checks the
 * classifier cases end to end (results returned as scalars, so it's independent
 * of aggregate *returns*). */
#include <stdint.h>

union U8  { void *p; unsigned long long u; };   /* 8B  -> 1 INTEGER reg   */
struct S8 { int x, y; };                         /* 8B  -> 1 INTEGER reg   */
struct S16i { long a, b; };                      /* 16B -> 2 INTEGER regs  */
struct S2d { double a, b; };                     /* 16B -> 2 SSE regs      */
struct Smix { long i; double d; };               /* 16B -> INTEGER + SSE   */
struct S3 { char a, b, c; };                     /* 3B  -> 1 partial reg   */
struct Big { long a, b, c, d; };                 /* 32B -> MEMORY (stack)  */

static unsigned long long take_u8(union U8 v)      { return v.u; }
static int    take_s8(struct S8 s)                 { return s.x * 10 + s.y; }
static long   take_s16i(struct S16i s)             { return s.a * 1000 + s.b; }
static double take_s2d(struct S2d s)               { return s.a * 100.0 + s.b; }
static double take_mix(int lead, struct Smix s)    { return (double)(lead + s.i) + s.d; }
static int    take_s3(struct S3 s)                 { return s.a + s.b * 10 + s.c * 100; }
static long   take_big(struct Big s)               { return s.a + s.b + s.c + s.d; }
/* a small struct after 5 leading ints (register pressure) */
static long   take_late(int a,int b,int c,int d,int e, struct S8 s) { return a+b+c+d+e + s.x + s.y; }

int main(void)
{
    union U8 u; u.u = 0xABCDEF;
    if (take_u8(u) != 0xABCDEF) return 1;

    struct S8 s8 = { 5, 3 };
    if (take_s8(s8) != 53) return 2;

    struct S16i s16 = { 100, 7 };
    if (take_s16i(s16) != 100007) return 3;

    struct S2d s2d = { 2.0, 0.5 };
    if (take_s2d(s2d) != 200.5) return 4;

    struct Smix mx = { 40, 0.25 };
    if (take_mix(2, mx) != 42.25) return 5;

    struct S3 s3 = { 1, 2, 3 };
    if (take_s3(s3) != 1 + 20 + 300) return 6;

    struct Big big = { 1, 2, 3, 4 };
    if (take_big(big) != 10) return 7;

    if (take_late(1, 2, 3, 4, 5, s8) != 15 + 8) return 8;

    return 0;
}
