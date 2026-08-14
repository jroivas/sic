/* System V by-value aggregate RETURNS: a small struct/union comes back in
 * registers (RAX:RDX / XMM0:XMM1 by eightbyte class); a large one via sret. sic
 * used to return every aggregate via sret, which is wrong for gcc/glibc interop.
 * These functions return aggregates by value and the caller reads them back. */

struct S8   { int x, y; };            /* 8B  -> RAX            */
struct S16i { long a, b; };           /* 16B -> RAX:RDX        */
struct S2d  { double a, b; };         /* 16B -> XMM0:XMM1      */
struct Smix { long i; double d; };    /* 16B -> RAX + XMM0     */
struct S3   { char a, b, c; };        /* 3B  -> RAX (partial)  */
struct Big  { long a, b, c, d; };     /* 32B -> sret           */
union  U8   { unsigned long long u; void *p; };

static struct S8   mk_s8(int x, int y)          { struct S8 s   = { x, y }; return s; }
static struct S16i mk_s16(long a, long b)       { struct S16i s = { a, b }; return s; }
static struct S2d  mk_s2d(double a, double b)   { struct S2d s  = { a, b }; return s; }
static struct Smix mk_mix(long i, double d)     { struct Smix s = { i, d }; return s; }
static struct S3   mk_s3(char a, char b, char c){ struct S3 s   = { a, b, c }; return s; }
static struct Big  mk_big(long a)               { struct Big s  = { a, a+1, a+2, a+3 }; return s; }
static union  U8   mk_u8(unsigned long long v)  { union U8 u; u.u = v; return u; }

int main(void)
{
    struct S8 a = mk_s8(5, 3);
    if (a.x != 5 || a.y != 3) return 1;

    struct S16i b = mk_s16(111, 222);
    if (b.a != 111 || b.b != 222) return 2;

    struct S2d c = mk_s2d(1.5, 2.5);
    if (c.a != 1.5 || c.b != 2.5) return 3;

    struct Smix d = mk_mix(7, 0.25);
    if (d.i != 7 || d.d != 0.25) return 4;

    struct S3 e = mk_s3(1, 2, 3);
    if (e.a != 1 || e.b != 2 || e.c != 3) return 5;

    struct Big f = mk_big(10);
    if (f.a != 10 || f.b != 11 || f.c != 12 || f.d != 13) return 6;

    union U8 g = mk_u8(0xDEADBEEFCAFEULL);
    if (g.u != 0xDEADBEEFCAFEULL) return 7;

    /* chained: return value used directly as a struct */
    if (mk_s16(40, 2).a != 40) return 8;

    return 0;
}
