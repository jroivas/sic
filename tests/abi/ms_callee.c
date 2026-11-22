// `ms_abi` callees for the differential test (abi.sh): built by GCC or by
// sic, and called from ms_caller.c built by the other one.
#include <stdarg.h>
#include "ms_abi.h"

#define MS __attribute__((ms_abi))

MS long ints8(int a, long b, short c, char d, long e, int f, unsigned char g, long h) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

MS double mixed(int a, double b, long c, float d, double e, int f, double g) {
    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7;
}

MS float fsum(float a, float b, float c, float d, float e) { return a + b + c + d + e; }

MS void *ptrs(void *a, char *b, long off) { return b + off + (a != 0); }

MS long aggs(S1 a, S2 b, S3 c, S4 d, S8 e, S16 f, S24 g, int tail) {
    long r = a.a + b.a * 2 + c.a[0] + c.a[1] + c.a[2] + d.a * 3 + e.a * 4
        + f.a + f.b * 5 + g.a + g.b + g.c * 6 + tail * 7;
    // The callee's copies: changing them changes nothing of the caller's.
    f.a = 999; g.c = 999; c.a[1] = 99;
    return r + f.a + g.c + c.a[1] - 999 - 999 - 99;
}

MS S1 ret1(int v) { S1 s = { (char)v }; return s; }
MS S4 ret4(int v) { S4 s = { v * 3 }; return s; }
MS S8 ret8(long v) { S8 s = { v * 5 }; return s; }
MS S3 ret3(int v) { S3 s = { { (char)v, (char)(v + 1), (char)(v + 2) } }; return s; }
MS S16 ret16(long a, long b) { S16 s = { a, b }; return s; }
MS S24 ret24(long a) { S24 s = { a, a + 1, a + 2 }; return s; }
MS double retd(double x) { return x * 1.5; }

MS long vsum(int n, ...) {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, n);
    long r = 0;
    for (int i = 0; i < n; i++) r = r * 3 + __builtin_va_arg(ap, long);
    __builtin_ms_va_end(ap);
    return r;
}

// Variadic doubles, a big struct, and a copied list. A struct of other than
// 1, 2, 4 or 8 bytes is passed by reference, so its slot holds a pointer: read
// as one here, as GCC's `va_arg(ap, S24)` wrongly reads the slots in place
// (sic and Clang take the pointer; see test_0778).
MS double vmix(int n, ...) {
    __builtin_ms_va_list ap, aq;
    __builtin_ms_va_start(ap, n);
    double r = 0;
    for (int i = 0; i < n; i++) {
        int kind = __builtin_va_arg(ap, int);
        if (kind == 0) r += __builtin_va_arg(ap, double);
        else if (kind == 1) { S24 *s = __builtin_va_arg(ap, S24 *); r += s->a + s->b + s->c; }
        else { S8 s = __builtin_va_arg(ap, S8); r += s.a * 10; }
    }
    __builtin_ms_va_copy(aq, ap);
    __builtin_ms_va_end(aq);
    __builtin_ms_va_end(ap);
    return r;
}

MS long apply(MS long (*f)(long, long), long a, long b) { return f(a, b) + 1; }

// A System V callee from an ms_abi function: rsi, rdi and xmm6-15 must
// survive it for the ms_abi caller.
long sysv_clobber(long x) {
    __asm__ volatile("xorps %%xmm6, %%xmm6; xorps %%xmm7, %%xmm7; xorq %%rsi, %%rsi; xorq %%rdi, %%rdi"
                     ::: "xmm6", "xmm7", "rsi", "rdi");
    return x + 1;
}
MS long calls_sysv(long x) { return sysv_clobber(x) * 2; }

// The kernel's forms: a typedef'd function type, `__efiapi *`, and the
// grouped pointer declarator.
typedef long efi_fn_t(long a, long b);
struct table {
    efi_fn_t MS *sub;
    long (MS *mul)(long, long);
};
static MS long do_sub(long a, long b) { return a - b; }
static MS long do_mul(long a, long b) { return a * b; }
struct table the_table = { do_sub, do_mul };
