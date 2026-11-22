// System V callees for the struct-passing differential test (abi.sh): a
// struct or union passed by value through `...` (sic passed its address), and
// one that no longer fits in the argument registers left (it goes whole on
// the stack; sic split it between the registers and the stack).
#include <stdarg.h>
#include "va_abi.h"

long vints(int n, ...) {
    va_list ap;
    va_start(ap, n);
    long r = 0;
    for (int i = 0; i < n; i++) {
        V8 a = va_arg(ap, V8);
        V16 b = va_arg(ap, V16);
        V24 c = va_arg(ap, V24);
        V3 d = va_arg(ap, V3);
        r = r * 7 + a.a + b.a * 2 + b.b * 3 + c.a + c.b * 5 + c.c * 6 + d.a[0] + d.a[2];
    }
    va_end(ap);
    return r;
}

double vfloats(int n, ...) {
    va_list ap;
    va_start(ap, n);
    double r = 0;
    for (int i = 0; i < n; i++) {
        VD a = va_arg(ap, VD);
        VDL b = va_arg(ap, VDL);
        VFF c = va_arg(ap, VFF);
        VU u = va_arg(ap, VU);
        r = r * 3 + a.d + b.d * 2 + b.l + c.a + c.b * 4 + u.l;
    }
    va_end(ap);
    return r;
}

long named_gp(long a, long b, long c, long d, long e, V16 p, long g) {
    return a + b + c + d + e + p.a * 100 + p.b * 10 + g * 1000;
}

double named_fp(double a, double b, double c, double d, double e, double f,
                double g, VDL x, VD y, double h, VFF z) {
    return a + b + c + d + e + f + g + x.d * 10 + x.l * 100 + y.d * 1000 + h * 7 + z.a + z.b * 3;
}
