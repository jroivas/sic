// System V callers for the struct-passing differential test; see va_callee.c.
#include <stdio.h>
#include "va_abi.h"

long vints(int n, ...);
double vfloats(int n, ...);
long named_gp(long, long, long, long, long, V16, long);
double named_fp(double, double, double, double, double, double, double, VDL, VD, double, VFF);

int main(void) {
    V8 a = { 1 }; V16 b = { 2, 3 }; V24 c = { 4, 5, 6 }; V3 d = { { 7, 8, 9 } };
    // Three rounds: the later ones are past the argument registers.
    printf("vints %ld\n", vints(3, a, b, c, d, a, b, c, d, a, b, c, d));
    VD x = { 1.5 }; VDL y = { 2.5, 3 }; VFF z = { 0.25f, 0.5f }; VU u = { .l = 9 };
    printf("vfloats %.4f\n", vfloats(3, x, y, z, u, x, y, z, u, x, y, z, u));
    printf("named_gp %ld\n", named_gp(1, 2, 3, 4, 5, b, 6));
    printf("named_fp %.4f\n", named_fp(1, 2, 3, 4, 5, 6, 7, y, x, 8, z));
    return 0;
}
