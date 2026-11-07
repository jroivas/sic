// _Complex: a { re, im } pair with C99/GNU semantics (musl's src/complex).
// Arithmetic, mixed real/complex operands, conversions, imaginary constants,
// __real__/__imag__, constant initializers, and calls taking and returning
// every complex type (`_Complex long double` returns in x87 st(0)/st(1)).
#include <math.h>

#define CMPLX(x, y) ((union { _Complex double __z; double __xy[2]; }){.__xy = {(x),(y)}}.__z)
#define cimag(x) (+(union { _Complex double __z; double __xy[2]; }){(_Complex double)(x)}.__xy[1])
#define creal(x) ((double)(x))
#define I (0.0f + 1.0fi)

struct S { char c; _Complex double z; _Complex float f; };
static _Complex double gz = 1.0 + 2.0 * I;
static _Complex float gf = 3.0f;
static _Complex double garr[3] = { 1.0, 2.0 * I, -1.5 - 0.5 * I };
static struct S gs = { 'x', 3.0 - 1.0 * I, 2.0f * I };
static _Complex long double gl = 4.0L - 8.0L * I;

__attribute__((noinline)) static _Complex double mul(_Complex double a, _Complex double b) { return a * b; }
__attribute__((noinline)) static _Complex float addf(_Complex float a, float b) { return a + b; }
__attribute__((noinline)) static _Complex long double twice(_Complex long double a) { return a * 2; }
__attribute__((noinline)) static double re_of(_Complex double z) { return z; }
__attribute__((noinline)) static _Complex double from_real(double x) { return x; }
__attribute__((noinline)) static _Complex double (*pick(void))(_Complex double, _Complex double) { return mul; }

__attribute__((noinline)) static double twice_real(double x) { return x * 2; }

static int eq(_Complex double z, double re, double im) { return __real__ z == re && __imag__ z == im; }

int main(void)
{
    if (sizeof(_Complex double) != 16 || sizeof(_Complex float) != 8 || sizeof(_Complex long double) != 32) return 1;
    if (_Alignof(_Complex double) != 8 || sizeof(struct S) != 32 || sizeof(_Complex short) != 4) return 2;

    _Complex double a = 1.5 - 2.0 * I, b = -0.5 + 4.0 * I;
    if (!eq(a + b, 1, 2) || !eq(a - b, 2, -6) || !eq(a * b, 7.25, 7) || !eq(-a, -1.5, 2) || !eq(~a, 1.5, 2)) return 3;
    if (!eq(a / (2.0 - 2.0 * I), 0.875, -0.125)) return 4;
    if (!eq(a * 2, 3, -4) || !eq(2 * a, 3, -4) || !eq(a / 2, 0.75, -1) || !eq(a + 1, 2.5, -2) || !eq(1 - a, -0.5, 2)) return 5;
    if (!eq(2 / (1.0 + 1.0 * I), 1, -1)) return 6;

    // Annex G: an infinite operand gives an infinite result, not NaN.
    _Complex double inf = INFINITY + 0.0 * I;
    _Complex double m = inf * (1.0 + 1.0 * I);
    if (!isinf(__real__ m)) return 7;
    _Complex double q = (1.0 + 1.0 * I) / (0.0 + 0.0 * I);
    if (!isinf(__real__ q) && !isinf(__imag__ q)) return 8;

    // Comparisons and truth values.
    _Complex double zero = 0;
    if (!(a == a) || !(a != b) || !(a == 1.5 - 2.0 * I) || zero != 0 || !(zero == 0.0)) return 9;
    if (!a || zero || (zero ? 1 : 0) || !(a && 1) || (_Bool)zero || !(_Bool)a) return 10;
    if (!(0.0 + 1.0 * I)) return 11;

    // Conversions.
    if ((int)a != 1 || re_of(a) != 1.5 || !eq(from_real(2.5), 2.5, 0)) return 12;
    double d = a; float f = b; _Complex float cf = a; _Complex double cd = cf;
    if (d != 1.5 || f != -0.5f || !eq(cd, 1.5, -2)) return 13;
    _Complex double t = 1 ? a : 2.0;
    if (!eq(t, 1.5, -2)) return 14;
    t = 0 ? a : 2.0;
    if (!eq(t, 2, 0)) return 15;

    // Compound assignment, lvalue parts, pointers.
    _Complex double c = a;
    c += b; if (!eq(c, 1, 2)) return 16;
    c *= b; if (!eq(c, -8.5, 3)) return 17;
    c /= 2.0; if (!eq(c, -4.25, 1.5)) return 18;
    c -= 1; if (!eq(c, -5.25, 1.5)) return 19;
    double dd = 5; dd += a; if (dd != 6.5) return 20;
    __real__ c = 7; __imag__ c = -8;
    if (!eq(c, 7, -8) || __real__ c != 7 || __imag__ c != -8 || __real__ 3.0 != 3 || __imag__ 3.0 != 0) return 21;
    _Complex double *p = &c;
    *p = 3; if (!eq(c, 3, 0) || !eq(p[0] * 2, 6, 0)) return 22;

    // Constant initializers.
    if (!eq(gz, 1, 2) || __real__ gf != 3 || __imag__ gf != 0) return 23;
    if (!eq(garr[0], 1, 0) || !eq(garr[1], 0, 2) || !eq(garr[2], -1.5, -0.5)) return 24;
    if (gs.c != 'x' || !eq(gs.z, 3, -1) || __real__ gs.f != 0 || __imag__ gs.f != 2) return 25;
    if (__real__ gl != 4 || __imag__ gl != -8) return 26;

    // Calls with every complex type, direct and through a pointer.
    if (!eq(mul(a, b), 7.25, 7) || !eq(pick()(a, b), 7.25, 7)) return 27;
    _Complex float s = addf(1.0f + 2.0f * I, 0.5f);
    if (__real__ s != 1.5f || __imag__ s != 2.0f) return 28;
    _Complex long double l = twice(gl);
    if (__real__ l != 8 || __imag__ l != -16) return 29;

    // GNU integer complex, and imaginary integer constants.
    _Complex int ci = 3 + 4i;
    _Complex int cj = ci * ci;
    if (__real__ cj != -7 || __imag__ cj != 24) return 30;
    cj = ci / (1 + 1i);
    if (__real__ cj != 3 || __imag__ cj != 0) return 31;

    // musl's CMPLX/cimag through a union; a negative zero part survives.
    _Complex double w = CMPLX(1.0, -0.0);
    if (creal(w) != 1 || !signbit(cimag(w))) return 32;
    if (!eq(__builtin_complex(2.0, 3.0), 2, 3) || __builtin_creal(a) != 1.5 || __builtin_cimag(a) != -2) return 33;
    if (!eq(__builtin_conj(a), 1.5, 2) || __builtin_crealf(cf) != 1.5f) return 34;

    // `++`/`--` step the real part (GNU); a complex argument for a real parameter.
    _Complex double n = a;
    n++; ++n; n--;
    _Complex double old = n--;
    if (!eq(n, 1.5, -2) || !eq(old, 2.5, -2) || twice_real(a) != 3) return 35;
    return 0;
}
