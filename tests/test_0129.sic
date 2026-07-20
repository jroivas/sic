// Floating-point classification / comparison builtins and __builtin_signbit
// (QEMU util/cutils.c uses signbit() and the <math.h> is* macros, which glibc
// implements via these builtins).
int main(void){
    double inf = 1e308 * 10.0;   // +infinity
    double nan = inf - inf;      // NaN
    double fin = 3.5, z = 0.0, nz = -0.0, neg = -2.0;
    float  ffin = -1.0f, fpos = 4.0f;
    int ok = 1;

    // signbit (correct for -0.0)
    if (!__builtin_signbit(neg) || __builtin_signbit(fin)) ok=0;
    if (!__builtin_signbit(nz) || __builtin_signbit(z)) ok=0;
    if (!__builtin_signbitf(ffin) || __builtin_signbitf(fpos)) ok=0;

    // isnan / isinf / isfinite / isnormal
    if (!__builtin_isnan(nan) || __builtin_isnan(fin)) ok=0;
    if (!__builtin_isinf(inf) || __builtin_isinf(fin) || __builtin_isinf(nan)) ok=0;
    if (!__builtin_isfinite(fin) || __builtin_isfinite(inf) || __builtin_isfinite(nan)) ok=0;
    if (!__builtin_isnormal(fin) || __builtin_isnormal(z) || __builtin_isnormal(inf)) ok=0;

    // relational (NaN-safe) comparisons
    if (!__builtin_isgreater(3.0, 2.0) || __builtin_isgreater(2.0, 3.0)) ok=0;
    if (!__builtin_islessequal(2.0, 2.0) || __builtin_islessequal(3.0, 2.0)) ok=0;
    if (__builtin_isless(nan, 3.0)) ok=0;           // unordered → false
    if (!__builtin_isunordered(nan, 1.0) || __builtin_isunordered(1.0, 2.0)) ok=0;

    return ok ? 0 : 1;
}
