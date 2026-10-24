// Builtins that gave wrong answers: __builtin_frame_address(0) was NULL;
// __builtin_isinf_sign lost the sign; isnormal/fpclassify called subnormals
// normal (and fpclassify evaluated x three times); __builtin_constant_p was 0
// even for a literal. Returns 42.
#include <float.h>

static int calls;
static double once(double v) { calls++; return v; }

__attribute__((noinline)) static void *caller_frame(void) { return __builtin_frame_address(1); }

__attribute__((noinline)) static int frames(void)
{
    char local[16];
    void *fp = __builtin_frame_address(0);
    local[0] = 0;
    if (!fp || (char *)fp < local) return 0;
    return caller_frame() == fp;
}

int main(void)
{
    if (!frames()) return 1;
    if (__builtin_isinf_sign(-__builtin_inf()) != -1) return 2;
    if (__builtin_isinf_sign(__builtin_inf()) != 1) return 3;
    if (__builtin_isinf_sign(1.0) != 0) return 4;
    double sub = DBL_MIN / 4;
    if (__builtin_isnormal(sub) || !__builtin_isnormal(DBL_MIN)) return 5;
    if (__builtin_isnormal(FLT_MIN / 4) || !__builtin_isnormal(FLT_MIN)) return 6;
    if (__builtin_fpclassify(0, 1, 4, 3, 2, sub) != 3) return 7;
    if (__builtin_fpclassify(0, 1, 4, 3, 2, -0.0) != 2) return 8;
    if (__builtin_fpclassify(0, 1, 4, 3, 2, once(1.5)) != 4 || calls != 1) return 9;
    int x = 3;
    if (!__builtin_constant_p(5) || !__builtin_constant_p(2 * 3) || !__builtin_constant_p(1.5)
        || !__builtin_constant_p("s") || __builtin_constant_p(x)) return 10;
    return 42;
}
