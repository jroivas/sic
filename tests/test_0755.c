/* _Generic and __builtin_types_compatible_p tell `long` from `long long` (one
 * IR type in sic, two C types): `long long` took the `long` association, and
 * types_compatible_p(long, long long) was 1. Returns 42. */
#include <stdint.h>

#define K(x) _Generic((x), int: 1, long: 2, long long: 3, unsigned long: 4, unsigned long long: 5, \
                       long *: 6, long long *: 7, default: 0)

typedef long long my_ll;
struct s { long a; long long b; my_ll *p; };
static long long f(void) { return 1; }
static const int at_file_scope = _Generic((long long)0, long: 2, long long: 3);

int main(void) {
    long a = 0; long long b = 0; unsigned long c = 0; unsigned long long d = 0;
    int64_t e = 0; my_ll g = 0; int i = 0;
    struct s st = { 0, 0, 0 };
    if (K(a) != 2 || K(b) != 3 || K(c) != 4 || K(d) != 5) return 1;
    if (K(e) != 2 || K(g) != 3) return 2;                    /* glibc: int64_t is long */
    if (K(st.a) != 2 || K(st.b) != 3 || K(st.p) != 7) return 3;
    if (K(f()) != 3 || K((long long)i) != 3 || K((long)i) != 2) return 4;
    if (K(b + i) != 3 || K(a + i) != 2 || K(i) != 1 || K(-b) != 3 || K(b << 2) != 3) return 5;
    if (K(&a) != 6 || K(&b) != 7) return 6;
    if (K(sizeof a) != 4) return 7;                         /* size_t */
    if (__builtin_types_compatible_p(long, long long)) return 8;
    if (!__builtin_types_compatible_p(long, int64_t) || !__builtin_types_compatible_p(my_ll, long long)) return 9;
    if (__builtin_types_compatible_p(typeof(a), typeof(b)) || __builtin_types_compatible_p(long *, long long *)) return 10;
    if (at_file_scope != 3) return 11;
    return 42;
}
