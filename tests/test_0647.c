// GNU `a ?: b` (omitted middle operand: `a` when nonzero) folds in constant
// expressions — Linux's __cacheline_group_begin_aligned uses
// `__aligned((__VA_ARGS__ + 0) ? : SMP_CACHE_BYTES)` (sic dropped the
// alignment, then rejected it), also in initializers, enums and array sizes.
#include <stddef.h>

#define CACHE 64
#define group_begin(G, ...) unsigned char G##_begin[0] __attribute__((__aligned__((__VA_ARGS__ + 0) ? : CACHE)))

struct ns {
    char c;
    group_begin(icmp);
    int credit;
    group_begin(small, 16);
    int x;
};
_Static_assert(offsetof(struct ns, credit) == 64 && offsetof(struct ns, x) == 80, "aligned groups");
_Static_assert(_Alignof(struct ns) == 64, "struct alignment");

enum { E1 = 0 ? : 7, E2 = 5 ? : 9 };
static int g1 = (32 + 0) ? : 64;
static int g2 = ( + 0) ? : 64;
static char arr[3 ? : 1];

int main(void) {
    return E1 + E2 + (g1 == 32) + (g2 == 64) + (int)sizeof arr + 25;   // 7+5+1+1+3+25
}
