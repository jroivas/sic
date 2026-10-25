// Static assertions at file scope, in a block and as a struct member (Linux's
// BUILD_BUG_ON_ZERO is `sizeof(struct { _Static_assert(…); })`), with and
// without a message, are checked; a true one compiles to nothing.
#include <stddef.h>

struct pair { int a; long b; };
_Static_assert(sizeof(int) == 4, "int is 32-bit");
_Static_assert(offsetof(struct pair, b) == 8, "b after padding");
static_assert(sizeof(long) == 8);

#define BUILD_BUG_ON_ZERO(e) ((int)sizeof(struct { _Static_assert(!(e), "BUILD_BUG_ON_ZERO: " #e); }))

int main(void)
{
    _Static_assert(__builtin_clz(1) == 31, "folded");
    int z = BUILD_BUG_ON_ZERO(sizeof(char) != 1);
    struct s { char c; _Static_assert(1, "member"); int i; } v = { 1, 41 };
    return z + v.c + v.i;
}
