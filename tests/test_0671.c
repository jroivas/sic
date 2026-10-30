// An enum constant in an `aligned` attribute's value (Linux's
// `__aligned(1 << WORK_STRUCT_PWQ_SHIFT)`): the attribute's expression did not
// see enum constants, wherever it stood.
enum bits { FLAGS = 4, COLOR = 4, SHIFT = FLAGS + COLOR, MANY };

struct tagged { int a; } __attribute__((__aligned__(1 << SHIFT)));
union both { int a; char b; } __attribute__((aligned(1 << FLAGS)));
struct member { char c; int n __attribute__((aligned(1 << (SHIFT - 1)))); };

_Static_assert(_Alignof(struct tagged) == 256, "struct");
_Static_assert(_Alignof(union both) == 16, "union");
_Static_assert(__builtin_offsetof(struct member, n) == 128, "member");

int main(void) {
    enum { LOCAL = 3 };
    struct inner { char c; } __attribute__((aligned(1 << LOCAL)));
    _Static_assert(_Alignof(struct inner) == 8, "local");
    static struct tagged t;
    return ((unsigned long)&t & 255) == 0 ? 42 : 1;
}
