// __attribute__((packed)) on a member makes that member 1-byte aligned (sic
// ignored it: Linux's compat_sigaction has `compat_sigset_t sa_mask __packed;`).
// Before the declarators it applies to each; an explicit aligned(N) still wins.
#include <stddef.h>

struct m { char c; int x __attribute__((packed)); char d; long y; };
struct n { char c; __attribute__((packed)) long x, z; };
struct o { char c; struct { int a; } s __attribute__((packed)); };
struct p { char c; int x __attribute__((packed, aligned(2))); };
union u { char c; int i __attribute__((packed)); };
struct hu { char c; union u u; };
struct bf { unsigned char c; unsigned v : 30 __attribute__((packed)); };
typedef struct { unsigned sig[2]; } sigset2;
struct sa { void *handler; unsigned long flags; sigset2 mask __attribute__((packed)); char tail; };

_Static_assert(offsetof(struct m, x) == 1 && offsetof(struct m, d) == 5 && offsetof(struct m, y) == 8, "m");
_Static_assert(offsetof(struct n, x) == 1 && offsetof(struct n, z) == 9 && sizeof(struct n) == 17, "n");
_Static_assert(sizeof(struct o) == 5, "o");
_Static_assert(offsetof(struct p, x) == 2, "p");
_Static_assert(sizeof(union u) == 4 && _Alignof(union u) == 1 && sizeof(struct hu) == 5, "u");
_Static_assert(sizeof(struct sa) == 32 && offsetof(struct sa, tail) == 24, "sa");

int main(void) {
    struct m v = { 1, 0x01020304, 2, 3 };
    volatile struct m *pv = &v;
    struct bf b = { 7, 0x2aaaaaaa };
    struct sa s = { 0, 1, { { 5, 6 } }, 9 };
    int ok = (pv->x == 0x01020304) + (pv->d == 2) + (b.v == 0x2aaaaaaa && b.c == 7)
           + (s.mask.sig[1] == 6 && s.tail == 9);
    return ok + 38 + (int)(sizeof(struct bf) - sizeof(struct bf));
}
