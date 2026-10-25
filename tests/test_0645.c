// aligned(EXPR) where EXPR needs type sizes — sizeof(struct S) / a typedef —
// is evaluated when lowering (sic skipped it), and an alignment on a typedef
// of a struct reference applies (Linux's call_single_data_t:
// `typedef struct __call_single_data call_single_data_t
//      __aligned(sizeof(struct __call_single_data));`, moving struct rq).
// A stray `;` among members declares nothing (it added an int).
#include <stddef.h>

struct csd { void *next; unsigned flags; unsigned short src, dst; void (*func)(void *); void *info; };
typedef struct csd csd_t __attribute__((__aligned__(sizeof(struct csd))));
typedef unsigned int word_t;
struct rq_like { long a; int b; csd_t c; char d; };
struct m { char c; int x __attribute__((aligned(sizeof(word_t) * 2))); };
struct t { char c; } __attribute__((aligned(sizeof(struct csd) / 2)));
typedef struct { unsigned seq; ; } seq_t;
struct semis { int x; ; ; char y; };

_Static_assert(sizeof(struct csd) == 32 && _Alignof(struct csd) == 8, "csd");
_Static_assert(_Alignof(csd_t) == 32 && sizeof(csd_t) == 32, "csd_t");
_Static_assert(offsetof(struct rq_like, c) == 32 && offsetof(struct rq_like, d) == 64, "rq_like");
_Static_assert(sizeof(struct rq_like) == 96 && _Alignof(struct rq_like) == 32, "rq_like size");
_Static_assert(offsetof(struct m, x) == 8, "m");
_Static_assert(_Alignof(struct t) == 16 && sizeof(struct t) == 16, "t");
_Static_assert(sizeof(seq_t) == 4 && sizeof(struct semis) == 8, "semis");

int main(void) {
    struct rq_like r = { 1, 2, { 0, 7 }, 3 };
    csd_t arr[2];
    return (int)(r.c.flags + r.d + (sizeof arr == 64) * 32);
}
