// Regression: `sizeof(T)` and `__builtin_offsetof(T, m)` used as an *array
// dimension* must be constant-folded. sic's array-size evaluator only handled
// plain integer arithmetic, so a dimension like `offsetof(List,a)+sizeof(Item)`
// (SQLite's SZ_SRCLIST_1) collapsed to 0. The array — and any union built around
// it — then came out too small, so a following `memset(&u, 0, sizeof(u))` left
// trailing members as stack garbage. In SQLite that garbage set a bit-field
// (SrcItem.fg.isNestedFrom) and crashed CREATE TABLE ... UNIQUE.

#include <stddef.h>
#include <string.h>

struct Item {
    char *a;
    char *b;
    char *c;
    int   fg;
    int   cur;
    unsigned long u;
};

struct List {
    int      n;
    unsigned nAlloc;
    struct Item a[];        // flexible array member
};

#define SZ (offsetof(struct List, a) + sizeof(struct Item))

int main(void)
{
    // sizeof(T) as a dimension.
    char buf[sizeof(struct Item)];
    if (sizeof(buf) != sizeof(struct Item)) return 1;

    // offsetof(...) + sizeof(...) as a dimension (the failing pattern).
    unsigned char space[SZ];
    if (sizeof(space) != offsetof(struct List, a) + sizeof(struct Item)) return 2;

    // A union that must be large enough to hold one embedded Item, so a full
    // memset zeroes the whole thing.
    union {
        struct List   sl;
        unsigned char space[SZ];
    } u;
    if (sizeof(u) < SZ) return 3;

    memset(&u, 0, sizeof(u));
    u.sl.n = 1;
    u.sl.a[0].a = "x";
    // These trailing members were garbage when the dimension folded to 0.
    if (u.sl.a[0].fg  != 0) return 4;
    if (u.sl.a[0].cur != 0) return 5;
    if (u.sl.a[0].b   != 0) return 6;
    if (u.sl.a[0].c   != 0) return 7;
    if (u.sl.a[0].u   != 0) return 8;

    // sizeof combined with arithmetic in a dimension.
    int arr[sizeof(struct Item) / sizeof(char *) + 2];
    if (sizeof(arr) / sizeof(int) != sizeof(struct Item) / sizeof(char *) + 2)
        return 9;

    return 0;
}
