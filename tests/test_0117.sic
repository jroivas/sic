// Regression: a GCC `__extension__` prefix on a struct/union member declaration
// must be skipped, not treated as an un-consumed token. sic's declaration-
// specifier parser had no case for `__extension__`, so the struct-member loop
// never advanced and allocated fields until it ran out of memory. glibc's
// `__atomic_wide_counter` (pulled in by <stdlib.h>) has exactly this shape.

typedef union {
    __extension__ unsigned long long int v64;
    struct { unsigned int lo; unsigned int hi; } v32;
} awc;

struct S {
    __extension__ long long a;
    int b;
    __extension__ unsigned long long c;
};

int main(void)
{
    if (sizeof(awc) != 8) return 1;
    if (sizeof(struct S) != 24) return 2;   // 8 + 4(+4 pad) + 8

    awc u;
    u.v64 = 0x1122334455667788ULL;
    if (u.v32.lo != 0x55667788u) return 3;   // little-endian low word
    if (u.v32.hi != 0x11223344u) return 4;

    struct S s;
    s.a = -5; s.b = 7; s.c = 100;
    if (s.a != -5 || s.b != 7 || s.c != 100) return 5;

    return 0;
}
