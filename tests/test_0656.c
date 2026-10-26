// An "i" operand read from a variable the asm (or later code) writes again:
// the value is the variable's latest store before the asm. Linux's
// rip_rel_ptr(p) is `asm("leaq %c1(%%rip), %0" : "=r"(p) : "i"(p))` in an
// always_inline function; sic resolved only variables stored once, and
// rejected it ("impossible constraint").
long table[4] = { 10, 20, 30, 42 };
long other = 7;

static inline __attribute__((always_inline)) void *rip_rel_ptr(void *p) {
    asm("leaq %c1(%%rip), %0" : "=r"(p) : "i"(p));
    return p;
}

static inline __attribute__((always_inline)) long twice_loaded(long *p) {
    long a, b;
    asm("movq %c1(%%rip), %0" : "=r"(a) : "i"(p));
    p = &other;                                        // rebound before the second asm
    asm("movq %c1(%%rip), %0" : "=r"(b) : "i"(p));
    return a + b;
}

int main(void) {
    long *t = rip_rel_ptr(&table[3]);
    return (int)(*t - twice_loaded(&table[0]) + 17);   // 42 - (10 + 7) + 17 = 42
}
