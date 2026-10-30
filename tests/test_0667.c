// An input may share a fixed register with a plain output: both read %eax here,
// `"=a"(out)` and `"a"(in)` (Linux's XSTATE_OP, for xsave and xrstor).
struct area { int base; };

static int add(struct area *st, int in, int hi) {
    int out;
    asm volatile("addl %[mem], %%eax\n\taddl %%edx, %%eax"
                 : [out] "=a"(out)
                 : [mem] "m"(*st), "a"(in), "d"(hi)
                 : "memory");
    return out;
}

// In both orders, and with the input of the wider type.
static long both(long in) {
    int mem = 2;
    long lo;
    unsigned long d;
    asm("incq %%rdx\n\taddq %%rdx, %%rax\n\taddl %[m], %%eax"
        : "=a"(lo), "=d"(d)
        : "d"(in), [m] "m"(mem), "a"(in));
    return lo + (long)d;
}

int main(void) {
    struct area a = { 30 };
    if (add(&a, 10, 2) != 42) return 1;
    if (both(5) != 5 + 6 + 2 + 6) return 2;
    return 42;
}
