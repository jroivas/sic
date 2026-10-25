// The bit builtins fold in constant expressions (Linux's order_base_2/ilog2
// are `__builtin_constant_p(n) ? … 63 - __builtin_clzll(n) … : runtime`, used
// as an "i" asm operand in kernel/bounds.c); clz/ctz of 0 is not a constant.
#define ilog2(n) (__builtin_constant_p(n) ? ((n) < 2 ? 0 : 63 - __builtin_clzll(n)) : -1)
#define order_base_2(n) (__builtin_constant_p(n) ? (((n) == 0 || (n) == 1) ? 0 : ilog2((n) - 1) + 1) : -1)

enum {
    A = order_base_2(64), B = order_base_2(65), C = __builtin_popcountll(0xff00ffULL),
    D = __builtin_ffs(8), E = __builtin_clz(1), F = __builtin_ctzl(1UL << 40),
    G = __builtin_parity(7), H = __builtin_ffsll(0),
};

int main(void)
{
    return (A == 6 && B == 7 && C == 16 && D == 4 && E == 31 && F == 40 && G == 1 && H == 0) ? 42 : 1;
}
