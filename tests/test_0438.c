/* C unary operators' types: `-x`/`~x` have the PROMOTED operand type, `!x` is
 * int, `+c` promotes. sic typed -x/~x/!x as int and dropped unary +, so
 * sizeof(-x) for a long was 4, `typeof(-x) t = 1L << 40` truncated to 0, and
 * _Generic(-u, ...) picked the wrong arm. Returns 42. */
int main(void) {
    long x = 1; char c = 1; double d = 1; unsigned long long u = 0; short s = -2;
    if (sizeof(-x) != 8 || sizeof(~x) != 8 || sizeof(+c) != sizeof(int) || sizeof(-d) != 8) return 1;
    if (sizeof(!x) != sizeof(int) || sizeof(~0ULL) != 8 || sizeof(-1ULL >> 32) != 8 || sizeof(-s) != sizeof(int)) return 2;
    if (_Generic(-u, unsigned long long: 1, default: 0) != 1 || _Generic(~c, int: 1, default: 0) != 1) return 3;
    __typeof__(-x) t = 1L << 40;
    if (t != 1099511627776L) return 4;
    __typeof__(~0ULL) m = ~0ULL >> 1;
    if (m != 0x7fffffffffffffffULL || (-1ULL >> (64 - 32)) != 0xffffffffULL) return 5;
    if (+s != -2 || -s != 2 || +c + 1 != 2) return 6;
    return 42;
}
