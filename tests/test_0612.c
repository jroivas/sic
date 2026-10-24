// A builtin call has the type GCC gives it: `c ? __builtin_bswap64(v) : 0`
// and `sizeof(__builtin_bswap64(v))` took it for an `int` (the value was cut to
// 32 bits); a `__builtin_<libc function>` has the function's type. Returns 42.
int main(void)
{
    unsigned long long v = 0x0102030405060708ULL;
    int c = 1;
    char buf[8];
    unsigned long long a = c ? __builtin_bswap64(v) : 0;
    if (a != 0x0807060504030201ULL) return 1;
    if (sizeof(__builtin_bswap64(v)) != 8 || sizeof(__builtin_bswap16(1)) != 2) return 2;
    if (sizeof(__builtin_expect(1, 1)) != sizeof(long) || sizeof(__builtin_inff()) != 4) return 3;
    void *p = c ? __builtin_memcpy(buf, "abc", 4) : 0;
    if (p != buf) return 4;
    long long big = c ? __builtin_llabs(-5000000000LL) : 0;
    if (big != 5000000000LL || sizeof(__builtin_strlen("x")) != sizeof(unsigned long)) return 5;
    if ((c ? __builtin_stdc_bit_floor(v) : 0) != 0x0100000000000000ULL) return 6;
    return 42;
}
