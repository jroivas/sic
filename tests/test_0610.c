// GCC and Clang builtins sic lacked, against the values both compilers give:
// typed overflow checks, powi, atomic NAND and __sync_swap, CPU features,
// bswap128, the type-generic bit builtins and C23's __builtin_stdc_*, signaling
// NaNs, bit reversal, rotations, alignment, the inline memcpy/memset and the
// hints. Returns 42.
#include <stdio.h>
#include <string.h>

static char out[2048];
static int len;
#define P(...) (len += snprintf(out + len, sizeof out - len, __VA_ARGS__))

int main(void) {
    unsigned char uc = 0x16; unsigned short us = 0x0123; unsigned u = 0x80000001u; unsigned long long ull = 0x00F0000000000001ULL;
    int r; long lr; unsigned ur;
    int o1 = __builtin_sadd_overflow(0x7fffffff, 1, &r), o2 = __builtin_ssubl_overflow(0, 1, &lr), o3 = __builtin_umul_overflow(0x10000u, 0x10000u, &ur);
    int o4 = __builtin_uadd_overflow(1u, 2u, &ur);
    P("ovf %d %d %d %d %u %d %ld\n", o1, o2, o3, o4, ur, r, lr);
    P("pow %g\n", __builtin_powi(2.0, 10));
    int x = 6; __atomic_fetch_nand(&x, 3, 5); int y = 6; int ny = __sync_nand_and_fetch(&y, 3); int w = 6; int ow = __sync_fetch_and_nand(&w, 3);
    P("atom %d %d %d %d %d\n", x, y, ny, w, ow);
    P("cpu %d\n", !!__builtin_cpu_supports("sse2"));
    unsigned __int128 v = ((unsigned __int128)0x0102030405060708ULL << 64) | 0x090A0B0C0D0E0F10ULL;
    unsigned __int128 s = __builtin_bswap128(v);
    P("bswap128 %llx %llx\n", (unsigned long long)(s >> 64), (unsigned long long)s);
    P("g %d %d %d %d %d %d %d\n", __builtin_clzg(1u), __builtin_ctzg(8ULL), __builtin_clzg((unsigned short)1), __builtin_popcountg((unsigned char)0xFF), __builtin_parityg(7u), __builtin_ffsg(0), __builtin_clrsbg(1));
    P("stdc %u %u %u %u %u %u %u %u\n", __builtin_stdc_leading_zeros((unsigned char)1), __builtin_stdc_leading_ones((unsigned char)0xE0), __builtin_stdc_trailing_zeros(0u), __builtin_stdc_trailing_ones(7u), __builtin_stdc_first_leading_one((unsigned short)0x10), __builtin_stdc_first_trailing_zero((unsigned char)0xFF), __builtin_stdc_count_zeros((unsigned char)1), __builtin_stdc_bit_width(255u));
    P("stdc2 %u %u %u %u %d %u %u\n", (unsigned)__builtin_stdc_bit_floor(100u), (unsigned)__builtin_stdc_bit_ceil(100u), (unsigned)__builtin_stdc_bit_ceil((unsigned char)200), (unsigned)__builtin_stdc_bit_floor(0u), __builtin_stdc_has_single_bit(64u), (unsigned)__builtin_stdc_rotate_left((unsigned char)0x81, 9), (unsigned)__builtin_stdc_rotate_right((unsigned short)1, 1));
    P("stdc3 %u %u %u %u\n", __builtin_stdc_first_leading_zero((unsigned char)0xF0), __builtin_stdc_first_trailing_one(12u), __builtin_stdc_count_ones(0xF0F0u), (unsigned)__builtin_stdc_bit_ceil(1u));
    double sn = __builtin_nans(""); float snf = __builtin_nansf(""); double qn = __builtin_nan("");
    P("nan %d %d %d %d %d\n", __builtin_issignaling(sn), __builtin_issignaling(snf), __builtin_issignaling(qn), __builtin_issignaling(1.0), sn != sn);
    P("fp2 %d %d %d %d\n", __builtin_isnanf(snf), __builtin_iseqsig(1.0, 1.0), __builtin_isinfl(1.0L / 0.0L), __builtin_finite(1.0));
    P("pow2 %g\n", (double)__builtin_powif(3.0f, -1));
    P("spec %d\n", __builtin_speculation_safe_value(4));
    P("rev %x %x %x %llx\n", __builtin_bitreverse8(uc), __builtin_bitreverse16(us), __builtin_bitreverse32(u), (unsigned long long)__builtin_bitreverse64(ull));
    P("rot %x %x %d\n", __builtin_rotateleft8(0x81, 1), __builtin_rotateright32(1u, 1), __builtin_rotateleft64(1ULL, 63) == 0x8000000000000000ULL);
    int z = 5; int oz = __sync_swap(&z, 9);
    P("swap %d %d\n", z, oz);
    _Alignas(16) char buf[64];
    P("align %d %d %ld %ld\n", __builtin_is_aligned(buf, 16), __builtin_is_aligned(buf + 1, 16), (long)((char *)__builtin_align_up(buf + 1, 16) - buf), (long)__builtin_align_down(37, 8));
    char d[4]; __builtin_memcpy_inline(d, "abc", 4); __builtin_memset_inline(d, 'z', 1);
    P("misc %s %d %d\n", d, __builtin_unpredictable(3), (__builtin_assume(x != 0), 1));
    static const char want[] =
    "ovf 1 0 1 0 3 -2147483648 -1\n"
    "pow 1024\n"
    "atom -3 -3 -3 -3 6\n"
    "cpu 1\n"
    "bswap128 100f0e0d0c0b0a09 807060504030201\n"
    "g 31 3 15 8 1 0 30\n"
    "stdc 7 3 32 3 12 0 7 8\n"
    "stdc2 64 128 0 0 1 3 32768\n"
    "stdc3 5 3 8 1\n"
    "nan 1 1 0 0 1\n"
    "fp2 1 1 1 1\n"
    "pow2 0.333333\n"
    "spec 4\n"
    "rev 68 c480 80000001 8000000000000f00\n"
    "rot 3 80000000 1\n"
    "swap 9 5\n"
    "align 1 0 16 32\n"
    "misc zbc 3 1\n"
    ;
    if (strcmp(out, want) != 0) { fputs(out, stdout); return 1; }
    // The generic overflow builtins work on the exact values (not the values
    // converted to the result type first).
    unsigned char u8; unsigned uu; unsigned long long ull2;
    if (!__builtin_add_overflow(300, 0, &u8) || u8 != 44) return 2;
    if (!__builtin_add_overflow(-1, 0u, &uu)) return 3;
    if (!__builtin_mul_overflow(-1LL, 1LL, &ull2)) return 4;
    if (!__builtin_mul_overflow(0xFFFFFFFFFFFFFFFFULL, 2ULL, &ull2) || ull2 != 0xFFFFFFFFFFFFFFFEULL) return 5;
    if (__builtin_mul_overflow(-3LL, 5ULL, &r) || r != -15) return 6;
    if (__builtin_sub_overflow(5u, 3, &uu) || uu != 2) return 7;
    return 42;
}
