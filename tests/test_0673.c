// __builtin_bswap* in constant expressions (Linux's cpu_to_be16(1) as an enum value).
#define S16(x) (unsigned short)__builtin_bswap16((unsigned short)(x))
#define S32(x) __builtin_bswap32(x)
#define S64(x) __builtin_bswap64(x)
enum e { A = S16(1), B = S16(0x8000), C = (unsigned short)S16(0xc001) };
enum f { D = S32(1), E = S32(0x80) };
static unsigned short g1 = S16(0x1234);
static unsigned g2 = S32(0x12345678);
static unsigned long long g3 = S64(0x0102030405060708ULL);
unsigned short g4[2] = { S16(1), S16(2) };
char arr[S16(0x0100)];
_Static_assert(S32(0x01000000) == 1, "x");
_Static_assert(__builtin_constant_p(S16(1)), "y");
_Static_assert(S64(1) >> 56 == 1, "z");
_Static_assert(sizeof(__builtin_bswap16(1)) == 2, "s");
_Static_assert(__builtin_bswap16(-1) == 0xffff, "n");
_Static_assert(__builtin_bswap32(-1) > 0, "u");
_Static_assert(__builtin_bswap64(0xff) > 0, "u8");
int sw(int v) { switch (v) { case S16(1): return 1; case S16(0x200): return 2; } return 0; }
int main(void) {
	if (A != 0x100 || B != 0x80 || C != 0x1c0) return 1;
	if (D != 0x1000000 || E != (int)0x80000000) return 2;
	if (g1 != 0x3412 || g2 != 0x78563412 || g3 != 0x0807060504030201ULL) return 3;
	if (g4[1] != 0x200 || sizeof(arr) != 1) return 4;
	if (sw(0x100) != 1 || sw(2) != 2) return 5;
	return 42;
}
