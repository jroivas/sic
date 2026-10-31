// Branches folded from constants, once the function is inlined: 128-bit values and
// narrow unsigned shifts evaluate at their own width, and a shift count past the
// width is left alone. The folder treated everything as 64 bits.
#include <stdio.h>
#include <stdint.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

static inline uint64_t hi(__int128 a) { return (uint64_t)(a >> 64); }
static inline unsigned __int128 mul(unsigned __int128 a, unsigned __int128 b) { return a * b; }
static inline unsigned lsr32(unsigned x, int n) { return x >> n; }
static inline unsigned short lsr16(unsigned short x) { return (unsigned short)(x >> 4); }
static inline int asr32(int x) { return x >> 4; }
static inline unsigned shl32(unsigned x) { return x << 31; }
static inline int cmp128(__int128 a, __int128 b) { return a < b; }

int main(void)
{
	if (hi((__int128)0x8000000) != 0)
		CHECK(0);
	if (hi((__int128)1 << 100) != 0x1000000000ULL)
		CHECK(0);
	if ((uint64_t)(mul((unsigned __int128)1 << 40, (unsigned __int128)1 << 40) >> 64) != 0x10000)
		CHECK(0);
	if (!cmp128(-((__int128)1 << 70), 0))
		CHECK(0);
	if (cmp128((__int128)1 << 70, 1))
		CHECK(0);

	if (lsr32(0xffffffffU, 4) != 0x0fffffffU)
		CHECK(0);
	if (lsr16((unsigned short)0xffff) != 0x0fff)
		CHECK(0);
	if (asr32(-16) != -1)
		CHECK(0);
	if (shl32(3) != 0x80000000U)
		CHECK(0);
	return 42;
}
