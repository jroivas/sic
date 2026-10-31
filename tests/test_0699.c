// A statement expression whose last statement has a label yields that statement's
// value. It yielded 0: Linux's FIND_NEXT_BIT ends in `out: sz; })`, so
// _find_next_bit always returned 0 and every for_each_set_bit-style loop stayed
// on bit 0 until memory ran out.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define BITS 64
#define FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS - 1)))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define FIND_NEXT(FETCH, MUNGE, size, start)					\
({										\
	unsigned long mask, idx, tmp, sz = (size), __start = (start);		\
										\
	if (__start >= sz)							\
		goto out;							\
										\
	mask = MUNGE(FIRST_WORD_MASK(__start));					\
	idx = __start / BITS;							\
										\
	for (tmp = (FETCH) & mask; !tmp; tmp = (FETCH)) {			\
		if ((idx + 1) * BITS >= sz)					\
			goto out;						\
		idx++;								\
	}									\
										\
	sz = min(idx * BITS + __builtin_ctzl(MUNGE(tmp)), sz);			\
out:										\
	sz;									\
})

static __attribute__((noinline)) unsigned long next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start)
{
	return FIND_NEXT(addr[idx], /* nop */, nbits, start);
}

int main(void)
{
	unsigned long a[2] = { 1, 0 }, b[2] = { 0x12, 0x101 };
	int n = 0, sum = 0;

	CHECK(next_bit(a, 64, 1) == 64 && next_bit(a, 64, 0) == 0 && next_bit(a, 64, 64) == 64);
	CHECK(next_bit(b, 128, 2) == 4 && next_bit(b, 128, 5) == 64 && next_bit(b, 128, 73) == 128);
	for (unsigned long i = next_bit(b, 128, 0); i < 128; i = next_bit(b, 128, i + 1)) { n++; sum += i; }
	CHECK(n == 4 && sum == 1 + 4 + 64 + 72);

	CHECK(({ int x = 5; goto l1; x = 6; l1: x; }) == 5);
	CHECK(({ int x = 7; goto l2; l2: l3: x + 1; }) == 8);
	CHECK(sizeof(({ long x = 7; goto l4; l4: x; })) == sizeof(long));
	CHECK(({ long x = 1; if (x) goto l5; x = 2; l5: x; }) == 1);
	long v = ({ long x = 1L << 40; goto l6; l6: x; });
	CHECK(v == 1L << 40);
	return 42;
}
