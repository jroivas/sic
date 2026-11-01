// Array member lengths that need type sizes: `__builtin_clzll` of an expression with
// sizeof, sizeof of an arithmetic expression. They came out 0, and every later member
// moved: Linux's `vmemmap_tails[NR_VMEMMAP_TAILS]` left `struct zone` 128 bytes short,
// so `next_zone` walked into the middle of the node and a pointer was read as a page.
#include <stdio.h>
#include <stddef.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

struct page { long a[8]; };
#define PAGE_SIZE (1UL << 12)
#define PAGE_SHIFT 12
#define SZ_16G 0x0000000400000000ULL
#define ilog2(n) (__builtin_constant_p(n) ? ((n) < 2 ? 0 : 63 - __builtin_clzll(n)) : (sizeof(n) <= 4) ? 1 : 2)
#define MAX_ORDER (ilog2(SZ_16G) - PAGE_SHIFT)
#define MIN_ORDER (ilog2(2 * PAGE_SIZE / sizeof(struct page)))
#define NR_RAW (MAX_ORDER - MIN_ORDER + 1)
#define NR (NR_RAW > 0 ? NR_RAW : 0)

struct zone { long x; struct page *tails[NR]; long y; };
struct zones { struct zone z[3]; int after; };
union u { char a[NR]; long b; };
struct clz { int a[63 - __builtin_clzll(4096UL / sizeof(struct page))]; };
struct ctz { int a[__builtin_ctzll(sizeof(struct page))]; };
struct pop { int a[__builtin_popcountll(sizeof(struct page) - 1)]; };
struct cl32 { int a[31 - __builtin_clz((unsigned)sizeof(struct page))]; };
struct swap { int a[__builtin_bswap16((unsigned short)(sizeof(struct page) << 8))]; };
struct se { int a[sizeof(4096UL / sizeof(struct page))]; };
struct se4 { int a[sizeof(1 + 2)]; };
struct se1 { int a[sizeof((char)1 + 2)]; };
struct cond { int a[(sizeof(4096UL / sizeof(struct page)) <= 4) ? 1 : 2]; };
struct nest { int a[NR][ilog2(sizeof(struct page))]; };
struct flex { int n; int a[]; };
struct zero { int n; int a[0]; int m; };

int main(void)
{
	CHECK(NR == 16);
	CHECK(sizeof(struct zone) == 8 + 16 * 8 + 8);
	CHECK(offsetof(struct zone, y) == 136);
	CHECK(offsetof(struct zones, after) == 432);
	CHECK(sizeof(union u) == 16);
	CHECK(sizeof(struct clz) == 6 * 4);
	CHECK(sizeof(struct ctz) == 6 * 4);
	CHECK(sizeof(struct pop) == 6 * 4);
	CHECK(sizeof(struct cl32) == 6 * 4);
	CHECK(sizeof(struct swap) == 64 * 4);
	CHECK(sizeof(struct se) == 8 * 4);
	CHECK(sizeof(struct se4) == 4 * 4);
	CHECK(sizeof(struct se1) == 4 * 4);
	CHECK(sizeof(struct cond) == 2 * 4);
	CHECK(sizeof(struct nest) == 16 * 6 * 4);
	CHECK(sizeof(struct flex) == 4 && sizeof(struct zero) == 8);

	struct zones zs;
	zs.z[1].y = 5;
	zs.z[1].tails[15] = 0;
	CHECK(&zs.z[2] == &zs.z[1] + 1 && zs.z[1].y == 5);
	return 42;
}
