// A struct, union or enum defined in the return type or a parameter of an
// inline function nobody calls still exists afterwards. Linux's i915 intel_gtt.h:
// `static inline struct sgt_dma { ... } sgt_dma(...) { ... }`, used only by name.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

static inline __attribute__((unused)) struct unused_s {
	void *p;
	long dma, max;
} unused_s(int a) {
	return (struct unused_s){ 0, a, a + 1 };
}

static inline __attribute__((unused)) struct ptr_s { int a; int b; } *ptr_ret(void) { return 0; }
static inline __attribute__((unused)) union unused_u { int i; char c[8]; } unused_u(void)
{
	union unused_u u = { 1 };
	return u;
}
static inline __attribute__((unused)) enum unused_e { E_A = 3, E_B } unused_e(void) { return E_A; }
inline __attribute__((unused)) static struct outer {
	struct inner { int x; } in;
	int y;
} outer_fn(void) { return (struct outer){ { 1 }, 2 }; }

static long get(struct unused_s *it) { return it->dma + it->max; }

// Called: the same, as a control.
static inline struct called_s { int v; } called_s(int a) { return (struct called_s){ a }; }

int main(void)
{
	struct unused_s s = { 0, 3, 4 };
	CHECK(get(&s) == 7);
	CHECK(sizeof(struct unused_s) == 3 * sizeof(long));

	struct ptr_s p = { 1, 2 };
	CHECK(p.b == 2 && sizeof(struct ptr_s) == 8);

	union unused_u u;
	u.i = 0x41;
	CHECK(u.c[0] == 0x41 && sizeof(union unused_u) == 8);

	enum unused_e e = E_B;
	CHECK(e == 4);

	struct outer o = { { 5 }, 6 };
	struct inner i = o.in;
	CHECK(i.x == 5 && o.y == 6);

	CHECK(called_s(9).v == 9);
	return 42;
}
