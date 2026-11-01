// The type of `?:` comes from both arms, whichever runs: the usual arithmetic
// conversions (C11 6.5.15p5). A constant condition took the chosen arm as it was,
// in lowering and in -O2's dead-branch pass, and a run-time one kept the first arm's
// sign. GNU `sizeof(void)` is 1.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

int fn(void);

int main(void)
{
	volatile int t = 1, f = 0;
	int i = -1;
	unsigned u = 1;
	char c = 1;
	short s = 2;
	long l = 4;
	double d;

	// constant condition
	d = (1 ? 1 : 2.0) / 2;
	CHECK(d == 0.5);
	d = (0 ? 2.0f : 3) / 2;
	CHECK(d == 1.5);
	CHECK((1 ? i : u) > 0);
	CHECK((0 ? 2u : -1) > 0);
	CHECK((1 ? i : 1L) < 0);
	CHECK((1 ? -1 : 0u) == 0xffffffffu);
	CHECK(sizeof((1 ? (unsigned char)200 : 1)) == 4);

	// run-time condition
	d = (t ? 1 : 2.0) / 2;
	CHECK(d == 0.5);
	CHECK((t ? i : u) > 0);
	CHECK((f ? 2u : -1) > 0);
	CHECK((t ? i : l) == -1 && (t ? i : l) < 0);
	CHECK((t ? (unsigned char)200 : (unsigned char)1) + 100 == 300);

	// the elvis form
	CHECK((i ?: u) > 0);
	d = (c ?: 2.0) / 2;
	CHECK(d == 0.5);

	// sizeof
	CHECK(sizeof(1 ? 1 : 2.0) == 8 && sizeof(0 ? 1 : 2.0f) == 4);
	CHECK(sizeof(1 ? c : c) == 4 && sizeof(1 ? s : l) == 8);
	CHECK(sizeof(t ? c : c) == 4);
	CHECK(sizeof((char)1) == 1);
	CHECK(sizeof(1 ? 1 : 2) == 4 && sizeof(1 ? 1L : 2) == 8);

	void *v = 0;
	int *p = 0;
	CHECK(sizeof(void) == 1 && sizeof(*v) == 1 && sizeof(fn) == 1);
	CHECK(sizeof(*(1 ? p : v)) == 1 && sizeof(*(0 ? p : v)) == 1);
	CHECK(_Generic(1 ? 1 : 2.0, double: 1, default: 0));
	CHECK(_Generic(0 ? 1u : 2, unsigned: 1, default: 0));
	return 42;
}
