// Constant expressions need type sizes everywhere one is required. A `case` holding
// `sizeof` was dropped without a word (every Linux `_IOR`/`_IOW` ioctl number), and
// the labels around it shifted: `tcgetattr` on any terminal gave ENOTTY, so no getty.
// Bit-field widths and array designators with sizeof were 0. And a switch keeps its
// promoted type (C11 6.8.4.2p5): it was cut to `int`, labels unconverted.
#include <stdio.h>
#include <stddef.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

struct t2 { unsigned a, b, c, d; unsigned char e[20]; unsigned f, g; };
#define _IOC(d, t, n, s) (((d) << 30) | ((t) << 8) | (n) | ((s) << 16))
#define _IOR(t, n, s) _IOC(2U, t, n, sizeof(s))
#define _IOW(t, n, s) _IOC(1U, t, n, sizeof(s))
#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCGETS2 _IOR('T', 0x2A, struct t2)
#define TCSETS2 _IOW('T', 0x2B, struct t2)

static int ioctls(unsigned cmd)
{
	switch (cmd) {
	case TCSETS2: return 1;
	case TCGETS2: return 2;
	case TCSETS: return 3;
	case TCGETS: return 4;
	case sizeof(struct t2): return 5;
	case (int)sizeof(long) + 100: return 6;
	case __alignof__(long) + 200: return 7;
	case offsetof(struct t2, e) + 300: return 9;
	case 0: return 8;
	default: return -1;
	}
}

static int ranges(int x)
{
	switch (x) {
	case sizeof(char) ... sizeof(long): return 1;
	case sizeof(struct t2) ... sizeof(struct t2) + 2: return 2;
	default: return 0;
	}
}

static int wide(unsigned long x)
{
	switch (x) {
	case 0x100000000UL: return 1;
	case 0xffffffffffffffffUL: return 2;
	case 5: return 3;
	case 0x200000000UL ... 0x2000000ffUL: return 4;
	case 0x8000000000000000UL ... 0x8000000000000001UL: return 5;
	default: return 0;
	}
}

static int narrow(unsigned char c, signed char s, short h)
{
	int r = 0;
	switch (c) { case 200: r += 1; break; case 0xff: r += 2; break; }
	switch (s) { case -1: r += 10; break; case 0xff: r += 20; break; }
	switch (h) { case -2: r += 100; break; }
	return r;
}

static int unsigned_range(unsigned u)
{
	switch (u) {
	case 0xf0000000u ... 0xffffffffu: return 1;
	case 1 ... 10: return 2;
	default: return 0;
	}
}

static int signed_range(int i)
{
	switch (i) {
	case -10 ... -1: return 1;
	case 0: return 2;
	default: return 0;
	}
}

static int constant(void)
{
	switch (0x100000005L) { case 5: return 1; case 0x100000005L: return 2; }
	return 0;
}

enum { E1 = sizeof(struct t2), E2 = offsetof(struct t2, e) };
struct b { unsigned x : sizeof(int); unsigned y : 2 * sizeof(short); unsigned z : offsetof(struct t2, c); };
int d1[sizeof(long) + 2] = { [sizeof(long)] = 5, [sizeof(int) ... sizeof(int) + 1] = 6 };
struct w { int v[4]; } g = { .v[sizeof(short)] = 9 };

int main(void)
{
	CHECK(ioctls(TCSETS2) == 1 && ioctls(TCGETS2) == 2);
	CHECK(ioctls(TCSETS) == 3 && ioctls(TCGETS) == 4);
	CHECK(ioctls(sizeof(struct t2)) == 5 && ioctls(108) == 6 && ioctls(208) == 7 && ioctls(316) == 9);
	CHECK(ioctls(0) == 8 && ioctls(99) == -1);

	CHECK(ranges(1) == 1 && ranges(8) == 1 && ranges(9) == 0 && ranges(44) == 2 && ranges(46) == 2);

	CHECK(wide(0x100000000UL) == 1 && wide(0) == 0 && wide(~0UL) == 2);
	CHECK(wide(0xffffffffUL) == 0 && wide(5) == 3 && wide(0x100000005UL) == 0);
	CHECK(wide(0x200000010UL) == 4 && wide(0x10UL) == 0);
	CHECK(wide(0x8000000000000001UL) == 5);

	CHECK(narrow(200, -1, -2) == 111 && narrow(255, 0, 0) == 2);
	CHECK(unsigned_range(0xf0000001u) == 1 && unsigned_range(5) == 2 && unsigned_range(0xefffffffu) == 0);
	CHECK(signed_range(-5) == 1 && signed_range(0) == 2 && signed_range(5) == 0);
	CHECK(constant() == 2);

	CHECK(E1 == 44 && E2 == 16);
	CHECK(sizeof(struct b) == 4);
	struct b bb = { 1, 2, 3 };
	CHECK(bb.z == 3);
	CHECK(d1[8] == 5 && d1[4] == 6 && d1[5] == 6 && g.v[2] == 9);
	int l[sizeof(long) + 1] = { [sizeof(int)] = 3 };
	static int s[3] = { [sizeof(short)] = 8 };
	CHECK(l[4] == 3 && s[2] == 8);
	return 42;
}
