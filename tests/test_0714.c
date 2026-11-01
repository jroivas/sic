// An unnamed bit-field takes up its bits but does not align the struct (SysV ABI):
// sic gave `struct { char c; long : 3; }` size 8 instead of 2.
#include <stdio.h>
#include <stddef.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

struct a { int : 1; };
struct b { char c; int : 3; char d; };
struct c { char c; int : 0; char d; };
struct d { char c; long : 3; };
struct e { long : 8; char c; };
struct f { char c; int x : 3; char d; };
struct g { short s; int : 20; char d; };
struct h { char c; long : 0; char d; };
struct i { int : 0; char c; };
struct j { unsigned a : 3; int : 5; unsigned b : 8; };
union k { int : 12; char c; };
struct l { char c[3]; int : 16; };
struct __attribute__((packed)) m { char c; int : 12; int x : 4; char d; };

#define S(t, sz, al) CHECK(sizeof(struct t) == sz && _Alignof(struct t) == al)

int main(void)
{
	S(a, 1, 1); S(b, 3, 1); S(c, 5, 1); S(d, 2, 1); S(e, 2, 1);
	S(f, 4, 4); S(g, 8, 2); S(h, 9, 1); S(i, 1, 1); S(j, 4, 4);
	S(l, 6, 1); S(m, 4, 1);
	CHECK(sizeof(union k) == 2 && _Alignof(union k) == 1);
	CHECK(offsetof(struct b, d) == 2 && offsetof(struct c, d) == 4);
	CHECK(offsetof(struct g, d) == 7 && offsetof(struct h, d) == 8);

	struct j v = { 5, 200 };
	CHECK(v.a == 5 && v.b == 200);
	struct b w = { 1, 2 };
	CHECK(w.c == 1 && w.d == 2);
	return 42;
}
