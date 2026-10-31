// typeof of an enumerator and of plain operators in a declaration outside a
// function. Linux's skbuff.c has a parameter of type `typeof(IPPROTO_IP)`.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

enum { PROTO_A = 0, PROTO_B = 6, NEG = -1 };
enum { WIDE = 0xffffffffU };
enum { WIDER = 0x1ffffffffLL };

static int pick(typeof(PROTO_A) proto, unsigned int off)
{
	switch (proto) {
	case PROTO_A: return 10 + off;
	case PROTO_B: return 20 + off;
	default: return -1;
	}
}

long gl;
char gc;
short gs;
float gf;
unsigned gu;
int arr[3];

typeof(PROTO_B) v_enum;
typeof(WIDE) v_wide;
typeof(WIDER) v_wider;
typeof(gc + gc) v_add;
typeof(gl + gc) v_long;
typeof(gu + 1) v_uns;
typeof(gf * 2) v_float;
typeof(gs << 1) v_shift;
typeof(gl << 1) v_shiftl;
typeof(gc == 1) v_cmp;
typeof(gl && gc) v_log;
typeof(!gl) v_not;
typeof(-gc) v_neg;
typeof(~gl) v_compl;
typeof((gc, gl)) v_comma;
typeof(1 ? gl : gl) v_tern;

_Static_assert(sizeof(v_enum) == 4 && sizeof(v_wide) == 4 && sizeof(v_wider) == 8, "enumerators");
_Static_assert(sizeof(v_add) == 4 && sizeof(v_long) == 8 && sizeof(v_uns) == 4, "arith");
_Static_assert(sizeof(v_float) == 4 && sizeof(v_shift) == 4 && sizeof(v_shiftl) == 8, "more arith");
_Static_assert(sizeof(v_cmp) == 4 && sizeof(v_log) == 4 && sizeof(v_not) == 4, "truth");
_Static_assert(sizeof(v_neg) == 4 && sizeof(v_compl) == 8, "unary");
_Static_assert(sizeof(v_comma) == 8 && sizeof(v_tern) == 8, "others");

static const typeof(PROTO_A) *const_ptr;
struct holds { typeof(PROTO_A) p; typeof(NEG) n; char c[sizeof(typeof(gl))]; };

int main(void)
{
	CHECK(pick(PROTO_A, 1) == 11 && pick(PROTO_B, 2) == 22 && pick(NEG, 0) == -1);
	CHECK(_Generic(v_enum, int: 1, default: 2) == 1);
	CHECK(_Generic(v_wide, unsigned: 1, default: 2) == 1);
	CHECK(_Generic(v_uns, unsigned: 1, default: 2) == 1);
	CHECK(_Generic(v_long, long: 1, default: 2) == 1);
	v_enum = -3;
	CHECK(v_enum == -3);
	v_uns = -1;
	CHECK(v_uns > 0);
	CHECK(sizeof(struct holds) == 16 && !const_ptr);
	return 42;
}
