// sizeof, alignof and offsetof are constants to __builtin_constant_p, whether or
// not sic's simple evaluator knows their value. Linux's __DEFINE_FLEX asserts
// `__builtin_constant_p(sizeof(struct x))`.
#include <stdio.h>
#include <stddef.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct S { char a[7]; long b; };
struct flex { int n; unsigned char optional[]; };
enum { E1 = 3 };
int g;
int garr[5];

_Static_assert(__builtin_constant_p(sizeof(struct S)), "sizeof type");
_Static_assert(__builtin_constant_p(sizeof(g)), "sizeof expr");
_Static_assert(__builtin_constant_p(sizeof(struct S) * 2 + 1), "arithmetic");
_Static_assert(__builtin_constant_p(ARRAY_SIZE(garr)), "array size");
_Static_assert(__builtin_constant_p(_Alignof(struct S)), "alignof type");
_Static_assert(__builtin_constant_p(__alignof__(g)), "alignof expr");
_Static_assert(__builtin_constant_p(offsetof(struct S, b)), "offsetof");
_Static_assert(__builtin_constant_p((int)sizeof(struct S)), "cast");
_Static_assert(__builtin_constant_p(~sizeof(g)), "complement");
_Static_assert(__builtin_constant_p(!sizeof(g)), "not");
_Static_assert(__builtin_constant_p(E1 + sizeof(g)), "with an enumerator");
_Static_assert(__builtin_constant_p(sizeof(g) ? sizeof(g) : 1), "ternary");
_Static_assert(!__builtin_constant_p(g), "variable");
_Static_assert(!__builtin_constant_p(g + sizeof(g)), "variable in arithmetic");
_Static_assert(!__builtin_constant_p(sizeof(g) / 0), "division by zero");

#define DEFINE_FLEX(type, name, member, count)					\
	_Static_assert(__builtin_constant_p(count), "const count");		\
	union {									\
		unsigned char bytes[sizeof(type) + (count)];			\
		type obj;							\
	} name##_u = {};							\
	type *name = (type *)&name##_u

// A `?:` on it takes the constant arm in code too.
#define PICK(x) (__builtin_constant_p(x) ? 1 : 2)

int main(void)
{
	int l = g;

	DEFINE_FLEX(struct flex, he, optional, sizeof(struct S));
	DEFINE_FLEX(struct flex, eht, optional, sizeof(l) * 3);
	CHECK(sizeof(he_u) == 4 + sizeof(struct S));
	CHECK(sizeof(eht_u) == 16);
	he->optional[sizeof(struct S) - 1] = 9;
	CHECK(he->optional[sizeof(struct S) - 1] == 9 && eht->n == 0);

	CHECK(PICK(sizeof(l)) == 1);
	CHECK(PICK(sizeof(l) + 1) == 1);
	CHECK(PICK(l) == 2);
	CHECK(PICK(l + sizeof(l)) == 2);
	CHECK(__builtin_choose_expr(__builtin_constant_p(sizeof(l)), 1, 2) == 1);

	// `sizeof` of a local as a member's array dimension: it came out 0
	long m[3];
	short s[2];
	union { char b[sizeof(l) * 3]; int o; } u;
	struct { char b[sizeof(m)]; } st;
	struct { char x[sizeof(s[0]) + sizeof(l)]; } w;
	struct named { struct { char y[sizeof(m) / sizeof(m[0])]; } in[sizeof(l)]; } nm;
	struct { typeof(l) v[sizeof(s)]; } tv;
	typedef struct { char t[sizeof(m[0])]; } td;
	typeof(l) ta[sizeof(s)];
	CHECK(sizeof(u) == 12 && sizeof(st) == 24 && sizeof(w) == 6);
	CHECK(sizeof(struct named) == 12 && sizeof(nm.in[0].y) == 3);
	CHECK(sizeof(tv) == 16 && sizeof(td) == 8 && sizeof(ta) == 16);
	CHECK(sizeof(struct { char a[sizeof(l)]; }) == 4);
	st.b[23] = 5;
	u.o = 1;
	CHECK(st.b[23] == 5 && u.o == 1);
	return 42;
}
