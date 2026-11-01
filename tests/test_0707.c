// Linux's DEFINE_FLEX: `union { u8 bytes[struct_size_t(type, member, count)]; type obj; }`.
// The length needs `__is_constexpr`, and that needs the conditional's type: a null
// pointer constant takes the other arm's (C11 6.5.15p6). Typed `void *`, the count
// looked non-constant and the on-stack buffer had no room for its flexible array.
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

typedef unsigned char u8;
static inline unsigned long size_add(unsigned long a, unsigned long b) { return a + b; }
static inline unsigned long size_mul(unsigned long a, unsigned long b) { return a * b; }
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define BUILD0(e, msg) ((int)sizeof(struct {_Static_assert(!(e), msg);}))
#define __is_array(a) (!__same_type((a), &(a)[0]))
#define __must_be_array(a) BUILD0(!__is_array(a), "must be array")
#define __is_constexpr(x) (sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define flex_array_size(p, member, count) \
	__builtin_choose_expr(__is_constexpr(count), \
		(count) * sizeof(*(p)->member) + __must_be_array((p)->member), \
		size_mul(count, sizeof(*(p)->member) + __must_be_array((p)->member)))
#define struct_size(p, member, count) \
	__builtin_choose_expr(__is_constexpr(count), \
		sizeof(*(p)) + flex_array_size(p, member, count), \
		size_add(sizeof(*(p)), flex_array_size(p, member, count)))
#define struct_size_t(type, member, count) struct_size((type *)NULL, member, count)
#define DEFINE_FLEX(type, name, member, count) \
	union { u8 bytes[struct_size_t(type, member, count)]; type obj; } name##_u = { }; \
	type *name = (type *)&name##_u

struct fh { unsigned n; int t; unsigned char h[]; };
struct wide { long a; int v[]; };
struct at_file { int x[struct_size_t(struct fh, h, 12)]; };
enum { COUNT = 6 };

struct pt { int a, b; };

int main(void)
{
	DEFINE_FLEX(struct fh, f, h, 12);
	CHECK(sizeof(f_u) == 20);
	memset(f->h, 0x5a, 12);
	CHECK(f->h[11] == 0x5a && f->n == 0);

	DEFINE_FLEX(struct wide, w, v, COUNT);
	CHECK(sizeof(w_u) == 32);
	w->v[COUNT - 1] = 3;
	CHECK(w->v[5] == 3);
	CHECK(sizeof(struct at_file) == 80);

	// not constant: the run-time arm
	int n = 12;
	CHECK(!__is_constexpr(n) && __is_constexpr(12) && __is_constexpr(COUNT + 1));
	CHECK(struct_size(f, h, n) == 20);

	// the conditional's type
	int v[2] = { 7, 8 }, *p = v;
	void *vp = v;
	struct pt s = { 1, 2 }, *sp = &s;
	CHECK(sizeof(*(1 ? (void *)0 : p)) == sizeof(int));
	CHECK(sizeof(*(1 ? p : (void *)0)) == sizeof(int));
	CHECK(sizeof(*(1 ? p : 0)) == sizeof(int));
	CHECK(sizeof(*(1 ? 0 : sp)) == sizeof(struct pt));
	CHECK(sizeof(*(1 ? vp : p)) == 1 && sizeof(*(1 ? p : vp)) == 1);
	CHECK(*(n ? p : (void *)0) == 7);
	CHECK((n ? (void *)0 : sp) == 0);
	CHECK((!n ? (void *)0 : sp)->b == 2);
	CHECK((n ? sp : NULL)->a == 1);
	return 42;
}
