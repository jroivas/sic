// typeof of a function nothing calls, which sic skips emitting: it still has its
// type. Linux's DECLARE_STATIC_CALL: `extern typeof(func) tramp;` with func a
// static inline nobody references.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

struct ev { int a; };
typedef unsigned long long u64;

static inline u64 unused_fn(struct ev *e, u64 *val) { return e->a + *val; }
static inline int unused_ret_int(void) { return 1; }
static inline char *unused_ptr(char *p, int n) { return p + n; }

// Same shape, a real function: what the declarations below resolve to.
u64 tramp(struct ev *e, u64 *val) { return e->a + *val + 100; }
extern typeof(unused_fn) tramp;

extern typeof(unused_ptr) tramp2;
char *tramp2(char *p, int n) { return p + n + 1; }

typeof(unused_fn) *global_fp = tramp;
typeof(&unused_fn) global_fp2 = tramp;
typeof(unused_ptr(0, 0)) *not_called;

struct holds {
	typeof(unused_fn) *fp;
	char tail;
};
_Static_assert(sizeof(struct holds) == 2 * sizeof(void *), "function pointer member");
_Static_assert(__builtin_types_compatible_p(typeof(unused_fn), typeof(tramp)), "same type");
_Static_assert(!__builtin_types_compatible_p(typeof(unused_fn), typeof(unused_ret_int)), "other type");

// A prototype only, in the same forms.
int proto_only(long, long);
typeof(proto_only) *proto_fp;
_Static_assert(sizeof(proto_fp) == sizeof(void *), "prototype");

int main(void)
{
	struct ev e = { 1 };
	u64 v = 2;
	char buf[4];
	CHECK(tramp(&e, &v) == 103);
	CHECK(global_fp(&e, &v) == 103 && global_fp2(&e, &v) == 103);
	CHECK(tramp2(buf, 1) == buf + 2);
	struct holds h = { tramp, 'x' };
	CHECK(h.fp(&e, &v) == 103 && h.tail == 'x');
	CHECK(sizeof(not_called) == sizeof(void *));
	CHECK(_Generic(global_fp, u64 (*)(struct ev *, u64 *): 1, default: 2) == 1);
	return 42;
}
