// An attribute opening a grouped declarator: the name inside was lost, and a
// struct member vanished. Linux's prmt.c: `efi_status_t (__efiapi *handler_addr)(u64, void *)`.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define ATTR __attribute__((noinline))
#define UNUSED __attribute__((unused))

struct s {
	int g;
	long (UNUSED *h)(long, void *);
	long x;
	int (UNUSED UNUSED *arr[2])(int);
	int (UNUSED plain);
};

typedef long (UNUSED *fn_t)(long);
typedef int (UNUSED arr_t)[3];

static long add1(long a, void *b) { (void)b; return a + 1; }
static long add2(long a) { return a + 2; }
static int twice(int a) { return a * 2; }

static long (UNUSED *gp)(long) = add2;
static int (UNUSED gv) = 5;
static int (UNUSED func_named)(int a) { return a + 3; }

// In a parameter these are a function type, not a group.
static int unnamed_param(int (UNUSED int a));
static int unnamed_param(int (*f)(int)) { return f(1); }
static int cb_param(long (UNUSED *cb)(long)) { return cb(1); }
static int (UNUSED *ret_fn(void))(int) { return twice; }

int main(void)
{
	struct s v = { .g = 1, .h = add1, .x = 7, .arr = { twice, twice }, .plain = 9 };
	CHECK(v.h(1, 0) == 2);
	CHECK(v.x == 7 && v.plain == 9);
	CHECK(v.arr[1](4) == 8);
	CHECK(sizeof(struct s) == 6 * sizeof(long));

	fn_t f = add2;
	long (UNUSED *l)(long) = add2;
	long (UNUSED *q)(long) = (long (UNUSED *)(long))add2;
	arr_t a = { 1, 2, 3 };
	CHECK(f(1) == 3 && l(2) == 4 && q(3) == 5 && gp(4) == 6);
	CHECK(sizeof(a) == 12 && a[2] == 3);
	CHECK(gv == 5 && func_named(1) == 4);
	CHECK(unnamed_param(twice) == 2);
	CHECK(cb_param(add2) == 3);
	CHECK(ret_fn()(5) == 10);
	return 42;
}
