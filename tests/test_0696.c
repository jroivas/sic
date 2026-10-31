// An address in a pointer-sized integer member, in a static initializer. sic could
// not serialize it and silently zero-filled the WHOLE object: Linux's init_task
// came out all zeros and the first kernel stack pointer was 0. A global that cannot
// be serialized is now a compile error at the element (see test_0697).
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

struct list { struct list *next, *prev; };
#define LIST_INIT(n) { &(n), &(n) }
typedef struct { unsigned long bits[2]; } cpumask_t;
extern unsigned long stack_top[];
unsigned long stack_top[4];
char other[32];
struct thread { unsigned long sp; unsigned long a; };
struct sub { struct list node; int t; };
struct scx { struct { struct list node; } dsq; int sticky; };
struct task {
	void *stack; const cpumask_t *cp; cpumask_t mask; struct sub se; struct scx x;
	char comm[16]; struct thread th; struct task *self; struct list l;
	struct { void (*fn)(void); } rb; long sess; unsigned long sigs[1];
};
static int called;
static void fn(void) { called = 1; }

struct task it __attribute__((aligned(64))) = {
	.stack = stack_top, .cp = &it.mask, .mask = { { [0 ... 1] = ~0UL } },
	.se = { .node = LIST_INIT(it.se.node), .t = 3 },
	.x = { .dsq.node = LIST_INIT(it.x.dsq.node), .sticky = -1 },
	.comm = "swapper", .th = { .sp = (unsigned long)&stack_top },
	.self = &it, .l = LIST_INIT(it.l), .rb = { .fn = fn }, .sess = (long)-1, .sigs = {{0}},
};

struct forms {
	unsigned long a, b, c, d;
	uintptr_t e;
	long f, g, h, i;
	unsigned long tail;
};
static struct forms fs = {
	.a = (unsigned long)&stack_top,
	.b = (unsigned long)stack_top,
	.c = (unsigned long)&stack_top[2],
	.d = (unsigned long)other + 8,
	.e = (uintptr_t)&other[4],
	.f = (long)fn,
	.g = (long)&fs,
	.h = (long)&fs.b,
	.i = (long)&it.th.a,
	.tail = 77,
};
// Pointer arithmetic in elements, integer arithmetic in bytes.
struct wide { long a, b; };
struct wide ws[4];
struct wide *const p1 = ws + 2;
struct wide *const p2 = &ws[3] - 1;
long *const p3 = &ws[1].b + 1;
char *const p4 = (char *)ws + 3;
const unsigned long u1 = (unsigned long)ws + 3;
const unsigned long u2 = (unsigned long)&ws[1] - 8;
const unsigned long u3 = sizeof(long) + (unsigned long)ws;
// An array member decays to its address (Linux's init_files).
struct fdt { unsigned max; void **fd; unsigned long *open_fds; unsigned long *row; };
struct files { struct fdt *fdt; struct fdt tab; unsigned long open_init[2]; void *fa[4]; unsigned long m[2][3]; };
struct files init_files = {
	.fdt = &init_files.tab,
	.tab = { .max = 64, .fd = &init_files.fa[0], .open_fds = init_files.open_init, .row = init_files.m[1] },
};

// _Generic of a null handler (Linux's device attributes).
struct device;
typedef long show_const_t(const struct device *);
typedef long store_const_t(const struct device *, int);
struct dattr { const char *name; long (*show)(struct device *); long (*store)(struct device *, int); };
#define ATTR(n, _show, _store) { .name = #n, \
	.show = _Generic(_show, show_const_t * : (void *)_show, default : _show), \
	.store = _Generic(_store, store_const_t * : (void *)_store, default : _store) }
static long a_show(struct device *d) { return 1; }
static long c_show(const struct device *d) { return 2; }
static long a_store(struct device *d, int v) { return 3; }
static struct dattr d1 = ATTR(a, a_show, NULL);
static struct dattr d2 = ATTR(b, a_show, a_store);
static struct dattr d3 = ATTR(c, c_show, NULL);

unsigned long lone = (unsigned long)&stack_top;
unsigned long list_of[] = { 1, (unsigned long)other, 3, (unsigned long)&other[1] };

int main(void)
{
	CHECK(it.stack == stack_top && it.cp == &it.mask && it.mask.bits[1] == ~0UL);
	CHECK(it.se.t == 3 && it.se.node.next == &it.se.node && it.x.sticky == -1);
	CHECK(it.x.dsq.node.prev == &it.x.dsq.node && !__builtin_strcmp(it.comm, "swapper"));
	CHECK(it.th.sp == (unsigned long)stack_top && it.self == &it && it.l.next == &it.l);
	CHECK(it.sess == -1);
	it.rb.fn();
	CHECK(called == 1);

	CHECK(fs.a == (unsigned long)stack_top && fs.b == fs.a);
	CHECK(fs.c == (unsigned long)&stack_top[2] && fs.d == (unsigned long)other + 8);
	CHECK(fs.e == (uintptr_t)&other[4] && fs.f == (long)fn);
	CHECK(fs.g == (long)&fs && fs.h == (long)&fs.b && fs.i == (long)&it.th.a);
	CHECK(p1 == &ws[2] && p2 == &ws[2] && p3 == &ws[2].a && p4 == (char *)ws + 3);
	CHECK(u1 == (unsigned long)ws + 3 && u2 == (unsigned long)ws + 8 && u3 == (unsigned long)ws + 8);
	CHECK(init_files.fdt == &init_files.tab && init_files.tab.max == 64);
	CHECK(init_files.tab.fd == &init_files.fa[0] && init_files.tab.open_fds == init_files.open_init);
	CHECK(init_files.tab.row == init_files.m[1]);
	CHECK(d1.show == a_show && !d1.store && d2.store == a_store && !d3.store && d3.show(0) == 2);
	CHECK(fs.tail == 77 && lone == (unsigned long)stack_top);
	CHECK(list_of[1] == (unsigned long)other && list_of[3] == (unsigned long)other + 1 && list_of[2] == 3);
	return 42;
}
