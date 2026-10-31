// Locals seen through once inlined. Linux needs each of these proved or its link
// fails, in the shapes it writes them: the seqlock canary, a parameter that is the
// same constant at every call of a `static` function, and a table only an inlined
// stub's unused argument refers to. The rest must not be folded.
#include <stdio.h>
#include <setjmp.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define __always_inline inline __attribute__((__always_inline__))
#define __cleanup(f) __attribute__((__cleanup__(f)))

extern void bug_seqlock(void), bug_target(void), bug_thp(void), bug_dax(void);
// Removing them takes optimization, in GCC and Clang too.
#ifndef __OPTIMIZE__
void bug_seqlock(void) {}
void bug_target(void) {}
void bug_thp(void) {}
void bug_dax(void) {}
#endif

// include/linux/seqlock.h, with a sequence counter that fails `retries` times.
typedef struct { unsigned seq; int lock; int locked; } seqlock_t;
enum ss_state { ss_done = 0, ss_lock = 1, ss_lock_irqsave = 2, ss_lockless = 3 };
struct ss_tmp { enum ss_state state; unsigned long data; int *lock; int *lock_irqsave; };

static int retries;
static __attribute__((noinline)) unsigned read_seqbegin(seqlock_t *l) { return l->seq; }
static __attribute__((noinline)) int read_seqretry(seqlock_t *l, unsigned s) { return retries-- > 0; }
static __attribute__((noinline)) void spin_lock(int *l) { ++*l; }
static __attribute__((noinline)) void spin_unlock(int *l) { --*l; }
static __attribute__((noinline)) unsigned long lock_irqsave(int *l) { ++*l; return 9; }
static __attribute__((noinline)) void unlock_irqrestore(int *l, unsigned long f) { --*l; }
#define spin_lock_irqsave(l, f) do { (f) = lock_irqsave(l); } while (0)

static __always_inline void __scoped_seqlock_cleanup(struct ss_tmp *sst)
{
	if (sst->lock)
		spin_unlock(sst->lock);
	if (sst->lock_irqsave)
		unlock_irqrestore(sst->lock_irqsave, sst->data);
}

static __always_inline void
__scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
{
	switch (sst->state) {
	case ss_done:
		bug_seqlock();
		return;
	case ss_lock:
	case ss_lock_irqsave:
		sst->state = ss_done;
		return;
	case ss_lockless:
		if (!read_seqretry(lock, sst->data)) {
			sst->state = ss_done;
			return;
		}
		break;
	}

	switch (target) {
	case ss_done:
		bug_target();
		return;
	case ss_lock:
		sst->lock = &lock->lock;
		spin_lock(sst->lock);
		sst->state = ss_lock;
		return;
	case ss_lock_irqsave:
		sst->lock_irqsave = &lock->lock;
		spin_lock_irqsave(sst->lock_irqsave, sst->data);
		sst->state = ss_lock_irqsave;
		return;
	case ss_lockless:
		sst->data = read_seqbegin(lock);
		return;
	}
}

static __always_inline void __cleanup_ctx(struct ss_tmp **s) {}

#define PASTE2(a, b) a##b
#define PASTE(a, b) PASTE2(a, b)
#define scoped_seqlock_read(_seqlock, _target) __read(_seqlock, _target, PASTE(_s, __LINE__), PASTE(_c, __LINE__))
#define __read(_seqlock, _target, _s, _c)					\
	for (struct ss_tmp _s __cleanup(__scoped_seqlock_cleanup) =		\
	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) },		\
	     *_c __cleanup(__cleanup_ctx) = (struct ss_tmp *)_seqlock;		\
	     _s.state != ss_done;						\
	     __scoped_seqlock_next(&_s, _seqlock, _target))

static int passes(seqlock_t *l, enum ss_state unused)
{
	int n = 0;
	scoped_seqlock_read (l, ss_lock) { n++; }
	return n;
}

static int passes_irq(seqlock_t *l)
{
	int n = 0;
	scoped_seqlock_read (l, ss_lock_irqsave) { n += l->lock; }
	return n;
}

static int leaves_early(seqlock_t *l)
{
	scoped_seqlock_read (l, ss_lock_irqsave) {
		if (l->seq == 5)
			return 1;
	}
	return 2;
}

// mm/swap_state.c with THP off.
static inline int highest_order(unsigned long orders) { return 0; }
static inline int next_order(unsigned long *orders, int prev) { *orders &= ~(1UL << prev); return 0; }

static __attribute__((noinline)) int alloc_one(unsigned gfp, unsigned order, int fail)
{
	if (fail)
		return 0;
	if (order)
		bug_thp();
	return gfp + order;
}

static int alloc(unsigned gfp, unsigned long orders, int fail)
{
	int order = highest_order(orders), ret = 0;

	if (!orders)
		return -1;
	do {
		ret = alloc_one(gfp, order, fail);
		if (ret)
			break;
		order = next_order(&orders, order);
	} while (orders);
	return ret;
}

// drivers/md/dm.c with DAX off.
struct dax_ops { long (*access)(void *); };
static long dm_access(void *d) { bug_dax(); return 1; }
static const struct dax_ops dm_ops = { .access = dm_access };
static inline void *alloc_dax(void *p, const struct dax_ops *ops) { return (void *)-95L; }

static long dm_setup(void *m)
{
	void *d = alloc_dax(m, &dm_ops);
	return (long)d == -95 ? 0 : 1;
}

// None of these may be folded.
static jmp_buf jb;
static void hop(void) { longjmp(jb, 1); }
static __attribute__((noinline)) int after_longjmp(void) { int x = 1; if (!setjmp(jb)) { x = 2; hop(); } return 7; }
static int volatile_read(void) { volatile int v = 3; int r = 0; for (int i = 0; i < 3; i++) if (v != 3) r++; return r; }
static void set9(int *p) { *p = 9; }
static int escaped(void) { int x = 0; set9(&x); return x == 0; }
static int loop_carried(int n) { int s = 0, r = 0; for (int i = 0; i < n; i++) { if (s == 2) r += 10; s = s == 0 ? 1 : 2; } return r; }
static int state_machine(int n)
{
	int s = 0, c = 0;
	while (n--) {
		switch (s) {
		case 0: s = 1; break;
		case 1: s = 2; c += 1; break;
		case 2: c += 10; break;
		default: c += 100;
		}
	}
	return c;
}
struct st { int a; short b; char c; long d; };
static int fields(int n) { struct st s = { 0 }; s.b = 5; if (n) s.a = 7; if (s.b != 5) return 1; if (s.a == 7) return 2; return s.c == 0 ? 3 : 4; }
union un { int i; char c[4]; };
static int overlap(void) { union un x; x.i = 0; x.c[1] = 1; return x.i == 256; }
static int signs(void) { unsigned char c = 200; signed char d = -1; int r = 0; if (c == 200) r++; if (d == -1) r++; if ((signed char)c < 0) r++; if ((unsigned char)d == 255) r++; return r; }
static int bits_of_double(void) { double d = -2.0; return __builtin_signbit(d) != 0; }
static __attribute__((noinline)) int two_args(int a, int b) { return a * 10 + b; }
static int same_first(int n) { return two_args(4, n) + two_args(4, n + 1); }
static __attribute__((noinline)) int by_pointer(int a) { return a; }
static int (*fp)(int) = by_pointer;
static int kept_param(void) { return by_pointer(1) + fp(2); }
static __attribute__((noinline)) signed char narrow_param(signed char a) { return a < 0; }
static int narrow_arg(void) { return narrow_param(-1) + narrow_param(-1); }
static int goto_around(int n) { int s = 1; if (n) goto mid; s = 2; mid: return s; }
static int logical(void) { int e = 0, f = 1; return (e || (f && f)) + ((e && e) || f); }

int main(void)
{
	seqlock_t l = { 0, 0, 0 };

	retries = 0;
	CHECK(passes(&l, ss_done) == 1);
	retries = 1;
	CHECK(passes(&l, ss_done) == 2 && l.lock == 0);
	retries = 1;
	CHECK(passes_irq(&l) == 1 && l.lock == 0);
	l.seq = 5;
	retries = 0;
	CHECK(leaves_early(&l) == 1 && l.lock == 0);
	l.seq = 6;
	CHECK(leaves_early(&l) == 2);

	CHECK(alloc(8, 1, 0) == 8 && alloc(8, 1, 1) == 0 && alloc(8, 0, 0) == -1);
	CHECK(dm_setup(&l) == 0);

	CHECK(after_longjmp() == 7 && volatile_read() == 0 && escaped() == 0);
	CHECK(loop_carried(4) == 20 && state_machine(4) == 21);
	CHECK(fields(1) == 2 && fields(0) == 3 && overlap() == 1 && signs() == 4);
	CHECK(bits_of_double() == 1 && same_first(1) == 83 && kept_param() == 3);
	CHECK(narrow_arg() == 2 && goto_around(1) == 1 && goto_around(0) == 2 && logical() == 2);
	return 42;
}
