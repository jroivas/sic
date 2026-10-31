// A cleanup in a `for` init runs once however the loop ends. `break` ran it and then
// the end of the loop's scope ran it again: Linux's scoped_guard, which only leaves
// by `break`, unlocked twice per lock, and the preempt count went negative.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

static int locks, unlocks;
typedef struct { void *p; } cls_t;
static inline void dtor(cls_t *t) { if (t->p) unlocks++; }
static inline cls_t ctor(void *x) { cls_t t = { x }; locks++; return t; }
static inline void *lock_ptr(cls_t *t) { return t->p; }
#define CLASS(var) cls_t var __attribute__((cleanup(dtor))) = ctor
#define __PASTE2(a, b) a##b
#define __PASTE(a, b) __PASTE2(a, b)
#define __scoped(_label, args...)						\
	for (CLASS(scope)(args); lock_ptr(&scope) || !0; ({ goto _label; }))	\
		if (0) {							\
_label:										\
			break;							\
		} else
#define scoped(args...) __scoped(__PASTE(l, __COUNTER__), args)

static int x;
static int balanced(void) { return locks == unlocks; }

static void one_stmt(void) { scoped(&x) x++; }
static void block(void) { scoped(&x) { x++; } }
static int returns(void) { scoped(&x) { return 5; } return 6; }
static void continues(int n) { for (int i = 0; i < n; i++) { scoped(&x) { if (i == 1) continue; x++; } } }
static void nested(void) { scoped(&x) { scoped(&x) { x++; } } }
static int leaves_by_goto(void) { scoped(&x) { goto out; } return 1; out: return 2; }

// Plain loops: by the condition, by break, by continue, by return, by goto.
static int by_cond(void) { for (cls_t c __attribute__((cleanup(dtor))) = ctor(&x); x < 0; ) ; return 0; }
static int by_break(void) { for (cls_t c __attribute__((cleanup(dtor))) = ctor(&x); ; ) break; return 0; }
static int by_return(void) { for (cls_t c __attribute__((cleanup(dtor))) = ctor(&x); ; ) return 1; }
static int by_goto(void) { for (cls_t c __attribute__((cleanup(dtor))) = ctor(&x); ; ) goto done; done: return 3; }
static int by_inner_switch(int n)
{
	int r = 0;
	for (cls_t c __attribute__((cleanup(dtor))) = ctor(&x); r < 3; r++) {
		switch (n) {
		case 1: break;
		default: return r;
		}
	}
	return r;
}
static int by_nested_loop(void)
{
	int r = 0;
	for (cls_t c __attribute__((cleanup(dtor))) = ctor(&x); ; ) {
		for (cls_t d __attribute__((cleanup(dtor))) = ctor(&x); ; ) {
			r = 1;
			break;
		}
		break;
	}
	return r;
}
static int body_cleanup(void)
{
	int n = 0;
	for (int i = 0; i < 4; i++) {
		cls_t c __attribute__((cleanup(dtor))) = ctor(&x);
		if (i == 1) continue;
		if (i == 2) break;
		n++;
	}
	return n;
}

int main(void)
{
	one_stmt();
	CHECK(locks == 1 && balanced());
	block();
	CHECK(locks == 2 && balanced());
	CHECK(returns() == 5 && locks == 3 && balanced());
	continues(3);
	CHECK(locks == 6 && balanced());
	nested();
	CHECK(locks == 8 && balanced() && x == 5);
	CHECK(leaves_by_goto() == 2 && locks == 9 && balanced());

	by_cond();
	CHECK(locks == 10 && balanced());
	by_break();
	CHECK(locks == 11 && balanced());
	CHECK(by_return() == 1 && locks == 12 && balanced());
	CHECK(by_goto() == 3 && locks == 13 && balanced());
	CHECK(by_inner_switch(1) == 3 && locks == 14 && balanced());
	CHECK(by_inner_switch(2) == 0 && locks == 15 && balanced());
	CHECK(by_nested_loop() == 1 && locks == 17 && balanced());
	CHECK(body_cleanup() == 1 && locks == 20 && balanced());
	return 42;
}
