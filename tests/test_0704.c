// A variadic function reads its stack arguments where the caller left them. The
// prologue copied a fixed 64 slots, whatever the call passed: near the top of a
// stack that ran off its end (Linux's `_printk` from the first kernel thread), and
// a call with more arguments than that read garbage.
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

static __attribute__((noinline)) long sum(int n, ...)
{
	va_list ap;
	long s = 0;
	va_start(ap, n);
	for (int i = 0; i < n; i++)
		s += va_arg(ap, long);
	va_end(ap);
	return s;
}

static __attribute__((noinline)) double mixed(int n, ...)
{
	va_list ap;
	double s = 0;
	va_start(ap, n);
	for (int i = 0; i < n; i++) {
		s += va_arg(ap, int);
		s += va_arg(ap, double);
	}
	va_end(ap);
	return s;
}

// Named arguments on the stack push the varargs along.
static __attribute__((noinline)) long many_named(long a, long b, long c, long d, long e, long f, long g, long h, ...)
{
	va_list ap;
	va_start(ap, h);
	long x = va_arg(ap, long);
	long y = va_arg(ap, long);
	va_end(ap);
	return a + b + c + d + e + f + g * 10 + h * 100 + x * 1000 + y * 10000;
}

struct big { long a[4]; };
static __attribute__((noinline)) long by_value(struct big s, int n, ...)
{
	va_list ap;
	va_start(ap, n);
	long r = s.a[3];
	for (int i = 0; i < n; i++)
		r += va_arg(ap, long);
	va_end(ap);
	return r;
}

static __attribute__((noinline)) long double wide(int n, ...)
{
	va_list ap;
	va_start(ap, n);
	long double v = va_arg(ap, long double);
	long x = va_arg(ap, long);
	va_end(ap);
	return v + x;
}

static __attribute__((noinline)) struct big ret_big(int n, ...)
{
	va_list ap;
	struct big b;
	va_start(ap, n);
	for (int i = 0; i < 4; i++)
		b.a[i] = va_arg(ap, long);
	va_end(ap);
	return b;
}

static __attribute__((noinline)) int fwd(char *buf, size_t n, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = vsnprintf(buf, n, fmt, ap);
	va_end(ap);
	return r;
}

static __attribute__((noinline)) long copied(int n, ...)
{
	va_list ap, aq;
	va_start(ap, n);
	va_copy(aq, ap);
	long a = 0, b = 0;
	for (int i = 0; i < n; i++) a += va_arg(ap, long);
	for (int i = 0; i < n; i++) b += va_arg(aq, long);
	va_end(ap);
	va_end(aq);
	return a == b ? a : -1;
}

// The top of a stack with an inaccessible page right above it.
static ucontext_t main_ctx, top_ctx;
static volatile long top_result;
static void on_top(void) { top_result = sum(3, 1L, 2L, 3L); }

int main(void)
{
	CHECK(sum(0) == 0 && sum(2, 3L, 4L) == 7);
	CHECK(sum(8, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L) == 36);

	// past the old 64-slot copy
#define T(x) x##L, x##L + 1, x##L + 2, x##L + 3, x##L + 4, x##L + 5, x##L + 6, x##L + 7, x##L + 8, x##L + 9
	CHECK(sum(80, T(0), T(10), T(20), T(30), T(40), T(50), T(60), T(70)) == 3160);

	CHECK(mixed(10, 1, 0.5, 2, 0.5, 3, 0.5, 4, 0.5, 5, 0.5, 6, 0.5, 7, 0.5, 8, 0.5, 9, 0.5, 10, 0.5) == 60.0);
	CHECK(many_named(1, 2, 3, 4, 5, 6, 7, 8, 9L, 10L) == 21 + 70 + 800 + 9000 + 100000);
	struct big b = { { 1, 2, 3, 4 } };
	CHECK(by_value(b, 2, 5L, 6L) == 15);
	CHECK(by_value(b, 8, 1L, 1L, 1L, 1L, 1L, 1L, 1L, 1L) == 12);
	CHECK(wide(1, 2.5L, 3L) == 5.5L);
	struct big r = ret_big(0, 7L, 8L, 9L, 10L);
	CHECK(r.a[0] == 7 && r.a[3] == 10);

	char s[64];
	CHECK(fwd(s, sizeof(s), "%d %d %d %d %d %d %d %d %s", 1, 2, 3, 4, 5, 6, 7, 8, "x") == 17);
	CHECK(!strcmp(s, "1 2 3 4 5 6 7 8 x"));
	CHECK(copied(9, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L) == 45);

	long pg = 4096;
	char *mem = mmap(0, pg * 8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(mem != MAP_FAILED && mprotect(mem + pg * 7, pg, PROT_NONE) == 0);
	getcontext(&top_ctx);
	top_ctx.uc_stack.ss_sp = mem;
	top_ctx.uc_stack.ss_size = pg * 7;
	top_ctx.uc_link = &main_ctx;
	makecontext(&top_ctx, on_top, 0);
	swapcontext(&main_ctx, &top_ctx);
	CHECK(top_result == 6);
	return 42;
}
