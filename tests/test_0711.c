// One register variable as two asm operands is one register. Linux's call_on_stack
// has `"+r" (tos)` and `[tos] "r" (tos)`, tos in r11, and switches stacks around a call.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

static char stack[8192] __attribute__((aligned(16)));
static long seen;
static char *where;

static void __attribute__((noinline)) handler(long a, long b)
{
	char here;
	seen = a * 10 + b;
	where = &here;
}

#define call_on_stack(top, func, a1, a2) do {				\
	register void *tos asm("r11");					\
	tos = (void *)(top);						\
	asm volatile(							\
	"movq	%%rsp, (%[tos])\n"					\
	"movq	%[tos], %%rsp\n"					\
	"movq	%[arg2], %%rsi\n"					\
	"movq	%[arg1], %%rdi\n"					\
	"1: call %c[__func]\n"						\
	"popq	%%rsp\n"						\
	: "+r" (tos)							\
	: [__func] "i" (func), [tos] "r" (tos),				\
	  [arg1] "r" ((long)(a1)), [arg2] "r" ((long)(a2))		\
	: "cc", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "memory"); \
} while (0)

int main(void)
{
	long local = 7;
	call_on_stack(stack + sizeof(stack) - 16, handler, 4, 2);
	CHECK(seen == 42);
	CHECK(where >= stack && where < stack + sizeof(stack));
	CHECK(local == 7);
	return 42;
}
