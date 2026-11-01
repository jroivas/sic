// A local `register T x asm("reg")` is in that register as an asm operand, whatever
// the constraint says: Linux's put_user passes its value as `"r" (__val_pu)` with
// `__val_pu` in %rax, for a helper that reads %rax. sic put it anywhere, and the new
// process's argc was a kernel stack address.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

__asm__(".text\n.globl helper_rax\nhelper_rax:\n\tmov %rax, %rcx\n\tret\n");

static long via_helper(long x)
{
	long ret;
	void *p = 0;
	register long val asm("%rax");
	val = x;
	asm volatile("call helper_rax" : "=c"(ret) : "0"(p), "r"(val) : "ebx", "memory");
	return ret;
}

// The same name in another register, in another function.
static long other_reg(long x)
{
	long ret;
	register long val asm("r10") = x;
	asm volatile("mov %%r10, %0" : "=r"(ret) : "r"(val));
	return ret;
}

static long in_rdi(int x)
{
	int ret;
	register int v asm("edi") = x;
	asm volatile("movl %%edi, %0" : "=r"(ret) : "r"(v));
	return ret;
}

static long output(void)
{
	register long o asm("r11");
	asm volatile("mov $55, %%r11" : "=r"(o));
	return o;
}

static long both(long a, long b)
{
	register long x asm("r8") = a;
	register long y asm("r9") = b;
	register long r asm("rax");
	asm volatile("lea (%%r8,%%r9), %%rax" : "=r"(r) : "r"(x), "r"(y));
	return r;
}

// Only asm operands are bound: the variable is ordinary everywhere else.
static long ordinary(long a)
{
	register long v asm("r12") = a;
	v += 1;
	return v * 2;
}

long val = 9;	// a global of that name stays a plain variable

int main(void)
{
	CHECK(via_helper(12345) == 12345);
	CHECK(via_helper(-1) == -1);
	CHECK(other_reg(777) == 777);
	CHECK(in_rdi(21) == 21);
	CHECK(output() == 55);
	CHECK(both(40, 2) == 42);
	CHECK(ordinary(3) == 8);
	CHECK(val == 9);
	return 42;
}
