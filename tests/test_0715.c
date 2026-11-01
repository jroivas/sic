// `static inline` bodies are parsed only when something names them. Every way of
// naming one has to count, and a delayed body must parse as it would have in place.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

// only through another inline, in a chain
static inline int leaf(int x) { return x + 1; }
static inline int mid(int x) { return leaf(x) * 2; }
static inline int top(int x) { return mid(x) + 3; }

// mutual recursion
static inline int odd(int n);
static inline int even(int n) { return n == 0 ? 1 : odd(n - 1); }
static inline int odd(int n) { return n == 0 ? 0 : even(n - 1); }

// only by address, in a static initializer
static inline int by_ptr(void) { return 7; }
static int (*fp)(void) = by_ptr;
static inline int in_table(void) { return 8; }
static int (*table[2])(void) = { 0, in_table };

// only in asm text: `used` keeps it
static inline __attribute__((used)) int by_asm(int x) { return x + 100; }
long call_it(long x);
__asm__(".text\n.globl call_it\ncall_it:\n\tjmp by_asm\n");

// only through alias
static inline int aliased(void) { return 11; }
int the_alias(void) __attribute__((alias("aliased")));

// only in sizeof and typeof: a prototype must be enough
static inline long only_sizeof(void) { return 1; }
static inline short only_typeof(void) { return 1; }

// a parameter or local named like a typedef, delayed to after every typedef
typedef int T;
static inline int shadow(int T) { int r = T * 2; return r; }
static inline int local_shadow(void) { int T = 4; return T * T; }

// a typedef declared after the inline: the body meant the variable
int later = 6;
static inline int before_typedef(int a) { return a * later; }
typedef long after_t;

// a local struct, static and label
static inline int inner(int x)
{
	static int count;
	struct local { int v; } l = { x };
	goto out;
out:
	return l.v + ++count;
}

// never named: not even parsed
static inline int unused_one(int x) { return x / 0; }

// a constant of an enum declared in a body
static inline int local_enum(void) { enum { A = 5, B }; return B; }

int main(void)
{
	CHECK(top(1) == 7);
	CHECK(even(10) == 1 && odd(7) == 1);
	CHECK(fp() == 7 && table[1]() == 8);
	CHECK(call_it(1) == 101);
	CHECK(the_alias() == 11);
	CHECK(sizeof(only_sizeof()) == 8 && sizeof(typeof(only_typeof())) == 2);
	CHECK(shadow(3) == 6 && local_shadow() == 16);
	CHECK(before_typedef(7) == 42);
	CHECK(inner(1) == 2 && inner(1) == 3);
	CHECK(local_enum() == 6);
	return 42;
}
