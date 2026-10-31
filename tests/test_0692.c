// Dead code stays dead: Linux leaves calls to what a disabled config does not
// define in branches that fold away, and the link fails on any that survive. None
// of the functions named bug_* exists. Also `alloca` of a bounded size, which must
// work with no allocator.
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

extern void bug_mask(void), bug_cmp(void), bug_static(void), bug_nested(void), bug_static2(void);
extern const struct token *TOKEN;
extern int never_defined;

// Removing them takes optimization, in GCC and Clang too.
#ifndef __OPTIMIZE__
void bug_mask(void) {}
void bug_cmp(void) {}
void bug_static(void) {}
void bug_nested(void) {}
void bug_static2(void) {}
#endif

struct inode { unsigned i_flags; };
struct map { struct inode *host; };
#define S_DAX 0
#define IS_DAX(i) ((i)->i_flags & S_DAX)
static inline _Bool dax_mapping(struct map *m) { return m->host && IS_DAX(m->host); }
static inline _Bool mask_left(struct map *m) { return m->host && (S_DAX & m->host->i_flags); }

static inline int pmd_huge(unsigned long p) { return 0; }
static __attribute__((noinline)) int only_dead(int n) { bug_static(); return n; }
static __attribute__((noinline)) int only_dead2(int n) { bug_static2(); return only_dead(n); }

#define vcmp(A, OP, B) ({				\
	int __res = 0;					\
	if (!__builtin_strcmp(OP, "<"))			\
		__res = (long)((A) - (B)) < 0;		\
	else if (!__builtin_strcmp(OP, ">="))		\
		__res = (long)((A) - (B)) >= 0;		\
	else						\
		bug_cmp();				\
	__res;						\
})

static int t_mask(struct map *m, int x)
{
	if (dax_mapping(m))
		bug_mask();
	if (mask_left(m))
		bug_mask();
	return x;
}

static int t_static(unsigned long p, int n)
{
	if (pmd_huge(p))
		return only_dead2(n);
	return 0;
}

static int t_nested(unsigned long p)
{
	if (pmd_huge(p) || pmd_huge(p + 1)) {
		for (int i = 0; i < 3; i++)
			bug_nested();
	}
	return 1;
}

// A variable declared in a block `goto` jumps over stays usable past the dead code.
static int t_goto(void)
{
	goto skip;
	int kept;
skip:
	kept = 4;
	return kept;
}

// side effects of the left operand still happen
static int calls;
static struct inode *count_call(struct inode *i) { calls++; return i; }

static __attribute__((noinline)) unsigned bounded(unsigned x)
{
	unsigned char *p = __builtin_alloca(x & 0x3f8);
	memset(p, 7, x & 0x3f8);
	__asm__ volatile("" : : "r"(p) : "memory");
	return (x & 0x3f8) ? p[(x & 0x3f8) - 1] : 0;
}

static __attribute__((noinline)) int fixed_size(void)
{
	long *p = __builtin_alloca(4 * sizeof(long));
	for (int i = 0; i < 4; i++)
		p[i] = i;
	return p[3];
}

int main(void)
{
	struct inode in = { 3 };
	struct map m = { &in };

	CHECK(t_mask(&m, 5) == 5);
	CHECK(t_static(1, 2) == 0 && t_nested(1) == 1);
	CHECK(t_goto() == 4);
	CHECK(vcmp(1, "<", 2) == 1 && vcmp(1, ">=", 2) == 0);
	CHECK(__builtin_strcmp("a", "b") < 0 && __builtin_strcmp("b", "a") > 0);
	CHECK(__builtin_strcmp("ab", "ab") == 0);

	(void)TOKEN;
	(void)never_defined;

	int r = count_call(&in) && IS_DAX(&in);
	CHECK(r == 0 && calls == 1);

	CHECK(bounded(0x3ff) == 7 && bounded(0x7) == 0);
	CHECK(fixed_size() == 3);
	return 42;
}
