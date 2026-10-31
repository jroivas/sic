// A statement expression ending in a struct is that struct's address internally,
// like any aggregate. It loaded the bytes and then read through them: READ_ONCE()
// of Linux's one-field pmd_t dereferenced the page table entry as a pointer.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

typedef struct { unsigned long pmd; } pmd_t;
struct two { int a; int b; };
struct big { long a, b, c; };
union un { int i; long l; };

#define __cases(type) unsigned type: (unsigned type)0, signed type: (signed type)0
#define __unqual_scalar_typeof(x) typeof(_Generic((x), char: (char)0, __cases(char), __cases(short), \
		__cases(int), __cases(long), __cases(long long), default: (x)))
#define __READ_ONCE(x) (*(const volatile __unqual_scalar_typeof(x) *)&(x))
#define READ_ONCE(x) ({ _Static_assert(sizeof(x) <= 32, "size"); __READ_ONCE(x); })

static __attribute__((noinline)) pmd_t get(pmd_t *p) { return READ_ONCE(*p); }
static __attribute__((noinline)) struct two get2(struct two *p) { return READ_ONCE(*p); }
static __attribute__((noinline)) struct big get3(struct big *p) { return READ_ONCE(*p); }
static __attribute__((noinline)) union un get4(union un *p) { return READ_ONCE(*p); }
static __attribute__((noinline)) long getl(long *p) { return READ_ONCE(*p); }
static __attribute__((noinline)) unsigned long field(pmd_t *p) { pmd_t v = READ_ONCE(*p); return v.pmd; }
static __attribute__((noinline)) unsigned long through(pmd_t *p) { return READ_ONCE(*p).pmd; }
static __attribute__((noinline)) struct two by_value(struct two t) { t.a++; return t; }
static __attribute__((noinline)) struct two made(void) { return ({ struct two t = { 8, 9 }; t; }); }

int main(void)
{
	pmd_t m = { 0x1234 };
	struct two t = { 3, 4 };
	struct big b = { 5, 6, 7 };
	union un u = { .l = 1L << 40 };
	long l = 8;

	CHECK(get(&m).pmd == 0x1234 && get2(&t).b == 4 && get2(&t).a == 3);
	CHECK(get3(&b).c == 7 && get4(&u).l == 1L << 40 && getl(&l) == 8);
	CHECK(field(&m) == 0x1234 && through(&m) == 0x1234);
	CHECK(by_value(({ t; })).a == 4 && t.a == 3);
	CHECK(made().b == 9);

	pmd_t c = ({ m; });
	m.pmd = 1;
	CHECK(c.pmd == 0x1234);
	struct big d = ({ struct big e = { 1, 2, 3 }; e; });
	CHECK(d.c == 3);
	struct two arr[2] = { [1] = ({ t; }) };
	CHECK(arr[1].b == 4);
	CHECK((({ t; })).a == 3 && sizeof(({ b; })) == 3 * sizeof(long));
	return 42;
}
