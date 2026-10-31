// _Generic on a variable declared through typeof/__auto_type, and on casts:
// pointee qualifiers known only behind typeof must not block (or fake) a match.
// Linux's drivers/acpi/property.c selects on a `typeof((u8 *)val) __val`.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

typedef unsigned char u8;
typedef unsigned long long u64;
typedef int *intp;
typedef const char *ccp;

#define UINT_KIND(val) ({ typeof(val) __val = val; \
	_Generic(__val, u8 *: 8, unsigned short *: 16, unsigned *: 32, u64 *: 64); })

#define CLASSIFY(x) _Generic((x), char *: 1, const char *: 2, default: 3)

static int kind_all(void *val)
{
	return UINT_KIND((u8 *)val) + UINT_KIND((unsigned short *)val) +
	       UINT_KIND((unsigned *)val) + UINT_KIND((u64 *)val);
}

const char *gcs;
typeof(gcs) gcs2;

int main(void)
{
	void *p = 0;
	const void *q = 0;
	char *m = 0;
	const char *c = 0;

	CHECK(kind_all(p) == 120);

	// the qualifiers come through typeof from the operand
	typeof(m) tm = 0;
	typeof(c) tc = 0;
	typeof(tc) ttc = 0;
	CHECK(CLASSIFY(tm) == 1);
	CHECK(CLASSIFY(tc) == 2);
	CHECK(CLASSIFY(ttc) == 2);
	CHECK(CLASSIFY(gcs2) == 2);

	// a cast decides them; the operand's own do not matter
	CHECK(CLASSIFY((char *)c) == 1);
	CHECK(CLASSIFY((const char *)m) == 2);
	typeof((char *)q) cast_m = 0;
	CHECK(CLASSIFY(cast_m) == 1);

	// deref, and a name shadowed in an inner block
	const char *const *pc = 0;
	char **pm = 0;
	CHECK(_Generic(*pc, char *: 1, const char *: 2) == 2);
	CHECK(_Generic(*pm, char *: 1, const char *: 2) == 1);
	const char *s = 0;
	{
		char *s = 0;
		CHECK(CLASSIFY(s) == 1);
		(void)s;
	}
	CHECK(CLASSIFY(s) == 2);

	// a typeof association
	CHECK(_Generic(c, typeof(m): 1, typeof(c): 2) == 2);

	// __auto_type: only has to find the unqualified match
	__auto_type a = (u8 *)p;
	CHECK(_Generic(a, u8 *: 1, u64 *: 2) == 1);

	// a typedef below a pointer has fewer known levels on one side
	int i = 0;
	int *ip = &i;
	intp *ipp = &ip;
	int **ipp2 = &ip;
	CHECK(_Generic(ipp, int **: 1, default: 2) == 1);
	CHECK(_Generic(ipp2, intp *: 1, default: 2) == 1);
	ccp cc = 0;
	CHECK(_Generic(&cc, const char **: 1, default: 2) == 1);

	(void)tm; (void)tc; (void)ttc; (void)cast_m; (void)a; (void)cc;
	return 42;
}
