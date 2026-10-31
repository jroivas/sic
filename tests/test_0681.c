// `typeof(x) x` names the outer x: the operand of typeof is not the variable
// being declared. _Generic following that chain looped forever (Linux's
// netfilter conntrack helpers), and must still see the outer x's qualifiers.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

#define CLASSIFY(x) _Generic((x), char *: 1, const char *: 2, default: 3)
#define SHADOW(v) ({ typeof(v) v2 = (v); typeof(v2) v2_ = v2; CLASSIFY(v2_); })
#define SAME(x) ({ typeof(x) x = 0; CLASSIFY(x); })

extern int ext;
typeof(ext) ext;
int ext = 4;
extern const char *cext;
typeof(cext) cext;
const char *cext = 0;

int main(void)
{
	char *m = 0;
	const char *c = 0;

	CHECK(SHADOW(m) == 1);
	CHECK(SHADOW(c) == 2);
	CHECK(SAME(m) == 1);
	CHECK(SAME(c) == 2);

	{
		typeof(c) c = 0;
		CHECK(CLASSIFY(c) == 2);
		{
			typeof(c) c = 0;
			typeof(m) m = 0;
			CHECK(CLASSIFY(c) == 2);
			CHECK(CLASSIFY(m) == 1);
			(void)c; (void)m;
		}
		(void)c;
	}

	// a pointer to the outer type, and a qualifier on the typeof itself
	int i = 7;
	int *ip = &i;
	{
		typeof(ip) ip = &i;
		typeof(*ip) j = *ip;
		const typeof(j) k = j;
		CHECK(_Generic(ip, int *: 1, default: 2) == 1);
		CHECK(_Generic(&j, int *: 1, default: 2) == 1);
		CHECK(k == 7);
	}

	static const char *st = 0;
	{
		static typeof(st) st = 0;
		CHECK(CLASSIFY(st) == 2);
		(void)st;
	}

	CHECK(_Generic(ext, int: 1, default: 2) == 1);
	CHECK(CLASSIFY(cext) == 2);
	return 42;
}
