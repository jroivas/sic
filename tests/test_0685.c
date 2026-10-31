// `++x`, `x--` and va_arg have their operand's type, not int, wherever only the
// type is asked for: sizeof, typeof, _Generic and the shift-count warning (which
// -Werror turned into a failure on Linux's af_unix.c: `(++bucket) << 54`).
#include <stdio.h>
#include <stdarg.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

#define SHIFT 54
#define SET(b, o) ((b) << SHIFT | (o))

struct bits { unsigned long long wide : 40; unsigned narrow : 3; };

static int vatype(int n, ...)
{
	va_list ap;
	va_start(ap, n);
	// none of these reads an argument: they are not evaluated
	int r = sizeof(va_arg(ap, long)) * 10 + sizeof(va_arg(ap, char *));
	r += _Generic(va_arg(ap, double), double: 100, default: 0);
	long v = va_arg(ap, long);
	va_end(ap);
	return v == 7 ? r : -1;
}

int main(void)
{
	unsigned long b = 1;
	unsigned char c = 200;
	short s = 1;
	long a[2] = { 0, 0 };
	long *p = a;
	char *cp = 0;
	struct bits bf = { 0, 0 };

	CHECK(SET(++b, 1) == 0x80000000000001UL);
	CHECK(SET(b--, 0) == 0x80000000000000UL);
	CHECK(b == 1);
	CHECK(((--b) + 1) << 40 == 1UL << 40);

	// the operand is not evaluated, and has its own type
	CHECK(sizeof(++c) == 1 && sizeof(c++) == 1 && c == 200);
	CHECK(sizeof(++s) == sizeof(short) && sizeof(s--) == sizeof(short));
	CHECK(sizeof(++b) == sizeof(long) && sizeof(b--) == sizeof(long));
	CHECK(sizeof(p++) == sizeof(long *) && sizeof(*p++) == sizeof(long) && p == a);
	CHECK(sizeof(*++cp) == 1 && !cp);
	CHECK(sizeof(a[0]++) == sizeof(long));

	typeof(++b) t1;
	typeof(c++) t2;
	typeof(--p) t3 = a;
	CHECK(sizeof(t1) == sizeof(long) && sizeof(t2) == 1 && t3 == a);
	CHECK(_Generic(++b, unsigned long: 1, default: 2) == 1);
	CHECK(_Generic(c++, unsigned char: 1, default: 2) == 1);
	CHECK(_Generic(p--, long *: 1, default: 2) == 1);

	// the usual promotions still apply to the arithmetic around it
	CHECK(sizeof((++c) + 0) == sizeof(int));
	c = 200;
	CHECK((++c) << 1 == 402);

	(void)bf; (void)t1; (void)t2;
	CHECK(vatype(1, 7L) == 188);
	return 42;
}
