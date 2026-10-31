// A block-scope `static` or `extern` declaration obeys block scope: it hides an
// outer local, and is gone at the end of its block. And `static typeof(local)`
// has the local's type, not int.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

int g = 1;

static int after_block(void)
{
	{
		static int g = 2;
		g++;
	}
	return g;
}

static int hides_local(void)
{
	int a = 1;
	{
		static int a = 2;
		return a;
	}
}

static int extern_hides_local(void)
{
	int g = 7;
	{
		extern int g;
		return g;
	}
}

static int outer_static_back(void)
{
	static int a = 1;
	{
		static int a = 2;
		a++;
		{
			int a = 50;
			a++;
		}
		a++;
	}
	return a;
}

static int counter(void)
{
	static int n = 0;
	{
		static int n = 100;
		n++;
	}
	return ++n;
}

// Each macro expansion has its own static, like Linux's printk_once.
#define ONCE() ({ static int done; int first = !done; done = 1; first; })

static int once_each(void)
{
	int r = ONCE() * 10;
	r += ONCE();
	return r;
}

static int in_a_loop(void)
{
	int sum = 0;
	for (int i = 0; i < 3; i++) {
		static int s = 10;
		s++;
		sum += s;
	}
	return sum;
}

int main(void)
{
	CHECK(after_block() == 1);
	CHECK(hides_local() == 2);
	CHECK(extern_hides_local() == 1);
	CHECK(outer_static_back() == 1);
	CHECK(counter() == 1 && counter() == 2);
	CHECK(once_each() == 11);
	CHECK(in_a_loop() == 36);

	long x = 0;
	const char *c = "ab";
	static typeof(x) b = 5;
	static typeof(c) d;
	static typeof(*c) e[4] = { 'x' };
	static typeof(x) arr[] = { 1, 2, 3 };
	CHECK(sizeof(b) == sizeof(long) && b == 5);
	CHECK(sizeof(d) == sizeof(char *) && d == 0);
	CHECK(sizeof(e) == 4 && e[0] == 'x');
	CHECK(sizeof(arr) == 3 * sizeof(long) && arr[2] == 3);
	CHECK(_Generic(d, char *: 1, const char *: 2) == 2);
	return 42;
}
