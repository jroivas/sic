// An always_inline function that reaches itself through ordinary functions
// (Linux's zstd: FSE_readNCount_body -> FSE_readNCount -> ..._default -> body).
// Inlining never ended; the small wrappers are all inlining candidates.

#define INL static inline __attribute__((always_inline))

int top(int n);

static int wrap2(int n)
{
	return top(n);
}

static int wrap1(int n)
{
	return wrap2(n);
}

INL int body(int n)
{
	int s = 0;

	if (n <= 0)
		return 0;
	for (int i = 0; i < n; i++)
		s += i;
	return s + wrap1(n - 1);
}

int top(int n)
{
	return body(n);
}

// An always_inline function on a cycle of two.
static int odd(int n);

INL int even(int n)
{
	return n == 0 ? 1 : odd(n - 1);
}

static int odd(int n)
{
	return n == 0 ? 0 : even(n - 1);
}

int main(void)
{
	if (top(4) != 10)	// 6 + 3 + 1 + 0
		return 1;
	if (!even(10) || even(7))
		return 2;
	return 42;
}
