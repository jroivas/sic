// `__auto_type` as a for-init declaration (Linux's scoped_user_rw_access): the
// loop deleter asked for the type before the initializer was seen. Its cleanup
// attribute was also dropped, and `({ auto x = e; x; })` had no type.
struct S { int a; };

static int ends;

static void done(const struct S *const *p)
{
	ends += (*p)->a;
}

static void done_i(long *p)
{
	ends += *p;
}

#define scoped(p, elbl)							\
	for (_Bool fin = 0; !fin; fin = 1)				\
		for (__auto_type tmp = ({ if (!(p)) goto elbl; (p); }); !fin; fin = 1) \
			for (const __auto_type p __attribute__((cleanup(done))) = tmp; \
			     !fin; fin = 1)

static int rd(const struct S *u)
{
	int v = -1;

	scoped(u, fault) {
		v = u->a;
	}
	return v;
fault:
	return -2;
}

static int leave_goto(const struct S *u)
{
	scoped(u, fault) {
		if (u->a > 0)
			goto fault;
	}
	return 0;
fault:
	return 1;
}

// Linux's unsafe_get_user: leave through a local label in a dead block.
static int leave_local(const struct S *u)
{
	scoped(u, fault) {
		do {
			__label__ local;

			asm goto("jmp %l[local]" : : : : local);
			if (0) {
local:
				goto fault;
			}
		} while (0);
		return 0;
	}
	return 0;
fault:
	return 1;
}

static int back_count;

static void back_end(int *p)
{
	back_count += *p;
}

// A backward goto leaves the scope too, and a later label inside it does not.
static int leave_back(void)
{
	int n = 0;

again:
	{
		int v __attribute__((cleanup(back_end))) = 1;

		if (n++ < 3)
			goto again;
		goto inside;
inside:
		v = 10;
	}
	return back_count;
}

static int leave_return(const struct S *u)
{
	scoped(u, fault) {
		return u->a * 2;
	}
	return 0;
fault:
	return -1;
}

#define CHECK(c) do { if (!(c)) return __LINE__ & 0x7f; } while (0)

int main(void)
{
	struct S s = { 7 };
	char c = 1;
	int arr[3];

	CHECK(rd(&s) == 7 && ends == 7);
	CHECK(rd(0) == -2);
	CHECK(leave_goto(&s) == 1 && ends == 14);
	CHECK(leave_return(&s) == 14 && ends == 21);
	CHECK(leave_local(&s) == 1 && ends == 28);
	CHECK(leave_back() == 13);

	{
		__auto_type l __attribute__((cleanup(done_i))) = 100L;
		CHECK(sizeof(l) == 8);
	}
	CHECK(ends == 128);

	// Counting loops stay counting loops.
	long n = 0;
	for (__auto_type i = 0L; i < 5; i++)
		n += i;
	int last = 0;
	for (__auto_type i = 0; i < 5; i++)
		last = i;
	CHECK(n == 10 && last == 4);

	// A sizeof of a local in __builtin_choose_expr (Linux's __inttype).
	unsigned short h;
	unsigned int *w = 0;
	__typeof__(__builtin_choose_expr(sizeof(h) <= sizeof(char), (unsigned char)0, (unsigned short)0)) t1;
	__typeof__(__builtin_choose_expr(sizeof(*w) <= sizeof(short), (unsigned short)0,
		   __builtin_choose_expr(sizeof(*w) <= sizeof(int), (unsigned int)0, 0ULL))) t2;
	CHECK(sizeof(t1) == 2 && sizeof(t2) == 4);

	// The type of a statement expression ending in an auto variable.
	CHECK(sizeof(({ __auto_type x = 1L; x; })) == 8);
	CHECK(sizeof(({ __auto_type x = c; x; })) == 1);
	CHECK(sizeof(({ __auto_type x = arr; x; })) == 8);
	return 42;
}
