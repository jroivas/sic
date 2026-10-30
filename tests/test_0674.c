// GNU labels as values: `&&label` and `goto *expr` (Linux's BPF interpreter).

#define CHECK(c) do { if (!(c)) return __LINE__ & 0x7f; } while (0)

enum { PUSH, ADD, MUL, JNZ, DEC, HALT, BAD };

// Threaded dispatch through a static table with a range designator; the
// locals change in every op, and the pc moves backward too.
static long run(const int *code)
{
	static const void *const ops[8] __attribute__((section(".data.rel.ro.c_jump_table"))) = {
		[0 ... 7] = &&bad,
		[PUSH] = &&push,
		[ADD] = &&add,
		[MUL] = &&mul,
		[JNZ] = &&jnz,
		[DEC] = &&dec,
		[HALT] = &&halt,
	};
	long stack[8];
	int sp = 0;
	const int *pc = code;

#define NEXT goto *ops[*pc++]
	NEXT;
push:
	stack[sp++] = *pc++;
	NEXT;
add:
	sp--;
	stack[sp - 1] += stack[sp];
	NEXT;
mul:
	sp--;
	stack[sp - 1] *= stack[sp];
	NEXT;
dec:
	stack[sp - 1]--;
	NEXT;
jnz:
	if (stack[sp - 1])
		pc += *pc;
	else
		pc++;
	NEXT;
halt:
	return stack[0];
bad:
	return -1;
}

// A label address in a local variable, chosen at run time.
static int pick(int i)
{
	void *p = i ? &&one : &&two;

	goto *p;
one:
	return 10;
two:
	return 20;
}

// The documented offset form, in a static and at run time.
static int offsets(int i)
{
	static const int tbl[] = { &&a - &&a, &&b - &&a, &&c - &&a };

	goto *(&&a + tbl[i]);
a:
	return 1;
b:
	return 2;
c:
	return 3;
}

// `__label__` names are per block, and two functions use the same names.
static int local(int i)
{
	int r = 0;

	{
		__label__ x, y;
		void *t[] = { &&x, &&y };

		goto *t[i];
x:
		r += 1;
y:
		r += 2;
	}
	{
		__label__ x;

		goto *&&x;
		r = 100;
x:
		r += 4;
	}
	return r;
}

// A value compares like an address: not null, equal to itself only.
static int compare(void)
{
	void *p = &&l1, *q = &&l2, *r = &&l1;

	if (!p || p == q || p != r)
		return 0;
	goto *q;
l1:
	return 2;
l2:
	return 1;
}

// Inlined into a caller that has its own labels.
static inline int in(int i)
{
	static const void *const t[] = { &&p0, &&p1 };

	goto *t[i];
p0:
	return 5;
p1:
	return 6;
}

static int outer(int i)
{
	static const void *const t[] = { &&q0, &&q1 };
	int r = in(i) * 10;

	goto *t[i];
q0:
	return r + 1;
q1:
	return r + 2;
}

// The label sits in a branch that is constant false.
static int dead_branch(void)
{
	void *p = &&hidden;

	goto *p;
	if (0) {
hidden:
		return 9;
	}
	return 0;
}

// A loop whose body holds the labels.
static int inner_loop(void)
{
	int s = 0;

	for (int i = 0; i < 4; i++) {
		void *p = (i & 1) ? &&odd : &&even;

		goto *p;
odd:
		s += 10;
		continue;
even:
		s += 1;
	}
	return s;
}

int main(void)
{
	static const int sum[] = {
		PUSH, 2, PUSH, 3, ADD, PUSH, 4, MUL, HALT,
	};
	static const int loop[] = {
		PUSH, 5, DEC, JNZ, -2, PUSH, 7, ADD, HALT,
	};
	static const int bad[] = { BAD };

	CHECK(run(sum) == 20);
	CHECK(run(loop) == 7);
	CHECK(run(bad) == -1);
	CHECK(pick(1) == 10 && pick(0) == 20);
	CHECK(offsets(0) == 1 && offsets(1) == 2 && offsets(2) == 3);
	CHECK(local(0) == 7 && local(1) == 6);
	CHECK(compare() == 1);
	CHECK(outer(0) == 51 && outer(1) == 62);
	CHECK(inner_loop() == 22);
	CHECK(dead_branch() == 9);
	CHECK(sizeof(&&dummy) == sizeof(void *));
	return 42;
dummy:
	return 0;
}
