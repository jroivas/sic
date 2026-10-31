// Arithmetic on a pointer to an array steps by the whole array; a pointer difference
// divides by it. Linux: `target - __x86_indirect_thunk_array` (u8[32] elements) gave
// a byte count. And an "m" asm operand on a global is `sym+N(%rip)`, not a register:
// paravirt call sites must be the 6-byte `ff 15 disp32` the kernel patches.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

typedef unsigned char thunk_t[32];
thunk_t arr[16];
extern thunk_t ext[];
thunk_t ext[4];
struct s { int a, b, c; };

struct ops { long pad; long (*fn)(long); long tbl[3]; };
static long twice(long x) { return x * 2; }
struct ops gops = { 1, twice, { 10, 20, 30 } };
int gval = 7;

static long call_op(long v)
{
	long ret;
	asm volatile("mov %[v], %%rdi\n\tcall *%[op]\n\tmov %%rax, %[ret]"
		     : [ret] "=r"(ret)
		     : [v] "r"(v), [op] "m"(gops.fn)
		     : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory", "cc");
	return ret;
}

// The bytes of the call in that template, read back through a label.
static int call_encoding(void)
{
	extern const unsigned char site_start[];
	asm volatile("jmp 1f\n"
		     ".pushsection .data\n"
		     "site_data: .quad site_start\n"
		     ".popsection\n"
		     ".globl site_start\n"
		     "site_start:\n\tcall *%[op]\n"
		     "1:\n"
		     : : [op] "m"(gops.fn));
	return site_start[0] == 0xff && site_start[1] == 0x15;
}

static int load_field(void) { int r; asm("movl %1, %0" : "=r"(r) : "m"(gval)); return r; }
static long load_elem(void) { long r; asm("movq %1, %0" : "=r"(r) : "m"(gops.tbl[2])); return r; }

int main(void)
{
	thunk_t *p = arr + 7;
	void *v = (char *)arr + 0xe0;
	thunk_t *q = v;
	int m[4][5];
	int (*r)[5] = m + 2;
	struct s ss[3];
	struct s *ps = ss + 2;

	CHECK(q - arr == 7 && p - arr == 7 && arr - p == -7);
	CHECK((thunk_t *)((char *)ext + 64) - ext == 2);
	CHECK(r - m == 2 && ps - ss == 2 && &arr[5] - arr == 5 && (arr + 3) - p == -4);

	CHECK((char *)(p + 1) - (char *)p == 32);
	CHECK((char *)(1 + p) - (char *)p == 32);
	CHECK((char *)(p - 2) - (char *)arr == 5 * 32);
	CHECK((char *)(r + 1) - (char *)r == 20);
	CHECK((p + 1) + 1 == arr + 9 && (r + 1) - r == 1 && (arr + 2) + 1 == arr + 3);
	CHECK((char *)(&arr + 1) - (char *)&arr == 32 * 16);
	CHECK((char *)&arr[3][1] - (char *)arr == 97);
	CHECK(&p[1][2] == &arr[8][2] && &r[1][3] == &m[3][3]);
	CHECK(sizeof(*p) == 32 && sizeof(*r) == 20 && sizeof(p + 1) == sizeof(void *));
	r += 1;
	CHECK(r == m + 3);
	r--;
	CHECK(r == m + 2);
	++r;
	CHECK(r == m + 3);
	--r;
	r -= 1;
	CHECK(r++ == m + 1 && r == m + 2);
	CHECK(r-- == m + 2 && r == m + 1);
	thunk_t *pp = arr;
	pp += 2;
	CHECK(pp == arr + 2);

	// a plain decayed array still steps by its element
	int one[4];
	CHECK(one + 2 == &one[2] && &one[3] - one == 3);
	int *ip = one + 1;
	CHECK(ip - one == 1);

	CHECK(call_op(21) == 42);
	CHECK(call_encoding() == 1);
	CHECK(load_field() == 7 && load_elem() == 30);

	// a local named like a global is the local
	int gval = 9;
	int got;
	asm("movl %1, %0" : "=r"(got) : "m"(gval));
	CHECK(got == 9);
	static int st = 11;
	asm("movl %1, %0" : "=r"(got) : "m"(st));
	CHECK(got == 11);
	return 42;
}
