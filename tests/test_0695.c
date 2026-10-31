// A C array of the size of an integer, cast to that integer, is its address: it
// decays. Only a GCC vector reinterprets its bytes; the two share sic's IR type.
// Linux's ACPI_CAST_PTR(char, rsdp->signature) read the 8 signature bytes as a
// pointer, and the boot decompressor faulted before printing anything.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

typedef unsigned long uptr;
typedef char name_t[8];
typedef char v8c __attribute__((vector_size(8)));
typedef int v2i __attribute__((vector_size(8)));
typedef long long m64 __attribute__((vector_size(8)));

#pragma pack(1)
struct rsdp { char signature[8]; unsigned char checksum; char oem[6]; };
#pragma pack()
struct s { char a8[8]; char a4[4]; int a2[2]; short s4[4]; name_t n; char m[2][8]; v8c v; m64 w; v2i iv[2]; };
struct pair { char x[8]; char y[8]; };
union u { char c[8]; long l; };

char g8[8] = "abcdefg";
name_t gn = "hij";

#define CAST_PTR(t, p) ((t *)(uptr)(p))

int main(void)
{
	struct rsdp r = { "RSD PTR ", 1, "ab" };
	struct rsdp *pr = &r;
	struct s v = { "abcdefg", "abc", { 1, 2 }, { 3 }, "kl", { "m", "nop" } };
	struct s *p = &v;
	char l8[8] = "1234567";
	name_t ln = "q";
	char (*pa)[8] = &l8;
	union u un = { "uvw" };

	CHECK(CAST_PTR(char, pr->signature)[4] == 'P');
	CHECK((uptr)(p->a8) == (uptr)&v.a8[0]);
	CHECK((uptr)(v.a8) == (uptr)&v.a8[0]);
	CHECK((unsigned)(uptr)(p->a4) == (unsigned)(uptr)&v.a4[0]);
	CHECK((long)(p->a2) == (long)&v.a2[0]);
	CHECK((long)(p->s4) == (long)&v.s4[0]);
	CHECK((uptr)(p->n) == (uptr)&v.n[0]);
	CHECK((uptr)(p->m[1]) == (uptr)&v.m[1][0]);
	CHECK((uptr)l8 == (uptr)&l8[0] && (uptr)ln == (uptr)&ln[0]);
	CHECK((uptr)g8 == (uptr)&g8[0] && (uptr)gn == (uptr)&gn[0]);
	CHECK((uptr)*pa == (uptr)&l8[0]);
	CHECK((uptr)un.c == (uptr)&un);

	// differences of same-size array members are pointer differences
	struct pair q;
	CHECK(q.y - q.x == 8);
	CHECK(p->m[1] - p->m[0] == 8);

	// vectors still reinterpret
	v8c cv = { 1, 2, 3, 4, 5, 6, 7, 8 };
	v2i iv = { 1, 2 };
	m64 mv = { 0x0102030405060708LL };
	CHECK((unsigned long)cv == 0x0807060504030201UL);
	CHECK((long)iv == 0x0000000200000001L);
	CHECK((long long)mv == 0x0102030405060708LL);
	v.v = cv;
	v.w = mv;
	CHECK((unsigned long)p->v == 0x0807060504030201UL);
	CHECK((long long)v.w == 0x0102030405060708LL);
	v.iv[1] = iv;
	CHECK((long)p->iv[1] == 0x0000000200000001L);
	return 42;
}
