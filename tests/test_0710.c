// sizeof of an array inside its own initializer, after a header's `extern T a[];`: the
// initializer folded it through the incomplete declaration, to 0. Linux's ACPI tables
// hold `sizeof(table) / sizeof(entry)` as their own length, so no resource converted,
// the PCI root had no _CRS and no device was found.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

struct e { unsigned char a, b, c, d; };
#define N(t) (sizeof(t) / sizeof(struct e))

extern struct e t1[];
struct e t1[3] = { { 1, 2, 3, N(t1) }, { 4 }, { 5 } };
extern int t2[];
int t2[5] = { sizeof(t2) };
extern int t3[];
int t3[] = { 1, 2, 3 };
int z = sizeof(t3);
extern const struct e t4[];
const struct e t4[7] = { [2] = { .d = N(t4) } };
extern struct e t5[];
static int later = sizeof(t2) / sizeof(t2[0]);
struct e t5[2];
int zero[0];
int zs = sizeof(zero);

int main(void)
{
	CHECK(t1[0].d == 3);
	CHECK(t2[0] == 20);
	CHECK(z == 12);
	CHECK(t4[2].d == 7);
	CHECK(later == 5);
	CHECK(sizeof(t1) == 12 && sizeof(t4) == 28);
	CHECK(zs == 0);
	return 42;
}
