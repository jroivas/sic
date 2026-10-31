// `#pragma pack` was ignored, so every struct under it had its natural layout:
// Linux's ACPI tables among them ("Error parsing LAPIC NMI entry", as sizeof said 8
// for a 6-byte entry, and "Invalid BIOS MADT, disabling ACPI").
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

#pragma pack(1)
struct hdr { unsigned char type, length; };
struct nmi { struct hdr h; unsigned char id; unsigned short flags; unsigned char lint; };
struct mix { char c; int i; long l; };
#pragma pack()
struct plain { char c; int i; };

#pragma pack(push, 2)
struct two { char c; int i; };
#pragma pack(pop)
struct after_pop { char c; int i; };

#pragma pack(push)
#pragma pack(1)
struct in_push { char c; short s; };
#pragma pack(pop)
struct restored { char c; short s; };

#pragma pack(push, 1)
#pragma pack(push, 4)
struct nested_four { char c; long l; };
#pragma pack(pop)
struct nested_one { char c; long l; };
#pragma pack(pop)

#pragma pack(4)
struct four { char c; long l; short s; };
#pragma pack(8)
struct eight { char c; long l; };
#pragma pack()

#pragma pack(1)
union un { char c; int i; };
struct holds { struct plain in; char x; int y; };
typedef struct { char c; int i; } named;
struct bits { unsigned a : 3; unsigned b : 7; char c; int i : 20; };
struct aligned_member { char c; int i __attribute__((aligned(8))); };
struct __attribute__((aligned(16))) whole { char c; int i; };
union capped_un { char c; int i __attribute__((aligned(8))); };
#pragma pack(2)
struct capped2 { char c; int i __attribute__((aligned(8))); };
#pragma pack()
struct attr_packed { char c; int i __attribute__((aligned(8))); } __attribute__((packed));
typedef struct { char c; int i; } named_after;

#define PACKED_BEGIN _Pragma("pack(push, 1)")
#define PACKED_END _Pragma("pack(pop)")
PACKED_BEGIN
struct via_operator { char c; long l; };
PACKED_END

// Only definitions are affected: a reference elsewhere keeps its layout.
struct later;
#pragma pack(1)
struct uses_later { char c; struct later *p; };
#pragma pack()
struct later { char c; int i; };

int main(void)
{
	CHECK(sizeof(struct hdr) == 2 && sizeof(struct nmi) == 6 && offsetof(struct nmi, flags) == 3);
	CHECK(sizeof(struct mix) == 13 && offsetof(struct mix, l) == 5 && sizeof(struct plain) == 8);
	CHECK(sizeof(struct two) == 6 && offsetof(struct two, i) == 2 && sizeof(struct after_pop) == 8);
	CHECK(sizeof(struct in_push) == 3 && sizeof(struct restored) == 4);
	CHECK(sizeof(struct nested_four) == 12 && sizeof(struct nested_one) == 9);
	CHECK(sizeof(struct four) == 16 && offsetof(struct four, l) == 4 && _Alignof(struct four) == 4);
	CHECK(sizeof(struct eight) == 16 && _Alignof(struct mix) == 1);
	CHECK(sizeof(union un) == 4 && _Alignof(union un) == 1);
	CHECK(sizeof(struct holds) == 13 && offsetof(struct holds, y) == 9);
	CHECK(sizeof(named) == 5 && sizeof(named_after) == 8);
	CHECK(sizeof(struct via_operator) == 9 && sizeof(struct uses_later) == 9 && sizeof(struct later) == 8);
	// The pragma caps a member's `aligned` too, but not a whole type's; the
	// `packed` attribute keeps both, with the padding that takes at the end.
	CHECK(_Alignof(struct aligned_member) == 1 && offsetof(struct aligned_member, i) == 1);
	CHECK(sizeof(struct aligned_member) == 5 && sizeof(struct capped2) == 6 && _Alignof(struct capped2) == 2);
	CHECK(sizeof(struct whole) == 16 && _Alignof(struct whole) == 16);
	CHECK(sizeof(union capped_un) == 4 && _Alignof(union capped_un) == 1);
	CHECK(sizeof(struct attr_packed) == 16 && _Alignof(struct attr_packed) == 8 && offsetof(struct attr_packed, i) == 8);

	// misaligned members read and write through the object
	unsigned char raw[6] = { 4, 6, 1, 0x34, 0x12, 9 };
	struct nmi *e = (struct nmi *)raw;
	CHECK(e->h.length == sizeof(*e) && e->flags == 0x1234 && e->lint == 9);
	e->flags = 0xabcd;
	CHECK(raw[3] == 0xcd && raw[4] == 0xab);

	struct mix m;
	memset(&m, 0, sizeof(m));
	m.i = 0x01020304;
	m.l = -2;
	CHECK(m.i == 0x01020304 && m.l == -2);

	struct bits b = { 5, 100, 'x', -3 };
	CHECK(b.a == 5 && b.b == 100 && b.c == 'x' && b.i == -3);

	struct mix arr[2] = { { 1, 2, 3 }, { 4, 5, 6 } };
	CHECK((char *)&arr[1] - (char *)&arr[0] == 13 && arr[1].l == 6);
	return 42;
}
