// typeof of a member, global or array element in a declaration outside a
// function, and in a struct member inside one: both silently gave int. Linux's
// wmi core.c: `static_assert(sizeof(typeof_member(struct guid_block, guid)) == 16)`.
#include <stdio.h>
#include <stddef.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define typeof_member(T, m) typeof(((T *)0)->m)
#define __packed __attribute__((packed))

typedef struct { unsigned char b[16]; } guid_t;
struct guid_block {
	guid_t guid;
	union {
		char object_id[2];
		struct { unsigned char notify_id, reserved; };
	};
	unsigned char count;
	unsigned char flags;
} __packed;
_Static_assert(sizeof(typeof_member(struct guid_block, guid)) == 16, "member");
_Static_assert(sizeof(typeof_member(struct guid_block, notify_id)) == 1, "anon member");
_Static_assert(sizeof(typeof_member(struct guid_block, object_id)) == 2, "array member");
_Static_assert(sizeof(struct guid_block) == 20, "whole");

struct S { int a; long long b; char c[5]; struct S *next; short sh[3]; };
struct S gs;
long gl;
const char *gcp;
struct S gsa[4];

typeof(((struct S *)0)->b) f_arrow;
typeof(gs.c) f_field;
typeof(gl) f_ident;
typeof(gs) f_struct;
typeof(&gs) f_addr;
typeof(*gcp) f_deref;
typeof(gsa[0].next) f_index;
typeof(gs.next->sh[1]) f_chain;
typeof(gs.sh) *f_ptr_to_arr;
typeof(gl) f_arr[3];

struct uses_typeof {
	typeof(gl) a;
	typeof(gs.c) c;
	typeof(((struct S *)0)->b) b;
};
_Static_assert(sizeof(struct uses_typeof) == 24, "members");

typedef typeof(((struct S *)0)->sh) sh_t;
_Static_assert(sizeof(sh_t) == 6, "typedef");

extern int a_function(int);
int a_function(int x) { return x + 1; }
extern typeof(a_function) a_function;

#define UNALIGNED(ptr) ({ const struct { typeof(*(ptr)) x; } __packed *__p = (typeof(__p))(ptr); __p->x; })

int main(void)
{
	CHECK(sizeof(f_arrow) == 8 && sizeof(f_field) == 5 && sizeof(f_ident) == sizeof(long));
	CHECK(sizeof(f_struct) == sizeof(struct S) && sizeof(f_addr) == sizeof(void *));
	CHECK(sizeof(f_deref) == 1 && sizeof(f_index) == sizeof(void *) && sizeof(f_chain) == 2);
	CHECK(sizeof(*f_ptr_to_arr) == 6 && sizeof(f_arr) == 3 * sizeof(long));
	CHECK(a_function(1) == 2);

	// a member through typeof of a local
	long x = 0;
	unsigned short us = 0;
	long long *p64 = 0;
	struct { typeof(x) a; typeof(x) b; } s;
	union { typeof(p64) p; char c; } u;
	struct named { typeof(us) v[3]; struct { typeof(x) deep; } in; } n;
	typedef struct { typeof(us) a; typeof(us) b; } td_t;
	CHECK(sizeof(s) == 2 * sizeof(long) && sizeof(u) == sizeof(void *));
	CHECK(sizeof(n.v) == 6 && sizeof(n.in) == sizeof(long));
	CHECK(sizeof(struct named) == 2 * sizeof(long) && sizeof(td_t) == 4);
	CHECK(sizeof(struct { typeof(x) a; }) == sizeof(long));
	CHECK(sizeof(((struct { typeof(us) a[5]; } *)0)->a) == 10);

	s.b = 1;
	s.a = -5;
	CHECK(s.a == -5 && s.b == 1);
	n.in.deep = 1L << 40;
	CHECK(n.in.deep == 1L << 40);

	unsigned char buf[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	unsigned short *ps = (unsigned short *)(buf + 1);
	unsigned long long *pl = (unsigned long long *)(buf + 1);
	CHECK(UNALIGNED(ps) == 0x0302);
	CHECK(UNALIGNED(pl) == 0x0908070605040302ULL);

	// a pointer to a function with typeof in its signature
	long (*fp)(typeof(x), typeof(us)) = 0;
	CHECK(sizeof(fp) == sizeof(void *) && !fp);
	return 42;
}
