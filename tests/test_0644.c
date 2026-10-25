// __attribute__((packed)) on structs and unions — before the tag or after the
// closing brace — packs the members (sic parsed it and ignored it: Linux's
// boot_params / saved_context, QEMU's device structs were laid out naturally).
// A packed bit-field may straddle its type's width (b:30 at bit 3).
#include <stddef.h>

struct d { unsigned short s; unsigned long a; } __attribute__((packed));
struct __attribute__((packed)) e { unsigned short s; unsigned long a; };
struct f { char c; unsigned short p; struct d g; unsigned short q; } __attribute__((packed));
struct __attribute__((packed)) nest { char c; struct inner { char x; int y; } in; int z; };
union __attribute__((packed)) u { char c; int i; };
struct hasu { char c; union u u; };
struct bf { unsigned a:3; unsigned b:30; unsigned char c; } __attribute__((packed));
struct sbf { unsigned char t:5; int v:20; unsigned char after; } __attribute__((packed));
struct al { char c; int x; } __attribute__((packed, aligned(4)));
struct arr { char c; long v[2]; } __attribute__((packed));

_Static_assert(sizeof(struct d) == 10 && _Alignof(struct d) == 1, "d");
_Static_assert(sizeof(struct e) == 10, "e");
_Static_assert(sizeof(struct f) == 15 && offsetof(struct f, g) == 3 && offsetof(struct f, q) == 13, "f");
_Static_assert(sizeof(struct nest) == 13 && offsetof(struct nest, z) == 9 && sizeof(struct inner) == 8, "nest");
_Static_assert(sizeof(union u) == 4 && _Alignof(union u) == 1 && sizeof(struct hasu) == 5, "union");
_Static_assert(sizeof(struct bf) == 6 && offsetof(struct bf, c) == 5, "bf");
_Static_assert(sizeof(struct sbf) == 5, "sbf");
_Static_assert(sizeof(struct al) == 8 && _Alignof(struct al) == 4, "al");
_Static_assert(sizeof(struct arr) == 17, "arr");

struct bf gb = { 5, 0x2aaaaaaa, 7 };
struct sbf gs = { 9, -300000, 0x5a };

int main(void) {
    int ok = 0;
    struct f x = { 1, 2, { 3, 0x1122334455667788UL }, 9 };
    volatile struct f *px = &x;
    if (px->g.a == 0x1122334455667788UL && px->q == 9) ok++;
    if (gb.a == 5 && gb.b == 0x2aaaaaaa && gb.c == 7) ok++;
    struct bf b = gb;
    b.b += 1;
    b.a = 2;
    if (b.a == 2 && b.b == 0x2aaaaaab && b.c == 7) ok++;
    if (gs.t == 9 && gs.v == -300000 && gs.after == 0x5a) ok++;
    gs.v++;
    if (gs.v == -299999 && gs.t == 9 && gs.after == 0x5a) ok++;
    return ok + 37;
}
