// aligned on a typedef of a typedef, with a value that needs type sizes (Linux's
// `typedef guid_t efi_guid_t __aligned(__alignof__(u32));`). Values are gcc's.
#include <stddef.h>
typedef unsigned int u32;
typedef unsigned char u8;
typedef struct { u8 b[16]; } guid_t;
typedef guid_t efi_guid_t __attribute__((aligned(__alignof__(u32))));
typedef guid_t eg2 __attribute__((aligned(sizeof(u32) * 2)));
typedef efi_guid_t eg3;
typedef u8 small __attribute__((aligned(sizeof(guid_t))));
struct a { u8 c; efi_guid_t g; u8 d; };
struct b { u8 c; eg2 g; };
struct c { u8 c; eg3 g[2]; };
struct d { u8 c; small s; };
union u { u8 c; efi_guid_t g; };
static efi_guid_t g1 = { { 1 } };
efi_guid_t g2;
_Static_assert(_Alignof(efi_guid_t) == 4 && sizeof(efi_guid_t) == 16, "guid");
_Static_assert(_Alignof(eg2) == 8 && _Alignof(eg3) == 4 && _Alignof(small) == 16, "typedefs");
_Static_assert(sizeof(struct a) == 24 && offsetof(struct a, g) == 4 && _Alignof(struct a) == 4, "a");
_Static_assert(sizeof(struct b) == 24 && offsetof(struct b, g) == 8, "b");
_Static_assert(sizeof(struct c) == 36 && offsetof(struct c, g) == 4, "c");
_Static_assert(sizeof(struct d) == 32 && offsetof(struct d, s) == 16, "d");
_Static_assert(_Alignof(union u) == 4 && _Alignof(g2) == 4, "u");
int main(void)
{
    efi_guid_t l = (efi_guid_t){ { 3, 4 } };
    if (((unsigned long)&l & 3) || ((unsigned long)&g1 & 3) || ((unsigned long)&g2 & 3)) return 1;
    return l.b[0] + l.b[1] + g1.b[0] + 34;
}
