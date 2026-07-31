/* Designated initialization of a bit-field must read-modify-write its storage
 * unit so neighbouring bit-fields sharing the unit are preserved. sic wrote each
 * bit-field as a full store, so `{ .ptr = NIL, .skip = 1 }` had `.skip` clobber
 * `.ptr` (both share one 32-bit word). QEMU's PhysPageEntry (ptr:26, skip:6) is
 * initialized this way in address_space_dispatch_new; a zeroed .ptr made
 * phys_page_compact miss its `ptr == PHYS_MAP_NODE_NIL` early-return and deref a
 * NULL nodes array during memory-map init at boot. Covers static, local, and
 * compound-literal forms. */
#include <stdint.h>

typedef struct E { uint32_t skip : 6; uint32_t ptr : 26; } E;
#define NIL ((((uint32_t)~0) >> 6))     /* 0x03FFFFFF */

/* bit-fields declared low-to-high but initialized high-first (out of order) */
static const E gs = { .ptr = NIL, .skip = 1 };

struct Multi { uint8_t a : 3; uint8_t b : 3; uint8_t c : 2; };
static const struct Multi gm = { .c = 3, .a = 5, .b = 2 };

int main(void)
{
    if (gs.ptr != NIL || gs.skip != 1) return 1;        /* static */

    E l = { .ptr = NIL, .skip = 1 };
    if (l.ptr != NIL || l.skip != 1) return 2;          /* local */

    E c; c = (E){ .ptr = NIL, .skip = 1 };
    if (c.ptr != NIL || c.skip != 1) return 3;          /* compound literal */

    if (gm.a != 5 || gm.b != 2 || gm.c != 3) return 4;  /* three fields, one byte */

    struct Multi lm = { .c = 3, .a = 5, .b = 2 };
    if (lm.a != 5 || lm.b != 2 || lm.c != 3) return 5;

    return 0;
}
