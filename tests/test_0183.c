/* `_Generic(...)` in a static initializer must be evaluated at compile time
 * (select the matching association, then serialize it). sic left it NULL, so
 * QEMU's TCG `all_outop[]` table — `[INDEX_op_X] = _Generic(outop_X, T: &outop_X.base)`
 * — came out all NULL. Every op then had no constraint set: op_args_ct returned
 * con_set=-1, reg-alloc indexed all_cts[-1] garbage, and translating the very
 * first guest TB failed (temp_load on a bogus dead temp). */
#include <string.h>

typedef struct { int tag; } Base;
typedef struct { Base base; int payload; } Load;
typedef struct { Base base; long other; } Store;

static const Load  outop_ld = { .base = { 11 }, .payload = 42 };
static const Store outop_st = { .base = { 22 }, .other = 99 };

enum { OP_LD, OP_ST, OP_NOP, OP_MAX };

#define OUTOP(O, T, V) [O] = _Generic(V, T: &V.base)

static const Base *const all_outop[OP_MAX] = {
    OUTOP(OP_LD, Load,  outop_ld),
    OUTOP(OP_ST, Store, outop_st),
    /* OP_NOP intentionally left NULL */
};

int main(void)
{
    if (all_outop[OP_LD] != &outop_ld.base) return 1;
    if (all_outop[OP_ST] != &outop_st.base) return 2;
    if (all_outop[OP_NOP] != 0) return 3;
    if (all_outop[OP_LD]->tag != 11) return 4;
    if (all_outop[OP_ST]->tag != 22) return 5;
    return 0;
}
