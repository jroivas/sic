/* A constant-condition ternary selecting a pointer, in a static initializer,
 * must fold to the taken branch. sic's eval_ptr_reloc had no Ternary arm, so the
 * pointer field failed to resolve and (one unfoldable field zeroes the whole
 * static aggregate) the entire struct came out zero. QEMU's TCG outop tables use
 *   .out_rr = TCG_TARGET_HAS_extr_i64_i32 ? tgen_extrl_i64_i32 : NULL;
 * so outop_extrl_i64_i32 was all-zero -> its static_constraint read 0 -> the
 * register allocator used the wrong constraint set and translating an
 * extrl_i64_i32 op aborted (temp_load, tcg.c:4800) after ~9 SeaBIOS TBs. */

typedef struct { int sc; } Base;
typedef struct { Base base; void (*fn)(void); } Op;

static void real_fn(void) { }
#define HAS 1

static const Op op_true  = { .base.sc = 15, .fn = HAS ? real_fn : ((void *)0) };
static const Op op_false = { .base.sc = 9,  .fn = 0   ? real_fn : ((void *)0) };
/* also a plain (non-nested) pointer field */
static void (*const p_true)(void)  = 1 ? real_fn : 0;

int main(void)
{
    if (op_true.base.sc != 15) return 1;      /* whole struct was zeroed */
    if (op_true.fn != real_fn) return 2;
    if (op_false.base.sc != 9) return 3;
    if (op_false.fn != 0) return 4;           /* NULL branch taken */
    if (p_true != real_fn) return 5;
    return 0;
}
