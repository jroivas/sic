/* An enum-typed bit-field with only non-negative enumerators is unsigned (GCC
 * behaviour), so a value with its top field-bit set must read back as itself,
 * not sign-extend. sic lowered every enum to signed i32, so QEMU's TCGTemp
 * `TCGTempKind kind:3` read TEMP_CONST (4 = 0b100) as -4, and TCG liveness
 * analysis (la_bb_end) hit g_assert_not_reached during guest code translation.
 * An enum WITH a negative enumerator stays signed. */

typedef enum { K_FIXED, K_GLOBAL, K_TB, K_EBB, K_CONST } Kind;   /* 0..4, unsigned */
typedef enum { NEG = -1, ZERO = 0, POS = 1 } Signed;             /* has -1, signed */

/* mirror TCGTemp's leading bit-field packing so `kind` sits at bit offset 32 */
struct Temp {
    unsigned reg : 8;
    unsigned val_type : 8;
    unsigned base_type : 8;
    unsigned type : 8;
    Kind kind : 3;
    unsigned indirect : 1;
};

struct SBits { Signed s : 4; };

int main(void)
{
    struct Temp t;
    for (unsigned i = 0; i < sizeof t; i++) ((char *)&t)[i] = 0;
    t.kind = K_CONST;           /* 4 = 0b100 */
    t.reg = 200;
    if (t.kind != K_CONST) return 1;         /* was -4 */
    if (t.kind != 4) return 2;
    if (t.reg != 200) return 3;

    struct SBits sb;
    sb.s = NEG;
    if (sb.s != -1) return 4;                /* negative enum stays signed */

    return 0;
}
