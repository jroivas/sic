/* A global array whose dimension is `sizeof(other_global)/sizeof(elem)`
 * (ARRAY_SIZE of another global) must be sized correctly. sic's type-lowering
 * dimension pass has no symbol table, so it folded such a dimension to 0 and the
 * array became 1 byte. QEMU's tcg.c declares
 *   static TCGArgConstraint all_cts[ARRAY_SIZE(constraint_sets)][TCG_MAX_OP_ARGS];
 * the undersized array let process_constraint_sets() scribble past it into the
 * adjacent `current_machine` pointer, crashing at machine boot. */
#include <stdint.h>

typedef struct CS { uint8_t a, b; const char *s[4]; } CS;
static const CS constraint_sets[] = {
    { 0, 1, { "r" } },
    { 1, 2, { "r", "r" } },
    { 2, 4, { "r" } },
    { 1, 1, { "r" } },
    { 0, 2, { "r" } },
};
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef struct AC { unsigned ct : 16; uint32_t regs; } AC;
static AC all_cts[ARRAY_SIZE(constraint_sets)][8];

/* a global placed right after, to catch an overflow */
static unsigned long guard = 0x1122334455667788UL;

int main(void)
{
    if (ARRAY_SIZE(constraint_sets) != 5) return 1;
    if (sizeof(all_cts) / sizeof(all_cts[0]) != 5) return 2;   /* was 0/1 */
    if (sizeof(all_cts) != 5ul * 8 * sizeof(AC)) return 3;

    /* write the whole array; if undersized this clobbers `guard` */
    for (unsigned c = 0; c < 5; c++)
        for (int i = 0; i < 8; i++)
            all_cts[c][i].regs = 0xffffffffu;

    if (guard != 0x1122334455667788UL) return 4;
    return 0;
}
