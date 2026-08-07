/* A block-scope `extern` declaration refers to the file-scope (or other-TU)
 * global, not a new local. sic allocated a stack slot for it, so reads got
 * garbage. QEMU accesses `extern const TCGOpDef tcg_op_defs[];` inside functions
 * (and my own diagnostics did), which read a bogus stack address. */
#include <string.h>

int g_arr[5] = { 10, 20, 30, 40, 50 };
long g_scalar = 12345;
const char *g_str = "hello";

static int via_block_extern(void)
{
    extern int g_arr[];        /* must be the global, not a stack local */
    extern long g_scalar;
    return g_arr[3] + (int)g_scalar;
}

int main(void)
{
    extern int g_arr[];
    extern const char *g_str;

    if (g_arr[2] != 30) return 1;               /* array decays to global address */
    if (&g_arr[0] == 0) return 2;
    if (via_block_extern() != 40 + 12345) return 3;
    if (strcmp(g_str, "hello") != 0) return 4;  /* scalar pointer global */

    /* writes through the block-extern must hit the global */
    g_arr[2] = 99;
    if (g_arr[2] != 99) return 5;

    return 0;
}
