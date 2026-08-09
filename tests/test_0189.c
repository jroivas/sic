/* A ternary whose arms are structs (`cond ? struct_a : struct_b`) yields a
 * struct value. sic lowered every ternary as a scalar store/load, truncating
 * the struct to a register (and crashing). QEMU's i386 decoder does
 *   *entry = (s->prefix & PREFIX_REPZ) ? pause : nop;   // X86OpEntry copy
 * so a plain nop got a garbage X86OpEntry (with a code-bytes function pointer),
 * tripping decode_insn's assertion the moment 32-bit protected-mode code ran.
 * The selected struct must be copied whole. */
#include <string.h>

typedef struct { const char *name; int a, b, c; long tail; } S;

static const S sa = { .name = "A", .a = 1, .b = 2, .c = 3, .tail = 100 };
static const S sb = { .name = "B", .a = 4, .b = 5, .c = 6, .tail = 200 };

static void select_into(int cond, S *out) { *out = cond ? sa : sb; }

int main(void)
{
    S d;

    select_into(1, &d);
    if (strcmp(d.name, "A") != 0 || d.a != 1 || d.c != 3 || d.tail != 100) return 1;

    select_into(0, &d);
    if (strcmp(d.name, "B") != 0 || d.a != 4 || d.c != 6 || d.tail != 200) return 2;

    /* direct initialization from a struct ternary */
    int c = 0;
    S e = c ? sa : sb;
    if (strcmp(e.name, "B") != 0 || e.b != 5) return 3;

    /* reading a field straight off the ternary result */
    if ((1 ? sa : sb).a != 1) return 4;
    if ((0 ? sa : sb).tail != 200) return 5;

    return 0;
}
