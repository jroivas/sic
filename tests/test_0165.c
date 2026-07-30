/* `sizeof(*arr)` where `arr` is an array of structs must equal the struct size:
 * the array decays to a pointer, so `*arr` is the element. sic's Deref
 * type-inference only handled a pointer inner and fell back to int (4) for an
 * array, so QEMU's `qsort(hmp_cmds, .., sizeof(*hmp_cmds), ..)` over a
 * `static HMPCommand hmp_cmds[]` sorted with element size 4 → strcmp on garbage
 * pointers → SIGSEGV. The struct is self-referential (a `sub_table` member),
 * matching HMPCommand. */
typedef struct Cmd {
    const char *name;
    const char *args;
    void (*fn)(void);
    struct Cmd *sub_table;
    unsigned int flags;
    _Bool coro;
} Cmd;

static Cmd cmds[] = {
    { "a", "x", 0, 0, 0, 0 },
    { "b", "y", 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0 },
};

int main(void)
{
    if (sizeof(*cmds) != sizeof(cmds[0])) return 1;
    if (sizeof(*cmds) != sizeof(Cmd)) return 2;
    if (sizeof(*cmds) == 4) return 3;   /* the old wrong value */
    return 0;
}
