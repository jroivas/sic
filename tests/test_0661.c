// Constants in one named section: those holding pointers are writable in the
// object (for the dynamic loader), others not, and the assembler refused the
// mix ("changed section attributes", Linux's __initconst in .init.rodata). In
// non-PIC code the section is read-only, as with GCC. `T *const p` counts as
// constant (sic missed a `const` on the pointer itself).
#include <string.h>
#define RO __attribute__((section(".my.rodata"), used))

static const char *const names[3] RO = { "pkg", "core", "dram" };
static const char *const one RO = "uncore";
static const struct cfg { int id; const char *name; } table[2] RO = { { 1, "a" }, { 2, "b" } };
static const long plain RO = 5;

// Inline asm makes sic assemble this unit as text, where the clash was fatal.
static int nop(void) { int x = 1; asm("addl $0, %0" : "+r"(x)); return x; }

int main(void) {
    int ok = nop();
    ok += !strcmp(names[2], "dram") + !strcmp(one, "uncore");
    ok += table[1].id + !strcmp(table[0].name, "a") + (int)plain;   // 1 + 2 + 2 + 1 + 5
    return ok + 31;
}
