// "i" asm operands that are string literals (their address, printed as a
// label with %c) or locals initialized with a constant and never written
// (folded, as GCC/Clang do) — Linux's BUG()/WARN() bug_table entries:
// `.long %c[file] - .` with [file] "i"(__FILE__), [fl] "i"(__flags).
#include <string.h>

struct entry { int fmt; int file; unsigned short line, flags; };
extern struct entry __start_sic_tbl[], __stop_sic_tbl[];

#define REC(msg, bits) do {                                               \
    __auto_type __flags = 0x100 | (bits);                                 \
    asm volatile(".pushsection sic_tbl,\"aw\"\n"                        \
                 "2:\t.long %c[fmt] - .\n"                              \
                 "\t.long %c[file] - .\n"                               \
                 "\t.word %c[line]\n"                                   \
                 "\t.word %c[fl]\n"                                     \
                 "\t.org 2b + %c[size]\n"                               \
                 ".popsection"                                          \
                 : : [fmt] "i"(msg), [file] "i"(__FILE__),              \
                     [line] "i"(__LINE__), [fl] "i"(__flags),           \
                     [size] "i"(sizeof(struct entry)));                 \
} while (0)

static const char *at(const int *rel) { return (const char *)rel + *rel; }

int main(void) {
    REC("first \"quoted\"", 1);
    REC("second", 2);
    int ok = 0;
    for (struct entry *e = __start_sic_tbl; e < __stop_sic_tbl; e++) {
        if (strstr(at(&e->file), "test_0643.c")) ok++;
        if (e->flags == 0x101 && !strcmp(at(&e->fmt), "first \"quoted\"")) ok += 10;
        if (e->flags == 0x102 && !strcmp(at(&e->fmt), "second") && e->line > 20) ok += 10;
    }
    // An operand statement (with an output): a string literal's address.
    const char *p;
    asm("lea %c1(%%rip), %0" : "=r"(p) : "i"("hello"));
    if (!strcmp(p, "hello")) ok += 20;
    return (int)(__stop_sic_tbl - __start_sic_tbl) + ok - 4 + 2;
}
