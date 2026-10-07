/* Macro argument edge cases (QEMU hexagon's gen_semantics): an empty `##`
 * operand is a placemarker (`TG##_t##TG2` with TG2 empty = `TG_t`, it must not
 * paste the following `,`); GNU `, ## __VA_ARGS__` drops the comma only when
 * the variadic argument is omitted; a `##` inside an argument is plain text
 * (only the replacement list's `##` pastes); a backslash-newline inside a
 * multi-line invocation is a splice. Returns 42. */
#include <string.h>
#define STR(x) #x
#define XSTR(x) STR(x)
#define Q(TAG, BEH) STR(TAG) "|" XSTR(BEH)
#define TF(TG, TG2, DOT) Q(TG##_t##TG2, "if (P"DOT") R")
#define CAT3(a, b, c) a##b##c
#define CNT(...) count(0, ## __VA_ARGS__)
static int count(int z, ...) { return z; }
#define D(n, b) XSTR(b)
int main(void) {
    if (strcmp(TF(L4_return,,), "L4_return_t|\"if (P\"\") R\"") != 0) return 1;
    if (strcmp(TF(L4_return, new_pt, ".new"), "L4_return_tnew_pt|\"if (P\"\".new\"\") R\"") != 0) return 2;
    int ac = 5;
    if (CAT3(a,,c) != 5) return 3;
    if (CNT() != 0 || CNT(7) != 0) return 4;
    if (strcmp(D(m, (fCAST##REGSTYPE(SRC) >> 1)), "(fCAST##REGSTYPE(SRC) >> 1)") != 0) return 5;
    if (strcmp(STR({ x = 1 + \
                     2; }), "{ x = 1 + 2; }") != 0) return 6;
    return 42;
}
