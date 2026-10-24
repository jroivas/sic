// C11 `_Noreturn` function specifier, alone and next to GNU attributes
// (ggml.h: `_Noreturn __attribute__((format(printf, 3, 4))) void ggml_abort(...)`).
#include <stdlib.h>

_Noreturn __attribute__((format(printf, 1, 2))) static void die(const char *fmt, ...);
static _Noreturn void quit(int code) { exit(code); }
__attribute__((unused)) _Noreturn static inline void quit2(int code) { exit(code); }

static void die(const char *fmt, ...)
{
    (void)fmt;
    quit(42);
}

int main(void)
{
    die("%d", 1);
}
