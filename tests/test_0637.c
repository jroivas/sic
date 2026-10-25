// __attribute__((section)) and ((used)) as Linux uses them: an initcall-style
// table of function pointers placed in a section and walked through the
// linker's __start_/__stop_ symbols, a function-scope `static` in its own
// section (WARN_ONCE's .data.once), a function in a named section, and an
// uncalled `static` function kept by `used`.
#include <string.h>

typedef int (*initcall_t)(void);

static int calls;
static int init_a(void) { calls += 1; return 0; }
static int init_b(void) { calls += 10; return 0; }

#define INITCALL(fn) \
    static initcall_t __initcall_##fn __attribute__((__used__, __section__("sic_initcall"))) = fn

INITCALL(init_a);
INITCALL(init_b);

extern initcall_t __start_sic_initcall[], __stop_sic_initcall[];

static int once(void)
{
    static int done __attribute__((__section__(".data.once")));
    if (done) return 0;
    done = 1;
    return 1;
}

__attribute__((__section__(".text.unlikely"))) int cold_path(int x) { return x * 2; }

static void __attribute__((__used__)) only_from_asm(void) { }

const char tag[] __attribute__((__section__(".rodata.sic_tag"))) = "sic";

int main(void)
{
    for (initcall_t *p = __start_sic_initcall; p < __stop_sic_initcall; p++) (*p)();
    int r = once() + once();            // 1
    return calls + r + cold_path(15) + (int)strlen(tag) - 3; // 11 + 1 + 30 = 42
}
