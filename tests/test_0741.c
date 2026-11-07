/* typeof of a function name in a function is the function's type, not the pointer
   it decays to (Linux's DEFINE_IDTENTRY_SYSVEC static_assert on typeof(&__sysvec_x)). */
typedef unsigned int u32;
struct pt_regs;
struct big { long a[4]; };
static void sysvec(struct pt_regs *r);
static void common(struct pt_regs *r, u32 v);
static struct big makebig(int);
int fmt(const char *, ...);
static int add1(int x) { return x + 1; }
static int run(struct pt_regs *r) {
    _Static_assert(__builtin_types_compatible_p(typeof(&sysvec), void (*)(struct pt_regs *)), "sysvec");
    _Static_assert(__builtin_types_compatible_p(typeof(&common), void (*)(struct pt_regs *, u32)), "common");
    _Static_assert(__builtin_types_compatible_p(typeof(sysvec), void (struct pt_regs *)), "function type");
    _Static_assert(!__builtin_types_compatible_p(typeof(&sysvec), void (*)(long)), "other");
    _Static_assert(__builtin_types_compatible_p(typeof(&makebig), struct big (*)(int)), "struct return");
    _Static_assert(!__builtin_types_compatible_p(typeof(&fmt), int (*)(const char *)), "variadic");
    int (*p)(int) = add1;
    _Static_assert(__builtin_types_compatible_p(typeof(&add1), typeof(p)), "pointer variable");
    typeof(&add1) q = add1;
    typeof(add1) *s = add1;
    int got = __builtin_types_compatible_p(typeof(&add1), int (*)(int))
            + __builtin_types_compatible_p(typeof(add1), int (int)) * 2
            + __builtin_types_compatible_p(typeof(*p), int (int)) * 4;
    {
        long add1 = 5;
        _Static_assert(__builtin_types_compatible_p(typeof(add1), long), "hidden by a local");
        got += add1 - 5;
    }
    sysvec(r);
    return got == 7 && q(1) == 2 && s(2) == 3 && p(3) == 4 ? 0 : 1;
}
static void sysvec(struct pt_regs *r) { (void)r; }
int main(void) { return run(0); }
