// "i" asm operands that are symbol addresses (&global, &static, &s.field) —
// printed $sym / sym (%c) / sym(%rip) (%a), Linux's per-CPU `%gs:%a[var]` —
// including ones only constant after inlining (an always_inline function's
// parameter, Linux's arch_static_branch), and asm goto (%l[label] / %lN),
// with constant, register and output operands.
#include <string.h>

long g = 5;
static long st = 7;
struct pair { int a, b; } sv = { 1, 9 };
struct ent { long key; long br; };
extern struct ent __start_sic_jt[], __stop_sic_jt[];

static long load_a(void) { long v; asm("movq %a1, %0" : "=r"(v) : "i"(&g)); return v; }
static long load_st(void) { long v; asm("movq %c1(%%rip), %0" : "=r"(v) : "i"(&st)); return v; }
static int load_b(void) { int v; asm("movl %a1, %0" : "=r"(v) : "i"(&sv.b)); return v; }

static inline __attribute__((always_inline)) long load_p(long *p) {
    long v;
    asm("movq %a1, %0" : "=r"(v) : "i"(p));
    return v;
}

// A jump-label site: records (key, branch) and jumps when `on`.
static inline __attribute__((always_inline)) int branch(long *key, int on) {
    asm goto("cmpl $0, %c2(%%rip)\n\tjne %l[yes]\n"
             ".pushsection sic_jt,\"aw\"\n\t.quad %c0, %c1\n.popsection"
             : : "i"(key), "i"(on), "i"(&sv.a) : : yes);
    return 0;
yes:
    return 1;
}

static int classify(int x) {
    asm goto("cmpl $5, %0\n\tje %l[five]\n\tcmpl $7, %0\n\tje %l2" : : "r"(x) : "cc" : five, seven);
    return 0;
five:
    return 5;
seven:
    return 7;
}

static int out_goto(int x) {
    int v;
    asm goto("movl $3, %0\n\ttestl %1, %1\n\tjz %l[zero]" : "=&r"(v) : "r"(x) : "cc" : zero);
    return v;
zero:
    return 100;
}

int main(void) {
    int ok = 0;
    if (load_a() == 5) ok++;
    if (load_st() == 7) ok++;
    if (load_b() == 9) ok++;
    if (load_p(&g) == 5 && load_p(&st) == 7) ok++;
    if (branch(&g, 1) == 1) ok++;          // sv.a == 1 -> jumps
    sv.a = 0;
    if (branch(&st, 0) == 0) ok++;
    // Each site's (key, branch) is recorded (a compiler may duplicate a site).
    int on_g = 0, off_st = 0;
    for (struct ent *e = __start_sic_jt; e < __stop_sic_jt; e++) {
        on_g |= e->key == (long)&g && e->br == 1;
        off_st |= e->key == (long)&st && e->br == 0;
    }
    if (on_g && off_st) ok++;
    if (classify(5) == 5 && classify(7) == 7 && classify(1) == 0) ok++;
    if (out_goto(1) == 3 && out_goto(0) == 100) ok++;
    return ok + 33;
}
