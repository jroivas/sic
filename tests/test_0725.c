// A volatile access happens, as written: through a pointer, a member, a typedef,
// `volatile typeof(x)` (Linux's READ_ONCE) or a bit-field, not only a variable
// declared so. Both back ends merged them at -O2: the IR could not say so.
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

typedef volatile int vint;
struct R { volatile int a; int b; volatile int *p; unsigned f : 3; volatile unsigned g : 3; };
#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))

static volatile sig_atomic_t tick;
static int plain;
static jmp_buf env;

static void on_alarm(int s) { (void)s; tick = 1; plain = 1; }

// Spins forever if the read is folded or hoisted out of the loop.
static int wait_pointer(volatile sig_atomic_t *p) { while (!*p) ; return 1; }
static int wait_once(void) { while (!READ_ONCE(plain)) ; return 1; }

static int after_longjmp(void)
{
    volatile int a = 1;
    if (setjmp(env)) return a;
    a = 2;
    longjmp(env, 1);
}

// The store through q must be seen by the reads through p.
static int order(volatile int *p, volatile int *q)
{
    *p = 1;
    *q = 2;
    return *p;
}

static int member(struct R *r, volatile int *q)
{
    r->a = 1;
    *q = 2;
    return r->a;
}

static int bits(struct R *r, volatile unsigned *q)
{
    r->g = 1;
    *q = 0x28;     // r->g = 5, in the unit they share
    return r->g;
}

static int by_typedef(vint *p, volatile int *q)
{
    *p = 1;
    *q = 2;
    return *p;
}

int main(void)
{
    signal(SIGALRM, on_alarm);
    alarm(1);
    if (!wait_pointer(&tick)) return 1;
    if (!wait_once()) return 2;
    if (after_longjmp() != 2) return 3;
    int v;
    if (order(&v, &v) != 2) return 4;
    struct R r;
    if (member(&r, &r.a) != 2) return 5;
    if (bits(&r, (volatile unsigned *)((char *)&r + __builtin_offsetof(struct R, p) + 8)) != 5) return 6;
    if (by_typedef(&v, &v) != 2) return 7;
    return 42;
}
