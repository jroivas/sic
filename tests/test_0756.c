/* A volatile member of a non-volatile struct local is volatile: it keeps the
 * value a longjmp returns to, and a signal handler's write is seen by a loop
 * polling it (TODO.md said such locals were not volatile; both back ends are
 * right, pinned here). Returns 42. */
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
static jmp_buf j;
__attribute__((noinline)) static void jump(int v) { longjmp(j, v); }
struct st { volatile int count; int other; };
struct fl { volatile sig_atomic_t hit; int pad; };
static struct fl *gp;
static void on_alarm(int s) { (void)s; gp->hit = 1; }
int main(void) {
    struct st s = { 0, 7 };
    int r = setjmp(j);
    if (r < 5) { s.count++; jump(r + 1); }
    if (s.count != 5) return 1;
    struct fl f = { 0, 0 };
    gp = &f;
    signal(SIGALRM, on_alarm);
    ualarm(1000, 0);
    long spins = 0;
    while (!f.hit) { if (++spins > 4000000000L) return 2; }
    return 42;
}
