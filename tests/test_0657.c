// An asm statement on a branch that a constant condition rules out is not
// assembled: Linux's cmpxchg macros `switch (sizeof(*ptr))` with an asm per
// size, and for a 4-byte operand the `case 1:` arm's `cmpxchgb` on a 32-bit
// register does not assemble ("%esi not allowed with cmpxchgb"). GCC and Clang
// drop the dead arms before emitting asm.
#include <stdbool.h>

static inline __attribute__((always_inline)) bool try_cmpxchg(int *ptr, int *old, int new) {
    bool ok;
    int o = *old;
    switch (sizeof(*ptr)) {
    case 1:
        asm volatile("lock cmpxchgb %[new], %[ptr]" : "=@ccz"(ok), [ptr] "+m"(*ptr), [old] "+a"(o) : [new] "q"(new) : "memory");
        break;
    case 4:
        asm volatile("lock cmpxchgl %[new], %[ptr]" : "=@ccz"(ok), [ptr] "+m"(*ptr), [old] "+a"(o) : [new] "r"(new) : "memory");
        break;
    }
    if (0)
        asm volatile("movb %0, %%al" : : "r"(new));       // dead: a 32-bit register with movb
    *old = o;
    return ok;
}

int main(void) {
    int v = 5, old = 5;
    int a = try_cmpxchg(&v, &old, 40);                   // succeeds: v = 40
    old = 3;
    int b = try_cmpxchg(&v, &old, 7);                    // fails: old = 40
    return a + (b == 0) + (v == 40) + (old == 40) + 38;
}
