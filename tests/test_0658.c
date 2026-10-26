// `%a` on a register operand prints the address it holds, `(%reg)` — Linux's
// vDSO futex unlock: `lock cmpxchgl %k[zero], %a[lock]` with [lock] "D". sic
// rejected the modifier on registers ("unsupported inline assembly").
static unsigned try_unlock(unsigned *lock, unsigned tid, unsigned long *pop) {
    asm volatile("lock cmpxchgl %k[zero], %a[lock]\n\t"
                 "jnz 1f\n\t"
                 "movq %[zero], %a[pop]\n"
                 "1:"
                 : [tid] "+&a"(tid)
                 : [lock] "D"(lock), [pop] "d"(pop), [zero] "r"(0UL)
                 : "memory", "cc");
    return tid;
}

int main(void) {
    unsigned lock = 7;
    unsigned long pop = 99;
    unsigned r1 = try_unlock(&lock, 7, &pop);    // matches: lock = 0, pop = 0
    int ok = (lock == 0) + (pop == 0) + (r1 == 7);
    lock = 5; pop = 99;
    unsigned r2 = try_unlock(&lock, 7, &pop);    // differs: tid = 5, untouched
    ok += (lock == 5) + (pop == 99) + (r2 == 5);
    return ok + 36;
}
