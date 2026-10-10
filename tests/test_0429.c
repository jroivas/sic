/* __atomic_thread_fence(__ATOMIC_SEQ_CST) (C11 atomic_thread_fence, QEMU
 * smp_mb) and __sync_synchronize were NO-OPS in sic. Store-buffering litmus:
 * thread A `x = 1; fence; r1 = y`, thread B `y = 1; fence; r2 = x`. Without the
 * fences x86 can make both loads read 0 (each store still sits in its core's
 * store buffer); with seq_cst fences that outcome is forbidden. Returns 42. */
#include <pthread.h>
#define ROUNDS 20000
static volatile int x, y, r1, r2;
static int go_a, go_b, done;             /* round handshakes (atomics) */
static void *thread_b(void *arg) {
    (void)arg;
    for (int i = 1; i <= ROUNDS; i++) {
        while (__atomic_load_n(&go_b, __ATOMIC_ACQUIRE) != i) { }
        y = 1;
        if (i & 1) __atomic_thread_fence(__ATOMIC_SEQ_CST); else __sync_synchronize();
        r2 = x;
        __atomic_fetch_add(&done, 1, __ATOMIC_ACQ_REL);
    }
    return 0;
}
int main(void) {
    pthread_t t;
    if (pthread_create(&t, 0, thread_b, 0)) return 1;
    int both_zero = 0;
    for (int i = 1; i <= ROUNDS; i++) {
        x = 0; y = 0;
        __atomic_store_n(&go_b, i, __ATOMIC_RELEASE);   /* release B ... */
        x = 1;                                          /* ... and race it */
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        r1 = y;
        while (__atomic_load_n(&done, __ATOMIC_ACQUIRE) != i) { }
        if (r1 == 0 && r2 == 0) both_zero++;
    }
    pthread_join(t, 0);
    return both_zero == 0 ? 42 : 2;
}
