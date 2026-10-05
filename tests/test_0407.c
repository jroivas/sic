/* Real atomicity of the C atomic builtins under contention: 8 threads hammer an
 * atomic_flag spinlock (__atomic_test_and_set/__atomic_clear), atomic_fetch_add, a
 * compare-exchange loop, __atomic_add_fetch / __sync_fetch_and_add and exchange.
 * With plain (non-atomic) lowering, updates are lost. Exit 0 = exact totals. */
#include <stdatomic.h>
#include <pthread.h>

#define T 8
#define N 50000
static atomic_flag lock = ATOMIC_FLAG_INIT;
static long guarded = 0;                 /* protected by the flag spinlock */
static atomic_long adds = 0;             /* atomic_fetch_add */
static _Atomic int casd = 0;             /* CAS loop increments */
static long gnu = 0;                     /* __atomic_add_fetch / __sync_fetch_and_add */
static atomic_int xchg_tok = 0;          /* atomic_exchange token passing */
static long xchg_hits = 0;
static void *work(void *arg) {
    (void)arg;
    for (int i = 0; i < N; i++) {
        while (atomic_flag_test_and_set(&lock)) ;          /* spinlock */
        guarded++;
        atomic_flag_clear(&lock);
        atomic_fetch_add(&adds, 1);
        int e = atomic_load(&casd);
        while (!atomic_compare_exchange_weak(&casd, &e, e + 1)) ;   /* e refreshed on failure */
        __atomic_add_fetch(&gnu, 1, __ATOMIC_SEQ_CST);
        __sync_fetch_and_add(&gnu, 1);
        if (atomic_exchange(&xchg_tok, 1) == 0) { xchg_hits++; atomic_store(&xchg_tok, 0); }
    }
    return 0;
}
int main(void) {
    pthread_t th[T];
    for (int i = 0; i < T; i++) pthread_create(&th[i], 0, work, 0);
    for (int i = 0; i < T; i++) pthread_join(th[i], 0);
    long want = (long)T * N;


    return !(guarded == want && adds == want && casd == want && gnu == 2 * want);
}
