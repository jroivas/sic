/* `__thread` must be REAL thread-local storage, not a shared global. sic used to
 * ignore the specifier, so every thread shared one instance — QEMU's per-thread
 * bql_locked/rcu_reader/current_cpu got corrupted across its RCU/worker threads,
 * and bql_lock_impl's `assert(!bql_locked())` fired at machine boot. Verify each
 * thread sees its own copy. */
#include <pthread.h>

static __thread int tls_val;         /* zero-initialized TLS (.tbss) */
static __thread long tls_seed = 100; /* initialized TLS (.tdata) */

static void *worker(void *arg)
{
    long id = (long)arg;
    tls_val = (int)id;
    tls_seed += id;
    /* burn some cycles so the two threads interleave */
    for (volatile int i = 0; i < 2000000; i++) { }
    /* if TLS were shared, another thread's writes would show here */
    if (tls_val != (int)id) return (void *)1;
    if (tls_seed != 100 + id) return (void *)2;
    return (void *)0;
}

int main(void)
{
    pthread_t t[4];
    for (long i = 0; i < 4; i++) pthread_create(&t[i], 0, worker, (void *)(i + 1));
    for (int i = 0; i < 4; i++) {
        void *r;
        pthread_join(t[i], &r);
        if (r != (void *)0) return 10 + i;
    }
    /* main thread's own TLS is still its initial value */
    if (tls_val != 0 || tls_seed != 100) return 3;
    return 0;
}
