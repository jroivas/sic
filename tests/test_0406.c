/* gcc <stdatomic.h> end to end: atomic_flag (__atomic_test_and_set/__atomic_clear),
 * fetch ops, generic __atomic_exchange, compare-exchange (desired passed BY POINTER
 * in the generic form; the observed value is written back to *expected on failure),
 * load/store, lock-free queries. Returns 42. */
#include <stdatomic.h>
#include <stdbool.h>
int main(void) {
    atomic_flag f = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set(&f) != 0) return 1;
    if (atomic_flag_test_and_set(&f) != 1) return 2;
    atomic_flag_clear(&f);
    if (atomic_flag_test_and_set_explicit(&f, memory_order_acquire) != 0) return 3;
    atomic_int x = 40;
    if (atomic_fetch_add(&x, 2) != 40 || x != 42) return 4;
    atomic_fetch_sub(&x, 1); atomic_fetch_or(&x, 1); atomic_fetch_and(&x, ~0); atomic_fetch_xor(&x, 0);
    if (atomic_exchange(&x, 7) != 41 || x != 7) return 5;
    int exp = 7;
    if (!atomic_compare_exchange_strong(&x, &exp, 9) || x != 9) return 6;
    exp = 1;
    if (atomic_compare_exchange_weak(&x, &exp, 5) || exp != 9 || x != 9) return 7;
    atomic_store(&x, 11);
    if (atomic_load(&x) != 11) return 8;
    _Atomic long lg = 1;
    if (atomic_exchange_explicit(&lg, 5L, memory_order_seq_cst) != 1 || lg != 5) return 9;
    _Atomic(void *) ap = 0;
    if (atomic_exchange(&ap, (void *)&x) != 0 || ap != (void *)&x) return 10;
    if (!atomic_is_lock_free(&x) || ATOMIC_INT_LOCK_FREE != 2 || ATOMIC_POINTER_LOCK_FREE != 2) return 11;
    atomic_thread_fence(memory_order_seq_cst);
    atomic_signal_fence(memory_order_seq_cst);
    return kill_dependency(42);
}
