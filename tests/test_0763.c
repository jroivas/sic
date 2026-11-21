/* A `static __thread` (or `_Thread_local`) local is one variable per thread:
   the block-scope declaration lost the storage class, so every thread shared
   one. Returns 42. */
#include <pthread.h>

static int *mine(void) { static __thread int v; return &v; }
static int *mine11(void) { static _Thread_local int v = 7; return &v; }

static void *run(void *arg) {
    (void)arg;
    *mine() = 5;
    *mine11() = 9;
    return 0;
}

int main(void) {
    pthread_t t;
    *mine() = 1;
    if (pthread_create(&t, 0, run, 0) != 0) return 1;
    pthread_join(t, 0);
    if (*mine() != 1) return 2;
    if (*mine11() != 7) return 3;
    return 42;
}
