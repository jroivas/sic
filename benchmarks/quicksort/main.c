/* In-place quicksort of N pseudo-random ints — recursion, data-dependent branching
   and swaps, irregular array access (not simple counting loops). Recurses into the
   smaller partition and loops on the larger, bounding stack depth to O(log N).
   Prints an order-dependent checksum (so a mis-sort changes it). */
#include <stdio.h>
#include <stdlib.h>

#define N 3000000

static void qsort_ints(int *a, long lo, long hi) {
    while (lo < hi) {
        int pivot = a[hi];
        long i = lo;
        for (long j = lo; j < hi; j++)
            if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
        int t = a[i]; a[i] = a[hi]; a[hi] = t;
        if (i - lo < hi - i) { qsort_ints(a, lo, i - 1); lo = i + 1; }
        else                 { qsort_ints(a, i + 1, hi); hi = i - 1; }
    }
}

int main(void) {
    int *a = (int *)malloc((long)N * sizeof(int));
    unsigned long s = 123456789UL;
    for (long i = 0; i < N; i++) {
        s = s * 6364136223846793005UL + 1442695040888963407UL;
        a[i] = (int)((s >> 33) % 1000000UL);
    }
    qsort_ints(a, 0, N - 1);
    long sum = 0;
    for (long i = 0; i < N; i++) sum += (long)a[i] * (i % 251);
    printf("%ld\n", sum);
    free(a);
    return 0;
}
