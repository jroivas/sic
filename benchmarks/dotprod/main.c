/* Integer dot product of two large arrays — a pure vectorizable reduction
   (`sum += a[i]*b[i]`), no other work. LLVM auto-vectorizes it into SIMD
   multiply-accumulate + a horizontal sum; a scalar back end pays one multiply-add
   per element. Integer, so the sum is exact regardless of reduction order. Prints
   the dot product. */
#include <stdio.h>
#include <stdlib.h>

#define N 50000000

int main(void) {
    int *a = (int *)malloc((long)N * sizeof(int));
    int *b = (int *)malloc((long)N * sizeof(int));
    for (long i = 0; i < N; i++) { a[i] = (int)(i % 1000); b[i] = (int)((i * 3 + 1) % 1000); }
    long sum = 0;
    for (long i = 0; i < N; i++) sum += (long)a[i] * b[i];
    printf("%ld\n", sum);
    free(a); free(b);
    return 0;
}
