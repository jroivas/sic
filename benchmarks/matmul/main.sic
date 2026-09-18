/* Dense integer matrix multiply (N x N), i-k-j order — a nested-loop / array
   indexing / arithmetic benchmark. Prints a checksum (sum of the product matrix)
   so all language versions can be compared. */
#include <stdio.h>
#include <stdlib.h>

#define N 1024

int main(void) {
    int *a = (int *)malloc((long)N * N * sizeof(int));
    int *b = (int *)malloc((long)N * N * sizeof(int));
    int *c = (int *)malloc((long)N * N * sizeof(int));
    for (int i = 0; i < N * N; i++) {
        a[i] = (i * 7 + 1) % 100;
        b[i] = (i * 3 + 2) % 100;
        c[i] = 0;
    }
    for (int i = 0; i < N; i++)
        for (int k = 0; k < N; k++) {
            int aik = a[i * N + k];
            for (int j = 0; j < N; j++)
                c[i * N + j] += aik * b[k * N + j];
        }
    long sum = 0;
    for (int i = 0; i < N * N; i++) sum += c[i];
    printf("%ld\n", sum);
    free(a); free(b); free(c);
    return 0;
}
