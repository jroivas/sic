/* Sieve of Eratosthenes up to N — an array / tight-loop / memory benchmark.
   Prints the number of primes found so all language versions can be compared. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 100000000

int main(void) {
    char *sieve = (char *)malloc(N + 1);
    memset(sieve, 1, N + 1);
    long count = 0;
    for (long i = 2; i <= N; i++) {
        if (sieve[i]) {
            count++;
            for (long j = i * i; j <= N; j += i) sieve[j] = 0;
        }
    }
    printf("%ld\n", count);
    free(sieve);
    return 0;
}
