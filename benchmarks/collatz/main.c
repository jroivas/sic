/* Collatz conjecture step-count sum — a pure arithmetic / branch-prediction
   benchmark. Sums the number of Collatz steps for 1..N and prints the checksum
   so all language versions can be compared. */
#include <stdio.h>
#include <stdint.h>

static void bench_collatz(void) {
    const uint64_t N = 3000000;
    uint64_t total = 0;
    for (uint64_t i = 1; i <= N; i++) {
        uint64_t n = i, steps = 0;
        while (n != 1) {
            n = n % 2 == 0 ? n / 2 : 3 * n + 1;
            steps += 1;
        }
        total += steps;
    }
    printf("checksum %llu\n", (unsigned long long)total);
}

int main(void) {
    bench_collatz();
    return 0;
}