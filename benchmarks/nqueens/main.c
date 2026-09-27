// N-queens backtracking — standalone extracted C benchmark
#include <stdio.h>
#include <stdint.h>

static uint64_t nq_solve(uint32_t cols, uint32_t d1, uint32_t d2, uint32_t full) {
    if (cols == full) return 1;
    uint64_t count = 0;
    uint32_t avail = (~(cols | d1 | d2)) & full;
    while (avail != 0) {
        uint32_t bit = avail & (0u - avail);
        avail -= bit;
        count += nq_solve(cols | bit, ((d1 | bit) * 2u) & full, (d2 | bit) / 2u, full);
    }
    return count;
}

static void bench_nqueens(void) {
    const int NQ = 14;
    uint32_t full = (1u << NQ) - 1u;
    uint64_t total = nq_solve(0, 0, 0, full);
    printf("checksum %llu\n", (unsigned long long)total);
}

int main(void) {
    bench_nqueens();
    return 0;
}