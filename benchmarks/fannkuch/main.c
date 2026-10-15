/* fannkuch-redux (n = 10) — the Computer Language Benchmarks Game.
   Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/fannkuchredux.html
   (algorithm as in the single-threaded C programs there; revised BSD licence).
   Adapted: single-threaded, fixed n, prints one checksum = checksum*1000 + maxflips
   instead of the two-line report. Stresses small-array permutation loops. */
#include <stdio.h>

#define N 10

int main(void) {
    int perm[N], perm1[N], count[N];
    int maxflips = 0, checksum = 0, permcount = 0;
    for (int i = 0; i < N; i++) perm1[i] = i;
    int r = N;
    for (;;) {
        while (r != 1) { count[r - 1] = r; r--; }
        for (int i = 0; i < N; i++) perm[i] = perm1[i];
        int flips = 0;
        int k = perm[0];
        while (k != 0) {
            for (int i = 0, j = k; i < j; i++, j--) {
                int t = perm[i]; perm[i] = perm[j]; perm[j] = t;
            }
            flips++;
            k = perm[0];
        }
        if (flips > maxflips) maxflips = flips;
        checksum += (permcount % 2 == 0) ? flips : -flips;
        /* next permutation (rotate the first r+1 elements, odometer count) */
        for (;;) {
            if (r == N) {
                printf("%d\n", checksum * 1000 + maxflips);
                return 0;
            }
            int perm0 = perm1[0];
            for (int i = 0; i < r; i++) perm1[i] = perm1[i + 1];
            perm1[r] = perm0;
            count[r]--;
            if (count[r] > 0) break;
            r++;
        }
        permcount++;
    }
}
