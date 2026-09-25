// The auto-vectorizer also applies to C sources compiled with sic (raw malloc'd
// pointers, no bounds checks — unchecked like the scalar loop). Correctness across
// the SAXPY / copy / add forms, the scalar remainder, and — critically for C,
// where pointers alias freely — the runtime alias guard falling back to the scalar
// path when regions overlap. Returns 42.
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);

    // i32 SAXPY over raw pointers, length 1023 (remainder for a 4-lane vector)
    int n = 1023;
    int *c = malloc(n * 4), *b = malloc(n * 4);
    for (int j = 0; j < n; j++) { c[j] = j; b[j] = 2; }
    int s = 5;
    for (int j = 0; j < n; j++) c[j] += s * b[j];         // c[j] = j + 10
    long sum = 0; for (int j = 0; j < n; j++) sum += c[j];
    if (sum != (long)(n - 1) * n / 2 + 10L * n) return 1;

    // add two distinct arrays
    int *p = malloc(50 * 4), *q = malloc(50 * 4), *r = malloc(50 * 4);
    for (int j = 0; j < 50; j++) { p[j] = j; q[j] = j * 2; }
    for (int j = 0; j < 50; j++) r[j] = p[j] + q[j];      // 3j
    long rs = 0; for (int j = 0; j < 50; j++) rs += r[j];
    if (rs != 3 * (49 * 50 / 2)) return 2;

    // aliasing hazard: a backward dependence through overlapping pointers must match
    // the scalar result (the alias guard falls back to scalar).
    int *a = malloc(64 * 4);
    for (int j = 0; j < 64; j++) a[j] = j + 1;
    int *w = a + 1;                                        // w overlaps a
    for (int j = 0; j < 63; j++) w[j] += a[j];             // a[j+1] += a[j]
    int *ref = malloc(64 * 4);
    for (int j = 0; j < 64; j++) ref[j] = j + 1;
    for (int j = 0; j < 63; j++) ref[j + 1] += ref[j];
    for (int j = 0; j < 64; j++) if (a[j] != ref[j]) return 3;

    printf("autovec-c: OK\n");
    return 42;
}
