/* spectral-norm (n = 3000) — the Computer Language Benchmarks Game.
   Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/spectralnorm.html
   (algorithm as in the single-threaded C programs there; revised BSD licence).
   Adapted: single-threaded, no SIMD, fixed n; prints the norm scaled by 1e9 as an
   integer checksum. Stresses FP division/multiply in O(n^2) matrix-vector loops. */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define N 3000

static double eval_a(int i, int j) { return 1.0 / ((i + j) * (i + j + 1) / 2 + i + 1); }

static void mul_av(const double *v, double *av) {
    for (int i = 0; i < N; i++) {
        double s = 0.0;
        for (int j = 0; j < N; j++) s += eval_a(i, j) * v[j];
        av[i] = s;
    }
}

static void mul_atv(const double *v, double *atv) {
    for (int i = 0; i < N; i++) {
        double s = 0.0;
        for (int j = 0; j < N; j++) s += eval_a(j, i) * v[j];
        atv[i] = s;
    }
}

static void mul_atav(const double *v, double *out, double *tmp) {
    mul_av(v, tmp);
    mul_atv(tmp, out);
}

int main(void) {
    double *u = malloc(N * sizeof(double)), *v = malloc(N * sizeof(double));
    double *tmp = malloc(N * sizeof(double));
    for (int i = 0; i < N; i++) u[i] = 1.0;
    for (int i = 0; i < 10; i++) {
        mul_atav(u, v, tmp);
        mul_atav(v, u, tmp);
    }
    double vbv = 0.0, vv = 0.0;
    for (int i = 0; i < N; i++) { vbv += u[i] * v[i]; vv += v[i] * v[i]; }
    printf("%lld\n", (long long)(sqrt(vbv / vv) * 1e9));
    free(u); free(v); free(tmp);
    return 0;
}
