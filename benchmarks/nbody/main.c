// N-body gravity simulation — standalone extracted C benchmark
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void bench_nbody(void) {
    const int N = 2048;
    const int STEPS = 8;
    const double DT = 0.01;
    const double EPS = 0.05;
    double *px = malloc(N * sizeof(double)), *py = malloc(N * sizeof(double)), *pz = malloc(N * sizeof(double));
    double *vx = malloc(N * sizeof(double)), *vy = malloc(N * sizeof(double)), *vz = malloc(N * sizeof(double));
    double *m = malloc(N * sizeof(double));
    uint32_t s = 7777;
    for (int i = 0; i < N; i++) {
        s = s * 1664525u + 1013904223u; px[i] = ((double)(s & 0xFFFFu) / 65536.0) * 2.0 - 1.0;
        s = s * 1664525u + 1013904223u; py[i] = ((double)(s & 0xFFFFu) / 65536.0) * 2.0 - 1.0;
        s = s * 1664525u + 1013904223u; pz[i] = ((double)(s & 0xFFFFu) / 65536.0) * 2.0 - 1.0;
        s = s * 1664525u + 1013904223u; m[i] = (double)(s & 0xFFFFu) / 65536.0 + 0.1;
        vx[i] = 0.0; vy[i] = 0.0; vz[i] = 0.0;
    }
    for (int step = 0; step < STEPS; step++) {
        for (int i = 0; i < N; i++) {
            double ax = 0.0, ay = 0.0, az = 0.0;
            double xi = px[i], yi = py[i], zi = pz[i];
            for (int j = 0; j < N; j++) {
                if (j == i) continue;
                double dx = px[j] - xi, dy = py[j] - yi, dz = pz[j] - zi;
                double d2 = dx * dx + dy * dy + dz * dz + EPS;
                double g = (d2 + 1.0) * 0.5;
                for (int k = 0; k < 8; k++) g = (g + d2 / g) * 0.5;
                double inv3 = 1.0 / (d2 * g);
                double f = m[j] * inv3;
                ax += dx * f; ay += dy * f; az += dz * f;
            }
            vx[i] += ax * DT; vy[i] += ay * DT; vz[i] += az * DT;
        }
        for (int i = 0; i < N; i++) { px[i] += vx[i] * DT; py[i] += vy[i] * DT; pz[i] += vz[i] * DT; }
    }
    uint32_t cs = 0;
    for (int i = 0; i < N; i++) {
        cs = cs * 1000003u + (uint32_t)(int64_t)(px[i] * 1024.0);
        cs = cs * 1000003u + (uint32_t)(int64_t)(py[i] * 1024.0);
        cs = cs * 1000003u + (uint32_t)(int64_t)(pz[i] * 1024.0);
    }
    printf("checksum %u\n", cs);
    free(px); free(py); free(pz); free(vx); free(vy); free(vz); free(m);
}

int main(void) {
    bench_nbody();
    return 0;
}