/* Software 3D rasterizer — renders a spinning, Gouraud-shaded UV sphere into an
   in-memory framebuffer with a z-buffer, for a fixed number of frames. Uses only
   +,-,*,/ and a hand-rolled polynomial sin/cos (libm's differ per language) so
   every language produces a bit-identical checksum. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define RASTER_W 640
#define RASTER_H 480
#define RASTER_RINGS 24
#define RASTER_SECTORS 24
#define RASTER_FRAMES 240
#define RASTER_NV ((RASTER_RINGS + 1) * (RASTER_SECTORS + 1))

static double r_floor(double y) {
    double f = (double)(int64_t)y;
    return f > y ? f - 1.0 : f;
}

static double r_sin(double x) {
    const double TWO_PI = 6.283185307179586;
    double k = r_floor(x / TWO_PI + 0.5);
    x = x - k * TWO_PI;
    double x2 = x * x;
    double p = -1.0 / 1307674368000.0;
    p = 1.0 / 6227020800.0 + x2 * p;
    p = -1.0 / 39916800.0 + x2 * p;
    p = 1.0 / 362880.0 + x2 * p;
    p = -1.0 / 5040.0 + x2 * p;
    p = 1.0 / 120.0 + x2 * p;
    p = -1.0 / 6.0 + x2 * p;
    p = 1.0 + x2 * p;
    return x * p;
}

static double r_cos(double x) {
    const double HALF_PI = 1.5707963267948966;
    return r_sin(x + HALF_PI);
}

static double edge(double ax, double ay, double bx, double by, double cx, double cy) {
    return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
}

static void bench_raster(void) {
    const double FOCAL = 500.0;
    const double CAM_DIST = 3.0;

    static double bx[RASTER_NV], by[RASTER_NV], bz[RASTER_NV];
    int nv = 0;
    for (int i = 0; i <= RASTER_RINGS; i++) {
        double theta = 3.141592653589793 * ((double)i / (double)RASTER_RINGS);
        double st = r_sin(theta);
        double ct = r_cos(theta);
        for (int j = 0; j <= RASTER_SECTORS; j++) {
            double phi = 6.283185307179586 * ((double)j / (double)RASTER_SECTORS);
            double sp = r_sin(phi);
            double cp = r_cos(phi);
            bx[nv] = st * cp;
            by[nv] = ct;
            bz[nv] = st * sp;
            nv += 1;
        }
    }

    static double sx[RASTER_NV], sy[RASTER_NV], sz[RASTER_NV], si[RASTER_NV];

    unsigned char *color = (unsigned char *)malloc(RASTER_W * RASTER_H);
    double *zbuf = (double *)malloc(RASTER_W * RASTER_H * sizeof(double));

    uint64_t checksum = 0;

    for (int f = 0; f < RASTER_FRAMES; f++) {
        double ang = (double)f * 0.0125;
        double cy = r_cos(ang);
        double syr = r_sin(ang);
        double ax = ang * 0.5;
        double cx = r_cos(ax);
        double sxr = r_sin(ax);

        for (int v = 0; v < nv; v++) {
            double px0 = bx[v], py0 = by[v], pz0 = bz[v];
            double rx = px0 * cy + pz0 * syr;
            double rz = -px0 * syr + pz0 * cy;
            double ry = py0;
            double ry2 = ry * cx - rz * sxr;
            double rz2 = ry * sxr + rz * cx;
            double inten = -rz2;
            if (inten < 0.0) inten = 0.0;
            double zc = rz2 + CAM_DIST;
            double invz = 1.0 / zc;
            sx[v] = rx * invz * FOCAL + (double)RASTER_W * 0.5;
            sy[v] = ry2 * invz * FOCAL + (double)RASTER_H * 0.5;
            sz[v] = zc;
            si[v] = inten;
        }

        for (int i = 0; i < RASTER_W * RASTER_H; i++) { color[i] = 0; zbuf[i] = 1.0e30; }

        for (int ri = 0; ri < RASTER_RINGS; ri++) {
            for (int sj = 0; sj < RASTER_SECTORS; sj++) {
                int a = ri * (RASTER_SECTORS + 1) + sj;
                int b = a + (RASTER_SECTORS + 1);
                int tris[2][3] = {{a, b, a + 1}, {a + 1, b, b + 1}};
                for (int t = 0; t < 2; t++) {
                    int i0 = tris[t][0], i1 = tris[t][1], i2 = tris[t][2];
                    double area = edge(sx[i0], sy[i0], sx[i1], sy[i1], sx[i2], sy[i2]);
                    if (area <= 0.0) continue;
                    double mnx = sx[i0];
                    if (sx[i1] < mnx) mnx = sx[i1];
                    if (sx[i2] < mnx) mnx = sx[i2];
                    double mxx = sx[i0];
                    if (sx[i1] > mxx) mxx = sx[i1];
                    if (sx[i2] > mxx) mxx = sx[i2];
                    double mny = sy[i0];
                    if (sy[i1] < mny) mny = sy[i1];
                    if (sy[i2] < mny) mny = sy[i2];
                    double mxy = sy[i0];
                    if (sy[i1] > mxy) mxy = sy[i1];
                    if (sy[i2] > mxy) mxy = sy[i2];
                    if (mnx < 0.0) mnx = 0.0;
                    if (mxx > (double)(RASTER_W - 1)) mxx = (double)(RASTER_W - 1);
                    if (mny < 0.0) mny = 0.0;
                    if (mxy > (double)(RASTER_H - 1)) mxy = (double)(RASTER_H - 1);
                    int x0 = (int)mnx, x1 = (int)mxx, y0 = (int)mny, y1 = (int)mxy;
                    for (int py = y0; py <= y1; py++) {
                        double pcy = (double)py + 0.5;
                        for (int px = x0; px <= x1; px++) {
                            double pcx = (double)px + 0.5;
                            double w0 = edge(sx[i1], sy[i1], sx[i2], sy[i2], pcx, pcy);
                            double w1 = edge(sx[i2], sy[i2], sx[i0], sy[i0], pcx, pcy);
                            double w2 = edge(sx[i0], sy[i0], sx[i1], sy[i1], pcx, pcy);
                            if (w0 >= 0.0 && w1 >= 0.0 && w2 >= 0.0) {
                                double l0 = w0 / area, l1 = w1 / area, l2 = w2 / area;
                                double depth = l0 * sz[i0] + l1 * sz[i1] + l2 * sz[i2];
                                int idx = py * RASTER_W + px;
                                if (depth < zbuf[idx]) {
                                    zbuf[idx] = depth;
                                    double inten = l0 * si[i0] + l1 * si[i1] + l2 * si[i2];
                                    if (inten < 0.0) inten = 0.0;
                                    if (inten > 1.0) inten = 1.0;
                                    color[idx] = (unsigned char)(inten * 255.0);
                                }
                            }
                        }
                    }
                }
            }
        }

        uint64_t frame_sum = 0;
        for (int i = 0; i < RASTER_W * RASTER_H; i++) frame_sum += color[i];
        checksum = checksum * 1000003 + frame_sum;
    }

    printf("checksum %llu\n", (unsigned long long)checksum);

    free(color);
    free(zbuf);
}

int main(void) {
    bench_raster();
    return 0;
}