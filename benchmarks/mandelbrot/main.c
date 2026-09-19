/* Mandelbrot set point count over a W x H grid — a floating-point compute
   benchmark (double add/mul/compare in a tight iteration loop), no arrays. Prints
   the number of grid points still bounded after MAXIT iterations (in the set), so
   all language versions can be compared with an integer checksum. */
#include <stdio.h>

#define W 1000
#define H 1000
#define MAXIT 256

int main(void) {
    long count = 0;
    for (int py = 0; py < H; py++) {
        double y0 = (double)py / H * 2.0 - 1.0;      // -1 .. 1
        for (int px = 0; px < W; px++) {
            double x0 = (double)px / W * 3.0 - 2.0;  // -2 .. 1
            double x = 0.0, y = 0.0;
            int it = 0;
            while (x * x + y * y <= 4.0 && it < MAXIT) {
                double xt = x * x - y * y + x0;
                y = 2.0 * x * y + y0;
                x = xt;
                it++;
            }
            if (it == MAXIT) count++;
        }
    }
    printf("%ld\n", count);
    return 0;
}
