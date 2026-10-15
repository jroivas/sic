/* The auto-vectorized loop tests `j < vend` at the bottom of its body (one
 * branch per vector step). Boundary lengths: none, under one vector, exact
 * multiples and remainders, plus a non-zero start. Returns 42. */
static int a[64], b[64];
static void run(int lo, int hi) {
    for (int j = lo; j < hi; j++) a[j] += b[j] * 3;
}
int main(int argc, char **argv) {
    for (int i = 0; i < 64; i++) { b[i] = i + argc; a[i] = 0; }
    long expect = 0, got = 0;
    for (int n = 0; n <= 17; n++) {
        for (int i = 0; i < 64; i++) a[i] = 0;
        run(0, n);
        run(n + 1, n + 1 + n);           /* a second range starting off zero */
        for (int i = 0; i < 64; i++) got += a[i] * (i + 1);
        for (int j = 0; j < n; j++) expect += (long)b[j] * 3 * (j + 1);
        for (int j = n + 1; j < 2 * n + 1; j++) expect += (long)b[j] * 3 * (j + 1);
    }
    return got == expect ? 42 : 1;
}
