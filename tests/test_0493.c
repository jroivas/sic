/* -O2 rewrites a signed `x % 2^k` whose every use is `== 0` / `!= 0` into
 * `x & (2^k-1)`; a remainder used as a VALUE must stay signed (`-6 % 4` is -2).
 * Also exercises ir-fold's constant-condition `select` and small SExt folding.
 * Returns 42. */
int main(int argc, char **argv) {
    long hits = 0, vals = 0;
    for (long n = -50; n <= 50; n++) {
        long v = n + argc - 1;
        if (v % 2 == 0) hits += 1;
        if (v % 8 != 0) hits += 100;
        long r = v % 4;
        vals += r * (r == 0 ? 7 : 1);
        int q = (int)v % 16 == 0;
        hits += q * 10000;
    }
    if (hits != 78851 || vals != 0) return 1;
    long m = -6 + argc - 1;
    if (m % 4 != -2 || (m & 3) != 2) return 2;
    return 42;
}
