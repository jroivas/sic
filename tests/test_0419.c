/* __int128 min/max (`x < y ? x : y`, every predicate, signed and unsigned):
 * Cranelift's mid-end rewrote such selects into smin/umin/smax/umax, which the
 * x64 back end cannot lower on i128 (QEMU int128_min/max at -O2:
 * "should be implemented in ISLE"). Returns 42. */
typedef __int128 S;
typedef unsigned __int128 U;
__attribute__((noinline)) S smin(S x, S y) { return x < y ? x : y; }
__attribute__((noinline)) S smax(S x, S y) { return x >= y ? x : y; }
__attribute__((noinline)) U umin(U x, U y) { return y <= x ? y : x; }
__attribute__((noinline)) U umax(U x, U y) { return x > y ? x : y; }
int main(void) {
    S big = (S)1 << 100, neg = -((S)7 << 90);
    if (smin(big, neg) != neg || smax(big, neg) != big) return 1;
    if (smin(-1, 1) != -1 || smax(-1, 1) != 1) return 2;
    U top = (U)1 << 127;
    if (umin(top, 1) != 1 || umax(top, 1) != top) return 3;
    if (umin((U)-1, (U)1 << 64) != (U)1 << 64) return 4;
    return 42;
}
