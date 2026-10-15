/* -O2: in `select(x % 2^k == 0, x / 2^k, other)` the signed division is exact
 * whenever it is chosen, so it becomes an arithmetic shift. Negative values,
 * a mismatched power (`x % 4 == 0 ? x / 2`) and a division with another use
 * must keep exact C results. Returns 42. */
int main(int argc, char **argv) {
    long acc = 0;
    for (long v = -40; v <= 40; v++) {
        long x = v + argc - 1;
        long a = x % 2 == 0 ? x / 2 : 3 * x + 1;
        long b = (x & 7) == 0 ? x / 8 : -x;
        long c = x % 4 == 0 ? x / 2 : 0;            /* k mismatch: x / 2 stays right */
        long q = x / 4;
        long d = x % 4 == 0 ? q : 1;
        acc += a * 3 + b * 5 + c * 7 + d * 11 + q;  /* q also used here */
    }
    long ref = 0;
    for (long v = -40; v <= 40; v++) {
        long x = v + argc - 1;
        volatile long two = 2, eight = 8, four = 4;
        long a = x % two == 0 ? x / two : 3 * x + 1;
        long b = x % eight == 0 ? x / eight : -x;
        long c = x % four == 0 ? x / two : 0;
        long q = x / four;
        long d = x % four == 0 ? q : 1;
        ref += a * 3 + b * 5 + c * 7 + d * 11 + q;
    }
    return acc == ref ? 42 : 1;
}
