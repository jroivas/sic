/* In C, an index `x ± c` with x a narrow signed integer is lowered as
 * sext(x) ± c (exact: signed overflow is undefined). Unsigned and wrapping
 * forms keep their exact C value. Returns 42. */
static int a[40];
int main(int argc, char **argv) {
    for (int k = 0; k < 40; k++) a[k] = k * 3;
    int s = 0;
    int base = argc + 9;                     /* 10 */
    for (int i = 1; i < 30; i++) s += a[i - 1] + a[i + 2] + a[3 + i] + a[i - (-2)];
    short sh = (short)(argc + 4);            /* 5 */
    signed char sc = (signed char)(argc + 1);/* 2 */
    s += a[sh - 1] + a[sc + 5] + a[base - 10];
    unsigned u = 5;
    unsigned char uc = 1;
    s += a[u - 1] + a[uc + 1];               /* unsigned: exact as before */
    int *p = &a[20];
    s += p[-1 + argc - 1] + p[argc - 3];     /* p[-1], p[-2] */
    /* expected: computed independently with long arithmetic */
    long e = 0;
    for (long i = 1; i < 30; i++) e += 3 * (i - 1) + 3 * (i + 2) + 3 * (3 + i) + 3 * (i + 2);
    e += 3 * 4 + 3 * 7 + 3 * 0 + 3 * 4 + 3 * 2 + 3 * 19 + 3 * 18;
    return s == e ? 42 : 1;
}
