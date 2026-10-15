/* `_Generic` compared types without pointee qualifiers, so a `const int *`
 * matched `int *` (`int * const` is `int *` after lvalue conversion; neither is
 * `const int *`). c-testsuite 00219. Returns 42. */
const char *gs;
int main(void) {
    const int * const p = 0;
    int *q = 0;
    const char *ti = 0;
    volatile int *vp = 0;
    int r = 0;
    r += _Generic(p, int *: 1, int * const: 2, default: 20);       /* 20 */
    r += _Generic(q, const int *: 100, int *: 3);                  /*  3 */
    r += _Generic(ti, char *: 100, const char *: 4);               /*  4 */
    r += _Generic(gs, char *: 100, const char *: 5);               /*  5 */
    r += _Generic(vp, int *: 100, volatile int *: 6, default: 50); /*  6 */
    r += _Generic("lit", char *: 4, const char *: 100);            /*  4 */
    return r;
}
