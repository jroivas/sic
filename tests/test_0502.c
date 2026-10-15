/* -O2 LICM of C array reads (a local or function-static `T a[N]` whose name is
 * only an index base). Must NOT hoist when: a non-leaf call may re-enter and
 * change a static array; the read is conditional (a speculated out-of-range
 * read would fault); the array escapes through a pointer the loop writes; the
 * loop writes it. A leaf call does not block hoisting. Returns 42. */
static int leaf(int x) { return x * 2; }
static int f(int depth, int k) {
    static int arr[4];
    if (depth) {
        int s = 0;
        for (int i = 0; i < 3; i++) { s += arr[k]; f(0, k); }   /* arr[k]: 0,1,2 */
        return s;
    }
    arr[k]++;
    return 0;
}
int main(int argc, char **argv) {
    int r = 0;
    if (f(1, argc) != 3) r |= 1;
    int a[4] = {1, 2, 3, 4};
    long big = 1000000000L * argc;
    int s = 0;
    for (int i = 0; i < 4; i++) s += i < 0 ? a[big] : a[1] + leaf(i);   /* a[big] never read */
    if (s != 2 * 4 + 12) r |= 2;
    int b[4] = {5, 5, 5, 5};
    int *p = b;
    int t = 0;
    for (int i = 0; i < 3; i++) { t += b[2]; p[2]++; }                 /* 5 + 6 + 7 */
    if (t != 18) r |= 4;
    int c[4] = {1, 1, 1, 1};
    int u = 0;
    for (int i = 0; i < 3; i++) { u += c[0]; c[0] = c[0] * 2; }        /* 1 + 2 + 4 */
    if (u != 7) r |= 8;
    return r ? r : 42;
}
