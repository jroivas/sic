/* -O2 self-inlining: a small directly self-recursive function gets copies of
 * its own body at its recursive call sites (breadth-first, bounded). Shapes:
 * two calls (fib), several returns, side effects in call order, a pointer
 * argument, deep recursion. Returns 42. */
static long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
static int order[64], pos;
static int walk(int d) {
    if (d == 0) { order[pos++] = 0; return 1; }
    order[pos++] = d;
    int a = walk(d - 1);
    if (d % 3 == 0) return a + 100;
    return a + walk(d - 2 < 0 ? 0 : d - 2);
}
static int sum_list(const int *p, int n) { return n == 0 ? 0 : *p + sum_list(p + 1, n - 1); }
static unsigned depth(unsigned n) { return n == 0 ? 0 : 1 + depth(n - 1); }
int main(void) {
    int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    if (fib(25) != 75025) return 1;
    int w = walk(6);
    if (w != 309 || pos != 20 || order[0] != 6 || order[3] != 3 || order[19] != 0) return 2;
    if (sum_list(arr, 10) != 55) return 3;
    if (depth(100000) != 100000) return 4;
    return 42;
}
