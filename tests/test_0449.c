/* `&&` / `||` in if/while/for/do conditions lower to direct branches: operands
 * are evaluated left to right and only when needed, in every statement form and
 * nested combination. Returns 42. */
static int calls;
static int t(int v) { calls++; return v; }
int main(void) {
    int n = 0;
    calls = 0; if (t(0) && t(1)) n += 100; if (calls != 1) return 1;
    calls = 0; if (t(1) || t(0)) n += 1;   if (calls != 1) return 2;   /* n = 1 */
    calls = 0; if ((t(0) || t(1)) && !(t(0) && t(1))) n += 1; if (calls != 3) return 3;  /* n = 2 */
    int i = 0, guard = 0;
    while (i < 10 && (i % 7 != 6 || guard++)) i++;                  /* stops at 6 */
    if (i != 6 || guard != 1) return 4;
    for (i = 0; i < 100 && !(i > 3 && i % 2 == 0); i++) {}          /* stops at 4 */
    if (i != 4) return 5;
    i = 0;
    do { i++; } while (i < 5 || (i < 9 && i % 4 != 0));             /* 8 */
    if (i != 8) return 6;
    const char *p = 0;
    if (p && *p) return 7;                                           /* no NULL deref */
    if (!p || *p) n += 40;                                           /* n = 42 */
    return n;
}
