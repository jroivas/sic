/* Rotated loops (entry test + bottom test): the condition still runs exactly
 * once per iteration plus once at exit, zero-trip loops skip the body,
 * `continue` reaches the (bottom) test and `for`'s post, `break` leaves, and a
 * loop after `return` compiles. Returns 42. */
static int evals;
static int lt(int a, int b) { evals++; return a < b; }
static int dead(int n) { return n; while (lt(0, n)) n--; for (;;) {} }
int main(void) {
    int i, n = 0;
    evals = 0; for (i = 0; lt(i, 5); i++) n++;            /* 6 evals */
    if (n != 5 || evals != 6) return 1;
    evals = 0; i = 0; while (lt(i, 0)) i++;                /* zero-trip: 1 eval */
    if (i != 0 || evals != 1) return 2;
    evals = 0; for (i = 10; lt(i, 3); i++) n += 100;       /* zero-trip for */
    if (n != 5 || evals != 1) return 3;
    evals = 0; i = 0; n = 0;
    while (lt(i, 10)) { i++; if (i % 2) continue; n += i; }   /* 2+4+6+8+10 */
    if (n != 30 || evals != 11) return 4;
    n = 0;
    for (i = 0; i < 10; i++) { if (i == 3) continue; if (i == 7) break; n += i; }  /* 0+1+2+4+5+6 */
    if (n != 18 || i != 7) return 5;
    int j, cnt = 0;
    for (i = 0; i < 4; i++) for (j = 0; j < i && j < 2; j++) cnt++;   /* 0+1+2+2 */
    if (cnt != 5) return 6;
    if (dead(3) != 3) return 7;
    return 42;
}
