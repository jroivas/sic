/* A constant-false branch that control can still enter was dropped: `if (0)
 * label: …` reached by a goto from outside, or a `case` of the enclosing switch
 * inside `if (0) { … }`. c-testsuite 00207. A branch whose only entries are its
 * own switch or its own gotos is still dropped (never_linked() is undefined).
 * Returns 42. */
extern void never_linked(void);
static int hits;
static void f1(int argc) {
    if (0)
    label:
        hits++;
    if (argc-- == 0)
        return;
    goto label;
}
static int g(int k) {
    int r = 0;
    switch (k) {
    case 1:
        if (0) {
    case 2:
            r += 20;
        }
        r += 1;
        break;
    }
    if (0) { switch (k) { case 9: never_linked(); } }
    if (0) { again: never_linked(); goto again; }
    return r;
}
int main(void) {
    f1(2);
    if (hits != 2) return 1;
    if (g(1) != 1 || g(2) != 21 || g(3) != 0) return 2;
    return 42;
}
