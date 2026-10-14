/* A goto inside a GNU statement expression `({ … })` was not seen when
 * deciding whether a constant-false branch defining its label is reachable, so
 * the branch was dropped and the goto jumped nowhere. c-testsuite 00213.
 * Returns 42. */
int main(void) {
    int hits = 0;
    int i = ({
        int j = 1;
        if (0) {
            while (j--) {
                hits += 10;
    enter:
                hits += 1;
            }
        }
        if (j >= 0)
            goto enter;
        j; });
    /* enter: +1; one more pass (j 1 -> 0): +10 +1; then j 0 -> -1 exits */
    if (i != -1) return 1;
    return hits == 12 ? 42 : hits;
}
