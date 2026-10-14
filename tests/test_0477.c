/* A case label nested inside a loop or if within the switch body (Duff's device)
 * was not collected: the switch never reached it and the copy did nothing.
 * c-testsuite 00143. A nested switch keeps its own labels. Returns 42. */
static int f(int k) {
    int r = 0, i = 0;
    switch (k) {
    case 0:
        for (i = 0; i < 3; i++) {
            if (i == 1) {
    case 5:
                r += 100;
            } else {
    case 6:
                r += 10;
            }
            switch (i) { case 1: r += 1000; break; case 7: r += 99999; }
        }
        break;
    default:
        r = -1;
    }
    return r;
}
int main(void) {
    short a[39], b[39];
    for (int n = 0; n < 39; n++) { a[n] = n; b[n] = 0; }
    short *from = a, *to = b;
    int count = 39, n = (count + 7) / 8;
    switch (count % 8) {
    case 0: do { *to++ = *from++;
    case 7:      *to++ = *from++;
    case 6:      *to++ = *from++;
    case 5:      *to++ = *from++;
    case 4:      *to++ = *from++;
    case 3:      *to++ = *from++;
    case 2:      *to++ = *from++;
    case 1:      *to++ = *from++;
            } while (--n > 0);
    }
    for (int k = 0; k < 39; k++) if (a[k] != b[k]) return 1;
    if (f(0) != 1120 || f(5) != 1210 || f(6) != 1120 || f(3) != -1) return 2;
    return 42;
}
