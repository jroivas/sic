// Regression: `break` inside a `switch` that is nested in a loop must break only
// the switch, not the enclosing loop. sic used to route the switch's break to the
// loop's exit block, so any statement after the switch (still in the loop body)
// was skipped and the loop terminated early. This silently broke SQLite's printf
// engine (every %-conversion bailed out of the format loop).

int main(void)
{
    // for + switch: `total += 10` must run on every iteration.
    int total = 0;
    for (int i = 0; i < 3; i++) {
        switch (i) {
            case 0: break;
            case 1: total += 1; break;
            default: break;
        }
        total += 10;            // must execute all 3 iterations
    }
    if (total != 31) return 1;  // 10 + (1+10) + 10

    // while + switch: loop must keep iterating after the switch breaks.
    int t = 0, i = 0;
    while (i < 3) {
        switch (t % 2) { case 0: break; default: break; }
        t += 100;
        i++;
    }
    if (t != 300) return 2;

    // do-while + switch.
    int d = 0, n = 0;
    do {
        switch (n) { case 1: break; default: break; }
        d += 1;
        n++;
    } while (n < 4);
    if (d != 4) return 3;

    // `continue` inside a switch must target the *loop*, not the switch.
    int sum = 0;
    for (int k = 0; k < 5; k++) {
        switch (k) {
            case 2: continue;   // skip sum += k for k == 2
            default: break;
        }
        sum += k;
    }
    if (sum != 0 + 1 + 3 + 4) return 4;

    // nested switch inside switch inside loop.
    int acc = 0;
    for (int a = 0; a < 2; a++) {
        switch (a) {
            case 0:
                switch (a + 1) { case 1: acc += 5; break; default: break; }
                break;
            default:
                acc += 100;
                break;
        }
        acc += 1;               // runs every iteration
    }
    if (acc != 5 + 1 + 100 + 1) return 5;

    return 0;
}
