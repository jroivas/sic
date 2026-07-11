// Regression: switch statement codegen. Previously the `Switch` terminator's
// arm blocks were left empty (each case body was emitted into a different,
// unreachable block), so a matching case trapped with an illegal instruction,
// and `default:` was skipped. Also, statements after a terminating case (e.g.
// `case: return;`) were dropped as dead code, taking the following case labels
// with them. Exercise matching cases, default, fall-through, and break.

static int classify(int x)
{
    switch (x) {
        case 1: return 100;
        case 2: return 200;
        default: return 999;
    }
}

int main(void)
{
    // Case bodies that return.
    if (classify(1) != 100) return 1;
    if (classify(2) != 200) return 2;
    if (classify(5) != 999) return 3; // default

    // Fall-through accumulation (enter at case 3, fall into 4, then break).
    int r = 0;
    switch (3) {
        case 1: r += 1;
        case 2: r += 2;
        case 3: r += 4;
        case 4: r += 8;
                break;
        case 5: r += 100;
    }
    if (r != 12) return 4;

    // break stops fall-through.
    r = 0;
    switch (1) {
        case 1: r = 7; break;
        case 2: r = 9; break;
    }
    if (r != 7) return 5;

    // No default and no matching case: control passes through untouched.
    r = 42;
    switch (99) {
        case 1: r = 0; break;
    }
    if (r != 42) return 6;

    return 0;
}
