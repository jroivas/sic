// Tree-recursion elimination (the fib recurrence-to-loop transform, -O2) must fire
// ONLY on genuine `f(n) = n<2 ? n : f(n-1)+f(n-2)`. Regression: it hardcodes the
// `n<2` base, the `n-1`/`n-2` recurrence and the `return n` base value, so it must
// verify all three or it silently miscompiles look-alike functions. Each of these
// matches the rough shape but differs, so each must compute the ordinary recursive
// result. Returns 42.
#include <stdio.h>

static long fib(int n)  { return n < 2 ? n : fib(n - 1) + fib(n - 2); }   // real fib (gets transformed)
static long thr(int n)  { return n < 5 ? n : thr(n - 1) + thr(n - 2); }   // different base threshold
static long gap(int n)  { return n < 2 ? n : gap(n - 2) + gap(n - 3); }   // different recurrence
static long one(int n)  { return n < 2 ? 1 : one(n - 1) + one(n - 2); }   // base returns 1, not n

int main(void) {
    volatile int n = 20;
    if (fib(n) != 6765) return 1;      // fib(20)
    if (thr(n) != 9349) return 2;      // threshold-5 variant
    if (gap(n) != 21) return 3;        // n-2/n-3 variant
    if (one(n) != 10946) return 4;     // fib(21) shape (base 1)
    return 42;
}
