/* Recursive Fibonacci — a pure function-call / recursion benchmark.
   The argument is read through a `volatile` so the compiler cannot fold the whole
   recursion to a constant or hoist it; all versions do the real work. Prints
   fib(42) as a checksum so every language version can be compared. */
#include <stdio.h>

static long fib(int n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

int main(void) {
    volatile int n = 42;
    printf("%ld\n", fib(n));
    return 0;
}
