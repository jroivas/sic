/* An integer division by zero traps, even when its result is unused: the
   optimizer dropped the dead division (taking a zero divisor for impossible)
   so the program went on, and LLVM could also drop the `y == 0` test after
   it. Dies of the trap (SIGILL: 132). */
int seen;
__attribute__((noinline)) void g(void) { seen = 1; }
__attribute__((noinline)) int f(int x, int y) {
    int q = x / y;
    (void)q;
    if (y == 0) g();
    return 0;
}
int main(void) {
    f(1, 0);
    return seen ? 1 : 2;
}
