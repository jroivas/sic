// An "i" operand that is not a constant after optimization is an error (as
// GCC's "impossible constraint in asm"), not a trap at run time.
void f(int n) {
    int q = 3;
    if (n) q = 4;
    asm volatile(".long %c0" :: "i"(q));
}
int main(void) { f(1); return 0; }
