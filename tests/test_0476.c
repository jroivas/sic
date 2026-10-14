/* A block-scope function declaration (`int f1(char *);` inside main) became a
 * local variable of function type, and calls went through that uninitialized
 * slot (SIGSEGV). It declares the file-scope function. c-testsuite 00078.
 * Returns 42. */
int f1(char *p) { return *p + 1; }
int later(int);
int main() {
    char s = 1;
    int v[1000];
    int f1(char *);
    int abs(int);            /* libc, declared only here */
    double sqrt(double), x = 2.0;
    int r = later(3);
    if (f1(&s) != 2) return 1;
    if (abs(-5) != 5) return 2;
    if (x != 2.0 || r != 6) return 3;
    return 42;
}
int later(int k) { return k * 2; }
