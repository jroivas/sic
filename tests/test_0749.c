/* `asm goto` with outputs, as Linux's unsafe_get_user: which label was taken
 * must survive whatever registers the outputs get (sic's stub once stored
 * through an input pointer that an output had overwritten). */
__attribute__((noinline)) int get(const int *p, int *out) {
    int x;
    asm goto("mov %[m], %[o]\n\tcmpl $0, %[o]\n\tjl %l[neg]" : [o] "=r"(x) : [m] "m"(*p) : "cc" : neg);
    *out = x;
    return 0;
neg:
    return -14;
}
__attribute__((noinline)) long many(const long *p) {
    long a, b, c, d, s, x;
    asm goto("mov (%[p]), %[x]\n\tmov $1, %[a]\n\tmov $2, %[b]\n\tmov $3, %[c]\n\tmov $4, %[d]\n\tmov $5, %[s]\n\ttest %[x], %[x]\n\tjz %l[zero]"
             : [x] "=r"(x), [a] "=a"(a), [b] "=b"(b), [c] "=c"(c), [d] "=d"(d), [s] "=S"(s) : [p] "D"(p) : "cc", "memory" : zero);
    return x + a + b + c + d + s;
zero:
    return -1;
}
int main(void) {
    int v = 41, n = -3, out = 0;
    if (get(&v, &out) != 0 || out != 41) return 1;
    if (get(&n, &out) != -14) return 2;
    long w = 27, z = 0;
    if (many(&w) != 42) return 3;
    if (many(&z) != -1) return 4;
    return 42;
}
