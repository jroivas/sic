/* Several declarators in one external declaration starting with a function
 * prototype (`int f(int), g(int), a = 5;`) failed to parse: "unexpected token
 * Comma". c-testsuite 00121. Returns 42. */
int f(int), g(int a), a = 5, *p;
int h(int a), b;
int main(void) {
    int f(int), g(int), k = 2;
    p = &a;
    b = 23;
    return f(1) - g(1) + *p + b + h(3) + k;   /* 10 - 1 + 5 + 23 + 3 + 2 */
}
int f(int x) { return x * 10; }
int g(int x) { return x; }
int h(int x) { return x; }
