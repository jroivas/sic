/* `*arr` on an array object yielded the array's ADDRESS instead of reading its
 * first element (no load was emitted): `int v[4]; v[0] = 2; return *v;`
 * returned garbage. c-testsuite 00130. Returns 42. */
struct P { int a, b; };
int g[3] = {7, 8, 9};
int main(void) {
    int v[4] = {2, 3};
    char a[2][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}};
    struct P ps[2] = {{10, 20}, {30, 40}};
    double d[2] = {1.5, 2.5};
    if (*v != 2 || **a != 1 || (*a)[2] != 3 || *a[1] != 5) return 1;
    if ((*ps).b != 20 || *d != 1.5 || *g != 7 || *(a[1] + 2) != 7) return 2;
    *v = 11;
    **a = 12;
    (*ps).a = 13;
    if (v[0] != 11 || a[0][0] != 12 || ps[0].a != 13 || sizeof(*a) != 4) return 3;
    return 42;
}
