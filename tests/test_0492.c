/* A block-scope `typedef enum { e, f, g } h;` did not define its constants:
 * "undefined name 'e'". c-testsuite 00198. Returns 42. */
int main(void) {
    typedef enum { e = 3, f, g } h;
    typedef struct { enum { K = 20 } k; } T;
    h v = g;
    T t;
    t.k = K;
    return e + f + v + t.k + 10;    /* 3 + 4 + 5 + 20 + 10 */
}
