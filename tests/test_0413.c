/* Macro rescanning (C11 6.10.3.4): a macro's own name met during its
 * replacement is painted and never expanded again — glibc's C23
 * `strchr(S, C) -> _Generic(..., strchr (S, C))` used to re-expand each pass
 * and grow exponentially; the replacement is rescanned together with the rest
 * of the source (`f(2)(9)`, `id(g)(3)`, an open call `open_add 5)`), and a name not
 * followed by `(` in its own context is not a call (`DEFER(A)()`). Returns 42. */
#include <string.h>
#define STR(...) #__VA_ARGS__
#define XSTR(...) STR(__VA_ARGS__)
#define gen(P, CALL) _Generic(P, default: CALL)
#define strchr2(S, C) gen(S, strchr2(S, C))
#define foo foo + 1
#define f(a) a*g
#define g(a) f(a)
#define id(x) x
#define h2(x) [x]
#define add(x) ((x) + 37)
#define open_add add(
#define EMPTY
#define DEFER(x) x EMPTY
#define EXPAND(...) __VA_ARGS__
#define A() 123
#define AA BB
#define BB AA
int main(void) {
    if (strcmp(XSTR(strchr2(p, 1)), "_Generic(p, default: strchr2(p, 1))") != 0) return 1;
    if (strcmp(XSTR(foo), "foo + 1") != 0) return 2;
    if (strcmp(XSTR(f(2)(9)), "2*9*g") != 0) return 3;
    if (strcmp(XSTR(id(h2)(3)), "[3]") != 0) return 4;
    if (open_add 5) != 42) return 5;
    if (strcmp(XSTR(DEFER(A)()), "A ()") != 0) return 6;
    if (strcmp(XSTR(EXPAND(DEFER(A)())), "123") != 0) return 7;
    if (strcmp(XSTR(AA BB), "AA BB") != 0) return 8;
    return 42;
}
