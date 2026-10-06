/* Macro arguments split at top-level comma TOKENS only: a comma inside a
 * string or char literal does not separate arguments (SQLite's
 * `OpHelp("…=NULL, goto P2")` was cut at its comma), while brackets and
 * braces do not group (C11 6.10.3p11). Returns 42. */
#include <string.h>
#define ONE(X) X
#define HELP(X) "\0" X
#define TWO(a, b) b
#define CNT(...) #__VA_ARGS__
#define STR(x) #x
#define SECOND(a, b) STR(b)
int main(void) {
    const char *s = ONE("a, b");
    if (strcmp(s, "a, b") != 0) return 1;
    const char h[] = "Op" HELP("x=NULL, goto P2");
    if (strcmp(h + 3, "x=NULL, goto P2") != 0) return 2;
    if (TWO(',', 7) != 7 || TWO(')', 8) != 8) return 3;
    if (TWO((1, 2), 7) != 7) return 4;
    if (strcmp(SECOND({1, 2}), "2}") != 0) return 5;      /* braces don't group */
    if (strcmp(SECOND(a[1, 2]), "2]") != 0) return 6;     /* nor brackets */
    if (strcmp(CNT(1, ',', ")"), "1, ',', \")\"") != 0) return 7;
    return 42;
}
