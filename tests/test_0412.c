/* `sizeof` of a compound literal is its whole type: `(int[]){1, 2, 3}` is
 * 12 bytes (it used to report `int`'s 4), `(char[]){"abc"}` is sized by its
 * string — also for the temporary's storage — and file-scope initializers
 * fold the same sizes. Returns 42. */
#include <string.h>
struct P { int a; char b[6]; };
#define COUNT(...) (sizeof((int[]){__VA_ARGS__}) / sizeof(int))
static const unsigned long g_n = sizeof((int[]){1, 2, 3, 4});
static const unsigned long g_s = sizeof((char[]){"hello"});
int main(void) {
    if (sizeof((int[]){1, 2, 3}) != 3 * sizeof(int)) return 1;
    if (COUNT(7, 8, 9, 10, 11) != 5) return 2;
    if (sizeof((int[]){[9] = 1}) != 10 * sizeof(int)) return 3;
    if (sizeof((int[3]){1}) != 3 * sizeof(int)) return 4;
    if (sizeof((char[]){"abc"}) != 4) return 5;
    if (sizeof((struct P){1, "x"}) != sizeof(struct P)) return 6;
    if (g_n != 4 * sizeof(int) || g_s != 6) return 7;
    char *s = (char[]){"abc"};
    int guard[4] = {5, 5, 5, 5};
    if (strcmp(s, "abc") != 0 || guard[0] != 5 || guard[3] != 5) return 8;
    return 42;
}
