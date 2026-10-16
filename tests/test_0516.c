/* Variable-length arrays are sized at run time: `int a[n]` was a FIXED
 * 1024-element stack array, so a larger n overran the stack (SIGSEGV at
 * n=5000, silent corruption just past 1024) and `sizeof a` was 4096. Now a
 * VLA is a zeroed heap block freed at scope exit; `sizeof` is n*sizeof(T); a
 * runtime outer dimension (`int a[n][4]`) works. Returns 42. */
#include <string.h>
static long sum(int n) {
    int guard = 0x1234;
    int a[n];
    for (int i = 0; i < n; i++) a[i] = i;
    long s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    if (sizeof a != (unsigned long)n * sizeof(int) || guard != 0x1234) return -1;
    return s;
}
static int rows(int n) {
    int a[n][4];
    for (int i = 0; i < n; i++) for (int j = 0; j < 4; j++) a[i][j] = i + j;
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i][3];
    return s;
}
int main(void) {
    if (sum(10) != 45 || sum(5000) != 12497500L || sum(100000) != 4999950000L) return 1;
    if (rows(1000) != 502500) return 2;
    int tot = 0;
    for (int k = 1; k < 200; k++) {            /* freed each iteration */
        char v[k];
        memset(v, 1, sizeof v);
        for (int i = 0; i < k; i++) tot += v[i];
        if (k == 150) break;
    }
    if (tot != 11325) return 3;
    return 42;
}
