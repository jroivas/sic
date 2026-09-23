// Regression: the C array subscript is commutative — `a[b]` is `*(a + b)`, so
// `3[arr]` == `arr[3]` and `i[p]` == `p[i]`. sic assumed the base was always the
// pointer, so the "integer[pointer]" form computed address arithmetic off the
// integer and dereferenced garbage (SIGSEGV). Returns 42.
#include <stdio.h>

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    int arr[5] = {10, 20, 30, 40, 50};

    // Reversed subscript on an array.
    if (3[arr] != 40) return 1;
    if (0[arr] != 10) return 2;
    if (4[arr] != arr[4]) return 3;

    // Reversed subscript through a pointer, including a runtime index.
    int *p = arr;
    int i = 2;
    if (i[p] != 30) return 4;
    if (1[p + 1] != 30) return 5;   // (p+1)[1] == arr[2]

    // Write through the reversed form.
    2[arr] = 99;
    if (arr[2] != 99) return 6;

    // Char string, reversed.
    char *s = "hello";
    if (1[s] != 'e') return 7;

    // A normal 2-D access must be unaffected (base is an array, no swap).
    int m[2][3] = {{1, 2, 3}, {4, 5, 6}};
    if (m[1][2] != 6) return 8;

    return 42;
}
