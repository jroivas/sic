// Regression: multi-dimensional array declarators must nest their dimensions
// left-to-right. `int a[2][3]` is "array-2 of array-3 of int", so `sizeof(a[0])`
// is 3*sizeof(int) and the row stride is 3 ints. sic's declarator parser wrapped
// the suffixes inside-out, building `int[3][2]` instead (dimensions swapped).
// Invisible for square dimensions (e.g. sqlite's trans[8][8]).

int main(void)
{
    int a[2][3];
    if (sizeof(a)       != 2 * 3 * sizeof(int)) return 1;
    if (sizeof(a[0])    != 3 * sizeof(int))     return 2;
    if (sizeof(a[0][0]) != sizeof(int))         return 3;

    // Row stride: &a[1][0] - &a[0][0] must be the inner dimension (3 ints).
    if (&a[1][0] - &a[0][0] != 3) return 4;

    // Byte strides on a char array make the layout explicit.
    char b[2][5];
    if (sizeof(b)    != 10) return 5;
    if (sizeof(b[0]) != 5)  return 6;
    if ((char *)&b[1][0] - (char *)&b[0][0] != 5) return 7;

    // Row-major initializer must land in memory in declaration order.
    int n[2][3] = { { 10, 20, 30 }, { 40, 50, 60 } };
    int want[6] = { 10, 20, 30, 40, 50, 60 };
    int *p = (int *)n;
    for (int i = 0; i < 6; i++)
        if (p[i] != want[i]) return 8;
    if (n[0][2] != 30) return 9;
    if (n[1][0] != 40) return 10;

    // Three dimensions, all distinct.
    int c[2][3][4];
    if (sizeof(c)          != 2 * 3 * 4 * sizeof(int)) return 11;
    if (sizeof(c[0])       != 3 * 4 * sizeof(int))     return 12;
    if (sizeof(c[0][0])    != 4 * sizeof(int))         return 13;
    if (sizeof(c[0][0][0]) != sizeof(int))             return 14;

    return 0;
}
