// Regression: indexing a multi-dimensional array `a[i][j]` must treat the inner
// index result `a[i]` (which is itself an array) as a *row address* that decays
// to a pointer — not load the row's bytes as a scalar. sic used to emit a load
// for `a[i]`, so `a[i][j]` dereferenced the loaded data as if it were a pointer
// (a crash / garbage). This was the SQLite shell crash via its trans[8][8] table.

static const unsigned char t[3][4] = {
    {  0,  1,  2,  3 },
    { 10, 11, 12, 13 },
    { 20, 21, 22, 23 },
};

int main(void)
{
    // Static 2-D array, variable indices.
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            if (t[i][j] != (unsigned char)(i * 10 + j)) return 1;

    // Local 2-D array: fill and read back with variable indices.
    int m[3][4];
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            m[i][j] = i * 100 + j;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            if (m[i][j] != i * 100 + j) return 2;

    // `m[i]` decays to `int*` pointing at the row.
    int *row = m[1];
    if (row[0] != 100 || row[3] != 103) return 3;

    // Constant index on one axis, variable on the other.
    for (int j = 0; j < 4; j++)
        if (m[2][j] != 200 + j) return 4;

    // 3-D array.
    int c[2][3][4];
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 3; j++)
            for (int k = 0; k < 4; k++)
                c[i][j][k] = i * 100 + j * 10 + k;
    if (c[1][2][3] != 123) return 5;
    if (c[0][0][0] != 0)   return 6;
    if (c[1][0][0] != 100) return 7;

    return 0;
}
