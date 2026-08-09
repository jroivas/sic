// Regression: relational comparisons of pointers must be UNSIGNED. sic lumped
// pointers into the signed-compare path, so a high address like (void*)-1
// (0xffff...ffff) looked negative and compared *below* every real address.
// This broke `sqlite3Utf8CharLen(z, -1)` (which loops while `z < (u8*)-1`),
// making `.tables` fail with "ESCAPE expression must be a single character".

int main(void)
{
    int arr[4];
    int *lo = &arr[0];
    int *hi = &arr[3];

    // Ordinary ordering.
    if (!(lo < hi)) return 1;
    if (!(hi > lo)) return 2;
    if (lo >= hi)   return 3;
    if (hi <= lo)   return 4;
    if (!(lo <= lo)) return 5;
    if (!(lo >= lo)) return 6;

    // The key case: a max-value pointer must compare ABOVE a real address.
    unsigned char *p = (unsigned char *)"x";
    unsigned char *pmax = (unsigned char *)(-1);   // 0xffff...ffff
    if (!(p < pmax))  return 7;   // signed compare would make this false
    if (!(pmax > p))  return 8;
    if (p >= pmax)    return 9;

    // A null pointer compares below everything.
    unsigned char *pnull = (unsigned char *)0;
    if (!(pnull < p)) return 10;
    if (!(p > pnull)) return 11;

    // Emulate the sqlite3Utf8CharLen(-1) loop.
    const unsigned char *z = (const unsigned char *)"_";
    const unsigned char *zTerm = (const unsigned char *)(-1);
    int r = 0;
    while (*z != 0 && z < zTerm) { z++; r++; }
    if (r != 1) return 12;

    // Pointer difference-based ordering still works with big addresses.
    const unsigned char *a = (const unsigned char *)"hello";
    if (!(a < a + 5)) return 13;
    if (a + 5 < a)    return 14;

    return 0;
}
