#define SHIFT_LEN (3 << 10)   // 3072
#define MUL_LEN   (40 * 50)   // 2000

int shift_arr[SHIFT_LEN];
int mul_arr[MUL_LEN];

int main()
{
    // sizeof must reflect the folded length, not a degenerate 1-element array.
    if (sizeof(shift_arr) != SHIFT_LEN * sizeof(int))
        return 1;
    if (sizeof(mul_arr) != MUL_LEN * sizeof(int))
        return 2;

    // A local array sized by an expression must fold too.
    int local[8 << 4]; // 128
    if (sizeof(local) != 128 * sizeof(int))
        return 3;

    // Actually touch the last element of each: if the storage were undersized
    // these writes/reads would land out of bounds.
    shift_arr[SHIFT_LEN - 1] = 0x1234;
    mul_arr[MUL_LEN - 1] = 0x5678;
    local[127] = 0x9abc;

    if (shift_arr[SHIFT_LEN - 1] != 0x1234)
        return 4;
    if (mul_arr[MUL_LEN - 1] != 0x5678)
        return 5;
    if (local[127] != 0x9abc)
        return 6;

    // First elements should be independent of the last (no aliasing from a
    // collapsed length).
    shift_arr[0] = 1;
    if (shift_arr[SHIFT_LEN - 1] != 0x1234)
        return 7;

    return 0;
}
