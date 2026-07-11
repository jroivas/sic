// Regression: 64-bit integer literals and constant arithmetic must be computed
// at 64-bit width, not truncated to 32-bit. Previously literals dropped their
// `L`/`LL` suffix and magnitude, so `val_type` treated every integer constant
// as 32-bit; 64-bit arithmetic (subtraction, shifts) was then done in 32 bits
// (e.g. LLONG_MIN via `-LLONG_MAX - 1` produced 0). Comparisons and stores of
// 64-bit constants were likewise truncated in the backend.

int main(void)
{
    // Most-negative long long, formed by arithmetic (the reported case).
    long long lmin = -9223372036854775807LL - 1;
    if (lmin != (-1LL << 63))
        return 1;

    // Large decimal that doesn't fit in 32 bits.
    long long big = 5000000000LL;
    if (big - 1 != 4999999999LL)
        return 2;

    // Shifts on suffix-typed literals whose *value* fits in 32 bits.
    if ((1LL << 62) != 4611686018427387904LL)
        return 3;
    if ((1UL << 40) != 1099511627776UL)
        return 4;

    // A hex constant that fits `unsigned int` stays 32-bit unsigned, so it
    // compares equal to (int)-1 under the usual conversions.
    int m1 = -1;
    if (m1 != 0xFFFFFFFF)
        return 5;

    // 64-bit constant compared against a 64-bit value read from memory.
    unsigned long uv = 0xFFFFFFFFFFFFFFFFUL;
    if (uv != 0xFFFFFFFFFFFFFFFFUL)
        return 6;
    if ((unsigned long)m1 != 0xFFFFFFFFFFFFFFFFUL)
        return 7;

    // Store a 64-bit constant into memory, then read it back.
    long long arr[2];
    arr[0] = 0x1122334455667788LL;
    arr[1] = arr[0] - 1;
    if (arr[0] != 0x1122334455667788LL)
        return 8;
    if (arr[1] != 0x1122334455667787LL)
        return 9;

    // Reinterpret double bits as a 64-bit integer (union), then compare.
    union { double d; long b; } u;
    u.d = 1.1;
    if (u.b != 4607632778762754458L)
        return 10;

    return 0;
}
