// Regression: a constant integer cast must truncate AND re-sign to the target
// width at compile time, in every constant context. `(int)0x80000000` is
// -2^31, so `(long long)(int)0x80000000` must sign-extend to -2^31, not keep the
// unsigned +2^31; likewise `(signed char)300 == 44`. This was mis-folded both in
// value lowering (coerce) and in the type-blind constant evaluator used for `if`
// conditions / case labels / array sizes. Returns 42.
#include <stdio.h>

int arr_min[(int)0x80000000 == -2147483648 ? 3 : 1];  // array size folds the cast
int arr_sc[(signed char)300 == 44 ? 5 : 1];

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);

    // Value lowering (assignment).
    long long a = (long long)(int)0x80000000;
    long long b = (long long)(int)0xFFFFFFFF;
    if (a != -2147483648LL || b != -1LL) return 1;
    if ((signed char)300 != 44) return 2;
    if ((long long)(signed char)200 != -56LL) return 3;
    if ((long long)(short)0x8000 != -32768LL) return 4;
    if ((unsigned)(int)0xFFFFFFFF != 0xFFFFFFFFu) return 5;
    if ((long long)(unsigned)0xFFFFFFFF != 4294967295LL) return 6;

    // Constant evaluator used for `if`-condition folding (dead-branch).
    if ((long long)(int)0x80000000 != -2147483648LL) return 7;
    if ((signed char)300 != 44) return 8;

    // Case labels are folded by the same evaluator.
    int hit = 0;
    switch (44) {
        case (signed char)300: hit = 1; break;   // 300 -> (signed char) -> 44
        default: hit = 2;
    }
    if (hit != 1) return 9;

    // Array sizes folded the cast (sizeof reflects the chosen dimension).
    if (sizeof(arr_min) / sizeof(int) != 3) return 10;
    if (sizeof(arr_sc) / sizeof(int) != 5) return 11;

    return 42;
}
