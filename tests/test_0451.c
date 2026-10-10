/* Reads of a `const` integer global fold to its value (an immediate instead of
 * a load per use — loop bounds like `const i64 N`), keeping its type; `&N`
 * still addresses the real global, and a same-named static local is separate.
 * Returns 42. */
#include <stdint.h>
const int N = 7;
static const uint8_t U8 = 200;          /* 200 + 100 must not wrap to u8 */
const int64_t BIG = 5000000000LL;
const int NEG = -3;
const _Bool YES = 1;
extern const int LATE;                  /* defined after its first use */
static int use_late(void) { return LATE; }
const int LATE = 11;
static int shadow(void) { static int N = 100; return N++; }
int main(void) {
    int s = 0;
    for (int i = 0; i < N; i++) s += i;                 /* 21 */
    if (s != 21) return 1;
    if (U8 + 100 != 300 || (uint8_t)(U8 + 100) != 44) return 2;
    if (BIG / 1000000000 != 5 || NEG * 2 != -6 || !YES) return 3;
    const int *p = &N;
    if (*p != 7 || p != &N) return 4;
    if (shadow() != 100 || shadow() != 101 || N != 7) return 5;
    if (use_late() != 11) return 6;
    return s + N + 14;                                  /* 21 + 7 + 14 */
}
