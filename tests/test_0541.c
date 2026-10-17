/* Array dimensions that are constant expressions over VARIABLES via sizeof /
   __builtin_types_compatible_p (QEMU's ARRAY_SIZE): a multi-dim local
   (tests/bench/qtree-bench.c `double res[ARRAY_SIZE(a)][ARRAY_SIZE(b)][..]`)
   was rejected as a VLA, an inner dim over a local or a global folded to 0
   (sizeof 0), and a struct field dim over a global was 0 too. */
#define QEMU_BUILD_BUG_ON_STRUCT(x) struct { int:(x) ? -1 : 1; }
#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))
#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), typeof(&(x)[0])))
#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
static const int g[] = {1, 2, 3};
static double gres[ARRAY_SIZE(g)][sizeof(g) / sizeof(g[0]) + 1];
struct S { int v[ARRAY_SIZE(g)]; char c[2][sizeof(g)]; long w[sizeof(*g)]; };
int main(void) {
    int sizes[] = {1, 2};
    double res[ARRAY_SIZE(g)][ARRAY_SIZE(sizes)][2];
    double b[3][sizeof(sizes) / sizeof(sizes[0])];
    double c[3][sizeof(g) / sizeof(g[0])];
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 2; j++) { res[i][j][1] = i * 10 + j; b[i][j] = j; }
    if (sizeof(res) != 3 * 2 * 2 * 8 || sizeof(res[0]) != 32) return 1;
    if (sizeof(b) != 48 || sizeof(c) != 72) return 2;
    if (res[2][1][1] != 21 || b[2][1] != 1) return 3;
    if (sizeof(gres) != 96 || sizeof(struct S) != 4 * 3 + 2 * 12 + 4 + 32) return 4;
    return 42;
}
