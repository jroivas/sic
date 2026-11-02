/* __builtin_types_compatible_p is a constant: in static initializers (QEMU's
   plugins/core.c), under ?:, through typedefs and typeof. */
typedef unsigned int u32t;
struct I { unsigned flags; unsigned tm; };
static int gv;
static unsigned g = __builtin_types_compatible_p(int, int) ? 4 : 8;
static unsigned h = (1 | (__builtin_types_compatible_p(int, long) ? 4 : 8));
static unsigned t = __builtin_types_compatible_p(typeof(gv), int);
static unsigned u = __builtin_types_compatible_p(const int, int) + !__builtin_types_compatible_p(int *, int);
static int arr[__builtin_types_compatible_p(u32t, unsigned int) ? 3 : 1];
static int f(int fl) {
    static struct I info[4] = {
        [1].flags = 2,
        [0 ... 3].tm = (1 | (__builtin_types_compatible_p(u32t, unsigned int) ? 4 : 8) | 16),
    };
    return info[fl].tm + info[1].flags;
}
int main(void) {
    if (g != 4) return 1;
    if (h != 9) return 2;
    if (t != 1) return 3;
    if (u != 2) return 4;
    if (sizeof(arr) != 3 * sizeof(int)) return 5;
    if (f(2) != 23 || f(0) != 23) return 6;
    return 0;
}
