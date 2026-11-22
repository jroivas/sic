/* `__attribute__((ms_abi))` (EFI's `__efiapi`): the function is called with
   the Microsoft x64 convention. It was a warning and the System V convention
   for a definition, and silently System V for a function pointer, so EFI
   firmware and the kernel's EFI stub disagreed on every argument. (Calls
   between sic and GCC are tested by tests/abi/abi.sh.) Returns 42. */
#define MS __attribute__((ms_abi))

typedef struct { long a, b, c; } Big;
typedef struct { short a; } Two;

MS long six(long a, long b, long c, long d, long e, long f) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f;
}

/* A by-reference struct is the callee's own copy. */
MS long big(Big b) { long r = b.a + b.b + b.c; b.a = 0; return r; }
MS Big mkbig(long v) { Big b = { v, v, v }; return b; }

/* `va_arg` of a by-reference struct takes the pointer in its slot (as Clang
   does; GCC reads the slots in place). */
MS long vbig(int n, ...) {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, n);
    long r = 0;
    while (n--) {
        Big b = __builtin_va_arg(ap, Big);
        Two t = __builtin_va_arg(ap, Two);
        r += b.a + b.b + b.c + t.a;
    }
    __builtin_ms_va_end(ap);
    return r;
}

MS double vdbl(int n, ...) {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, n);
    double r = 0;
    for (int i = 0; i < n; i++) r += __builtin_va_arg(ap, double);
    __builtin_ms_va_end(ap);
    return r;
}

typedef long op_t(long, long);
static MS long sub(long a, long b) { return a - b; }
struct ops { op_t MS *sub; long (MS *add)(long, long); };
static MS long add(long a, long b) { return a + b; }

int main(void) {
    int r = 0;
    if (six(1, 2, 3, 4, 5, 6) == 91) r++;
    Big b = { 1, 2, 3 };
    if (big(b) == 6 && b.a == 1) r++;
    if (mkbig(7).c == 7) r++;
    Two t = { 4 };
    if (vbig(2, b, t, mkbig(10), t) == 6 + 4 + 30 + 4) r++;
    if (vdbl(5, 0.5, 1.5, 2.5, 3.5, 4.0) == 12.0) r++;
    struct ops o = { sub, add };
    if (o.sub(50, 8) == 42 && o.add(40, 2) == 42) r++;
    return r == 6 ? 42 : r;
}
