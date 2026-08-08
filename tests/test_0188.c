/* offsetof with a NON-constant array index (a GCC extension) is a runtime value
 * const_offset + index*elem_size. sic folded offsetof to a constant and treated
 * a variable index as 0, so `offsetof(T, arr[i].field)` in a loop always yielded
 * the arr[0] offset. QEMU registers its per-segment TCG globals this way
 * (offsetof(CPUX86State, segs[i].base) for i in 0..6); every segment base
 * pointed at segs[0], so the CS segment base was read as ES's (0), breaking
 * %cs:-relative addressing (the lgdt in SeaBIOS's protected-mode switch read the
 * wrong address, loaded a zero GDT limit, and the far jump #GP'd). */
#include <stddef.h>

typedef struct { long selector; long base; long limit; long flags; } Seg;
typedef struct { int pad; Seg segs[6]; long tail; } CPU;

int main(void)
{
    for (int i = 0; i < 6; i++) {
        size_t off = offsetof(CPU, segs[i].base);
        size_t expect = offsetof(CPU, segs[0].base) + (size_t)i * sizeof(Seg);
        if (off != expect) return 1 + i;      /* i=1..5 were all wrong (==segs[0]) */
    }

    /* constant index still folds correctly */
    if (offsetof(CPU, segs[3].limit) != offsetof(CPU, segs[0].limit) + 3 * sizeof(Seg))
        return 20;

    /* index from a runtime expression */
    int j = 2;
    if (offsetof(CPU, segs[j + 1].base) != offsetof(CPU, segs[0].base) + 3 * sizeof(Seg))
        return 21;

    return 0;
}
