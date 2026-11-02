/* sizeof and _Alignof of a local in a static initializer are constants: only the
   type is used (QEMU's hw/nvme/ctrl.c). They were zero-filled, then an error. */
#include <stddef.h>
struct T { int a[8]; char c; };
static int sizes(int *p, struct T *q) {
    char l[4096] = {};
    struct T t;
    long v;
    static const int plain = sizeof(l);
    static const int array = sizeof(l) / sizeof(l[0]);
    static const int mix = sizeof(l) * 2 + 1;
    static const int member = sizeof(t.a);
    static const int ptr = sizeof(p), deref = sizeof(*p), arrow = sizeof(q->a);
    static const int al = _Alignof(v);
    static const struct { int n; int m[2]; } s = { sizeof(l), { [1] = sizeof(t) } };
    static const size_t list[] = { sizeof(v), sizeof(l) };
    if (plain != 4096 || array != 4096 || mix != 8193) return 1;
    if (member != 32 || ptr != sizeof(int *) || deref != 4 || arrow != 32) return 2;
    if (al != _Alignof(long)) return 3;
    if (s.n != 4096 || s.m[1] != sizeof(struct T)) return 4;
    if (list[0] != sizeof(long) || list[1] != 4096) return 5;
    return l[0];
}
static int shadow(void) {
    char x[4];
    {
        char x[8];
        static const int inner = sizeof(x);
        if (inner != 8) return 1;
    }
    static const int outer = sizeof(x);
    return outer != 4;
}
int main(void) {
    int i = 0;
    struct T t;
    int r = sizes(&i, &t);
    if (r) return r;
    if (shadow()) return 6;
    return 0;
}
