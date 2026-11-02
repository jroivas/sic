/* A const object's integer value in a static initializer (QEMU's fsl-imx8mm.c), and
   constant sizeof of an array whose element struct came after its typedef (GLib). */
typedef unsigned long u64;
enum { X, Y, Z };
static const struct { u64 addr; unsigned size; const char *name; } map[] = {
    [X] = { 0x1000, 16, "x" }, [Y] = { 0x2000, 32, "y" }, [Z] = { 0x3000, 64, "z" },
};
static const int k = 5;
static const signed char neg = -3;
static const unsigned char uc = 200;
static const int arr[3] = { 1, 2, 3 };
static const struct { int a; struct { short s; } in; } nest = { 7, { 8 } };
static const struct { u64 addr; unsigned irq; } tab[2] = {
    { map[Y].addr, map[Z].size }, { map[X].addr + 1, 3 }
};
static const u64 sc = map[Z].addr, plus = arr[2] + k, ns = nest.in.s;
static const int sneg = neg, suc = uc, tern = k > 3 ? arr[0] : arr[1];

typedef struct _E E;
struct _E { int c; const char *n; };
static const E ents[] = { { 0, "a" }, { 1, "b" }, { 2, "c" } };
_Static_assert(sizeof(ents) == 3 * sizeof(E), "size");
_Static_assert(sizeof(ents) / sizeof((ents)[0]) == 3, "count");
_Static_assert(_Alignof(ents) == _Alignof(E), "align");
static const int count = sizeof(ents) / sizeof(ents[0]);

static int f(int i) {
    static const struct { u64 a; } t[2] = { { map[Y].addr }, { arr[1] } };
    return t[i].a;
}
static int vla(void) {
    int a[k];
    return sizeof(a) == 5 * sizeof(int);
}
int main(void) {
    if (tab[0].addr != 0x2000 || tab[0].irq != 64 || tab[1].addr != 0x1001) return 1;
    if (sc != 0x3000 || plus != 8 || ns != 8) return 2;
    if (sneg != -3 || suc != 200 || tern != 1) return 3;
    if (f(0) != 0x2000 || f(1) != 2) return 4;
    if (count != 3) return 5;
    if (!vla()) return 6;
    return 0;
}
