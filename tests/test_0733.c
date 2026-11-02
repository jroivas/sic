typedef unsigned char u8;
typedef int ints[4];
typedef int fn_t(long a[2], double d[2]);
typedef ints ints2;
typedef float v4 __attribute__((vector_size(16)));
struct ops {
    int (*bytes)(void *d, u8 id[16], int type);
    int (*four)(int a[4]);
    int (*grid)(int g[2][3]);
    int (*named)(ints a);
    fn_t *td;
};
static int bytes(void *d, u8 id[16], int type) { id[0] = 7; return id[1] + type + (d == 0); }
static int four(int a[4]) { a[3] = 9; return a[0]; }
static int grid(int g[2][3]) { return g[1][2]; }
static int named(ints a) { return a[1]; }
static int td(long a[2], double d[2]) { return (int)a[1] + (int)d[1]; }
static int (*gfp)(int a[4]) = four;
static int run(int cb(int a[4]), int *x) { return cb(x); }
static int same(ints a, int *o) { return a == o; }
static int size(ints2 a) { return sizeof(a); }
static int vec(v4 x) { return sizeof(x); }
int main(void) {
    struct ops o = { bytes, four, grid, named, td };
    u8 id[16] = { 1, 2 };
    int a[4] = { 3, 4, 5, 6 };
    int g[2][3] = { { 1, 2, 3 }, { 4, 5, 6 } };
    long l[2] = { 10, 20 };
    double d[2] = { 1.0, 2.0 };
    if (o.bytes(&o, id, 5) != 7 || id[0] != 7) return 1;
    if (o.four(a) != 3 || a[3] != 9) return 2;
    if (o.grid(g) != 6) return 3;
    if (o.named(a) != 4) return 4;
    if (o.td(l, d) != 22) return 5;
    if (gfp(a) != 3) return 6;
    if (run(four, a) != 3) return 7;
    if (!same(a, a)) return 8;
    if (size(a) != sizeof(int *)) return 9;
    v4 w = { 0 };
    if (vec(w) != 16) return 10;
    return 0;
}
