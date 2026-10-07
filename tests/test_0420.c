/* -O2 devirtualization of calls through function tables: the slot of each
 * target comes from its byte offset (NULL slots have no relocation — QEMU's
 * qdestroy[] { [0]=NULL, [1]=NULL, [2]=qnum… } dispatched two slots off and
 * crashed qemu-system-i386), and a table that may change at run time (written,
 * escaping, a runtime value in a local table) is left indirect. Returns 42. */
static int a(int x) { return x + 1; }
static int b(int x) { return x * 2; }
static int c(int x) { return x - 3; }
static int d(int x) { return 100; }
static int (*holes[6])(int) = { [2] = a, [3] = b, [5] = c };
static int (*mut[3])(int) = { a, b, c };
static int (*esc[3])(int) = { a, b, c };
static int (*const ctab[4])(int) = { a, b, c, d };
static void patch(int (**t)(int)) { t[1] = d; }
__attribute__((noinline)) static int call_holes(int i, int x) { return holes[i](x); }
__attribute__((noinline)) static int call_mut(int i, int x) { return mut[i](x); }
__attribute__((noinline)) static int call_esc(int i, int x) { return esc[i](x); }
__attribute__((noinline)) static int call_ctab(int i, int x) { return ctab[i](x); }
__attribute__((noinline)) static int call_local(int i, int x, int (*extra)(int)) {
    int (*t[3])(int) = { a, b, c };
    t[2] = extra;
    return t[i](x);
}
int main(void) {
    if (call_holes(2, 10) != 11 || call_holes(3, 10) != 20 || call_holes(5, 10) != 7) return 1;
    mut[1] = d;
    if (call_mut(0, 10) != 11 || call_mut(1, 10) != 100 || call_mut(2, 10) != 7) return 2;
    patch(esc);
    if (call_esc(1, 10) != 100) return 3;
    if (call_ctab(0, 10) != 11 || call_ctab(3, 10) != 100) return 4;
    if (call_local(2, 10, d) != 100 || call_local(1, 10, d) != 20) return 5;
    return 42;
}
