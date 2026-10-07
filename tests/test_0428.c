/* `c ? array1 : array2` decays to a pointer to the selected ARRAY. sic copied
 * the arm into a stack temporary and returned that slot's address, so QEMU's
 * `return info ? hmp_info_cmds : hmp_cmds;` handed out a dangling pointer and
 * the monitor crashed on `screendump`/`quit`. Returns 42. */
typedef struct { const char *name; long x; } Cmd;
static Cmd a_cmds[] = { { "a1", 1 }, { "a2", 2 }, { 0, 0 } };
static Cmd b_cmds[] = { { "b1", 3 }, { 0, 0 } };
__attribute__((noinline)) static Cmd *pick(int info) { return info ? b_cmds : a_cmds; }
__attribute__((noinline)) static void clobber(void) { volatile char junk[512]; for (int i = 0; i < 512; i++) junk[i] = (char)i; }
typedef int v4si __attribute__((vector_size(16)));
int main(int argc, char **argv) {
    (void)argv;
    Cmd *p = pick(0), *q = pick(1);
    clobber();
    if (p != a_cmds || q != b_cmds || p[1].x != 2 || q[0].x != 3) return 1;
    int n = 0;
    for (Cmd *c = pick(argc > 5); c->name; c++) n++;
    if (n != 2) return 2;
    int arr1[3] = { 1, 2, 3 }, arr2[2] = { 7, 8 }, same[3] = { 4, 5, 6 }, k = argc;
    int *r = k ? arr2 : arr1;
    if (r != arr2 || sizeof(k ? arr1 : arr2) != sizeof(int *)) return 3;
    int *s = !k ? arr1 : same;                 /* same array type */
    if (s != same || s[2] != 6) return 4;
    int *t = k ? arr1 : (int *)0;              /* array vs pointer */
    if (t != arr1 || (!k ? arr1 : (int *)0) != 0) return 5;
    (k ? arr1 : same)[1] = 50;                 /* lvalue through the decayed pointer */
    if (arr1[1] != 50) return 6;
    v4si v1 = { 1, 2, 3, 4 }, v2 = { 10, 20, 30, 40 };
    v4si w = k ? v2 : v1;                      /* GCC vector: a value */
    v4si u = (k ? v1 : v2) + w;
    if (w[0] != 10 || w[3] != 40 || u[0] != 11 || u[3] != 44) return 7;
    return 42;
}
