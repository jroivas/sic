/* A cast of a struct value to its own struct type (`(struct S)w->s`, a GNU
 * extension) was lowered as a scalar conversion and crashed. c-testsuite
 * 00216. Returns 42. */
struct S { int a, b; };
struct W { struct S s; int k; };
static struct S pick(struct W *w) { return (struct S)w->s; }
int main(void) {
    struct W w = {{40, 2}, 7};
    struct S c = (struct S)w.s;
    struct S d = pick(&w);
    union U { int i; float f; } u = {3}, v = (union U)u;
    return c.a + d.b + v.i - 3;
}
