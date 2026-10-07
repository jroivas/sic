/* GCC transparent_union (glibc's __SOCKADDR_ARG with _GNU_SOURCE): a parameter of
 * that type is passed as its FIRST member, and any member type may be passed.
 * sic passed the union by value — bind(fd, (struct sockaddr *)&un, len) handed
 * libc the struct's first 8 bytes as the address (EFAULT; QEMU's monitor and
 * every socket call failed). Returns 42. */
struct A { int x; };
struct B { long y; };
typedef union { struct A *a; struct B *b; } ARG __attribute__((__transparent_union__));
static int take(ARG p) { return p.a->x; }
static int via_ptr(ARG p, struct A *expect) { return (void *)p.a == (void *)expect; }
int main(void) {
    struct A a = { 40 };
    struct B b = { 2 };
    if (take(&a) != 40) return 1;
    if (!via_ptr(&a, &a)) return 2;
    if (!via_ptr((struct A *)&b, (struct A *)&b)) return 3;
    return take(&a) + (int)b.y;
}
