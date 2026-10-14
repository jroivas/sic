/* A global initialized by a compound literal — the whole object
 * (`struct S g = (struct S){1, 2};`, parenthesized too) or a member/element
 * (`{(struct S){7, 8}, 9}`) — was zero-filled: the literal was not serialized
 * as a constant. c-testsuite 00216. Returns 42. */
struct S { unsigned char a, b; unsigned char c[2]; };
struct V { struct S s; unsigned char x; };
typedef struct {} empty_s;
struct E { unsigned char a; empty_s e; unsigned char b; };
struct Wrap { void (*func)(void); };
static int calls;
static void inc(void) { calls++; }
struct S gs = ((struct S){1, 2, 3, 4});
struct S gs1 = (struct S){5, 6, {7, 8}};
struct V gv = {(struct S){7, 8, {9, 10}}, 48};
struct V gv2 = {((struct S){1, 2, {3, 4}}), 49};
struct E ge = { { (1) }, (empty_s){}, 022, };
struct Wrap gw[] = { ((struct Wrap){inc}), inc };
int main(void) {
    if (gs.a != 1 || gs.c[1] != 4 || gs1.b != 6 || gs1.c[0] != 7) return 1;
    if (gv.s.a != 7 || gv.s.c[1] != 10 || gv.x != 48) return 2;
    if (gv2.s.c[0] != 3 || gv2.x != 49) return 3;
    if (ge.a != 1 || ge.b != 18) return 4;
    gw[0].func();
    gw[1].func();
    return calls == 2 ? 42 : 5;
}
