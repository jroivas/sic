/* C brace elision (C11 6.7.9p20): a bare value for an aggregate member starts
 * that member's initialization without its braces. sic had none: a global was
 * silently zero-filled and a local crashed or came out wrong (`int m[2][2] =
 * {1, 2, 3, 4}` gave 1 0 2 0). c-testsuite 00050. Returns 42. */
struct In { int a, b; };
struct Out { int x; struct In in; int y; };
struct U { int k; union { int c; float f; }; int z; };
struct Nm { char name[8]; int v; };
struct BF { int a; int :4; int b; };

struct Out g1 = {1, 2, 3, 4};
int g2[2][2] = {1, 2, 3, 4};
struct U g3 = {7, 8, 9};
struct Nm g4[] = {"ab", 1, "cd", 2};
int g5[][3] = {1, 2, 3, 4};
struct Out g6[2] = {1, 2, 3, 4, [1].in.b = 7};
struct BF g7 = {1, 2};

static int check(struct Out o, int a, int b, int c, int d) {
    return o.x == a && o.in.a == b && o.in.b == c && o.y == d;
}

int main(void) {
    struct In iv = {5, 6};
    struct Out l1 = {1, 2, 3, 4};
    int l2[2][2] = {1, 2, 3, 4};
    struct U l3 = {7, 8, 9};
    struct Nm l4[] = {"ab", 1, "cd", 2};
    int l5[][3] = {1, 2, 3, 4};
    struct Out l6 = {1, iv, 2};                  /* a struct value fills the slot */
    struct Out l7 = (struct Out){1, 2, 3, 4};

    if (!check(g1, 1, 2, 3, 4) || !check(l1, 1, 2, 3, 4)) return 1;
    if (g2[1][0] != 3 || g2[1][1] != 4 || l2[0][1] != 2 || l2[1][0] != 3) return 2;
    if (g3.c != 8 || g3.z != 9 || l3.c != 8 || l3.z != 9) return 3;
    if (sizeof g4 / sizeof g4[0] != 2 || g4[1].name[1] != 'd' || g4[1].v != 2) return 4;
    if (sizeof l4 / sizeof l4[0] != 2 || l4[1].name[0] != 'c' || l4[1].v != 2) return 5;
    if (sizeof g5 / sizeof g5[0] != 2 || g5[1][0] != 4 || g5[1][2] != 0) return 6;
    if (sizeof l5 / sizeof l5[0] != 2 || l5[1][0] != 4) return 7;
    if (!check(g6[0], 1, 2, 3, 4) || g6[1].in.b != 7 || g6[1].x != 0) return 8;
    if (g7.a != 1 || g7.b != 2) return 9;                 /* unnamed bit-field skipped */
    if (!check(l6, 1, 5, 6, 2) || !check(l7, 1, 2, 3, 4)) return 10;
    return 42;
}
