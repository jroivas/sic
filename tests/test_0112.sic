// Regression: compound literals `(T){ ... }`. The parser rejected designated
// initializers inside them ("unexpected token Dot"), and the lowering returned a
// pointer to the temporary instead of copying the value, so `T v = (T){...}`
// stored garbage / crashed.

typedef struct { int a; int b; int c; } S;
typedef struct { int *q; int n; } P;

int arr[3] = { 10, 20, 30 };

int main(void)
{
    // Positional compound literal, copied into a local.
    S s1 = (S){ 1, 2, 3 };
    if (s1.a != 1 || s1.b != 2 || s1.c != 3) return 1;

    // In-order designated initializers.
    S s2 = (S){ .a = 4, .b = 5, .c = 6 };
    if (s2.a != 4 || s2.b != 5 || s2.c != 6) return 2;

    // Compound literal with pointer fields (the qwen3.c shape).
    P p = (P){ .q = arr, .n = 3 };
    if (p.q[0] != 10 || p.q[2] != 30 || p.n != 3) return 3;

    // Compound literal assigned to an existing struct (not just an initializer).
    S s3;
    s3 = (S){ 7, 8, 9 };
    if (s3.a != 7 || s3.b != 8 || s3.c != 9) return 4;

    // Partial initializer: unset fields are zero.
    S s4 = (S){ .a = 42 };
    if (s4.a != 42 || s4.b != 0 || s4.c != 0) return 5;

    // Field access directly on a compound literal.
    if ((S){ 100, 200, 300 }.b != 200) return 6;

    return 0;
}
