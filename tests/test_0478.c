/* A file-scope pointer initialized with the address of a compound literal
 * (`struct S *s = &(struct S){1, 2};`) was left NULL (SIGSEGV on use): the
 * literal has static storage and must be materialized. c-testsuite 00149/00150.
 * Returns 42. */
struct S1 { int a; int b; };
struct S2 { struct S1 s1; struct S1 *ps1; int arr[2]; };
struct S1 gs1 = { .a = 1, 2 };
struct S1 *p1 = &(struct S1) { 1, 2 };
struct S2 *p2 = &(struct S2) { {.b = 2, .a = 1}, &gs1, {[0] = 1, 1 + 1} };
int *pi = &(int) { 40 };
int *arr = (int[]) { 3, 4 };
int main(void) {
    if (p1->a != 1 || p1->b != 2) return 1;
    if (p2->s1.a != 1 || p2->s1.b != 2 || p2->ps1->b != 2) return 2;
    if (p2->arr[0] != 1 || p2->arr[1] != 2) return 3;
    if (arr[1] != 4) return 4;
    return *pi + 2;
}
