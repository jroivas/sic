/* The type of `arr->field` on an array (which decays to a pointer to its
 * first element) was not inferred — it fell back to `int`, so
 * `sizeof(cases->c)` was 4 instead of the member's size. c-testsuite 00205.
 * Returns 42. */
typedef struct { long c[4]; long b; char tag; } PT;
PT cases[2];
int main(void) {
    PT loc[2];
    PT *p = cases;
    if (sizeof(cases->c) != 4 * sizeof(long) || sizeof(loc->c) != sizeof(p->c)) return 1;
    if (sizeof(cases->c[0]) != sizeof(long) || sizeof(cases->tag) != 1) return 2;
    if (sizeof(cases->c) / sizeof(cases->c[0]) != 4) return 3;
    cases->b = 40;
    loc->tag = 2;
    return (int)(cases[0].b + loc[0].tag);
}
