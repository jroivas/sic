/* A global struct whose flexible array member is initialized needs larger
 * storage, but its TYPE is still the declared struct: `sizeof(gw)` counted the
 * flexible elements (C 6.7.2.1p18 excludes them). c-testsuite 00216.
 * Returns 42. */
struct S { unsigned char a, b; unsigned char c[2]; };
struct W { int n; struct S s[]; };
struct W gw = {3, {{1, 2, {3, 4}}, {5, 6, {7, 8}}, {9, 10, {11, 12}}}};
struct Q { int n; int v[]; } gq = {2, {40, 2}};
int main(void) {
    static struct Q sq = {1, {5, 6, 7}};
    if (sizeof(gw) != sizeof(struct W) || sizeof gq != sizeof(struct Q)) return 1;
    if (sizeof sq != sizeof(struct Q) || sq.v[2] != 7) return 2;
    if (gw.s[2].c[1] != 12 || gw.n != 3) return 3;
    return gq.v[0] + gq.v[1];
}
