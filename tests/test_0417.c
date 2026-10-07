/* GCC vector extension through pointers: `v2di *p` → `p[i]` is a vector (it
 * was typed as its lane, so `v = p[i]` stored the address and `v |= p[i]` or-ed
 * addresses — QEMU buffer_zero_sse2); `v op= w` is element-wise with its left
 * side evaluated once; and `int (*r)[4]` → `r[i]` is a row (C). Returns 42. */
typedef long long v2di __attribute__((vector_size(16)));
typedef int v4si __attribute__((vector_size(16)));
int main(void) {
    v2di a[4] = {{1,2},{4,8},{16,32},{64,128}};
    v2di *p = a;
    v2di v = p[0]; v2di w = p[2];
    v |= w; v |= p[1]; v = v | p[3];
    if (v[0] != 85 || v[1] != 170) return 1;
    v4si x = {1,2,3,4}, y = {10,20,30,40}; v4si *q = &y;
    x += *q; x -= q[0]; x ^= y; x &= q[0];
    if (x[0] != 10 || x[1] != 20 || x[2] != 28 || x[3] != 40) return 2;
    int i = 0; p[i++] |= w;
    if (i != 1 || a[0][0] != 17 || a[0][1] != 34) return 3;
    int m[3][4] = {{1,2,3,4},{5,6,7,8},{9,10,11,12}};
    int (*r)[4] = m;
    if (r[1][0] != 5 || r[2][3] != 12 || sizeof(r[1]) != 16 || sizeof(*r) != 16) return 4;
    return 42;
}
