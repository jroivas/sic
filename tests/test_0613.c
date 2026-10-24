// The vector builtins: __builtin_shufflevector (Clang, constant indices into
// a ++ b), __builtin_shuffle (GCC, a runtime mask) and __builtin_convertvector
// (lane-wise conversion to another vector type). Returns 42.
typedef int v4 __attribute__((vector_size(16)));
typedef int v8 __attribute__((vector_size(32)));
typedef float f4 __attribute__((vector_size(16)));
typedef unsigned char u16v __attribute__((vector_size(16)));

int main(void)
{
    v4 a = {1, 2, 3, 4}, b = {5, 6, 7, 8};
    f4 f = {1.5f, -2.5f, 3.75f, 100.25f};
    v4 fi = __builtin_convertvector(f, v4);
    f4 af = __builtin_convertvector(a, f4);
    if (fi[0] != 1 || fi[1] != -2 || fi[3] != 100 || af[1] != 2.0f || af[3] != 4.0f) return 1;
    v4 m = {3, 0, 5, 6};
    v4 s1 = __builtin_shuffle(a, m);
    v4 s2 = __builtin_shuffle(a, b, m);
    if (s1[0] != 4 || s1[1] != 1 || s1[2] != 2 || s1[3] != 3) return 2;
    if (s2[0] != 4 || s2[1] != 1 || s2[2] != 6 || s2[3] != 7) return 3;
    v4 r = __builtin_shufflevector(a, b, 7, 0, 5, 2);
    v8 w = __builtin_shufflevector(a, b, 0, 1, 2, 3, 4, 5, 6, 7);
    if (r[0] != 8 || r[1] != 1 || r[2] != 6 || r[3] != 3 || w[0] != 1 || w[7] != 8) return 4;
    u16v bytes = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    u16v rev = __builtin_shufflevector(bytes, bytes, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    if (rev[0] != 15 || rev[15] != 0) return 5;
    v4 sum = __builtin_shufflevector(a, a, 3, 2, 1, 0) + a;
    if (sum[0] != 5 || sum[3] != 5 || sizeof(__builtin_shufflevector(a, a, 0, 1)) != 8) return 6;
    return 42;
}
