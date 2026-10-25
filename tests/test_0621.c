// Unary `-` and `~` on GCC vectors are lane-wise (GCC's <fmaintrin.h> writes
// _mm_fmsubadd_pd as vfmaddsubpd(a, b, -c)); they crashed, the vector's
// address taken for a scalar.
typedef double v2df __attribute__((vector_size(16)));
typedef float v8sf __attribute__((vector_size(32)));
typedef int v4si __attribute__((vector_size(16)));
typedef short v4hi __attribute__((vector_size(8)));
typedef char v4qi __attribute__((vector_size(4)));

int main(void)
{
    v2df c = { 10, -0.0 };
    v2df n = -c;
    if (n[0] != -10 || __builtin_signbit(n[1])) return 1;
    v8sf f = { 1, 2, 3, 4, 5, 6, 7, 8 };
    v8sf g = -f;
    for (int i = 0; i < 8; i++) if (g[i] != -(i + 1)) return 2;
    v4si a = { 1, -2, 0, 0x7fffffff };
    v4si b = ~a, m = -a;
    if (b[0] != -2 || b[1] != 1 || b[2] != -1 || m[3] != -0x7fffffff || m[1] != 2) return 3;
    v4hi h = { 1, 2, 3, -4 };
    v4hi hn = -h;
    if (hn[0] != -1 || hn[3] != 4) return 4;
    v4qi q = { 1, 2, 3, 4 };
    v4qi qn = ~q;
    if (qn[0] != -2 || qn[3] != -5) return 5;
    return 42;
}
