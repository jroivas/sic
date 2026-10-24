// GCC vector <-> scalar casts of the same size reinterpret the bits
// (<mmintrin.h>: `(__m64)i`, `(long long)m`). The scalar used to be taken
// for the vector's address: `_mm_cvtsi64_m64` crashed.
typedef int v2si __attribute__((vector_size(8)));
typedef short v4hi __attribute__((vector_size(8)));

static long long id(long long x) { return x; }

int main(void)
{
    v2si a = (v2si)id(0x0000000700000005LL);
    if (a[0] != 5 || a[1] != 7) return 1;
    v4hi b = (v4hi)a;
    if (b[0] != 5 || b[2] != 7) return 2;
    long long back = (long long)b;
    if (back != 0x0000000700000005LL) return 3;
    unsigned long long u = (unsigned long long)(v2si){ -1, 0 };
    if (u != 0xffffffffULL) return 5;
    return 42;
}
