/* `vector_size` over a TYPEDEF element: the parser only knows typedef names, so
 * it assumed a 1-byte element — `int64_t __attribute__((vector_size(16)))` had
 * 16 lanes (128 bytes) and broke unions with __int128 (QEMU X86Int128Union-like
 * code). Returns 42. */
#include <stdint.h>
typedef int64_t v2i64 __attribute__((vector_size(16)));
typedef uint32_t v4u32 __attribute__((vector_size(16)));
typedef uint8_t v32u8 __attribute__((vector_size(32)));
typedef union { v2i64 v; __int128 s; } U;
int main(void) {
    if (sizeof(v2i64) != 16 || sizeof(v4u32) != 16 || sizeof(v32u8) != 32 || sizeof(U) != 16) return 1;
    v4u32 a = { 1, 2, 3, 4 }, b = { 10, 20, 30, 40 };
    v4u32 c = a + b;
    if (c[0] != 11 || c[3] != 44) return 2;
    v2i64 d = { -5, 7 }, e = { 3, 3 };
    d = d * e;
    if (d[0] != -15 || d[1] != 21) return 3;
    U u = { .v = d };
    if ((long long)u.s != -15 || (long long)(u.s >> 64) != 21) return 4;
    return 42;
}
