/* `__attribute__((packed))` on an enum makes its underlying type the smallest
 * integer that holds all enumerators (1 byte for small values), which shrinks
 * any struct containing it. sic ignored packed and used 4 bytes, so QEMU's
 *   typedef enum __attribute__((packed)) { ... } FloatClass;   // 1 byte
 *   typedef struct { FloatClass cls; bool sign; int32_t exp;
 *                    uint64_t frac_hi, frac_lo; } FloatParts128; // 24 bytes
 * became 32 bytes; the size/offset mismatch corrupted the x87 softfloat add
 * path and GWBASIC crashed (a struct copy with a bad size/pointer). */
#include <stddef.h>
#include <stdint.h>

typedef enum __attribute__((packed)) {
    C_unclassified, C_zero, C_normal, C_denormal, C_inf, C_qnan, C_snan
} FloatClass;

typedef struct {
    FloatClass cls;
    _Bool sign;
    int32_t exp;
    uint64_t frac_hi, frac_lo;
} Parts;

/* multi-byte and signed packed enums */
typedef enum __attribute__((packed)) { W0, W_BIG = 40000 } Wide;   /* 2 bytes */
typedef enum __attribute__((packed)) { S0, S_NEG = -1 } Signed;    /* 1 byte, signed */
typedef enum { Plain0, Plain1 } Plain;                             /* unpacked: 4 */

int main(void)
{
    if (sizeof(FloatClass) != 1) return 1;
    if (sizeof(Parts) != 24) return 2;                 /* was 32 */
    if (offsetof(Parts, exp) != 4) return 3;
    if (offsetof(Parts, frac_hi) != 8) return 4;
    if (offsetof(Parts, frac_lo) != 16) return 5;

    if (sizeof(Wide) != 2) return 6;
    if (sizeof(Signed) != 1) return 7;
    if (sizeof(Plain) != 4) return 8;

    /* the packed field round-trips its value */
    Parts p = { .cls = C_qnan, .sign = 1, .exp = -3, .frac_hi = 0xABCD };
    if (p.cls != C_qnan || p.sign != 1 || p.exp != -3 || p.frac_hi != 0xABCD) return 9;

    return 0;
}
