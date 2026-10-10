/* A block-scope `typedef __typeof(expr) T;` was lowered without the function's
 * scope, so T became `int` whatever expr was — QEMU loongarch DO_VMUH:
 * `typedef __typeof(Vd->D(0)) T; … ((T)a * (T)b) >> 32` multiplied in 32 bits
 * (and -Wshift-count-overflow fired). Returns 42. */
#include <stdint.h>
typedef union { int64_t D[2]; uint32_t UW[4]; } VReg;
#define D(x) D[x]
#define UW(x) UW[x]
int main(void) {
    VReg v = { .UW = { 0xffffffffu, 3, 0, 0 } }, *Vd = &v;
    typedef __typeof(Vd->D(0)) T;
    typedef __typeof(Vd->D) TA;
    typedef __typeof(&Vd->UW[1]) TP;
    if (sizeof(T) != 8 || sizeof(TA) != 16 || sizeof(*(TP)0) != 4) return 1;
    uint32_t r = ((T)Vd->UW(0)) * ((T)Vd->UW(0)) >> 32;
    if (r != 4294967294u) return 2;
    TP p = &Vd->UW[1];
    if (*p != 3) return 3;
    return 42;
}
