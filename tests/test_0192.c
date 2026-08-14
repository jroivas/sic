/* __attribute__((aligned(N))) on a struct/union member raises the member's — and
 * therefore the aggregate's — alignment, shifting every following field.
 *
 * This is exactly QEMU's FPReg union (a 16-aligned `floatx80 d` member) inside
 * CPUX86State: without honoring it, sic laid the struct out 24 bytes smaller and
 * mis-placed fpregs/xmm_regs/etc. TCG then generated guest-state accesses at the
 * wrong offsets, corrupting the emulated CPU. */
#include <stddef.h>

/* A stray aligned() on an unrelated declaration must NOT leak onto a later
 * struct's members (that once over-aligned every following struct, including
 * libc's, and crashed). */
int g_unrelated __attribute__((aligned(64)));
struct NoLeak { char a; int b; };   /* stays align 4, size 8 */

typedef struct { unsigned long low; unsigned short high; } fx80; /* 10 bytes, align 8 */

typedef union {
    fx80 d __attribute__((aligned(16)));
    unsigned long mmx;
} FPReg;

/* aligned on a plain struct member too */
struct A {
    char c;
    int x __attribute__((aligned(16)));
};

/* mimics the CPUX86State neighbourhood around fpregs */
struct CpuLike {
    unsigned int fpstt;   /* 0 */
    unsigned short fpus;  /* 4 */
    unsigned short fpuc;  /* 6 */
    unsigned char fptags[8]; /* 8..16 */
    FPReg fpregs[8];      /* must be 16-aligned -> offset 16 */
    unsigned int mxcsr;
};

/* Type-level aligned: on the tag, and on a typedef with a constant-expression
 * argument (QEMU's QEMU_ALIGNED(2 * sizeof(void *)) on CPUTLBDescFast). */
struct __attribute__((aligned(32))) TagAligned { int x; };
typedef struct { unsigned long a, b; } TdFast __attribute__((aligned(2 * sizeof(void *))));
struct HoldsFast { char c; TdFast f[2]; };

int main(void)
{
    if (_Alignof(struct TagAligned) != 32) return 20;
    if (sizeof(struct TagAligned)   != 32) return 21;

    if (_Alignof(TdFast) != 16) return 22;       /* 2*sizeof(void*) */
    if (sizeof(TdFast)   != 16) return 23;
    /* the 16-aligned type forces f[] to start at offset 16, stride 16 */
    if (offsetof(struct HoldsFast, f) != 16) return 24;
    if (offsetof(struct HoldsFast, f[1]) - offsetof(struct HoldsFast, f[0]) != 16) return 25;


    if (_Alignof(struct NoLeak) != 4) return 10;
    if (sizeof(struct NoLeak)   != 8) return 11;

    if (_Alignof(FPReg) != 16) return 1;
    if (sizeof(FPReg)   != 16) return 2;

    if (_Alignof(struct A) != 16) return 3;
    if (offsetof(struct A, x) != 16) return 4;
    if (sizeof(struct A) != 32) return 5;

    if (_Alignof(struct CpuLike) != 16) return 6;
    if (offsetof(struct CpuLike, fpregs) != 16) return 7;
    if (offsetof(struct CpuLike, mxcsr) != 16 + 16 * 8) return 8;

    /* the override must survive the array: element stride stays 16 */
    if (offsetof(struct CpuLike, fpregs[1]) - offsetof(struct CpuLike, fpregs[0]) != 16)
        return 9;

    return 0;
}
