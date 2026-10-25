// C inline asm with register, memory and flag operands (as Linux uses them):
// operands are loaded into the registers their constraints name, the template
// runs, outputs come back. Checked against the hash GCC's build computes.

#include <string.h>
struct pair { long a, b; };
static unsigned fls32(unsigned x) { int r; asm("bsrl %1,%0" : "=r"(r) : "rm"(x), "0"(-1)); return r + 1; }
static unsigned long fls64(unsigned long x) { long r = -1; asm("bsrq %1,%q0" : "+r"(r) : "rm"(x)); return r + 1; }
static int ffs32(int x) { int r; asm("bsfl %1,%0" : "=r"(r) : "rm"(x), "0"(-1)); return r + 1; }
static long xadd(long *p, long v) { asm volatile("lock xaddq %0, %1" : "+r"(v), "+m"(*p) : : "memory"); return v; }
static int cas(int *p, int old, int new) { int z; asm volatile("lock cmpxchgl %[n], %[m]" : "=@ccz"(z), [m] "+m"(*p), "+a"(old) : [n] "r"(new) : "memory"); return z * 100 + old; }
static int carry(unsigned a, unsigned b) { int c; asm("addl %2, %1" : "=@ccc"(c), "+r"(a) : "r"(b)); return c; }
static unsigned char lowb(unsigned v) { unsigned char r; asm("movb %b1, %0" : "=q"(r) : "q"(v)); return r; }
static unsigned char highb(unsigned v) { unsigned char r; asm("movb %h1, %0" : "=q"(r) : "Q"(v)); return r; }
static unsigned short w16(unsigned short a, unsigned short b) { asm("addw %1, %0" : "+r"(a) : "r"(b)); return a; }
static long imm_add(long a) { asm("addq %1, %0\n\taddq $%c2+1, %0" : "+r"(a) : "i"(1000), "n"(4)); return a; }
static void cpuid0(unsigned *a, unsigned *b, unsigned *c, unsigned *d) { asm volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "0"(0), "2"(0)); }
static void fill(char *p, int ch, long n) { asm volatile("rep stosb" : "+D"(p), "+c"(n) : "a"(ch) : "memory"); }
static void copy(void *d, const void *s, long n) { asm volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) : : "memory"); }
static long sum_pair(struct pair *p) { long r; asm("movq %1, %0\n\taddq %2, %0" : "=&r"(r) : "m"(p->a), "m"(p->b)); return r; }
static long shift_k(long x) { asm("shll $3, %k0" : "+r"(x)); return x; }
static long neg_q(long x) { asm("negq %q0" : "+r"(x)); return x; }
int main(void)
{
    unsigned long h = 0;
    #define MIX(v) h = h * 1000003 + (unsigned long)(v)
    MIX(fls32(0)); MIX(fls32(1)); MIX(fls32(0x80000000u)); MIX(fls64(1UL << 40)); MIX(fls64(0)); MIX(ffs32(12));
    long x = 5; MIX(xadd(&x, 7)); MIX(x);
    int m = 3; MIX(cas(&m, 3, 9)); MIX(m); MIX(cas(&m, 3, 1)); MIX(m);
    MIX(carry(0xffffffffu, 1)); MIX(carry(1, 1));
    MIX(lowb(0x1234)); MIX(highb(0x1234)); MIX(w16(0xfff0, 0x20));
    MIX(imm_add(10));
    unsigned a, b, c, d; cpuid0(&a, &b, &c, &d); MIX(a > 0); MIX(b == 0x756e6547 || b == 0x68747541);
    char buf[32]; memset(buf, 0, sizeof buf); fill(buf + 2, 'q', 5); MIX(buf[1]); MIX(buf[2]); MIX(buf[6]); MIX(buf[7]);
    char src[8] = "abcdefg", dst[8] = {0}; copy(dst, src, 8); MIX(strcmp(dst, "abcdefg"));
    struct pair pr = { 40, 2 }; MIX(sum_pair(&pr));
    MIX(shift_k(0x100000001L)); MIX(neg_q(5));
    return h == 0x667a102c560ab84fUL ? 42 : 1;
}
