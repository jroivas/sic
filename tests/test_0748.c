/* A wider input tied to a narrower output ("0"(pointer) with "=c"(int)), as
 * Linux's put_user calls __put_user_8: the callee gets the whole pointer (as
 * GCC passes it, and clang widens the output), not its low 32 bits. The
 * narrower case extends the input to the output. */
unsigned long seen;
__asm__(".text\n.globl tie_put8\ntie_put8:\n\tmovq %rcx, seen(%rip)\n\tmovl $7, %ecx\n\tret");
__attribute__((noinline)) int put(void *p, long v) {
    int ret;
    register long val __asm__("rax") = v;
    __asm__ volatile("call tie_put8" : "=c"(ret) : "0"(p), "r"(val) : "ebx", "memory");
    return ret;
}
int main(void) {
    void *p = (void *)0x7ffed9065770ul;
    if (put(p, 1) != 7) return 1;                 /* the narrowed result */
    if (seen != (unsigned long)p) return 2;       /* the whole pointer went in */
    unsigned char c = 200; unsigned long w;
    __asm__("" : "=r"(w) : "0"(c));               /* narrower input: extended */
    if ((w & 0xff) != 200) return 3;
    long big = 0x123456789ll; int lo;
    __asm__("" : "=r"(lo) : "0"(big));
    if (lo != 0x23456789) return 4;
    return 42;
}
