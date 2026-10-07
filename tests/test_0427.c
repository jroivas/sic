/* Valgrind client requests (<valgrind/valgrind.h>, used by QEMU's coroutine
 * stack registration) are a native no-op marker: `rolq` x4 on %rdi (= 2 full
 * turns) + `xchgq %rbx,%rbx`. Outside Valgrind the request returns its
 * default. sic warned "unsupported" and would have trapped. Returns 42. */
static unsigned long client_request(unsigned long dflt, unsigned long req) {
    volatile unsigned long args[6] = { req, 1, 2, 3, 4, 5 };
    volatile unsigned long result;
    __asm__ volatile("rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"
                     "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
                     "xchgq %%rbx,%%rbx"
                     : "=d" (result)
                     : "a" (&args[0]), "0" (dflt)
                     : "cc", "memory");
    return result;
}
int main(void) {
    __asm__ volatile("rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"
                     "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
                     "xchgq %%rdi,%%rdi\n\t" : : : "cc", "memory");
    return (int)client_request(42, 0x1501);
}
