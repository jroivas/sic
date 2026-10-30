// Basic asm (no colon) is emitted as written: `%` is not operand syntax, so
// `%al` is a register, not the modifier `a` on an operand `l` (Linux's
// `asm volatile ("outb %al, $0x80")`).
volatile int saved;

int main(void) {
    asm("nop");
    asm volatile("movb %al, %al");                  // no fixed template for it
    asm volatile("testb %al, %al");
    asm volatile("push %rax\n\tpop %rax");
    asm("movl $40, saved(%rip)");
    asm volatile("addl $2, saved(%rip)");           // writes the variable
    return saved;
}
