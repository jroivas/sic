// A global register variable (GNU C `register T x asm("rsp")`) is the register
// itself, with no storage: Linux's `current_stack_pointer`. sic defined it as
// data in every object ("multiple definition" in the vDSO link). Reading it
// gives the stack pointer; as an asm operand (ASM_CALL_CONSTRAINT) it only
// says the asm uses the stack.
register unsigned long current_stack_pointer asm("rsp");
#define ASM_CALL_CONSTRAINT "+r"(current_stack_pointer)

static __attribute__((noinline)) int on_stack(void *p) {
    unsigned long sp = current_stack_pointer;
    unsigned long a = (unsigned long)p;
    return a > sp && a - sp < 4096;                // a caller's local, just above
}

int main(void) {
    int local = 1;
    int ok = on_stack(&local);
    unsigned long before = current_stack_pointer;
    int x = 40;
    asm volatile("addl $2, %0" : "+r"(x), ASM_CALL_CONSTRAINT);
    ok += (current_stack_pointer - before) < 256;  // the stack did not move
    return x + ok - 2;                              // 42 + 2 - 2
}
