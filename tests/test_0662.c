// An always_inline call is expanded however large the caller already is: its
// `"i"` operand is a constant only once inlined. sic's inline caps left such
// calls out of line in a huge caller, which is an impossible asm constraint
// (Linux's arch_static_branch in intel_pmu_init).
static inline __attribute__((always_inline)) long imm(long k) {
    long r;
    asm("mov %1, %0" : "=r"(r) : "i"(k));
    return r;
}

#define A s += imm(1);
#define B A A A A
#define C B B B B
#define D C C C C
#define E D D D D
#define F E E E E

int main(void) {
    long s = 0;
    F F F F     // 4096 calls: past both the count and the size cap
    return s == 4096 ? 42 : 1;
}
