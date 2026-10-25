// C inline assembly with only constant operands ("i"/"n") is passed to the
// system assembler (Linux's asm-offsets DEFINE()s and its section tables):
// operands print as GCC does (%0 -> $v, %c0 -> v, %n0 -> -v), the text runs
// where the statement is, and data it places in a section is linked in.
#define RECORD(v) asm volatile(".pushsection sic_rec,\"a\"\n\t.long %c0\n\t.popsection" : : "i"(v))
#define NEGREC(v) asm volatile(".pushsection sic_rec,\"a\"\n\t.long %n0\n\t.popsection" : : "n"(v))

extern const int __start_sic_rec[], __stop_sic_rec[];

static int sum_records(void)
{
    int s = 0;
    for (const int *p = __start_sic_rec; p < __stop_sic_rec; p++) s += *p;
    return s;
}

int main(void)
{
    asm volatile("nop");
    asm volatile("nop\n\tnop" : : "i"(1));
    RECORD(40);
    RECORD(sizeof(long));
    NEGREC(6);
    asm volatile("jmp 1f\n1:\n" ".pushsection sic_rec,\"a\"\n.long 0\n.popsection");
    // 40 + 8 - 6 + 0
    return sum_records();
}
