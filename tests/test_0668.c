// Two asm statements with the same text and a deferred "i" operand are helpers
// of their own, and each needs its own labels: for a string operand and `%=`
// they got the same ones, "symbol already defined" (Linux's WARN()s, which
// repeat the file name, in one unit).
#define NOTE(k) asm(".pushsection .rodata\n\t.long %c0 - . + %c1\n\t.popsection\n" \
                    ".Lnote%=:" : : "i"("file.c"), "i"(k))

static inline __attribute__((always_inline)) void first(int k) { NOTE(k); }
static inline __attribute__((always_inline)) void second(int k) { NOTE(k); }

int main(void) {
    first(1);
    second(1);
    first(2);
    second(2);
    int k = 3;
    NOTE(k);
    NOTE(k);
    return 42;
}
