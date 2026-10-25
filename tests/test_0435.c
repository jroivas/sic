/* -Werror also covers sic's own -Wunsupported-asm (an asm template sic cannot
 * lower traps if executed). Vector-register operands ("x") are still
 * unsupported (constant, general-register and memory operands are assembled:
 * test_0633, test_0636). */
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 100) __asm__ volatile("movq %0, %%xmm1" : : "x"((double)argc));
    return 0;
}
