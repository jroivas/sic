/* -Werror also covers sic's own -Wunsupported-asm (an asm template sic cannot
 * lower traps if executed). Templates with register operands are still
 * unsupported (constant-operand ones are assembled, test_0633). */
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 100) __asm__ volatile("mov %0, %%cr0" : : "r"((long)argc));
    return 0;
}
