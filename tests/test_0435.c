/* -Werror also covers sic's own -Wunsupported-asm (an asm template sic cannot
 * lower traps if executed). */
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 100) __asm__ volatile("hlt");
    return 0;
}
