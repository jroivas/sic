/* Warning flags in order: -Wno-error=<w> keeps a warning non-fatal under
 * -Werror, -Wno-<w> disables it, and -w silences everything. Returns 42. */
int main(int argc, char **argv) {
    (void)argv;
    int unused_local = 1;
    if (argc > 100) return argc / 0 + (argc << 40);
    return 42;
}
