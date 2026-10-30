// always_inline functions calling each other in a cycle cannot all be expanded:
// inlining stays bounded, and what is left is called as usual.
static inline __attribute__((always_inline)) int odd(int n);
static inline __attribute__((always_inline)) int even(int n) { return n == 0 ? 1 : odd(n - 1); }
static inline __attribute__((always_inline)) int odd(int n) { return n == 0 ? 0 : even(n - 1); }

int main(int argc, char **argv) {
    (void)argv;
    return even(argc + 41) ? 42 : odd(argc + 40) + 1;
}
