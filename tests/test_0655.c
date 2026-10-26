// __attribute__((section)) on functions with -fno-function-sections (Linux's
// __init → .init.text): only the placed functions move. sic renamed the one
// shared code section, so every function of the unit went to the named
// section (Linux's wait_for_initramfs in .init.text, freed after boot).
extern char __start_sic_init[], __stop_sic_init[];

__attribute__((section("sic_init"), noinline)) int setup_a(int x) { return x + 1; }
__attribute__((section("sic_init"), noinline)) int setup_b(int x) { return x * 2; }
__attribute__((noinline)) int runtime_fn(int x) { return x - 3; }
static __attribute__((noinline)) int helper(int x) { return runtime_fn(x) + setup_a(x); }

static int in_init(void *p) { return (char *)p >= __start_sic_init && (char *)p < __stop_sic_init; }

int main(void) {
    int ok = in_init((void *)setup_a) + in_init((void *)setup_b)
           + !in_init((void *)runtime_fn) + !in_init((void *)helper) + !in_init((void *)main);
    return ok + helper(10) + setup_b(4) + 11;   // 5 + 18 + 8 + 11 = 42
}
