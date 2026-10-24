/* x86 CPU feature tests behind `__builtin_cpu_supports` / `__builtin_cpu_is`
   (the compiler maps the feature name to its CPUID bit). Prepended
   (post-preprocess) only when the unit mentions those builtins; weak-linked. */

static void __sic_cpuid(unsigned leaf, unsigned sub, unsigned r[4]) {
    unsigned a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(sub));
    r[0] = a; r[1] = b; r[2] = c; r[3] = d;
}

/* Whether CPUID `leaf`/`sub` sets `bit` of register `reg` (0 = eax … 3 = edx),
   and the OS enabled the XCR0 state `xcr0` the feature needs (AVX, AVX-512). */
__attribute__((weak)) int __sic_cpu_supports(unsigned leaf, unsigned sub, unsigned reg, unsigned bit, unsigned xcr0) {
    unsigned r[4];
    __sic_cpuid(leaf & 0x80000000u, 0, r);
    if (r[0] < leaf) return 0;
    __sic_cpuid(leaf, sub, r);
    if (!((r[reg] >> bit) & 1)) return 0;
    if (xcr0) {
        unsigned lo, hi;
        __sic_cpuid(1, 0, r);
        if (!((r[2] >> 27) & 1)) return 0; /* OSXSAVE */
        __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        if ((lo & xcr0) != xcr0) return 0;
    }
    return 1;
}

/* The CPU vendor: 1 = Intel ("GenuineIntel"), 2 = AMD ("AuthenticAMD"). */
__attribute__((weak)) int __sic_cpu_is(int vendor) {
    unsigned r[4];
    __sic_cpuid(0, 0, r);
    if (vendor == 1) return r[1] == 0x756e6547u && r[3] == 0x49656e69u && r[2] == 0x6c65746eu;
    if (vendor == 2) return r[1] == 0x68747541u && r[3] == 0x69746e65u && r[2] == 0x444d4163u;
    return 0;
}
