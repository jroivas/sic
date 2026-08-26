//! Self-contained runtime for sic's native `std.Print` / `std.Println`
//! (sic.md §"Match"/std). The compiler lowers `std.Print(a, b, …)` into a
//! sequence of per-argument writer calls chosen by each argument's static type;
//! these writers do the formatting. Prepended (post-preprocess) ahead of the
//! user code only when `std.Print`/`std.Println` is used, so a unit that never
//! prints links nothing extra. All symbols are weak. I/O goes straight to fd 1
//! via `write(2)`; numeric/float formatting uses `snprintf` (both in libc).

/// The runtime source, prepended ahead of the user code when `uses_std`.
pub const STD_RUNTIME: &str = r#"
#ifndef __SIC_STD_RUNTIME
#define __SIC_STD_RUNTIME
extern long write(int, const void *, unsigned long);
extern int snprintf(char *, unsigned long, const char *, ...);
extern unsigned long strlen(const char *);

__attribute__((weak)) void __sic_print_str(const char *d, unsigned long n) {
    if (d && n) write(1, d, n);
}
__attribute__((weak)) void __sic_print_cstr(const char *s) {
    if (s) write(1, s, strlen(s));
}
__attribute__((weak)) void __sic_print_i64(long long v) {
    char b[32]; int n = snprintf(b, sizeof b, "%lld", v); if (n > 0) write(1, b, n);
}
__attribute__((weak)) void __sic_print_u64(unsigned long long v) {
    char b[32]; int n = snprintf(b, sizeof b, "%llu", v); if (n > 0) write(1, b, n);
}
__attribute__((weak)) void __sic_print_f64(double v) {
    char b[64]; int n = snprintf(b, sizeof b, "%g", v); if (n > 0) write(1, b, n);
}
__attribute__((weak)) void __sic_print_bool(long long v) {
    __sic_print_cstr(v ? "true" : "false");
}
__attribute__((weak)) void __sic_print_ptr(const void *p) {
    if (!p) { __sic_print_cstr("(null)"); return; }
    char b[32]; int n = snprintf(b, sizeof b, "%p", p); if (n > 0) write(1, b, n);
}
/* A UTF-8 code point (sic `char`, up to 4 bytes) encoded and written. */
__attribute__((weak)) void __sic_print_char(unsigned int c) {
    unsigned char b[4];
    if (c < 0x80) { b[0] = (unsigned char)c; write(1, b, 1); }
    else if (c < 0x800) {
        b[0] = 0xC0 | (c >> 6); b[1] = 0x80 | (c & 0x3F); write(1, b, 2);
    } else if (c < 0x10000) {
        b[0] = 0xE0 | (c >> 12); b[1] = 0x80 | ((c >> 6) & 0x3F);
        b[2] = 0x80 | (c & 0x3F); write(1, b, 3);
    } else {
        b[0] = 0xF0 | (c >> 18); b[1] = 0x80 | ((c >> 12) & 0x3F);
        b[2] = 0x80 | ((c >> 6) & 0x3F); b[3] = 0x80 | (c & 0x3F); write(1, b, 4);
    }
}
__attribute__((weak)) void __sic_print_nl(void) { write(1, "\n", 1); }
#endif
"#;

/// Whether the (preprocessed) source uses `std.Print` / `std.Println` — the
/// signal to prepend [`STD_RUNTIME`]. A cheap substring test is enough: the
/// tokens `std.Print` only appear where the intrinsic is called.
pub fn uses_std(src: &str) -> bool {
    src.contains("std.Print")   // covers Print / Println / Printf
        || src.contains("std.Eprint")
}
