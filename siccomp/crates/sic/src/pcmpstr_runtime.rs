//! The SSE4.2 string comparisons behind `__builtin_ia32_pcmp{e,i}str*`; see
//! `pcmpstr_runtime.c`. Prepended, in C and in SIC, only when a unit uses them.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const PCMPSTR_RUNTIME: &str = include_str!("pcmpstr_runtime.c");

/// True if `src` calls one of the string-comparison builtins.
pub fn uses_pcmpstr(src: &str) -> bool {
    src.contains("__builtin_ia32_pcmpestr") || src.contains("__builtin_ia32_pcmpistr")
}
