//! The x86 SIMD builtins lowered to calls (the SSE4.2 string comparisons,
//! F16C's float-to-half); see `ia32_runtime.c`. Prepended, in C and in SIC,
//! only when a unit uses them.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const IA32_RUNTIME: &str = include_str!("ia32_runtime.c");

/// True if `src` calls one of the builtins the runtime implements.
pub fn uses_ia32(src: &str) -> bool {
    src.contains("__builtin_ia32_pcmpestr") || src.contains("__builtin_ia32_pcmpistr")
        || src.contains("__builtin_ia32_vcvtps2ph")
}
