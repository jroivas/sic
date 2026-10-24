//! The x86 CPU feature tests behind `__builtin_cpu_supports` /
//! `__builtin_cpu_is`; see `cpu_runtime.c`. Prepended, in C and in SIC, only
//! when a unit mentions one of them.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const CPU_RUNTIME: &str = include_str!("cpu_runtime.c");

/// True if `src` calls `__builtin_cpu_supports` or `__builtin_cpu_is`.
pub fn uses_cpu(src: &str) -> bool {
    src.contains("__builtin_cpu_supports") || src.contains("__builtin_cpu_is")
}
