//! sic's task runtime for `async`/`await` (sic.md §"Async"): a cooperative
//! scheduler per thread, each task on a stack of its own. Plain C, prepended
//! when a unit uses `async`, `await`, `Task` or the `art` module (see
//! [`uses_async`]). Everything is `__attribute__((weak))`, so the copies in a
//! program's units are one; the `art` module has no copy and calls the
//! program's.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const ASYNC_RUNTIME: &str = include_str!("async_runtime.c");

/// True if `src` uses async support (so the runtime must be prepended): a crude
/// word-boundary scan for `async`, `await` or `Task`, or `import art`.
pub fn uses_async(src: &str) -> bool {
    if src.contains("import art") { return true; }
    let bytes = src.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for kw in ["async", "await", "Task"] {
        let mut i = 0;
        while let Some(pos) = src[i..].find(kw) {
            let start = i + pos;
            let end = start + kw.len();
            let before_ok = start == 0 || !is_word(bytes[start - 1]);
            let after_ok = end >= bytes.len() || !is_word(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
            i = end;
        }
    }
    false
}
