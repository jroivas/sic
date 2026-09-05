//! Minimal synchronous stub runtime for sic's `async`/`await` (sic.md §"Async").
//! Plain C over `malloc`/`free`, prepended only when a unit uses `async`/`await`/
//! `Task` (see [`uses_async`]). Every function is `__attribute__((weak))` so copies
//! dedupe at link.
//!
//! This is a placeholder: an async call runs eagerly and its result is wrapped in a
//! ready `Task`; `await` just returns the stored value. A real executor (scheduling,
//! stack switching, an I/O reactor) is a separate runtime module that replaces these
//! weak symbols.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const ASYNC_RUNTIME: &str = include_str!("async_runtime.c");

/// True if `src` uses async support (so the runtime must be prepended). A crude
/// word-boundary scan for `async`, `await`, or `Task`.
pub fn uses_async(src: &str) -> bool {
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
