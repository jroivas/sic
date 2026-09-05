//! Self-contained growable-array runtime for sic's built-in `list` (sic.md §"List").
//! Plain C over `malloc`/`realloc`/`free`, prepended only when a unit uses `list`
//! (see [`uses_list`]). Elements use the same `(type-info, slot, owned)` box as the
//! dict runtime, so strings/structs are owned and freed identically. Weak-linked.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const LIST_RUNTIME: &str = include_str!("list_runtime.c");

/// True if `src` uses the `list` type (so the runtime must be prepended). A crude
/// word-boundary scan for the `list` keyword, ignoring substrings like `listen`.
pub fn uses_list(src: &str) -> bool {
    let bytes = src.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(pos) = src[i..].find("list") {
        let start = i + pos;
        let end = start + 4;
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        i = end;
    }
    false
}
