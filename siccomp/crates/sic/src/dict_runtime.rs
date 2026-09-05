//! Self-contained hash-map runtime for sic's built-in `dict` (sic.md §"Dict").
//! Plain C over `malloc`/`realloc`/`free` — no external library — prepended to a
//! translation unit only when it uses `dict` (see [`uses_dict`]). Every function is
//! `__attribute__((weak))` so copies dedupe at link and unused ones are dropped.
//!
//! Design follows CPython's dict: an insertion-ordered `entries` array plus a
//! sparse open-addressing `index` table of entry slots, so iteration order is stable
//! and deletions leave the order of surviving keys intact. Keys are tagged
//! `(kind, a, b)`: kind 1 = integer (`a` = value), kind 2 = string (`a` = byte
//! pointer, `b` = length; the bytes are copied and owned by the dict), kind 3 =
//! pointer (`a` = address). Values are a single 64-bit slot (an integer or a
//! pointer). This is enough for `dict<K,int>` and `dict` with int/pointer values;
//! richer value types build on the same table.
//!
//! Keeping the key kind explicit leaves room for the planned type-specialized
//! optimization: when the frontend knows the key is, say, `int`, it can eventually
//! call a monomorphic fast path instead of the tagged one.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const DICT_RUNTIME: &str = include_str!("dict_runtime.c");

/// True if `src` uses the `dict` type (so the runtime must be prepended). A crude
/// word-boundary scan for the `dict` keyword, ignoring substrings like `predict`.
pub fn uses_dict(src: &str) -> bool {
    let bytes = src.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    // Match the word `dict`, `va_dict`, or `set` (all use this runtime).
    for kw in ["dict", "va_dict", "set"] {
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
