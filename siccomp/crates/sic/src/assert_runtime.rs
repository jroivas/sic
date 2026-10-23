//! Failure report of the prelude `assert` macro (sic.md §"Macros"); see
//! `assert_runtime.c`. Prepended only when a unit mentions `assert`.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const ASSERT_RUNTIME: &str = include_str!("assert_runtime.c");

/// True if `src` mentions `assert` or `unreachable` (word-boundary scan).
pub fn uses_assert(src: &str) -> bool {
    mentions(src, "assert") || mentions(src, "unreachable") || mentions(src, "__builtin_unreachable")
}

fn mentions(src: &str, word: &str) -> bool {
    let bytes = src.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(pos) = src[i..].find(word) {
        let start = i + pos;
        let end = start + word.len();
        if (start == 0 || !is_word(bytes[start - 1])) && (end >= bytes.len() || !is_word(bytes[end])) {
            return true;
        }
        i = end;
    }
    false
}
