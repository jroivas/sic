//! Runtime of sic's built-in `stringbuilder` (sic.md §"Stringbuilder"): plain C and
//! one struct, prepended only when a unit uses it (see [`uses_stringbuilder`]).

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const STRINGBUILDER_RUNTIME: &str = include_str!("stringbuilder_runtime.c");

/// True if `src` names the type or `string.builder`. A crude word-boundary scan.
pub fn uses_stringbuilder(src: &str) -> bool {
    let bytes = src.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for word in ["stringbuilder", "string.builder", "string::builder"] {
        let mut i = 0;
        while let Some(pos) = src[i..].find(word) {
            let start = i + pos;
            let end = start + word.len();
            if (start == 0 || !is_word(bytes[start - 1])) && (end >= bytes.len() || !is_word(bytes[end])) {
                return true;
            }
            i = end;
        }
    }
    false
}
