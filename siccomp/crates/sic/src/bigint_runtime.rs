//! Self-contained arbitrary-precision integer runtime for sic's `bigint`
//! (sic.md §"Integer sizes"). Written in plain C using only `malloc`/`free`
//! (already in libc) — no external bignum library. It is prepended to a
//! translation unit *only when that unit uses `bigint`* (see `uses_bigint`), so
//! programs without bigint pay nothing. Every function is `__attribute__((weak))`
//! so the copies emitted into each object dedupe at link and unused ones are
//! garbage-collected.
//!
//! Representation: sign-magnitude with base-2^32 little-endian limbs.
//! `{ int sign; unsigned len; unsigned limbs[]; }` — `sign` is 0 for zero,
//! ±1 otherwise; `len` counts significant limbs (no leading zeros).

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const BIGINT_RUNTIME: &str = include_str!("bigint_runtime.c");

/// True if `src` (post-preprocess text) uses `bigint` or `fixed` as a whole
/// word — the signal to prepend [`BIGINT_RUNTIME`] (fixed-point is built on the
/// same runtime). A bare substring match is avoided so `bigintish`/`fixedly` or a
/// string literal doesn't trigger it.
pub fn uses_bignum(src: &str) -> bool {
    word_present(src, "bigint") || word_present(src, "fixed")
}

/// Runtime for `string.utf8` (sic.md §"Integer sizes"): decode a UTF-8 byte
/// buffer into an array of 32-bit Unicode code points. Prepended only when a unit
/// uses `.utf8` (see [`uses_utf8`]); `__attribute__((weak))` like the bigint one.
pub const UTF8_RUNTIME: &str = include_str!("utf8_runtime.c");

/// True if `src` uses the `.utf8` accessor, or a range-`for` (which may iterate a
/// string's code points and desugars to `.utf8`) — the signal to prepend
/// [`UTF8_RUNTIME`]. The decoder is weak, so prepending it for a non-string
/// range-`for` only leaves a small unused function.
pub fn uses_utf8(src: &str) -> bool {
    word_present(src, "utf8") || uses_range_for(src)
}

/// True if `src` contains a range-`for` header `for ( … : … )`. A classic `for`
/// uses `;` separators, so a `:` inside the parenthesized header (with no `;`)
/// marks the sic colon form.
fn uses_range_for(src: &str) -> bool {
    let bytes = src.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(off) = src[i..].find("for") {
        let start = i + off;
        i = start + 3;
        // Whole-word `for`.
        if start > 0 && is_ident(bytes[start - 1]) { continue; }
        if i < bytes.len() && is_ident(bytes[i]) { continue; }
        // Skip whitespace to the opening paren.
        let mut j = i;
        while j < bytes.len() && (bytes[j] as char).is_whitespace() { j += 1; }
        if j >= bytes.len() || bytes[j] != b'(' { continue; }
        // Scan the parenthesized header for `:` before any `;`.
        let mut depth = 0i32;
        let mut k = j;
        let mut saw_colon = false;
        let mut saw_semi = false;
        while k < bytes.len() {
            match bytes[k] {
                b'(' => depth += 1,
                b')' => { depth -= 1; if depth == 0 { break; } }
                b';' if depth == 1 => saw_semi = true,
                b':' if depth == 1 => saw_colon = true,
                _ => {}
            }
            k += 1;
        }
        if saw_colon && !saw_semi { return true; }
    }
    false
}

fn word_present(src: &str, word: &str) -> bool {
    let bytes = src.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(off) = src[i..].find(word) {
        let start = i + off;
        let end = start + word.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        i = start + 1;
    }
    false
}
