# Differences from siccomp

Where a part written in SIC behaves differently from the Rust part it
replaces, on purpose. `sic/tests/diff-*.sh` compares the two; a difference that
shows there must be listed here.

## Lexer

- **Identifiers outside ASCII.** The SIC lexer takes the characters C11 allows
  in identifiers (Annex D.1, and not those of D.2 at the start), as GCC and
  Clang do. The Rust lexer took Rust's `char::is_alphabetic` and
  `is_alphanumeric`. For example, `a·b` (U+00B7) is one identifier now, where
  it was `a`, an unknown token and `b`, and an emoji letter like U+1F600 may be
  part of a name. Letters (`é`, `λ`, `漢`) are the same in both.
