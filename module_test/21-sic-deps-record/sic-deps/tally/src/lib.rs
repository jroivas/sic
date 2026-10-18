//! The SIC binding of `tally` — edit freely. `cargo sic build` regenerates
//! `generated.rs` (wrappers over the crate's public API) but never this file.
//! Add hand-written wrappers here: plain Rust with SIC-friendly types
//! (doc/rust-crates.md); they are bound like the generated ones.

mod generated;
pub use generated::*;
