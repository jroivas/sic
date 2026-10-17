# Rust crates

A Rust library can be used from SIC as an ordinary [module](modules.md). You write
a small **binding crate** whose root lists the API in plain Rust;
`sic --emit-module` reads it, generates the glue in both directions, builds
everything with cargo, and produces the usual `lib<name>.a` / `lib<name>.so` /
`module_<name>.smod`. SIC code then just `import`s it.

This needs a Rust toolchain (`cargo`; `$CARGO` overrides it).

## A binding crate

A folder holding a `Cargo.toml` is a Rust module. The repository's example is the
dependency-free test crate `module_test/13-rust-crate/mod-rsdemo`:

```toml
# mod-rsdemo/Cargo.toml
[package]
name = "rsdemo"
version = "0.1.0"
edition = "2021"
```

```rust
// mod-rsdemo/src/lib.rs
/// A named counter (an opaque handle type in sic).
pub struct Counter { n: i64, name: String }

impl Counter {
    pub fn new() -> Counter { Counter { n: 0, name: String::from("anon") } }
    pub fn named(name: &str) -> Self { Counter { n: 0, name: name.to_string() } }
    pub fn add(&mut self, k: i64) -> i64 { self.n += k; self.n }
    pub fn name(&self) -> &str { &self.name }
}

pub fn greet(name: &str) -> String { format!("hello, {}", name) }
pub fn words(s: &str) -> Vec<String> { s.split_whitespace().map(String::from).collect() }
pub fn parse_int(s: &str) -> Result<i64, std::num::ParseIntError> { s.trim().parse() }
```

```sh
sic --emit-module mod-rsdemo
sic main.sic -Imod-rsdemo -o main         # -static works too
```

```sic
import std;
import rsdemo;

int main() {
    rsdemo::Counter c;                               // Counter::new() as constructor
    c.add(5);
    rsdemo::Counter d = rsdemo::Counter::Named("d");
    std::Println("{}", rsdemo::Greet("sic"));        // hello, sic
    list<string> w = rsdemo::Words("one two three");
    i64 n = rsdemo::ParseInt(" 123 ") else return 1;
    return w.length == 3 && n == 123 ? 0 : 2;
}
```

### Wrapping a crates.io crate

In your own project, the binding crate can depend on any crate and turn its
generic, trait-based API into concrete functions SIC can call (for example
`pub fn encode(data: &[u8]) -> String { STANDARD.encode(data) }` over the `base64`
crate). cargo fetches the dependencies on the first build. A binding crate cannot
share its dependency's name, so name the SIC module explicitly:

```toml
[package.metadata.sic]
module = "base64"          # the SIC module name (default: the crate's name)
```

## What gets bound

sic reads the root of `src/lib.rs` and binds:

- every `pub fn` → a module function, renamed to SIC's CamelCase (`greet` →
  `rsdemo::Greet`, `parse_int` → `rsdemo::ParseInt`);
- every `pub struct` / `pub enum` (non-generic) → a SIC type of the same name;
- the `pub fn`s of its inherent `impl`:
  - methods (`&self` / `&mut self`) keep their Rust names: `c.add(5)`;
  - associated functions go in a namespace named after the type:
    `Counter::named("d")` → `rsdemo::Counter::Named("d")`;
  - an argument-less `new()` is also the type's **constructor**, so a plain
    declaration `rsdemo::Counter c;` holds a ready object (an initializer skips it).

Doc comments (`///`) are carried over. Anything sic cannot map — generic functions,
trait impls, `impl Trait`, closures, methods that take `self` by value — is skipped
with a warning naming the item and the reason:

```text
sic: warning: Rust module 'rsdemo': skipping fn `ident`: a generic fn (write a concrete wrapper)
```

## Type mapping

| Rust | SIC |
|------|-----|
| `i8`…`i64`, `u8`…`u64`, `isize`, `usize`, `f32`, `f64`, `bool` | the same |
| `char` | `u8char` |
| `&str`, `String`, `&String` | `string` |
| `&[u8]`, `Vec<u8>`, `&Vec<u8>` | `string` (a byte string) |
| `Vec<T>`, `&[T]`, `&Vec<T>` (T a scalar or `String`), `Vec<&str>` returned | `list<T>` |
| `&mut [T]` | `list<T>`, written back after the call |
| a bound type `S`, `&S`, `&mut S` | `S` |
| `Option<T>` (returned) | `Option<T>` |
| `Result<T, E>` (returned) | `Result<T, string>`, the error text from `E`'s `Display` |
| `Result<(), E>` (returned) | `Result<bool, string>` (`Ok(true)`) |

Values are converted at the boundary. A `string` argument becomes a `&str` (bytes
that are not valid UTF-8 are replaced with U+FFFD), and a returned `String` becomes
an owned SIC `string`. Lists and byte strings are copied too. Returned values are
owned by SIC and released like any other.

`Option` and `Result` come back as SIC's built-in enums, so the usual forms apply:

```sic
i64 n = rsdemo::ParseInt(text) else return 1;          // unwrap or bail out
match (rsdemo::ParseInt("x")) {
    Ok(v):  use(v);
    Err(e): std::Println("{}", e);                     // invalid digit found in string
}
rsdemo::Counter q = d.split(4) else return 2;          // Option<Counter>
```

## Rust objects in SIC

A bound type is a small SIC struct holding a refcounted handle to the Rust value:

```sic
rsdemo::Counter a = rsdemo::Counter::Named("a");   // a Rust value, owned by SIC
rsdemo::Counter b = a;                 // copies share the same object
a.add(3);                              // b.get() is 3 too
// the last copy's scope exit drops the Rust value
```

The Rust value is dropped (its `Drop` runs) when the last SIC copy goes out of
scope. A parameter of type `&S` or `&mut S` takes the SIC value directly
(`d.merge(c)`, `rsdemo::Total(c, 1)`). A value that was declared but never
constructed (a type without `new()`) is empty, and using it is reported as a
panic.

## Panics

The glue is built with `panic = "abort"`, so a Rust panic never unwinds into SIC
code. It prints Rust's message and aborts the program, like a failed `assert`:

```text
thread '<unnamed>' panicked at mod-x/src/lib.rs:12:5:
index out of bounds: the len is 3 but the index is 7
```

## How it is built

`sic --emit-module DIR` on a crate:

1. reads `src/lib.rs` (with the `syn` parser) and writes, under `DIR/target/sic-glue/`,
   a glue crate (`lib.rs`: the `extern "C"` functions that convert values and call
   the crate) and the SIC interface (`<module>.sic`: the module SIC code sees,
   written in SIC over the glue) — read it to see exactly what was bound;
2. builds the glue with `cargo` as a static library (`DIR/target`, so rebuilds are
   incremental);
3. compiles the SIC interface like any module, and links the Rust code into
   `lib<name>.so` and `lib<name>.a`. Rust's own debug info is stripped unless you
   pass `-g`.

The manifest records the system libraries Rust's standard library needs, so a
consumer passes only `-I<dir>`, dynamic or `-static`. Several Rust modules can be
linked into one program.

Next: [the standard library](standard-library.md).
