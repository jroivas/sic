# Rust crates

A Rust crate can be used from SIC as an ordinary [module](modules.md). `cargo sic`
fetches it with cargo, reads its public API, generates the bindings in both
directions and builds them; SIC code then just `import`s it.

This needs a Rust toolchain (`cargo`; `$CARGO` overrides it).

## `cargo sic`

`cargo-sic` is built next to `sic` (`siccomp/target/<profile>/cargo-sic`). With it
on your `PATH` it is a cargo subcommand:

```sh
cargo sic add semver                     # newest version from crates.io
cargo sic add hashbrown@0.17
cargo sic add --path ../mylib            # a local crate
sic app.sic -o app                       # no -I: sic finds the bindings
```

```sic
import semver;
import hashbrown;

int main() {
    semver::Version v = semver::Version::parse("1.4.2") else return 1;
    semver::VersionReq r = semver::VersionReq::parse(">=1.2, <2") else return 2;
    hashbrown::HashMap<string, i64> m = hashbrown::HashMap::new();
    m.insert("apple", 3);
    i64 n = m.get("apple") else return 3;
    return r.matches(v) && v.major() == 1 && n == 3 ? 0 : 4;
}
```

| command | does |
|---|---|
| `cargo sic add <crate>[@<ver>]` | record it (see [The project](#the-project)), generate its binding, build it. `@1.2.3` is that exact version (`=1.2.3`); `@^1.2` etc. a requirement; none, the newest. Options: `--features a,b`, `--no-default-features`, `--module NAME`, `--instance NAME=TYPE`, `--path DIR` |
| `cargo sic build [<crate>…]` | regenerate and build the bindings (after cloning a project, or editing one) |
| `cargo sic update [<crate>…]` | `cargo update` the locked versions, then build |
| `cargo sic remove <crate>` | drop it from `sic.toml` (if listed) and `sic-deps/` (an edited `lib.rs` is kept aside) |
| `cargo sic show <crate>` | print the SIC interface: everything you can call |
| `cargo sic list` | the crates and their modules |

`--global` uses `~/.sic-deps` instead of the project, so every program on the
machine can import those crates (a `~/.sic-deps/sic.toml` is optional, as below). `--offline` passes through to cargo; `-v` shows
the commands run.

### The project

The project is the nearest directory at or above the current one holding a
`sic-deps/` or a `sic.toml` (`add` starts one in the current directory). No
`sic.toml` is needed: each binding's own `sic-deps/<crate>/Cargo.toml` records the
crate — `add` writes it, and you change the version or features there, then run
`cargo sic build`:

```toml
# sic-deps/hashbrown/Cargo.toml
[package.metadata.sic]
module = "hashbrown"

[dependencies]
"hashbrown" = { version = "=0.17.1" }
```

Optionally a `sic.toml` lists the crates in one place, in Cargo's `[dependencies]`
syntax; an entry there wins over a binding's own record:

```toml
[dependencies]
semver = "1.0.28"
hashbrown = { version = "0.17.1", instantiate = [         # optional: see Generics
    { type = "HashMap<String, i64>", as = "StrIntMap" },
] }
mylib = { path = "../mylib", module = "mine" }       # `module` renames the SIC module
```

The bindings build in `sic-deps/`: one cargo workspace (a shared `Cargo.lock` and
`target/`), with a binding crate per dependency:

```
sic-deps/
  Cargo.toml  Cargo.lock  .gitignore  target/
  semver/
    src/generated.rs     # wrappers over the crate's API — regenerated every build
    src/lib.rs           # yours to edit: hand-written wrappers, kept across builds
    module_semver.smod   libsemver.{a,so}
```

`sic` searches `sic-deps/*` of the project, then `~/.sic-deps/*`, before `-I`, so
`import semver;` needs no flags. Commit `sic-deps/Cargo.lock`, `sic-deps/*/Cargo.toml`,
`sic-deps/*/instances`, any edited `sic-deps/*/src/lib.rs` (and `sic.toml` if you
use one); the generated `.gitignore` covers the rest.

### What is generated

`cargo sic` reads the crate's public API from rustdoc's JSON output (run with
`RUSTC_BOOTSTRAP=1` on a stable toolchain) and writes a plain-Rust wrapper for each
item whose signature it can map. The wrappers then go through the binding crate
mechanism below:

- the crate's module tree, as SIC namespaces, with Rust's own names:
  `demo::text::words(…)`, `hashbrown::hash_map::HashMap`, `semver::Version::parse(…)`.
  A re-export (`pub use`) is the same item under its other path too
  (`hashbrown::HashMap`, `base64::prelude::BASE64_STANDARD`);
- functions and constants: a literal constant is a SIC constant (`demo::LIMIT`); a
  computed one (`base64::engine::general_purpose::STANDARD`, an engine value) is a
  module global set when the library loads, so `STANDARD.encode(data)` reads as in
  Rust;
- types (non-generic structs and enums), with their inherent methods, the methods
  of the crate's own traits (provided methods too), and:
  - for public fields, a getter (`v.major()`) and, for scalars and strings, a
    setter (`v.set_major(2)`);
  - for enums, a constructor per payload-less variant (`demo::Color::Green()`)
    and `variant_name()`;
  - from `Display`, `to_string()`; `Clone` → `clone()`; `PartialEq` → `eq()`;
    `Ord` → `cmp()` (-1/0/1); `Default` → `default()`, and `new()` when the
    type has none (so `T x;` constructs it);
- generic types, at the type arguments a program uses (see [Generics](#generics)):
  the impls that apply to each instance, with the lookup-key generics resolved
  (`get(&self, k: &Q)` takes a `string`);
- generic parameters bounded by a conversion: `T: AsRef<str>` / `impl AsRef<[u8]>`
  / `Into<String>` take a `string`;
- a `Result` error becomes its `Display` text (else its `Debug` text);
- results that borrow are copied out: `&str` → `string`, `Option<&V>` →
  `Option<V>`; an iterator becomes a `list` of its items (`m.keys()`);
- a method that consumes `self`, or takes a type by value, clones it when the
  type is `Clone` (a builder `with_label(self, …) -> Self` returns a new value);
  one returning `&mut Self` (a builder chain) returns nothing.

Names are never changed: a Rust name that is a SIC keyword (`default`, `union`,
`new`, `match`) is still reachable, because a member is always written after
`::` or `.` (`hashbrown::HashMap::default()`, `a.union(b)`).

Everything else — other generics, `unsafe`/`async` functions, `&mut` results,
iterators of tuples, deprecated items — is listed with the reason at the end of
`generated.rs`. Wrap those by hand in `lib.rs`: it is plain Rust, and the
generated types live in the same crate, so you can add methods to them:

```rust
// sic-deps/hashbrown/src/lib.rs
mod generated;
pub use generated::*;

impl HashMap__String__i64 {        // the instance HashMap<String, i64>
    /// The entries, sorted by key.
    pub fn sorted_keys(&self) -> Vec<String> {
        let mut k: Vec<String> = self.0.keys().cloned().collect();
        k.sort();
        k
    }
}
```

### Generics

A Rust generic type is used with its type arguments, as in Rust. They come from
the declared type, or are written in the call:

```sic
hashbrown::HashMap<i64, string> m = hashbrown::HashMap::new();   // from the type
auto s = hashbrown::HashSet<string>::new();                       // in the call
usize count(hashbrown::HashSet<string> s) { return s.len(); }     // as a parameter
hashbrown::HashSet<u8char> none() { return hashbrown::HashSet::new(); }   // the return type
```

A type argument is a scalar (`i64`, `f64`, `bool`, …), `string` (Rust `String`),
`u8char` (`char`), or a type of the same crate. Each combination is an
**instance** compiled from Rust: when a program uses one its binding does not have
yet, sic records it in `sic-deps/<crate>/instances`, runs `cargo sic build` for
that crate, and compiles on — so only the first use is slow (commit the
`instances` file to keep the list). Listing an instance there (or in `sic.toml`'s
`instantiate`) pre-builds it; `HashMap<String, i64> as StrIntMap` also gives it an
extra name at the crate root (`hashbrown::StrIntMap`).

Without the arguments in either place there is nothing to instantiate:

```text
error: `hashbrown::HashMap::new`: the type arguments of the generic `hashbrown::HashMap`
(2–4 of them) are not known here — give them in the type (`hashbrown::HashMap<…> x =
hashbrown::HashMap::new(…);`) or the call (`hashbrown::HashMap<…>::new(…)`)
```

Defaulted parameters take their defaults (`HashMap<K, V>` is `HashMap<K, V,
DefaultHashBuilder>`). Trait bounds are checked by rustc when the instance builds
(`HashMap<f64, …>` fails there: `f64` is not `Hash`).

The repository's test of all this is `module_test/14-cargo-sic` (a local,
dependency-free crate; the repository itself holds no third-party crates).

## A binding crate

`cargo sic` drives a lower-level mechanism you can also use directly:
`sic --emit-module DIR` on a folder holding a `Cargo.toml` builds that crate as a
module, binding what the root of its `src/lib.rs` declares (and what it
re-exports with `pub use m::*` from a file module, as the generated binding does).
The repository's example is the dependency-free test crate
`module_test/13-rust-crate/mod-rsdemo`:

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
    rsdemo::Counter d = rsdemo::Counter::named("d");
    std::Println("{}", rsdemo::greet("sic"));        // hello, sic
    list<string> w = rsdemo::words("one two three");
    i64 n = rsdemo::parse_int(" 123 ") else return 1;
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

- every `pub fn` → a module function under its Rust name (`rsdemo::greet`,
  `rsdemo::parse_int`); an inline `pub mod m { … }` → the namespace `rsdemo::m`;
  `pub use` → the same item at that path; a literal `pub const` → a SIC constant;
- every `pub struct` / `pub enum` (non-generic) → a SIC type of the same name;
- the `pub fn`s of its inherent `impl`:
  - methods (`&self` / `&mut self`) keep their Rust names: `c.add(5)`;
  - associated functions go in a namespace named after the type:
    `Counter::named("d")` → `rsdemo::Counter::named("d")`;
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
i64 n = rsdemo::parse_int(text) else return 1;          // unwrap or bail out
match (rsdemo::parse_int("x")) {
    Ok(v):  use(v);
    Err(e): std::Println("{}", e);                     // invalid digit found in string
}
rsdemo::Counter q = d.split(4) else return 2;          // Option<Counter>
```

## Rust objects in SIC

A bound type is a small SIC struct holding a refcounted handle to the Rust value:

```sic
rsdemo::Counter a = rsdemo::Counter::named("a");   // a Rust value, owned by SIC
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
3. compiles the SIC interface like any module: `lib<name>.so` holds the SIC code
   and the Rust code (linked with `--strip-debug` unless `-g`: Rust's standard
   library ships with full debug info); `lib<name>.a` holds the SIC code and
   `lib<name>_rs.a` the Rust code, both linked by a `-static` consumer (pass
   `-Wl,--strip-debug` there for a small binary).

The C boundary between the two halves uses only scalars and pointers: a `string`
crosses as a pointer to its descriptor (results through an out-pointer), a
`u8char` as its `u32` code point, a Rust object as an opaque pointer — no struct is
passed or returned by value, so it does not depend on how a target's C ABI passes
aggregates.

The manifest records the system libraries Rust's standard library needs, so a
consumer passes only `-I<dir>`, dynamic or `-static`. Several Rust modules can be
linked into one program.

Next: [the standard library](standard-library.md).
