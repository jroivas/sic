//! Links in each part sic/build.sh built, and sets `cfg(sic_<part>)` for it. A part
//! is a SIC folder module `sic/<part>/` built with `--emit-crate`: the library
//! `sic/<part>/lib<part>.a` and its bindings `sic/<part>/rust/src/bindings.rs`,
//! included as `SIC_<PART>_BINDINGS`. A part that is not built is left out, and
//! its Rust stage runs. (The sicpp module and libstd come in through the sic crate.)

use std::path::Path;

/// The parts there are, as sic/<name>/ folders; parts.rs lists the stages they give.
const PARTS: &[&str] = &[];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let sic_dir = Path::new(&manifest).join("..");
    for part in PARTS {
        println!("cargo:rustc-check-cfg=cfg(sic_{})", part);
        let dir = sic_dir.join(part);
        let lib = dir.join(format!("lib{}.a", part));
        let bindings = dir.join("rust/src/bindings.rs");
        for f in [&lib, &bindings] { println!("cargo:rerun-if-changed={}", f.display()); }
        if !lib.exists() || !bindings.exists() { continue; }
        println!("cargo:rustc-cfg=sic_{}", part);
        println!("cargo:rustc-env=SIC_{}_BINDINGS={}", part.to_uppercase(), bindings.canonicalize().unwrap().display());
        println!("cargo:rustc-link-search=native={}", dir.display());
        println!("cargo:rustc-link-lib=static={}", part);
    }
}
