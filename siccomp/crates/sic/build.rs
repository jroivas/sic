//! Builds the `sicpp` module into sic, when it is there: sic then preprocesses in
//! process. It is built by sic itself, so the first build has none and is built
//! without (build.sh builds sic again afterwards). `SIC_NO_BUILTIN_CPP=1` leaves it
//! out in any case: sic then runs `sic-cpp`, or `cpp`.

use std::path::Path;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(builtin_cpp)");
    println!("cargo:rerun-if-env-changed=SIC_NO_BUILTIN_CPP");
    // The back ends' order (build.sh's `--backend`): the first is the default.
    println!("cargo:rerun-if-env-changed=SIC_BACKEND_ORDER");
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest).join("../../..");
    let lib_dir = root.join("sic-cpp/lib");
    let std_dir = root.join("siccomp/target/lib/sic");
    let sicpp = lib_dir.join("libsicpp.a");
    let libstd = std_dir.join("libstd.a");
    let bindings = lib_dir.join("rust/src/bindings.rs");
    for f in [&sicpp, &libstd, &bindings] { println!("cargo:rerun-if-changed={}", f.display()); }
    if std::env::var_os("SIC_NO_BUILTIN_CPP").is_some_and(|v| !v.is_empty()) { return; }
    if !sicpp.exists() || !libstd.exists() || !bindings.exists() { return; }
    println!("cargo:rustc-cfg=builtin_cpp");
    println!("cargo:rustc-env=SICPP_BINDINGS={}", bindings.canonicalize().unwrap().display());
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-search=native={}", std_dir.display());
    println!("cargo:rustc-link-lib=static=sicpp");
    println!("cargo:rustc-link-lib=static=std");
    println!("cargo:rustc-link-lib=m");
}
