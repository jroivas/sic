//! `sic --emit-crate DIR`: a Rust crate for a module, written to `DIR/rust`, the
//! other direction of `cargo sic` (doc/rust-crates.md). Everything comes from the
//! module's manifest, and the crate depends on nothing but the module's libraries.
//!
//! A function comes across when all its types do: integers, floats, `bool`, `string`,
//! `list` of those, and structs of those. Anything else is left out, with a comment
//! in the crate saying so.

use sic_frontend::ModuleManifest;
use sic_ir::{StructType, Type};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const RUNTIME: &str = include_str!("emit_crate_runtime.txt");
const LIST_RUNTIME: &str = include_str!("emit_crate_list.txt");

/// A SIC type as the crate sees it.
#[derive(Clone)]
enum Ty {
    Void,
    /// Passed as it is: the Rust spelling.
    Plain(String),
    Str,
    List(String),
    Struct(String),
    /// A parameter `S *p`: SIC may write through it.
    StructPtr(String),
}

/// `RunText` → `run_text`.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 && !out.ends_with('_') { out.push('_'); }
            out.push(c.to_ascii_lowercase());
        } else { out.push(c); }
    }
    ident(&out)
}

/// `point` → `Point`.
fn camel(name: &str) -> String {
    let mut c = name.chars();
    c.next().map_or(String::new(), |f| f.to_ascii_uppercase().to_string() + c.as_str())
}

fn ident(name: &str) -> String {
    const KEYWORDS: &[&str] = &["as", "async", "await", "box", "break", "const", "continue", "crate", "dyn",
        "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
        "move", "mut", "pub", "ref", "return", "static", "struct", "trait", "true", "type", "unsafe", "use",
        "where", "while"];
    if KEYWORDS.contains(&name) { format!("r#{}", name) } else { name.to_string() }
}

fn scalar(t: &Type) -> Option<String> {
    Some(match t {
        Type::Int { bits, signed } if matches!(bits, 8 | 16 | 32 | 64) =>
            format!("{}{}", if *signed { 'i' } else { 'u' }, bits),
        Type::Bool => "bool".to_string(),
        Type::Float32 => "f32".to_string(),
        Type::Float64 => "f64".to_string(),
        _ => return None,
    })
}

/// The element of a list type's marker name, `(list|string)`, when the crate has it.
fn list_elem(name: &str) -> Option<String> {
    let e = name.strip_prefix("(list|")?.strip_suffix(')')?;
    Some(match e {
        "string" => "SicString".to_string(),
        "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64" => e.to_string(),
        "int" => "i32".to_string(),
        _ => return None,
    })
}

fn map_type(t: &Type, m: &ModuleManifest) -> Option<Ty> {
    if matches!(t, Type::Void) { return Some(Ty::Void); }
    if let Some(s) = scalar(t) { return Some(Ty::Plain(s)); }
    match t {
        Type::Struct(st) if st.name.as_deref() == Some("__sic_string") => Some(Ty::Str),
        Type::Struct(st) => struct_of(st.name.as_deref()?, m).map(|n| Ty::Struct(n)),
        Type::Pointer(p) => match p.as_ref() {
            Type::Struct(st) => {
                let n = st.name.as_deref()?;
                list_elem(n).map(Ty::List).or_else(|| struct_of(n, m).map(Ty::StructPtr))
            }
            _ => None,
        },
        _ => None,
    }
}

/// `name`, if it is a struct whose fields all come across.
fn struct_of(name: &str, m: &ModuleManifest) -> Option<String> {
    let (_, Type::Struct(st)) = m.types.iter().find(|(n, _)| n == name)? else { return None };
    for (_, t) in &st.fields {
        match t {
            Type::Struct(s) if s.name.as_deref() == Some("__sic_string") => {}
            t if scalar(t).is_some() => {}
            _ => return None,
        }
    }
    Some(name.to_string())
}

/// How a parameter is written, in the Rust signature, and in the call.
fn param(name: &str, ty: &Ty, k: usize, setup: &mut String) -> (String, String, String) {
    let g = format!("A{}", k);
    match ty {
        Ty::Str => {
            let _ = writeln!(setup, "    let {name} = SicString::new({name});");
            (format!("{name}: impl AsRef<[u8]>"), "SicStr".to_string(), format!("{name}.raw()"))
        }
        Ty::List(e) => (format!("{name}: &SicList<{e}>"), "*mut c_void".to_string(), format!("{name}.raw()")),
        Ty::Struct(s) => {
            let c = camel(s);
            (format!("{name}: &{c}"), c, format!("std::ptr::read({name})"))
        }
        Ty::StructPtr(s) => {
            let c = camel(s);
            (format!("{name}: &mut {c}"), format!("*mut {c}"), format!("{name} as *mut {c}"))
        }
        Ty::Plain(p) => (format!("{name}: {p}"), p.clone(), name.to_string()),
        Ty::Void => { let _ = g; (String::new(), String::new(), String::new()) }
    }
}

fn gen_struct(out: &mut String, name: &str, st: &StructType, m: &ModuleManifest, size: u64) {
    let rust = camel(name);
    let n = st.fields.len();
    let order: Vec<usize> = match &st.layout_order { Some(p) if p.len() == n => p.clone(), _ => (0..n).collect() };
    let _ = writeln!(out, "\n/// `{name}`, with its fields in SIC's physical order.\n#[repr(C)]\npub struct {rust} {{");
    for &i in &order {
        let (fname, t) = &st.fields[i];
        let ty = scalar(t).unwrap_or_else(|| "SicStr".to_string());
        let _ = writeln!(out, "    pub {}: {},", ident(fname), ty);
    }
    let _ = writeln!(out, "    _not_send: PhantomData<*const ()>,\n}}");
    let _ = writeln!(out, "const _: () = assert!(std::mem::size_of::<{rust}>() == {size});");
    if let Some((_, dtor)) = m.struct_dtors.iter().find(|(s, _)| s == name) {
        let _ = writeln!(out, "impl Drop for {rust} {{\n    fn drop(&mut self) {{\n        extern \"C\" {{ fn {dtor}(p: *mut c_void); }}\n        unsafe {{ {dtor}(self as *mut {rust} as *mut c_void) }}\n    }}\n}}");
    }
}

/// The crate's `src/bindings.rs`.
pub fn generate(m: &ModuleManifest, ptr_size: u32) -> String {
    let mut fns = String::new();
    let mut structs = BTreeSet::new();
    let mut lists = false;
    let mut skipped = Vec::new();
    for e in &m.exports {
        let Type::Function(sig) = &e.ty else { continue };
        // Struct methods, destructors and the like: `__` in a name is the compiler's.
        if e.name.contains("__") { continue; }
        let tys: Option<Vec<Ty>> = sig.params.iter().map(|t| map_type(t, m)).collect();
        // A struct result is returned through a hidden first parameter in the IR.
        let (ret_t, tys) = match (&sig.ret, tys) {
            (r, Some(t)) => (map_type(r, m), t),
            _ => { skipped.push(e.name.clone()); continue; }
        };
        let Some(ret) = ret_t else { skipped.push(e.name.clone()); continue };
        if matches!(ret, Ty::StructPtr(_)) { skipped.push(e.name.clone()); continue; }
        let (mut sig_args, mut ffi_args, mut call_args, mut setup) = (Vec::new(), Vec::new(), Vec::new(), String::new());
        for (k, t) in tys.iter().enumerate() {
            let name = format!("a{}", k);
            let (a, f, c) = param(&name, t, k, &mut setup);
            sig_args.push(a);
            ffi_args.push(format!("{}: {}", name, f));
            call_args.push(c);
            if let Ty::Struct(s) | Ty::StructPtr(s) = t { structs.insert(s.clone()); }
            if let Ty::List(_) = t { lists = true; }
        }
        let (ffi_ret, rust_ret, wrap): (String, String, fn(&str) -> String) = match &ret {
            Ty::Void => (String::new(), String::new(), |c| format!("{};", c)),
            Ty::Plain(p) => (format!(" -> {}", p), format!(" -> {}", p), |c| c.to_string()),
            Ty::Str => (" -> SicStr".to_string(), " -> SicString".to_string(), |c| format!("SicString::from_raw({})", c)),
            Ty::List(el) => { lists = true; (" -> *mut c_void".to_string(), format!(" -> SicList<{}>", el), |c| format!("SicList::from_raw({})", c)) }
            Ty::Struct(s) => { structs.insert(s.clone()); (format!(" -> {}", camel(s)), format!(" -> {}", camel(s)), |c| c.to_string()) }
            Ty::StructPtr(_) => unreachable!(),
        };
        let call = wrap(&format!("{}({})", e.symbol, call_args.join(", ")));
        let _ = writeln!(fns, "\npub fn {}({}){} {{\n    extern \"C\" {{ fn {}({}){}; }}\n{}    unsafe {{ {} }}\n}}",
            snake(&e.name), sig_args.join(", "), rust_ret, e.symbol, ffi_args.join(", "), ffi_ret, setup, call);
    }
    let mut out = String::from(RUNTIME);
    if lists { out.push_str(LIST_RUNTIME); }
    for s in &structs {
        let Some((_, Type::Struct(st))) = m.types.iter().find(|(n, _)| n == s) else { continue };
        gen_struct(&mut out, s, st, m, Type::Struct(st.clone()).size_of(ptr_size));
    }
    out.push_str(&fns);
    if !skipped.is_empty() {
        let _ = writeln!(out, "\n// Left out, for types that do not come across: {}.", skipped.join(", "));
    }
    out
}

/// The crate's `build.rs`: the module's link line, as cargo directives. A library is
/// linked statically where a `.a` exists.
fn build_rs(m: &ModuleManifest) -> String {
    let (mut dirs, mut libs) = (Vec::new(), Vec::new());
    for l in m.links.iter().flat_map(|l| l.split_whitespace()) {
        if let Some(d) = l.strip_prefix("-L") { dirs.push(d.to_string()); }
        else if let Some(n) = l.strip_prefix("-l") { libs.push(n.to_string()); }
    }
    format!("fn main() {{\n    let dirs: &[&str] = &{:?};\n    let libs: &[&str] = &{:?};\n    for d in dirs {{ println!(\"cargo:rustc-link-search=native={{}}\", d); }}\n    for l in libs {{\n        let a = format!(\"lib{{}}.a\", l);\n        if dirs.iter().any(|d| std::path::Path::new(d).join(&a).exists()) {{\n            println!(\"cargo:rustc-link-lib=static={{}}\", l);\n            for d in dirs {{\n                let p = std::path::Path::new(d).join(&a);\n                if p.exists() {{ println!(\"cargo:rerun-if-changed={{}}\", p.display()); }}\n            }}\n        }} else {{\n            println!(\"cargo:rustc-link-lib={{}}\", l);\n        }}\n    }}\n}}\n", dirs, libs)
}

/// Write the crate of the module built in `dir`.
pub fn emit(dir: &str, ptr_size: u32) -> Result<(), Box<dyn std::error::Error>> {
    let smod = fs::read_dir(dir)?.filter_map(|e| e.ok()).map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "smod"))
        .ok_or_else(|| format!("--emit-crate: no module manifest in '{}'", dir))?;
    let m = ModuleManifest::parse(&fs::read_to_string(&smod)?, ptr_size)
        .map_err(|e| format!("--emit-crate: {}: {}", smod.display(), e))?;
    let root = Path::new(dir).join("rust");
    fs::create_dir_all(root.join("src"))?;
    fs::write(root.join("Cargo.toml"), format!(
        "# Generated by `sic --emit-crate`.\n[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n",
        m.module))?;
    fs::write(root.join("build.rs"), build_rs(&m))?;
    fs::write(root.join("src/bindings.rs"), generate(&m, ptr_size))?;
    fs::write(root.join("src/lib.rs"), format!(
        "//! Rust bindings of the SIC module `{}`, generated by `sic --emit-crate`: do not edit.\n//!\n//! Nothing here is `Send`: SIC's reference counts are not atomic.\n#![allow(dead_code, unused_imports, clippy::all)]\n\ninclude!(\"bindings.rs\");\n",
        m.module))?;
    Ok(())
}
