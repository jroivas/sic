//! Rust crates as sic modules (`sic --emit-module DIR` on a folder holding a
//! `Cargo.toml`).
//!
//! The folder is an ordinary Cargo library crate — usually a thin binding crate
//! that depends on a crates.io crate and exposes the API to bind in plain Rust:
//!
//! ```rust
//! // b64/src/lib.rs   (b64/Cargo.toml: [dependencies] base64 = "0.22")
//! use base64::Engine;
//! pub fn encode(data: &[u8]) -> String { base64::engine::general_purpose::STANDARD.encode(data) }
//! ```
//!
//! sic reads the root of `src/lib.rs` (with `syn`), and for every `pub fn`,
//! `pub struct` and inherent `impl` it can map, generates
//!
//! 1. a **glue crate** (`target/sic-glue/`): `extern "C"` functions that convert
//!    sic values to Rust ones, call the crate, and convert back; built with cargo
//!    as a static library (`panic = "abort"`, so a Rust panic never unwinds into
//!    sic code), and
//! 2. a **sic wrapper module** (`target/sic-glue/<name>.sic`): the sic-native
//!    API — `string`, `list<T>`, `Option`/`Result`, structs with methods and a
//!    destructor — over those glue functions,
//!
//! and the caller compiles the wrapper into an ordinary module whose archive and
//! shared library also carry the Rust code. A consumer just `import`s it.
//!
//! Type mapping (Rust → sic):
//!
//! | Rust | sic |
//! |------|-----|
//! | `i8`…`i64`, `u8`…`u64`, `isize`, `usize`, `f32`, `f64`, `bool` | same |
//! | `char` | `u8char` |
//! | `&str`, `String`, `&String` | `string` |
//! | `&[u8]`, `Vec<u8>`, `&Vec<u8>` | `string` (a byte string) |
//! | `Vec<T>`, `&[T]`, `&Vec<T>`, `&mut [T]` (T scalar or `String`) | `list<T>` |
//! | `pub struct S` (+ `impl S`) | `S`: a shared, refcounted handle |
//! | `Option<T>` (return) | `Option<T>` |
//! | `Result<T, E>` (return; `E: Display`) | `Result<T, string>` (`()` → `bool`) |
//!
//! Free functions become CamelCase (`encode` → `b64::Encode`), associated
//! functions live in a namespace named after the struct (`Rng::new` →
//! `rnd::Rng::New`), and methods keep their Rust names (`g.range(1, 7)`).
//! Anything else (generics, traits, closures, `impl Trait`, by-value `self`) is
//! skipped with a warning.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

use quote::ToTokens;

/// What `prepare` produced for the module build.
pub struct RustBuild {
    /// The generated sic wrapper source.
    pub sic_source: PathBuf,
    /// The glue crate's static library (Rust std + crate + glue).
    pub archive: PathBuf,
    /// The system libraries the Rust code needs (`-lgcc_s -lpthread …`).
    pub native_libs: Vec<String>,
}

/// A folder is a Rust module when it holds a Cargo manifest.
pub fn is_rust_module(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file()
}

// ── The binding model ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum Prim { I8, I16, I32, I64, U8, U16, U32, U64, Isize, Usize, F32, F64, Bool, Char }

impl Prim {
    fn from_ident(s: &str) -> Option<Prim> {
        Some(match s {
            "i8" => Prim::I8, "i16" => Prim::I16, "i32" => Prim::I32, "i64" => Prim::I64,
            "u8" => Prim::U8, "u16" => Prim::U16, "u32" => Prim::U32, "u64" => Prim::U64,
            "isize" => Prim::Isize, "usize" => Prim::Usize,
            "f32" => Prim::F32, "f64" => Prim::F64, "bool" => Prim::Bool, "char" => Prim::Char,
            _ => return None,
        })
    }
    /// The Rust type itself.
    fn rust(self) -> &'static str {
        match self {
            Prim::I8 => "i8", Prim::I16 => "i16", Prim::I32 => "i32", Prim::I64 => "i64",
            Prim::U8 => "u8", Prim::U16 => "u16", Prim::U32 => "u32", Prim::U64 => "u64",
            Prim::Isize => "isize", Prim::Usize => "usize",
            Prim::F32 => "f32", Prim::F64 => "f64", Prim::Bool => "bool", Prim::Char => "char",
        }
    }
    /// The type crossing the C boundary (`char` travels as its code point).
    fn ffi(self) -> &'static str {
        if self == Prim::Char { "u32" } else { self.rust() }
    }
    fn sic(self) -> &'static str {
        if self == Prim::Char { "u8char" } else { self.rust() }
    }
    /// Short tag for helper names (`vec_i64_push`).
    fn tag(self) -> &'static str { self.rust() }
}

/// A list element.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Elem { Prim(Prim), Str }

impl Elem {
    fn rust(self) -> &'static str {
        match self { Elem::Prim(p) => p.rust(), Elem::Str => "String" }
    }
    fn ffi(self) -> &'static str {
        match self { Elem::Prim(p) => p.ffi(), Elem::Str => "SicStr" }
    }
    fn sic(self) -> &'static str {
        match self { Elem::Prim(p) => p.sic(), Elem::Str => "string" }
    }
    fn tag(self) -> &'static str {
        match self { Elem::Prim(p) => p.tag(), Elem::Str => "str" }
    }
}

/// How a parameter's Rust type receives the converted value.
#[derive(Clone, Copy, Debug, PartialEq)]
enum How { Owned, Ref, RefMut, /// `&String` / `&Vec<T>` (a reference to the owned type)
    RefOwned }

#[derive(Clone, Debug, PartialEq)]
enum Ty {
    Unit,
    Prim(Prim),
    Str(How),
    Bytes(How),
    List(Elem, How),
    Obj(String, How),
    Option(Box<Ty>),
    /// `Result<T, E>`; the flag is `E == ()` (no `Display` to call).
    Result(Box<Ty>, bool),
}

struct Param { name: String, ty: Ty }

#[derive(PartialEq, Clone, Copy)]
enum Recv { None, Ref, RefMut }

struct Func {
    /// Rust name.
    name: String,
    doc: Vec<String>,
    recv: Recv,
    params: Vec<Param>,
    ret: Ty,
}

struct Struct {
    name: String,
    doc: Vec<String>,
    methods: Vec<Func>,
}

struct Binding {
    module: String,
    /// The crate's Rust identifier (`use <ident> as __c`).
    crate_ident: String,
    package: String,
    structs: Vec<Struct>,
    funcs: Vec<Func>,
    skipped: Vec<String>,
}

// ── Reading the crate ─────────────────────────────────────────────────────────

/// `[package] name`, `[lib] name` and `[package.metadata.sic] module` from a
/// Cargo.toml (a minimal reader: those keys are all sic needs).
fn cargo_names(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut section = String::new();
    let (mut pkg, mut lib, mut module) = (None, None, None);
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            section = l.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let v = v.trim();
        let v = v.split('#').next().unwrap_or("").trim().trim_matches('"').trim_matches('\'').to_string();
        match (section.as_str(), k.trim()) {
            ("package", "name") => pkg = Some(v),
            ("lib", "name") => lib = Some(v),
            ("package.metadata.sic", "module") => module = Some(v),
            _ => {}
        }
    }
    (pkg, lib, module)
}

fn doc_lines(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = Vec::new();
    for a in attrs {
        if !a.path().is_ident("doc") { continue; }
        if let syn::Meta::NameValue(nv) = &a.meta {
            if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) = &nv.value {
                for l in s.value().lines() { out.push(l.strip_prefix(' ').unwrap_or(l).to_string()); }
            }
        }
    }
    out
}

fn spell(t: &syn::Type) -> String {
    t.to_token_stream().to_string()
}

/// The single generic type argument of a path segment (`Vec<T>` → `T`).
fn generic_args(seg: &syn::PathSegment) -> Vec<&syn::Type> {
    match &seg.arguments {
        syn::PathArguments::AngleBracketed(a) => a.args.iter().filter_map(|g| match g {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        }).collect(),
        _ => Vec::new(),
    }
}

/// A list element type (`String` or a scalar).
fn elem_of(t: &syn::Type) -> Option<Elem> {
    if let syn::Type::Path(p) = t {
        if p.qself.is_some() { return None; }
        let seg = p.path.segments.last()?;
        let id = seg.ident.to_string();
        if id == "String" { return Some(Elem::Str); }
        return Prim::from_ident(&id).map(Elem::Prim);
    }
    None
}

/// Map a Rust type to the binding model. `self_ty` names the struct whose
/// `impl` is being read (`Self`); `structs` are the crate's public structs.
fn map_type(t: &syn::Type, self_ty: Option<&str>, structs: &[String]) -> Result<Ty, String> {
    let bad = || Err(format!("unsupported type `{}`", spell(t)));
    match t {
        syn::Type::Tuple(tt) if tt.elems.is_empty() => Ok(Ty::Unit),
        syn::Type::Paren(p) => map_type(&p.elem, self_ty, structs),
        syn::Type::Reference(r) => {
            let m = r.mutability.is_some();
            match &*r.elem {
                syn::Type::Slice(s) => {
                    if let Some(Elem::Prim(Prim::U8)) = elem_of(&s.elem) {
                        return if m { bad() } else { Ok(Ty::Bytes(How::Ref)) };
                    }
                    match elem_of(&s.elem) {
                        Some(e) => Ok(Ty::List(e, if m { How::RefMut } else { How::Ref })),
                        None => bad(),
                    }
                }
                syn::Type::Path(p) if p.qself.is_none() => {
                    let Some(seg) = p.path.segments.last() else { return bad() };
                    let id = seg.ident.to_string();
                    match id.as_str() {
                        "str" if !m => Ok(Ty::Str(How::Ref)),
                        "String" if !m => Ok(Ty::Str(How::RefOwned)),
                        "Vec" if !m => {
                            let a = generic_args(seg);
                            if a.len() != 1 { return bad(); }
                            match elem_of(a[0]) {
                                Some(Elem::Prim(Prim::U8)) => Ok(Ty::Bytes(How::RefOwned)),
                                Some(e) => Ok(Ty::List(e, How::RefOwned)),
                                None => bad(),
                            }
                        }
                        "Self" if self_ty.is_some() => Ok(Ty::Obj(self_ty.unwrap().to_string(), if m { How::RefMut } else { How::Ref })),
                        _ if structs.iter().any(|s| *s == id) && p.path.segments.len() == 1 =>
                            Ok(Ty::Obj(id, if m { How::RefMut } else { How::Ref })),
                        _ => bad(),
                    }
                }
                _ => bad(),
            }
        }
        syn::Type::Path(p) if p.qself.is_none() => {
            let Some(seg) = p.path.segments.last() else { return bad() };
            let id = seg.ident.to_string();
            if let Some(pr) = Prim::from_ident(&id) {
                return if seg.arguments.is_empty() { Ok(Ty::Prim(pr)) } else { bad() };
            }
            match id.as_str() {
                "String" => Ok(Ty::Str(How::Owned)),
                "Vec" => {
                    let a = generic_args(seg);
                    if a.len() != 1 { return bad(); }
                    // `Vec<&str>` is accepted as a return (each element is copied).
                    if let syn::Type::Reference(r) = a[0] {
                        if r.mutability.is_none() && spell(&r.elem) == "str" {
                            return Ok(Ty::List(Elem::Str, How::Ref));
                        }
                    }
                    match elem_of(a[0]) {
                        Some(Elem::Prim(Prim::U8)) => Ok(Ty::Bytes(How::Owned)),
                        Some(e) => Ok(Ty::List(e, How::Owned)),
                        None => bad(),
                    }
                }
                "Option" => {
                    let a = generic_args(seg);
                    if a.len() != 1 { return bad(); }
                    Ok(Ty::Option(Box::new(map_type(a[0], self_ty, structs)?)))
                }
                "Result" => {
                    let a = generic_args(seg);
                    if a.len() != 2 { return bad(); }
                    let unit_err = matches!(a[1], syn::Type::Tuple(tt) if tt.elems.is_empty());
                    Ok(Ty::Result(Box::new(map_type(a[0], self_ty, structs)?), unit_err))
                }
                "Self" if self_ty.is_some() => Ok(Ty::Obj(self_ty.unwrap().to_string(), How::Owned)),
                _ if structs.iter().any(|s| *s == id) && p.path.segments.len() == 1 && seg.arguments.is_empty() =>
                    Ok(Ty::Obj(id, How::Owned)),
                _ => bad(),
            }
        }
        _ => bad(),
    }
}

fn param_ok(t: &Ty) -> Result<(), String> {
    match t {
        Ty::Prim(_) | Ty::Str(_) | Ty::Bytes(_) => Ok(()),
        Ty::List(_, How::Ref) | Ty::List(_, How::RefMut) | Ty::List(_, How::RefOwned) | Ty::List(_, How::Owned) => Ok(()),
        Ty::Obj(_, How::Ref) | Ty::Obj(_, How::RefMut) => Ok(()),
        Ty::Obj(n, _) => Err(format!("takes `{}` by value (borrow it: `&{}`)", n, n)),
        Ty::Unit => Err("a `()` parameter".to_string()),
        Ty::Option(_) | Ty::Result(..) => Err("an `Option`/`Result` parameter".to_string()),
    }
}

fn ret_ok(t: &Ty, nested: bool) -> Result<(), String> {
    match t {
        Ty::Unit => if nested { Err("`Option<()>`".to_string()) } else { Ok(()) },
        Ty::Prim(_) | Ty::Str(_) | Ty::Bytes(_) | Ty::List(..) => Ok(()),
        Ty::Obj(_, How::Owned) => Ok(()),
        Ty::Obj(n, _) => Err(format!("returns a reference to `{}`", n)),
        Ty::Option(i) | Ty::Result(i, _) => {
            if nested { return Err("a nested `Option`/`Result`".to_string()); }
            if matches!(t, Ty::Result(..)) && **i == Ty::Unit { return Ok(()); }
            ret_ok(i, true)
        }
    }
}

/// Read one `fn` signature. `self_ty` is the struct of an inherent impl.
fn read_fn(sig: &syn::Signature, attrs: &[syn::Attribute], self_ty: Option<&str>, structs: &[String])
    -> Result<Func, String>
{
    if sig.asyncness.is_some() { return Err("an `async fn`".to_string()); }
    if sig.variadic.is_some() { return Err("a variadic fn".to_string()); }
    if sig.generics.params.iter().any(|g| !matches!(g, syn::GenericParam::Lifetime(_))) {
        return Err("a generic fn (write a concrete wrapper)".to_string());
    }
    let mut recv = Recv::None;
    let mut params = Vec::new();
    for (i, input) in sig.inputs.iter().enumerate() {
        match input {
            syn::FnArg::Receiver(r) => {
                if r.reference.is_none() {
                    return Err("takes `self` by value".to_string());
                }
                recv = if r.mutability.is_some() { Recv::RefMut } else { Recv::Ref };
            }
            syn::FnArg::Typed(pt) => {
                let name = match &*pt.pat {
                    syn::Pat::Ident(pi) => pi.ident.to_string(),
                    _ => format!("arg{}", i),
                };
                let ty = map_type(&pt.ty, self_ty, structs)?;
                param_ok(&ty)?;
                params.push(Param { name, ty });
            }
        }
    }
    let ret = match &sig.output {
        syn::ReturnType::Default => Ty::Unit,
        syn::ReturnType::Type(_, t) => map_type(t, self_ty, structs)?,
    };
    ret_ok(&ret, false)?;
    Ok(Func { name: sig.ident.to_string(), doc: doc_lines(attrs), recv, params, ret })
}

fn is_pub(v: &syn::Visibility) -> bool {
    matches!(v, syn::Visibility::Public(_))
}

fn read_binding(dir: &Path) -> Result<Binding, String> {
    let toml_path = dir.join("Cargo.toml");
    let toml = std::fs::read_to_string(&toml_path).map_err(|e| format!("{}: {}", toml_path.display(), e))?;
    let (pkg, lib, module) = cargo_names(&toml);
    let package = pkg.ok_or_else(|| format!("{}: no [package] name", toml_path.display()))?;
    let crate_ident = lib.unwrap_or_else(|| package.clone()).replace('-', "_");
    // The sic module name: `[package.metadata.sic] module`, else the crate's
    // (a binding crate cannot share the name of the crate it wraps).
    let module = module.unwrap_or_else(|| crate_ident.clone());
    if module.is_empty() || !module.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || module.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(format!("{}: `{}` is not a valid sic module name", toml_path.display(), module));
    }
    let lib_rs = dir.join("src").join("lib.rs");
    let src = std::fs::read_to_string(&lib_rs).map_err(|e| format!("{}: {}", lib_rs.display(), e))?;
    let parse = |path: &Path, src: &str| syn::parse_file(src).map_err(|e| {
        let l = e.span().start();
        format!("{}:{}:{}: {}", path.display(), l.line, l.column + 1, e)
    });
    let mut file = parse(&lib_rs, &src)?;
    // A file module whose items the root re-exports (`mod generated; pub use
    // generated::*;`, as `cargo sic` writes) is part of the root API: read it too.
    let globbed: Vec<String> = file.items.iter().filter_map(|it| match it {
        syn::Item::Use(u) if is_pub(&u.vis) => match &u.tree {
            syn::UseTree::Path(p) if matches!(&*p.tree, syn::UseTree::Glob(_)) => Some(p.ident.to_string()),
            _ => None,
        },
        _ => None,
    }).collect();
    let file_mods: Vec<String> = file.items.iter().filter_map(|it| match it {
        syn::Item::Mod(m) if m.content.is_none() && globbed.contains(&m.ident.to_string()) => Some(m.ident.to_string()),
        _ => None,
    }).collect();
    for m in file_mods {
        let cands = [dir.join("src").join(format!("{}.rs", m)), dir.join("src").join(&m).join("mod.rs")];
        let Some(path) = cands.iter().find(|p| p.is_file()) else { continue };
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        file.items.extend(parse(path, &text)?.items);
    }

    let mut b = Binding {
        module, crate_ident, package,
        structs: Vec::new(), funcs: Vec::new(), skipped: Vec::new(),
    };
    // Public, non-generic structs and enums are bound as opaque handle types.
    let mut names: Vec<String> = Vec::new();
    for item in &file.items {
        let (vis, ident, generics, attrs) = match item {
            syn::Item::Struct(s) => (&s.vis, &s.ident, &s.generics, &s.attrs),
            syn::Item::Enum(e) => (&e.vis, &e.ident, &e.generics, &e.attrs),
            _ => continue,
        };
        if !is_pub(vis) { continue; }
        if !generics.params.is_empty() {
            b.skipped.push(format!("type `{}`: generic types are not bound", ident));
            continue;
        }
        names.push(ident.to_string());
        b.structs.push(Struct { name: ident.to_string(), doc: doc_lines(attrs), methods: Vec::new() });
    }
    for item in &file.items {
        match item {
            syn::Item::Fn(f) if is_pub(&f.vis) => {
                match read_fn(&f.sig, &f.attrs, None, &names) {
                    Ok(func) => b.funcs.push(func),
                    Err(why) => b.skipped.push(format!("fn `{}`: {}", f.sig.ident, why)),
                }
            }
            syn::Item::Impl(im) if im.trait_.is_none() => {
                let syn::Type::Path(p) = &*im.self_ty else { continue };
                let Some(id) = p.path.get_ident().map(|i| i.to_string()) else { continue };
                let Some(si) = b.structs.iter().position(|s| s.name == id) else { continue };
                for it in &im.items {
                    let syn::ImplItem::Fn(m) = it else { continue };
                    if !is_pub(&m.vis) { continue; }
                    match read_fn(&m.sig, &m.attrs, Some(&id), &names) {
                        Ok(func) => b.structs[si].methods.push(func),
                        Err(why) => b.skipped.push(format!("fn `{}::{}`: {}", id, m.sig.ident, why)),
                    }
                }
            }
            _ => {}
        }
    }
    // A free function's sic name must not collide with a type's namespace.
    for f in &b.funcs {
        let n = camel(&f.name);
        if names.contains(&n) {
            return Err(format!("{}: fn `{}` (sic `{}::{}`) collides with type `{}`; rename one",
                lib_rs.display(), f.name, b.module, n, n));
        }
    }
    Ok(b)
}

// ── Names ─────────────────────────────────────────────────────────────────────

/// `random_range` → `RandomRange` (sic's CamelCase for module functions).
fn camel(s: &str) -> String {
    let mut out = String::new();
    let mut up = true;
    for c in s.chars() {
        if c == '_' { up = true; continue; }
        if up { out.extend(c.to_uppercase()); up = false; } else { out.push(c); }
    }
    if out.is_empty() { s.to_string() } else { out }
}

/// Words a Rust identifier may use but a sic one may not.
const SIC_RESERVED: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "string", "bigint", "fixed", "match", "defer", "new", "del", "list", "dict",
    "set", "tuple", "any", "bool", "true", "false", "unsafe", "async", "await", "module", "import",
    "namespace", "private", "atomic", "bitfield", "weak", "overflow", "exception", "fallthrough",
    "macro_rules", "typeid", "type", "NULL", "None", "Some", "Ok", "Err", "self", "h",
];

fn sic_ident(s: &str) -> String {
    if SIC_RESERVED.contains(&s) || s.starts_with("__") { format!("{}_", s) } else { s.to_string() }
}

// ── Code generation ──────────────────────────────────────────────────────────

/// The C-boundary type of a returned value (Rust spelling, sic spelling).
fn ffi_ret(t: &Ty) -> (String, String) {
    match t {
        Ty::Unit => ("()".into(), "void".into()),
        Ty::Prim(p) => (p.ffi().into(), p.sic().into()),
        Ty::Str(_) | Ty::Bytes(_) => ("SicStr".into(), "string".into()),
        Ty::List(..) | Ty::Obj(..) => ("*mut c_void".into(), "void *".into()),
        Ty::Option(i) | Ty::Result(i, _) => match **i {
            Ty::Unit => ("bool".into(), "bool".into()),
            _ => ffi_ret(i),
        },
    }
}

fn ffi_param(t: &Ty) -> (String, String) {
    match t {
        Ty::Prim(p) => (p.ffi().into(), p.sic().into()),
        Ty::Str(_) | Ty::Bytes(_) => ("SicStr".into(), "string".into()),
        _ => ("*mut c_void".into(), "void *".into()),
    }
}

/// The sic type a binding exposes.
fn sic_ty(t: &Ty, module: &str) -> String {
    let _ = module;
    match t {
        Ty::Unit => "void".into(),
        Ty::Prim(p) => p.sic().into(),
        Ty::Str(_) | Ty::Bytes(_) => "string".into(),
        Ty::List(e, _) => format!("list<{}>", e.sic()),
        Ty::Obj(n, _) => n.clone(),
        Ty::Option(i) => format!("Option<{}>", sic_ty(i, module)),
        Ty::Result(i, _) => {
            let inner = if **i == Ty::Unit { "bool".to_string() } else { sic_ty(i, module) };
            format!("Result<{}, string>", inner)
        }
    }
}

/// A zero value of a returned C-boundary type (for `None` / `Err`).
fn ffi_zero(t: &Ty) -> &'static str {
    match t {
        Ty::Unit => "false",
        Ty::Prim(Prim::Bool) => "false",
        Ty::Prim(Prim::F32) | Ty::Prim(Prim::F64) => "0.0",
        Ty::Prim(_) => "0",
        Ty::Str(_) | Ty::Bytes(_) => "SIC_EMPTY",
        _ => "std::ptr::null_mut()",
    }
}

/// Convert the Rust value `v` of (non-`Option`) type `t` to its C form.
fn rust_out(t: &Ty, v: &str) -> String {
    match t {
        Ty::Unit => "true".into(),
        Ty::Prim(Prim::Char) => format!("({}) as u32", v),
        Ty::Prim(_) => v.into(),
        Ty::Str(_) => format!("__sic_out(AsRef::<str>::as_ref(&{}).as_bytes())", v),
        Ty::Bytes(_) => format!("__sic_out(AsRef::<[u8]>::as_ref(&{}))", v),
        Ty::List(e, _) => {
            let conv = match e {
                Elem::Str => "__x.to_string()",
                Elem::Prim(_) => "*__x",
            };
            format!("__sic_box({}.iter().map(|__x| {}).collect::<Vec<{}>>())", v, conv, e.rust())
        }
        Ty::Obj(..) => format!("__sic_box({})", v),
        Ty::Option(_) | Ty::Result(..) => unreachable!(),
    }
}

/// Rust: bind the C argument `n` and return the expression to pass on.
fn rust_in(t: &Ty, n: &str, module: &str, out: &mut String) -> String {
    match t {
        Ty::Prim(Prim::Char) => {
            out.push_str(&format!("    let {n} = char::from_u32({n}).unwrap_or('\\u{{FFFD}}');\n"));
            n.into()
        }
        Ty::Prim(_) => n.into(),
        Ty::Str(h) => {
            out.push_str(&format!("    let {n} = __sic_str(&{n});\n"));
            match h {
                How::Owned => format!("{n}.into_owned()"),
                How::RefOwned => format!("&{n}.into_owned()"),
                _ => format!("&*{n}"),
            }
        }
        Ty::Bytes(h) => {
            out.push_str(&format!("    let {n} = __sic_bytes(&{n});\n"));
            match h {
                How::Owned => format!("{n}.to_vec()"),
                How::RefOwned => format!("&{n}.to_vec()"),
                _ => n.into(),
            }
        }
        Ty::List(e, h) => {
            out.push_str(&format!("    let {n}: &mut Vec<{}> = &mut *({n} as *mut Vec<{}>);\n", e.rust(), e.rust()));
            match h {
                How::Owned => format!("std::mem::take({n})"),
                How::RefMut => format!("&mut {n}[..]"),
                How::RefOwned => format!("&*{n}"),
                How::Ref => format!("&{n}[..]"),
            }
        }
        Ty::Obj(s, h) => {
            let get = format!("__sic_obj::<__c::{s}>({n}, \"{module}::{s}\")");
            if *h == How::RefMut { get } else { format!("&*{get}") }
        }
        _ => unreachable!(),
    }
}

/// Glue symbol of a function (`struct_` for a method / associated fn).
fn glue_sym(module: &str, owner: Option<&str>, f: &str) -> String {
    match owner {
        Some(s) => format!("__sicrs_{}_{}_{}", module, s, f),
        None => format!("__sicrs_{}_{}", module, f),
    }
}

/// Generate one glue `extern "C"` function.
fn glue_fn(module: &str, owner: Option<&str>, f: &Func) -> String {
    let sym = glue_sym(module, owner, &f.name);
    let fallible = matches!(f.ret, Ty::Option(_) | Ty::Result(..));
    let mut params: Vec<String> = Vec::new();
    if fallible { params.push("__ok: *mut bool".into()); }
    if f.recv != Recv::None { params.push("__self: *mut c_void".into()); }
    for p in &f.params {
        params.push(format!("{}: {}", p.name, ffi_param(&p.ty).0));
    }
    let (rret, _) = ffi_ret(&f.ret);
    let mut body = String::new();
    let mut args: Vec<String> = Vec::new();
    let callee = match owner {
        Some(s) => {
            if f.recv != Recv::None {
                let get = format!("__sic_obj::<__c::{s}>(__self, \"{module}::{s}\")");
                args.push(if f.recv == Recv::RefMut { get } else { format!("&*{get}") });
            }
            format!("__c::{}::{}", s, f.name)
        }
        None => format!("__c::{}", f.name),
    };
    for p in &f.params {
        args.push(rust_in(&p.ty, &p.name, module, &mut body));
    }
    let call = format!("{}({})", callee, args.join(", "));
    match &f.ret {
        Ty::Unit => body.push_str(&format!("    {};\n", call)),
        Ty::Option(i) => {
            body.push_str(&format!(
                "    match {call} {{\n        Some(__v) => {{ *__ok = true; {} }}\n        None => {{ *__ok = false; {} }}\n    }}\n",
                rust_out(i, "__v"), ffi_zero(i)));
        }
        Ty::Result(i, unit_err) => {
            let err = if *unit_err { "String::from(\"error\")" } else { "__e.to_string()" };
            let bind = if *unit_err { "_" } else { "__e" };
            body.push_str(&format!(
                "    match {call} {{\n        Ok(__v) => {{ *__ok = true; {} }}\n        Err({bind}) => {{ *__ok = false; __sic_set_err({err}); {} }}\n    }}\n",
                if **i == Ty::Unit { "let _ = __v; true".to_string() } else { rust_out(i, "__v") },
                ffi_zero(i)));
        }
        t => body.push_str(&format!("    let __r = {call};\n    {}\n", rust_out(t, "__r"))),
    }
    let ret = if rret == "()" { String::new() } else { format!(" -> {}", rret) };
    format!("#[no_mangle]\npub unsafe extern \"C\" fn {sym}({}){ret} {{\n{body}}}\n\n", params.join(", "))
}

/// Every list element kind used, for the `vec_*` helpers.
fn collect_elems(t: &Ty, out: &mut Vec<Elem>) {
    match t {
        Ty::List(e, _) => if !out.contains(e) { out.push(*e) },
        Ty::Option(i) | Ty::Result(i, _) => collect_elems(i, out),
        _ => {}
    }
}

fn all_funcs(b: &Binding) -> Vec<(Option<&str>, &Func)> {
    let mut v: Vec<(Option<&str>, &Func)> = Vec::new();
    for s in &b.structs {
        for m in &s.methods { v.push((Some(s.name.as_str()), m)); }
    }
    for f in &b.funcs { v.push((None, f)); }
    v
}

const GLUE_PRELUDE: &str = r#"// Generated by sic --emit-module: the C boundary between sic and the crate.
#![allow(non_snake_case, unused_unsafe, unused_mut, unused_variables, dead_code, clippy::all)]
use std::ffi::c_void;

/// sic's `string`: `{ data, size, rc }`. An owned string's `rc` is the start of
/// one malloc block holding the refcount, then the bytes; sic `free`s `rc`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SicStr { data: *const u8, size: usize, rc: *mut usize }

const SIC_EMPTY: SicStr = SicStr { data: std::ptr::null(), size: 0, rc: std::ptr::null_mut() };

extern "C" { fn malloc(n: usize) -> *mut c_void; }

unsafe fn __sic_bytes<'a>(s: &SicStr) -> &'a [u8] {
    if s.data.is_null() || s.size == 0 { &[] } else { std::slice::from_raw_parts(s.data, s.size) }
}

unsafe fn __sic_str<'a>(s: &SicStr) -> std::borrow::Cow<'a, str> {
    String::from_utf8_lossy(__sic_bytes(s))
}

/// A new owned sic string (refcount 1) holding a copy of `b`, NUL-terminated.
fn __sic_out(b: &[u8]) -> SicStr {
    unsafe {
        let hdr = std::mem::size_of::<usize>();
        let blk = malloc(hdr + b.len() + 1) as *mut u8;
        if blk.is_null() { std::process::abort(); }
        *(blk as *mut usize) = 1;
        let data = blk.add(hdr);
        std::ptr::copy_nonoverlapping(b.as_ptr(), data, b.len());
        *data.add(b.len()) = 0;
        SicStr { data, size: b.len(), rc: blk as *mut usize }
    }
}

fn __sic_box<T>(v: T) -> *mut c_void { Box::into_raw(Box::new(v)) as *mut c_void }

unsafe fn __sic_obj<'a, T>(p: *mut c_void, what: &str) -> &'a mut T {
    if p.is_null() {
        panic!("use of an empty `{}` (one not made by its constructor)", what);
    }
    &mut *(p as *mut T)
}

thread_local! {
    static __SIC_ERR: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
}

fn __sic_set_err(e: String) { __SIC_ERR.with(|c| *c.borrow_mut() = e); }

"#;

fn gen_glue(b: &Binding) -> String {
    let m = &b.module;
    let mut s = String::from(GLUE_PRELUDE);
    s.push_str(&format!("use ::{} as __c;\n\n", b.crate_ident));
    s.push_str(&format!(
        "#[no_mangle]\npub extern \"C\" fn __sicrs_{m}_last_error() -> SicStr {{\n    __SIC_ERR.with(|c| __sic_out(c.borrow().as_bytes()))\n}}\n\n"));
    for st in &b.structs {
        s.push_str(&format!(
            "#[no_mangle]\npub unsafe extern \"C\" fn __sicrs_{m}_{n}_drop(p: *mut c_void) {{\n    if !p.is_null() {{ drop(Box::from_raw(p as *mut __c::{n})); }}\n}}\n\n",
            n = st.name));
    }
    let mut elems = Vec::new();
    for (_, f) in all_funcs(b) {
        collect_elems(&f.ret, &mut elems);
        for p in &f.params { collect_elems(&p.ty, &mut elems); }
    }
    for e in &elems {
        let (t, rt, ft) = (e.tag(), e.rust(), e.ffi());
        let push_conv = match e {
            Elem::Str => "__sic_str(&x).into_owned()",
            Elem::Prim(Prim::Char) => "char::from_u32(x).unwrap_or('\\u{FFFD}')",
            Elem::Prim(_) => "x",
        };
        let get_conv = match e {
            Elem::Str => "__sic_out(v[i].as_bytes())",
            Elem::Prim(Prim::Char) => "v[i] as u32",
            Elem::Prim(_) => "v[i]",
        };
        s.push_str(&format!(
"#[no_mangle]
pub extern \"C\" fn __sicrs_{m}_vec_{t}_new() -> *mut c_void {{ __sic_box(Vec::<{rt}>::new()) }}
#[no_mangle]
pub unsafe extern \"C\" fn __sicrs_{m}_vec_{t}_push(v: *mut c_void, x: {ft}) {{ (*(v as *mut Vec<{rt}>)).push({push_conv}); }}
#[no_mangle]
pub unsafe extern \"C\" fn __sicrs_{m}_vec_{t}_len(v: *mut c_void) -> usize {{ (*(v as *mut Vec<{rt}>)).len() }}
#[no_mangle]
pub unsafe extern \"C\" fn __sicrs_{m}_vec_{t}_get(v: *mut c_void, i: usize) -> {ft} {{ let v = &*(v as *mut Vec<{rt}>); {get_conv} }}
#[no_mangle]
pub unsafe extern \"C\" fn __sicrs_{m}_vec_{t}_free(v: *mut c_void) {{ drop(Box::from_raw(v as *mut Vec<{rt}>)); }}

"));
    }
    for (owner, f) in all_funcs(b) {
        s.push_str(&glue_fn(m, owner, f));
    }
    s
}

fn push_doc(out: &mut String, doc: &[String], indent: &str) {
    for l in doc {
        if l.is_empty() { out.push_str(&format!("{}//\n", indent)); } else { out.push_str(&format!("{}// {}\n", indent, l)); }
    }
}

/// The sic wrapper of one function: its declaration and body.
fn sic_fn(b: &Binding, owner: Option<&str>, f: &Func, sic_name: &str, indent: &str) -> String {
    let m = &b.module;
    let mut out = String::new();
    push_doc(&mut out, &f.doc, indent);
    let mut decl: Vec<String> = Vec::new();
    if let (Some(s), true) = (owner, f.recv != Recv::None) {
        decl.push(format!("{} *self", s));
    }
    for p in &f.params {
        decl.push(format!("{} {}", sic_ty(&p.ty, m), sic_ident(&p.name)));
    }
    out.push_str(&format!("{}{} {}({}) {{\n", indent, sic_ty(&f.ret, m), sic_name, decl.join(", ")));
    let ind = format!("{}    ", indent);
    let mut pre = String::new();
    let mut post = String::new();
    let mut args: Vec<String> = Vec::new();
    let fallible = matches!(f.ret, Ty::Option(_) | Ty::Result(..));
    if fallible { args.push("&__ok".into()); }
    if let (Some(s), true) = (owner, f.recv != Recv::None) {
        args.push(format!("__rs_p_{}(self->h)", s));
    }
    for (i, p) in f.params.iter().enumerate() {
        let n = sic_ident(&p.name);
        match &p.ty {
            Ty::List(e, h) => {
                let v = format!("__v{}", i);
                let t = e.tag();
                pre.push_str(&format!("{ind}void *{v} = __sicrs_{m}_vec_{t}_new();\n"));
                pre.push_str(&format!("{ind}for ({} __x : {n}.values) __sicrs_{m}_vec_{t}_push({v}, __x);\n", e.sic()));
                if *h == How::RefMut {
                    post.push_str(&format!(
                        "{ind}for (usize __i = 0; __i < {n}.length; __i++) {n}[__i] = __sicrs_{m}_vec_{t}_get({v}, __i);\n"));
                }
                post.push_str(&format!("{ind}__sicrs_{m}_vec_{t}_free({v});\n"));
                args.push(v);
            }
            Ty::Obj(s, _) => args.push(format!("__rs_p_{}({}.h)", s, n)),
            _ => args.push(n),
        }
    }
    out.push_str(&pre);
    if fallible { out.push_str(&format!("{ind}bool __ok = false;\n")); }
    let call = format!("{}({})", glue_sym(m, owner, &f.name), args.join(", "));
    let (_, gret) = ffi_ret(&f.ret);
    if f.ret == Ty::Unit {
        out.push_str(&format!("{ind}{};\n", call));
        out.push_str(&post);
        out.push_str(&format!("{}}}\n", indent));
        return out;
    }
    out.push_str(&format!("{ind}{} __r = {};\n", gret, call));
    out.push_str(&post);
    // The sic value of the glue result `__r` (statements, then an expression).
    let conv = |t: &Ty, out: &mut String| -> String {
        match t {
            Ty::List(e, _) => {
                let tg = e.tag();
                out.push_str(&format!("{ind}{} __l;\n", sic_ty(t, m)));
                out.push_str(&format!("{ind}usize __n = __sicrs_{m}_vec_{tg}_len(__r);\n"));
                out.push_str(&format!("{ind}for (usize __i = 0; __i < __n; __i++) __l.add(__sicrs_{m}_vec_{tg}_get(__r, __i));\n"));
                out.push_str(&format!("{ind}__sicrs_{m}_vec_{tg}_free(__r);\n"));
                "__l".into()
            }
            Ty::Obj(s, _) => format!("__rs_wrap_{}(__r)", s),
            _ => "__r".into(),
        }
    };
    match &f.ret {
        Ty::Option(i) => {
            out.push_str(&format!("{ind}if (!__ok) return None;\n"));
            let e = conv(i, &mut out);
            out.push_str(&format!("{ind}return Option::Some({});\n", e));
        }
        Ty::Result(i, _) => {
            out.push_str(&format!("{ind}if (!__ok) return Result::Err(__sicrs_{m}_last_error());\n"));
            let e = if **i == Ty::Unit { "true".to_string() } else { conv(i, &mut out) };
            out.push_str(&format!("{ind}return Result::Ok({});\n", e));
        }
        t => {
            let e = conv(t, &mut out);
            out.push_str(&format!("{ind}return {};\n", e));
        }
    }
    out.push_str(&format!("{}}}\n", indent));
    out
}

/// The glue prototype of a function, in sic.
fn sic_proto(m: &str, owner: Option<&str>, f: &Func) -> String {
    let mut ps: Vec<String> = Vec::new();
    if matches!(f.ret, Ty::Option(_) | Ty::Result(..)) { ps.push("bool *__ok".into()); }
    if f.recv != Recv::None { ps.push("void *__self".into()); }
    for p in &f.params { ps.push(format!("{} {}", ffi_param(&p.ty).1, sic_ident(&p.name))); }
    let ps = if ps.is_empty() { "void".to_string() } else { ps.join(", ") };
    format!("{} {}({});\n", ffi_ret(&f.ret).1, glue_sym(m, owner, &f.name), ps)
}

fn gen_sic(b: &Binding) -> String {
    let m = &b.module;
    let mut s = String::new();
    s.push_str(&format!(
        "// Generated by sic --emit-module from the Rust crate `{}` (src/lib.rs).\n\
         // The sic interface of the crate; the functions call its Rust glue.\nmodule {};\n\n",
        b.package, m));
    // Glue prototypes.
    s.push_str(&format!("string __sicrs_{m}_last_error(void);\n"));
    for st in &b.structs { s.push_str(&format!("void __sicrs_{m}_{}_drop(void *p);\n", st.name)); }
    let mut elems = Vec::new();
    for (_, f) in all_funcs(b) {
        collect_elems(&f.ret, &mut elems);
        for p in &f.params { collect_elems(&p.ty, &mut elems); }
    }
    for e in &elems {
        let (t, st) = (e.tag(), e.sic());
        s.push_str(&format!(
            "void *__sicrs_{m}_vec_{t}_new(void);\nvoid __sicrs_{m}_vec_{t}_push(void *v, {st} x);\n\
             usize __sicrs_{m}_vec_{t}_len(void *v);\n{st} __sicrs_{m}_vec_{t}_get(void *v, usize i);\n\
             void __sicrs_{m}_vec_{t}_free(void *v);\n"));
    }
    for (owner, f) in all_funcs(b) { s.push_str(&sic_proto(m, owner, f)); }
    s.push('\n');

    // Every handle type is declared first, so a method may use a type that is
    // defined after its struct.
    for st in &b.structs { s.push_str(&format!("typedef struct {n} {n};\n", n = st.name)); }
    if !b.structs.is_empty() { s.push('\n'); }
    // Handle types: a private refcounted box owns the Rust object; the public
    // struct shares it (copies retain the box), and the last release drops it.
    for st in &b.structs {
        let n = &st.name;
        s.push_str(&format!(
            "private struct __rs_{n}_box {{\n    void *p;\n    ~__rs_{n}_box() {{ __sicrs_{m}_{n}_drop(p); }}\n}};\n\
             static struct {n} __rs_wrap_{n}(void *p);\n\
             static void *__rs_p_{n}(struct __rs_{n}_box *b) {{ if (b == NULL) return NULL; return b->p; }}\n\n"));
    }
    for st in &b.structs {
        let n = &st.name;
        push_doc(&mut s, &st.doc, "");
        s.push_str(&format!("struct {n} {{\n    __rs_{n}_box *h;\n    ~{n}() {{ del h; }}\n"));
        // `new()` with no arguments is also the sic constructor, so a plain
        // `mod::S x;` declaration holds a ready object (an initializer skips it).
        if let Some(f) = st.methods.iter().find(|f| f.name == "new" && f.recv == Recv::None
            && f.params.is_empty() && f.ret == Ty::Obj(n.clone(), How::Owned)) {
            push_doc(&mut s, &f.doc, "    ");
            s.push_str(&format!("    {n}() {{ h = new __rs_{n}_box; h->p = {}(); }}\n",
                glue_sym(m, Some(n), &f.name)));
        }
        for f in st.methods.iter().filter(|f| f.recv != Recv::None) {
            s.push('\n');
            s.push_str(&sic_fn(b, Some(n), f, &sic_ident(&f.name), "    "));
        }
        s.push_str("};\n\n");
        s.push_str(&format!(
            "static struct {n} __rs_wrap_{n}(void *p) {{\n    {n} v = {{ NULL }};\n    v.h = new __rs_{n}_box;\n    v.h->p = p;\n    return v;\n}}\n\n"));
    }
    for st in &b.structs {
        let assoc: Vec<&Func> = st.methods.iter().filter(|f| f.recv == Recv::None).collect();
        if assoc.is_empty() { continue; }
        s.push_str(&format!("namespace {} {{\n", st.name));
        for f in assoc {
            s.push_str(&sic_fn(b, Some(&st.name), f, &camel(&f.name), "    "));
            s.push('\n');
        }
        s.push_str("}\n\n");
    }
    for f in &b.funcs {
        s.push_str(&sic_fn(b, None, f, &camel(&f.name), ""));
        s.push('\n');
    }
    s
}

// ── Building ─────────────────────────────────────────────────────────────────

/// Decode one JSON string literal starting just after its opening quote; returns
/// the text and the rest after the closing quote.
fn json_string(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => return Some((out, &s[i + 1..])),
            '\\' => {
                let (_, e) = it.next()?;
                match e {
                    'n' => out.push('\n'), 't' => out.push('\t'), 'r' => out.push('\r'),
                    'b' => out.push('\u{8}'), 'f' => out.push('\u{c}'),
                    'u' => {
                        let mut code = String::new();
                        for _ in 0..4 { code.push(it.next()?.1); }
                        let mut cp = u32::from_str_radix(&code, 16).ok()?;
                        // A surrogate pair.
                        if (0xD800..0xDC00).contains(&cp) {
                            let rest: String = it.clone().take(6).map(|(_, c)| c).collect();
                            if let Some(lo) = rest.strip_prefix("\\u").and_then(|h| u32::from_str_radix(h, 16).ok()) {
                                for _ in 0..6 { it.next(); }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                        }
                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    }
                    other => out.push(other),
                }
            }
            c => out.push(c),
        }
    }
    None
}

/// The `"rendered"` diagnostic text of a cargo JSON `compiler-message` line.
fn rendered(line: &str) -> Option<String> {
    if !line.contains("\"reason\":\"compiler-message\"") { return None; }
    let at = line.find("\"rendered\":\"")?;
    json_string(&line[at + 12..]).map(|(s, _)| s)
}

/// Build the glue crate; returns the native libraries rustc reports.
fn cargo_build(glue_dir: &Path, target_dir: &Path, verbose: bool) -> Result<Vec<String>, String> {
    let cargo = std::env::var("CARGO").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "cargo".to_string());
    let mut cmd = Command::new(&cargo);
    cmd.arg("rustc").arg("--release").arg("--lib")
        .arg("--manifest-path").arg(glue_dir.join("Cargo.toml"))
        .arg("--target-dir").arg(target_dir)
        .arg("--message-format=json")
        .arg("--").arg("--print").arg("native-static-libs")
        .stdout(Stdio::piped());
    if !verbose { cmd.arg("-Awarnings"); }
    // Cargo's own progress goes to stderr (inherited); diagnostics are JSON on
    // stdout, rendered here, except the native-static-libs note, which is read.
    let mut child = cmd.spawn().map_err(|e| format!("cannot run `{}` (is Rust installed?): {}", cargo, e))?;
    let mut libs: Option<Vec<String>> = None;
    if let Some(out) = child.stdout.take() {
        for line in BufReader::new(out).lines().map_while(|l| l.ok()) {
            let Some(text) = rendered(&line) else { continue };
            if let Some(at) = text.find("native-static-libs:") {
                let rest = text[at + "native-static-libs:".len()..].lines().next().unwrap_or("");
                libs = Some(rest.split_whitespace().map(|s| s.to_string()).collect());
                continue;
            }
            if text.contains("link against the following native artifacts") { continue; }
            eprint!("{}", text);
        }
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("cargo failed to build the Rust glue in {}", glue_dir.display()));
    }
    // rustc prints the note only when it relinks; keep the last list.
    let cache = glue_dir.join("native-static-libs");
    match libs {
        Some(l) => { let _ = std::fs::write(&cache, l.join(" ")); Ok(l) }
        None => Ok(std::fs::read_to_string(&cache).ok()
            .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_else(|| ["-lgcc_s", "-lutil", "-lrt", "-lpthread", "-lm", "-ldl", "-lc"]
                .iter().map(|s| s.to_string()).collect())),
    }
}

/// Write `path` only if its content changed (keeps cargo's freshness check quiet).
fn write_if_changed(path: &Path, text: &str) -> Result<(), String> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(text) { return Ok(()); }
    std::fs::write(path, text).map_err(|e| format!("{}: {}", path.display(), e))
}

/// Read the crate, generate the glue crate and the sic wrapper, and build the
/// glue with cargo. `dir` must be absolute.
pub fn prepare(dir: &Path, verbose: bool) -> Result<RustBuild, String> {
    let b = read_binding(dir)?;
    for s in &b.skipped {
        eprintln!("sic: warning: Rust module '{}': skipping {}", b.module, s);
    }
    if b.funcs.is_empty() && b.structs.is_empty() {
        return Err(format!("{}: src/lib.rs has no public fn or struct sic can bind", dir.display()));
    }
    // `cargo sic` shares one target dir between a project's bindings
    // (`$SIC_CARGO_TARGET_DIR`); a lone crate builds in its own `target/`.
    let target_dir = std::env::var_os("SIC_CARGO_TARGET_DIR").filter(|s| !s.is_empty())
        .map(PathBuf::from).unwrap_or_else(|| dir.join("target"));
    let glue_dir = target_dir.join("sic-glue").join(&b.module);
    std::fs::create_dir_all(&glue_dir).map_err(|e| format!("{}: {}", glue_dir.display(), e))?;
    // Resolve the glue's dependencies as the project's lock file has them
    // (`$SIC_CARGO_LOCK`), so the binding builds against the versions it was
    // generated from.
    if let Some(lock) = std::env::var_os("SIC_CARGO_LOCK").map(PathBuf::from).filter(|p| p.is_file()) {
        let dst = glue_dir.join("Cargo.lock");
        let newer = |a: &Path, b: &Path| match (std::fs::metadata(a).and_then(|m| m.modified()), std::fs::metadata(b).and_then(|m| m.modified())) {
            (Ok(x), Ok(y)) => x > y,
            _ => true,
        };
        if !dst.is_file() || newer(&lock, &dst) {
            let _ = std::fs::copy(&lock, &dst);
        }
    }
    let glue_pkg = format!("sicglue_{}", b.module);
    let toml = format!(
        "# Generated by sic --emit-module.\n[package]\nname = \"{glue_pkg}\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n\
         [lib]\npath = \"lib.rs\"\ncrate-type = [\"staticlib\"]\n\n\
         [dependencies]\n{} = {{ path = \"{}\" }}\n\n\
         [profile.release]\npanic = \"abort\"\n\n[workspace]\n",
        b.package, dir.display().to_string().replace('\\', "/"));
    write_if_changed(&glue_dir.join("Cargo.toml"), &toml)?;
    write_if_changed(&glue_dir.join("lib.rs"), &gen_glue(&b))?;
    let sic_source = glue_dir.join(format!("{}.sic", b.module));
    write_if_changed(&sic_source, &gen_sic(&b))?;
    let native_libs = cargo_build(&glue_dir, &target_dir, verbose)?;
    let archive = target_dir.join("release").join(format!("lib{}.a", glue_pkg));
    if !archive.is_file() {
        return Err(format!("cargo produced no {}", archive.display()));
    }
    Ok(RustBuild { sic_source, archive, native_libs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_case() {
        assert_eq!(camel("encode"), "Encode");
        assert_eq!(camel("random_range"), "RandomRange");
        assert_eq!(camel("next_u64"), "NextU64");
    }

    #[test]
    fn cargo_toml_names() {
        let (p, l, m) = cargo_names("[package]\nname = \"my-crate\"\n[lib]\nname = 'mc' # x\n[package.metadata.sic]\nmodule = \"base64\"\n");
        assert_eq!(p.as_deref(), Some("my-crate"));
        assert_eq!(l.as_deref(), Some("mc"));
        assert_eq!(m.as_deref(), Some("base64"));
    }

    #[test]
    fn json_rendered() {
        let line = r#"{"reason":"compiler-message","message":{"rendered":"note: native-static-libs: -lgcc_s -lc\n\u00e9"}}"#;
        assert_eq!(rendered(line).unwrap(), "note: native-static-libs: -lgcc_s -lc\né");
    }

    #[test]
    fn type_mapping() {
        let t: syn::Type = syn::parse_str("Result<Vec<u8>, base64::DecodeError>").unwrap();
        assert_eq!(map_type(&t, None, &[]).unwrap(), Ty::Result(Box::new(Ty::Bytes(How::Owned)), false));
        let t: syn::Type = syn::parse_str("&mut [i64]").unwrap();
        assert_eq!(map_type(&t, None, &[]).unwrap(), Ty::List(Elem::Prim(Prim::I64), How::RefMut));
        let t: syn::Type = syn::parse_str("Option<Self>").unwrap();
        assert_eq!(map_type(&t, Some("Rng"), &[]).unwrap(), Ty::Option(Box::new(Ty::Obj("Rng".into(), How::Owned))));
        let t: syn::Type = syn::parse_str("impl Iterator<Item = u8>").unwrap();
        assert!(map_type(&t, None, &[]).is_err());
    }
}
