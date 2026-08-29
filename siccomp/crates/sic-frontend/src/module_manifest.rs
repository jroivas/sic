//! sic module manifests (`module_<name>.smod`) — sic.md §"Imports".
//!
//! A manifest is the **portable, self-describing** compiled form of a module: a
//! small line-oriented text file (no YAML/JSON dependency) that lists a module's
//! exported symbols with their sic types, the concrete mangled linker symbol, the
//! target triple it was built for, and the link flags a consumer needs. It sits
//! on top of a normal object/archive like pkg-config + a typed `.def`, so any
//! toolchain matching the triple can read the symbols and link — no compiler
//! private blob (unlike a C++20 BMI or Rust rmeta).
//!
//! Format (v2):
//! ```text
//! sicmod 2
//! module std
//! triple x86_64-linux-gnu
//! link -L/opt/sic/lib -lstd
//! struct __sic_string data:*i8 size:u64 rc:*u64
//! struct __sic_va_array data:*@__sic_any len:u64
//! fn Fmt (@__sic_string,@__sic_va_array) -> @__sic_string std_Fmt
//! var meaning i32 std_meaning
//! ```
//! A `fn` param list is comma-separated with no spaces; a trailing `...` marks a
//! variadic function. Type tokens come from [`encode_type`]: scalars (`i32`,
//! `u64`, `f64`, `bool`, `void`), pointers (`*<t>`), and aggregates referenced by
//! name (`@<name>`; `*@<name>` for a pointer to one). Every aggregate used **by
//! value** gets a `struct`/`union` record (emitted in dependency order, so a
//! nested by-value aggregate precedes its user); a pointer to an aggregate needs
//! no record (opaque, pointer-sized). v2 also carries `bool` and the four
//! compiler-known sic aggregates (`__sic_string`, `__sic_va_array`, `__sic_any`,
//! `__sic_type_info`), which decode via the `types::` constructors so their
//! layout is exactly the built-in one.

use sic_ir::{Type, StructType, UnionType, FunctionType, Linkage, Module};
use crate::lower::types as ltypes;

/// Current manifest format version. Bumped on any incompatible format change; a
/// consumer hard-errors on a version it does not understand. v2 adds `struct`/
/// `union` records and `@name` aggregate tokens (v1 was scalars + pointers only).
pub const MANIFEST_VERSION: u32 = 2;

/// One exported symbol in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Source-level (unmangled) name, e.g. `sq`.
    pub name: String,
    /// Concrete linker symbol, e.g. `math_sq`.
    pub symbol: String,
    /// The sic/IR type: `Type::Function(..)` for `fn`, the value type for `var`.
    pub ty: Type,
}

/// A parsed (or to-be-written) module manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleManifest {
    pub version: u32,
    pub module: String,
    pub triple: String,
    /// Link flags needed to link against this module (its own `-l*`/`-L*` plus
    /// any transitively imported modules' flags).
    pub links: Vec<String>,
    pub exports: Vec<Export>,
    /// sic module type export (sic.md §"Namespace"): public aggregate types this
    /// module defines, `(name, type)`, so a consumer can name `mod::Type`.
    pub types: Vec<(String, Type)>,
    /// sic module enum export: public payload-less enums, `(name, [(variant,
    /// value)])`, so a consumer can use `mod::Enum::Variant`.
    pub enums: Vec<(String, Vec<(String, i64)>)>,
    /// sic module tagged-enum export: `(name, [(variant, tag, payload type)])`, so a
    /// consumer can construct/match `mod::Enum::Variant(x)`.
    pub tagenums: Vec<(String, Vec<(String, i64, Option<Type>)>)>,
}

impl ModuleManifest {
    /// Build a manifest by scanning a lowered IR module for this unit's exports.
    /// Exports are the defined (bodied) functions and defined globals whose names
    /// carry the `<module>_` mangling prefix applied during lowering. An export
    /// whose type is not representable (a value-position aggregate with no name)
    /// is skipped and a note is written to stderr. `ptr_size` (bytes) is the
    /// target pointer width, used to detect the hidden sret parameter.
    pub fn from_ir(ir: &Module, module: &str, triple: &str, links: &[String], ptr_size: u32) -> Self {
        let prefix = format!("{}_", module);
        let mut exports = Vec::new();

        for f in &ir.functions {
            if f.linkage != Linkage::External || !f.name.starts_with(&prefix) {
                continue;
            }
            let unmangled = f.name[prefix.len()..].to_string();
            // Compiler-internal runtime symbols (the bigint/fixed core prepended
            // into a module that uses them) are an implementation detail, not part
            // of the module's public API — keep them in the object, off the manifest.
            if unmangled.starts_with("__sic_") {
                continue;
            }
            // The lowered signature of a struct/union-returning function carries a
            // hidden sret pointer as param 0 (frontend convention). Export the
            // USER-FACING signature (sret stripped) — a consumer re-derives the sret
            // ABI itself; leaving it in would double the pointer.
            let mut sig = f.sig.clone();
            if sic_ir::abi::ret_in_memory(&sig.ret, ptr_size) && !sig.params.is_empty() {
                sig.params.remove(0);
            }
            if !fn_type_representable(&sig) {
                eprintln!(
                    "sic: note: module '{}' export '{}' has an unnameable aggregate \
                     in its signature and is omitted from the manifest",
                    module, unmangled
                );
                continue;
            }
            exports.push(Export {
                name: unmangled,
                symbol: f.name.clone(),
                ty: Type::Function(Box::new(sig)),
            });
        }

        for g in &ir.globals {
            if g.linkage != Linkage::External || !g.name.starts_with(&prefix) {
                continue;
            }
            let unmangled = g.name[prefix.len()..].to_string();
            if encode_type(&g.ty).is_none() {
                eprintln!(
                    "sic: note: module '{}' export '{}' has a non-representable \
                     type and is omitted from the manifest",
                    module, unmangled
                );
                continue;
            }
            exports.push(Export {
                name: unmangled,
                symbol: g.name.clone(),
                ty: g.ty.clone(),
            });
        }

        // Public aggregate types this module defines (frontend-populated), kept
        // only if representable as a manifest record.
        let types: Vec<(String, Type)> = ir.type_defs.iter()
            .filter(|(_, t)| encode_aggregate_record(t).is_some())
            .cloned()
            .collect();

        ModuleManifest {
            version: MANIFEST_VERSION,
            module: module.to_string(),
            triple: triple.to_string(),
            links: links.to_vec(),
            exports,
            types,
            enums: ir.sic_enum_exports.clone(),
            tagenums: ir.sic_tagenum_exports.clone(),
        }
    }

    /// Serialize to the `.smod` text form.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("sicmod {}\n", self.version));
        s.push_str(&format!("module {}\n", self.module));
        s.push_str(&format!("triple {}\n", self.triple));
        if !self.links.is_empty() {
            s.push_str(&format!("link {}\n", self.links.join(" ")));
        }

        // Emit a record for every by-value aggregate reachable from an export, in
        // dependency (post-)order so a nested aggregate precedes the one using it.
        let mut aggs: Vec<Type> = Vec::new();
        for e in &self.exports {
            match &e.ty {
                Type::Function(ft) => {
                    collect_aggregates(&ft.ret, &mut aggs);
                    for p in &ft.params { collect_aggregates(p, &mut aggs); }
                }
                other => collect_aggregates(other, &mut aggs),
            }
        }
        // Public exported types also need their records (and any nested aggregates),
        // emitted before the `pubtype` markers that name them.
        for (_, t) in &self.types { collect_aggregates(t, &mut aggs); }
        // Tagged-enum payloads may be by-value aggregates — record them first.
        for (_, variants) in &self.tagenums {
            for (_, _, p) in variants {
                if let Some(t) = p { collect_aggregates(t, &mut aggs); }
            }
        }
        for a in &aggs {
            if let Some(rec) = encode_aggregate_record(a) { s.push_str(&rec); s.push('\n'); }
        }
        // Mark which records are public type exports (consumers register these).
        for (name, _) in &self.types {
            s.push_str(&format!("pubtype {}\n", name));
        }
        // Public payload-less enums: `enum Name V1=0,V2=5,…`.
        for (name, variants) in &self.enums {
            let vs: Vec<String> = variants.iter().map(|(v, n)| format!("{}={}", v, n)).collect();
            s.push_str(&format!("enum {} {}\n", name, vs.join(",")));
        }
        // Public tagged enums: `tagenum Name V:tag:ptok,…` (ptok `-` = no payload).
        for (name, variants) in &self.tagenums {
            let vs: Vec<String> = variants.iter().map(|(v, tag, p)| {
                let ptok = p.as_ref().and_then(encode_type).unwrap_or_else(|| "-".to_string());
                format!("{}:{}:{}", v, tag, ptok)
            }).collect();
            s.push_str(&format!("tagenum {} {}\n", name, vs.join(",")));
        }

        for e in &self.exports {
            match &e.ty {
                Type::Function(ft) => {
                    let params: Vec<String> = ft.params.iter()
                        .map(|p| encode_type(p).unwrap_or_else(|| "opaque".to_string()))
                        .collect();
                    let mut plist = params.join(",");
                    if ft.variadic {
                        if plist.is_empty() { plist.push_str("..."); }
                        else { plist.push_str(",..."); }
                    }
                    let ret = encode_type(&ft.ret).unwrap_or_else(|| "opaque".to_string());
                    s.push_str(&format!("fn {} ({}) -> {} {}\n", e.name, plist, ret, e.symbol));
                }
                _ => {
                    let ty = encode_type(&e.ty).unwrap_or_else(|| "opaque".to_string());
                    s.push_str(&format!("var {} {} {}\n", e.name, ty, e.symbol));
                }
            }
        }
        s
    }

    /// Parse the `.smod` text form. `ptr_size` (bytes) reconstructs pointer-sized
    /// (`usize`) fields of the compiler-known aggregates. Returns an error string
    /// on any malformed line or an unsupported version.
    pub fn parse(text: &str, ptr_size: u32) -> Result<ModuleManifest, String> {
        let mut version = None;
        let mut module = None;
        let mut triple = None;
        let mut links: Vec<String> = Vec::new();
        let mut exports = Vec::new();
        let mut types: Vec<(String, Type)> = Vec::new();
        let mut enums: Vec<(String, Vec<(String, i64)>)> = Vec::new();
        let mut tagenums: Vec<(String, Vec<(String, i64, Option<Type>)>)> = Vec::new();
        // Aggregate records decoded so far, keyed by name; later records and
        // exports resolve `@name` tokens against this (records are emitted in
        // dependency order, so a reference is always already present).
        let mut registry: std::collections::HashMap<String, Type> = std::collections::HashMap::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let mut it = line.split_whitespace();
            let kw = it.next().unwrap();
            match kw {
                "sicmod" => {
                    let v: u32 = it.next().and_then(|s| s.parse().ok())
                        .ok_or_else(|| format!("line {}: bad sicmod version", lineno + 1))?;
                    version = Some(v);
                }
                "module" => {
                    module = Some(it.next()
                        .ok_or_else(|| format!("line {}: module name missing", lineno + 1))?
                        .to_string());
                }
                "triple" => {
                    triple = Some(it.next()
                        .ok_or_else(|| format!("line {}: triple missing", lineno + 1))?
                        .to_string());
                }
                "link" => {
                    links.extend(it.map(|s| s.to_string()));
                }
                "struct" | "union" => {
                    let name = it.next()
                        .ok_or_else(|| format!("line {}: {} name missing", lineno + 1, kw))?;
                    let is_union = kw == "union";
                    let ty = decode_aggregate_record(name, is_union, it, ptr_size, &registry)
                        .ok_or_else(|| format!("line {}: bad {} record", lineno + 1, kw))?;
                    registry.insert(name.to_string(), ty);
                }
                "fn" => {
                    let name = it.next()
                        .ok_or_else(|| format!("line {}: fn name missing", lineno + 1))?;
                    let plist = it.next()
                        .ok_or_else(|| format!("line {}: fn params missing", lineno + 1))?;
                    let arrow = it.next();
                    if arrow != Some("->") {
                        return Err(format!("line {}: expected '->' in fn record", lineno + 1));
                    }
                    let ret_tok = it.next()
                        .ok_or_else(|| format!("line {}: fn return type missing", lineno + 1))?;
                    let symbol = it.next()
                        .ok_or_else(|| format!("line {}: fn linker symbol missing", lineno + 1))?;
                    let inner = plist.trim_start_matches('(').trim_end_matches(')');
                    let mut variadic = false;
                    let mut params = Vec::new();
                    for tok in inner.split(',') {
                        if tok.is_empty() { continue; }
                        if tok == "..." { variadic = true; continue; }
                        params.push(decode_type(tok, ptr_size, &registry)
                            .ok_or_else(|| format!("line {}: bad param type '{}'", lineno + 1, tok))?);
                    }
                    let ret = decode_type(ret_tok, ptr_size, &registry)
                        .ok_or_else(|| format!("line {}: bad return type '{}'", lineno + 1, ret_tok))?;
                    exports.push(Export {
                        name: name.to_string(),
                        symbol: symbol.to_string(),
                        ty: Type::Function(Box::new(FunctionType { ret, params, variadic })),
                    });
                }
                "var" => {
                    let name = it.next()
                        .ok_or_else(|| format!("line {}: var name missing", lineno + 1))?;
                    let ty_tok = it.next()
                        .ok_or_else(|| format!("line {}: var type missing", lineno + 1))?;
                    let symbol = it.next()
                        .ok_or_else(|| format!("line {}: var linker symbol missing", lineno + 1))?;
                    let ty = decode_type(ty_tok, ptr_size, &registry)
                        .ok_or_else(|| format!("line {}: bad var type '{}'", lineno + 1, ty_tok))?;
                    exports.push(Export { name: name.to_string(), symbol: symbol.to_string(), ty });
                }
                // A public payload-less enum: `enum Name V1=0,V2=5,…`.
                "enum" => {
                    let name = it.next()
                        .ok_or_else(|| format!("line {}: enum name missing", lineno + 1))?;
                    let mut variants = Vec::new();
                    if let Some(list) = it.next() {
                        for pair in list.split(',') {
                            if pair.is_empty() { continue; }
                            let (v, n) = pair.split_once('=')
                                .ok_or_else(|| format!("line {}: bad enum variant '{}'", lineno + 1, pair))?;
                            let val: i64 = n.parse()
                                .map_err(|_| format!("line {}: bad enum value '{}'", lineno + 1, n))?;
                            variants.push((v.to_string(), val));
                        }
                    }
                    enums.push((name.to_string(), variants));
                }
                // A public tagged enum: `tagenum Name V:tag:ptok,…`.
                "tagenum" => {
                    let name = it.next()
                        .ok_or_else(|| format!("line {}: tagenum name missing", lineno + 1))?;
                    let mut variants = Vec::new();
                    if let Some(list) = it.next() {
                        for spec in list.split(',') {
                            if spec.is_empty() { continue; }
                            let mut parts = spec.splitn(3, ':');
                            let v = parts.next()
                                .ok_or_else(|| format!("line {}: tagenum variant name missing", lineno + 1))?;
                            let tag: i64 = parts.next().and_then(|t| t.parse().ok())
                                .ok_or_else(|| format!("line {}: bad tagenum tag", lineno + 1))?;
                            let ptok = parts.next()
                                .ok_or_else(|| format!("line {}: tagenum payload token missing", lineno + 1))?;
                            let payload = if ptok == "-" { None } else {
                                Some(decode_type(ptok, ptr_size, &registry)
                                    .ok_or_else(|| format!("line {}: bad tagenum payload '{}'", lineno + 1, ptok))?)
                            };
                            variants.push((v.to_string(), tag, payload));
                        }
                    }
                    // Register the enum's `{tag,union}` struct type so a later `@Name`
                    // token (e.g. a function returning it by value) decodes correctly.
                    let payload_fields: Vec<(String, Type)> = variants.iter()
                        .filter_map(|(v, _, p)| p.clone().map(|t| (v.clone(), t))).collect();
                    let data = Type::Union(UnionType {
                        name: None, fields: payload_fields, field_aligns: vec![], min_align: None });
                    let st = Type::Struct(StructType::plain(Some(name.to_string()), vec![
                        ("tag".to_string(), Type::Int { bits: 32, signed: true }),
                        ("data".to_string(), data),
                    ], false));
                    registry.insert(name.to_string(), st);
                    tagenums.push((name.to_string(), variants));
                }
                // A public type export names an already-decoded aggregate record.
                "pubtype" => {
                    let name = it.next()
                        .ok_or_else(|| format!("line {}: pubtype name missing", lineno + 1))?;
                    let ty = registry.get(name).cloned()
                        .ok_or_else(|| format!("line {}: pubtype '{}' has no record", lineno + 1, name))?;
                    types.push((name.to_string(), ty));
                }
                other => {
                    return Err(format!("line {}: unknown record '{}'", lineno + 1, other));
                }
            }
        }

        Ok(ModuleManifest {
            version: version.ok_or("missing 'sicmod' version line")?,
            module: module.ok_or("missing 'module' line")?,
            triple: triple.ok_or("missing 'triple' line")?,
            types,
            enums,
            tagenums,
            links,
            exports,
        })
    }
}

/// True if every type in a function signature is representable in the manifest.
fn fn_type_representable(ft: &FunctionType) -> bool {
    encode_type(&ft.ret).is_some() && ft.params.iter().all(|p| encode_type(p).is_some())
}

/// The aggregate's tag name, if it has one (anonymous aggregates are unnameable).
fn agg_name(ty: &Type) -> Option<&str> {
    match ty {
        Type::Struct(s) => s.name.as_deref(),
        Type::Union(u) => u.name.as_deref(),
        _ => None,
    }
}

/// Collect, in dependency (post-)order, every named aggregate reached **by value**
/// from `ty` — its own by-value fields first, then itself. A pointer stops the
/// walk (its pointee is opaque and needs no record); an array recurses into its
/// element. Deduped by name.
fn collect_aggregates(ty: &Type, out: &mut Vec<Type>) {
    match ty {
        Type::Struct(s) => {
            for (_, fty) in &s.fields { collect_aggregates(fty, out); }
            push_agg(ty, out);
        }
        Type::Union(u) => {
            for (_, fty) in &u.fields { collect_aggregates(fty, out); }
            push_agg(ty, out);
        }
        Type::Array { elem, .. } => collect_aggregates(elem, out),
        // Pointer pointee is opaque (pointer-sized), function types don't occur
        // by value, scalars have no aggregates.
        _ => {}
    }
}

fn push_agg(ty: &Type, out: &mut Vec<Type>) {
    if let Some(name) = agg_name(ty) {
        if !out.iter().any(|t| agg_name(t) == Some(name)) {
            out.push(ty.clone());
        }
    }
}

/// Encode a `struct`/`union` record line (without the trailing newline), or
/// `None` for an unnameable aggregate.
fn encode_aggregate_record(ty: &Type) -> Option<String> {
    let (kw, name, fields): (&str, &str, &Vec<(String, Type)>) = match ty {
        Type::Struct(s) => ("struct", s.name.as_deref()?, &s.fields),
        Type::Union(u) => ("union", u.name.as_deref()?, &u.fields),
        _ => return None,
    };
    let mut toks = Vec::new();
    for (fname, fty) in fields {
        toks.push(format!("{}:{}", fname, encode_type(fty)?));
    }
    Some(format!("{} {} {}", kw, name, toks.join(" ")))
}

/// Decode a `struct`/`union` record's fields into an aggregate type. A
/// compiler-known aggregate (by name) is rebuilt via its `types::` constructor so
/// its layout is exactly the built-in one; the serialized fields are ignored.
fn decode_aggregate_record<'a>(
    name: &str,
    is_union: bool,
    field_toks: impl Iterator<Item = &'a str>,
    ptr_size: u32,
    registry: &std::collections::HashMap<String, Type>,
) -> Option<Type> {
    if let Some(t) = known_marker(name, ptr_size) { return Some(t); }
    let mut fields = Vec::new();
    for tok in field_toks {
        let (fname, tty) = tok.split_once(':')?;
        fields.push((fname.to_string(), decode_type(tty, ptr_size, registry)?));
    }
    Some(if is_union {
        Type::Union(UnionType { name: Some(name.to_string()), fields, field_aligns: Vec::new(), min_align: None })
    } else {
        Type::Struct(StructType::plain(Some(name.to_string()), fields, false))
    })
}

/// The four compiler-known sic aggregates, reconstructed with their exact
/// built-in layout. Returns the STRUCT value type (`__sic_type_info` is the
/// opaque pointee — a `type` value is a *pointer* to it).
fn known_marker(name: &str, ptr_size: u32) -> Option<Type> {
    match name {
        n if n == ltypes::SIC_STRING_NAME => Some(ltypes::sic_string_type(ptr_size)),
        n if n == ltypes::VA_ARRAY_MARKER => Some(ltypes::va_array_type(ptr_size)),
        n if n == ltypes::ANY_MARKER => Some(ltypes::any_type()),
        n if n == ltypes::TYPEINFO_MARKER => Some(Type::Struct(
            StructType::plain(Some(ltypes::TYPEINFO_MARKER.to_string()), vec![], false))),
        _ => None,
    }
}

/// Encode an IR type to the compact manifest token, or `None` if not
/// representable (an unnameable/anonymous aggregate, a bare function type).
pub fn encode_type(ty: &Type) -> Option<String> {
    Some(match ty {
        Type::Void => "void".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Int { bits, signed } => {
            format!("{}{}", if *signed { 'i' } else { 'u' }, bits)
        }
        Type::Float32 => "f32".to_string(),
        Type::Float64 => "f64".to_string(),
        Type::Float80 => "f80".to_string(),
        Type::Pointer(inner) => {
            // `*void` for opaque pointees keeps ABI (pointer-sized) correct even
            // when the pointee itself is not representable.
            let t = encode_type(inner).unwrap_or_else(|| "void".to_string());
            format!("*{}", t)
        }
        // A named aggregate is referenced by `@name`; its record carries the layout.
        Type::Struct(_) | Type::Union(_) => format!("@{}", agg_name(ty)?),
        Type::Array { .. } | Type::Function(_) => return None,
    })
}

/// Decode a manifest type token back to an IR type. `registry` resolves `@name`
/// aggregate references to their (already-decoded) type.
pub fn decode_type(tok: &str, ptr_size: u32, registry: &std::collections::HashMap<String, Type>) -> Option<Type> {
    if let Some(rest) = tok.strip_prefix('*') {
        let inner = decode_type(rest, ptr_size, registry)?;
        return Some(Type::Pointer(Box::new(inner)));
    }
    if let Some(name) = tok.strip_prefix('@') {
        // A by-value reference resolves from the registry; a pointer pointee not
        // in the registry is left opaque (a named, field-less struct — pointer-
        // sized, ABI-correct). Known markers always reconstruct exactly.
        if let Some(t) = registry.get(name) { return Some(t.clone()); }
        if let Some(t) = known_marker(name, ptr_size) { return Some(t); }
        return Some(Type::Struct(StructType::plain(Some(name.to_string()), vec![], false)));
    }
    Some(match tok {
        "void" => Type::Void,
        "bool" => Type::Bool,
        "f32" => Type::Float32,
        "f64" => Type::Float64,
        "f80" => Type::Float80,
        _ => {
            let (signed, num) = match tok.split_at(1) {
                ("i", n) => (true, n),
                ("u", n) => (false, n),
                _ => return None,
            };
            let bits: u32 = num.parse().ok()?;
            Type::Int { bits, signed }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn roundtrip_types() {
        let reg = HashMap::new();
        for ty in [
            Type::Void, Type::Bool, Type::Int { bits: 32, signed: true },
            Type::Int { bits: 64, signed: false }, Type::Float64,
            Type::Pointer(Box::new(Type::Int { bits: 8, signed: true })),
            Type::Pointer(Box::new(Type::Void)),
        ] {
            let enc = encode_type(&ty).unwrap();
            assert_eq!(decode_type(&enc, 8, &reg), Some(ty));
        }
    }

    #[test]
    fn roundtrip_manifest() {
        let m = ModuleManifest {
            version: MANIFEST_VERSION,
            module: "math".into(),
            triple: "x86_64-linux-gnu".into(),
            links: vec!["-lm".into()],
            exports: vec![
                Export {
                    name: "sq".into(), symbol: "math_sq".into(),
                    ty: Type::Function(Box::new(FunctionType {
                        ret: Type::Int { bits: 32, signed: true },
                        params: vec![Type::Int { bits: 32, signed: true }],
                        variadic: false,
                    })),
                },
                Export {
                    name: "meaning".into(), symbol: "math_meaning".into(),
                    ty: Type::Int { bits: 32, signed: true },
                },
            ],
            types: vec![],
            enums: vec![],
            tagenums: vec![],
        };
        let text = m.to_text();
        let back = ModuleManifest::parse(&text, 8).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn roundtrip_aggregate_signature() {
        // A std-like `string Fmt(string, va_array)` round-trips: the aggregates
        // get `struct` records and decode via the `types::` markers.
        let strt = ltypes::sic_string_type(8);
        let vat = ltypes::va_array_type(8);
        let m = ModuleManifest {
            version: MANIFEST_VERSION,
            module: "std".into(),
            triple: "x86_64-linux-gnu".into(),
            links: vec![],
            exports: vec![Export {
                name: "Fmt".into(), symbol: "std_Fmt".into(),
                ty: Type::Function(Box::new(FunctionType {
                    ret: strt.clone(), params: vec![strt.clone(), vat.clone()], variadic: false,
                })),
            }],
            types: vec![],
            enums: vec![],
            tagenums: vec![],
        };
        let text = m.to_text();
        assert!(text.contains("struct __sic_string"), "manifest:\n{}", text);
        assert!(text.contains("fn Fmt (@__sic_string,@__sic_va_array) -> @__sic_string std_Fmt"),
            "manifest:\n{}", text);
        let back = ModuleManifest::parse(&text, 8).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn roundtrip_user_struct_by_value() {
        // A user module exporting `Point mid(Point, Point)` by value: the `Point`
        // struct is serialized and reconstructed from its fields.
        let point = Type::Struct(StructType::plain(Some("Point".into()), vec![
            ("x".into(), Type::Int { bits: 32, signed: true }),
            ("y".into(), Type::Int { bits: 32, signed: true }),
        ], false));
        let m = ModuleManifest {
            version: MANIFEST_VERSION,
            module: "geo".into(),
            triple: "x86_64-linux-gnu".into(),
            links: vec![],
            exports: vec![Export {
                name: "mid".into(), symbol: "geo_mid".into(),
                ty: Type::Function(Box::new(FunctionType {
                    ret: point.clone(), params: vec![point.clone(), point.clone()], variadic: false,
                })),
            }],
            types: vec![],
            enums: vec![],
            tagenums: vec![],
        };
        let text = m.to_text();
        assert!(text.contains("struct Point x:i32 y:i32"), "manifest:\n{}", text);
        let back = ModuleManifest::parse(&text, 8).unwrap();
        assert_eq!(m, back);
    }
}
