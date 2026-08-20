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
//! Format (v1):
//! ```text
//! sicmod 1
//! module math
//! triple x86_64-linux-gnu
//! link -lm
//! fn sq (i32) -> i32 math_sq
//! fn addv (i32,i32) -> i32 math_addv
//! var meaning i32 math_meaning
//! ```
//! A `fn` param list is comma-separated with no spaces; a trailing `...` marks a
//! variadic function. Types are the compact tokens produced by [`encode_type`]
//! (scalars + pointers in v1; aggregates are not representable and their exports
//! are skipped by the writer).

use sic_ir::{Type, FunctionType, Linkage, Module};

/// Current manifest format version. Bumped on any incompatible format change; a
/// consumer hard-errors on a version it does not understand.
pub const MANIFEST_VERSION: u32 = 1;

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
}

impl ModuleManifest {
    /// Build a manifest by scanning a lowered IR module for this unit's exports.
    /// Exports are the defined (bodied) functions and defined globals whose names
    /// carry the `<module>_` mangling prefix applied during lowering. Aggregate
    /// types are not representable in v1, so such exports are skipped and a note
    /// is written to stderr.
    pub fn from_ir(ir: &Module, module: &str, triple: &str, links: &[String]) -> Self {
        let prefix = format!("{}_", module);
        let mut exports = Vec::new();

        for f in &ir.functions {
            if f.linkage != Linkage::External || !f.name.starts_with(&prefix) {
                continue;
            }
            let unmangled = f.name[prefix.len()..].to_string();
            if !fn_type_representable(&f.sig) {
                eprintln!(
                    "sic: note: module '{}' export '{}' has an aggregate in its \
                     signature and is omitted from the manifest (v1 supports \
                     scalars and pointers)",
                    module, unmangled
                );
                continue;
            }
            exports.push(Export {
                name: unmangled,
                symbol: f.name.clone(),
                ty: Type::Function(Box::new(f.sig.clone())),
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

        ModuleManifest {
            version: MANIFEST_VERSION,
            module: module.to_string(),
            triple: triple.to_string(),
            links: links.to_vec(),
            exports,
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

    /// Parse the `.smod` text form. Returns an error string on any malformed line
    /// or an unsupported version.
    pub fn parse(text: &str) -> Result<ModuleManifest, String> {
        let mut version = None;
        let mut module = None;
        let mut triple = None;
        let mut links: Vec<String> = Vec::new();
        let mut exports = Vec::new();

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
                        params.push(decode_type(tok)
                            .ok_or_else(|| format!("line {}: bad param type '{}'", lineno + 1, tok))?);
                    }
                    let ret = decode_type(ret_tok)
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
                    let ty = decode_type(ty_tok)
                        .ok_or_else(|| format!("line {}: bad var type '{}'", lineno + 1, ty_tok))?;
                    exports.push(Export { name: name.to_string(), symbol: symbol.to_string(), ty });
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
            links,
            exports,
        })
    }
}

/// True if every type in a function signature is representable in the manifest.
fn fn_type_representable(ft: &FunctionType) -> bool {
    encode_type(&ft.ret).is_some() && ft.params.iter().all(|p| encode_type(p).is_some())
}

/// Encode an IR type to the compact manifest token, or `None` if not
/// representable in v1 (aggregates, arrays, bare function types).
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
            // `*void` for opaque/aggregate pointees keeps ABI (pointer-sized)
            // correct even when the pointee itself is not representable.
            let t = encode_type(inner).unwrap_or_else(|| "void".to_string());
            format!("*{}", t)
        }
        Type::Array { .. } | Type::Struct(_) | Type::Union(_) | Type::Function(_) => return None,
    })
}

/// Decode a manifest type token back to an IR type.
pub fn decode_type(tok: &str) -> Option<Type> {
    if let Some(rest) = tok.strip_prefix('*') {
        let inner = decode_type(rest)?;
        return Some(Type::Pointer(Box::new(inner)));
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

    #[test]
    fn roundtrip_types() {
        for ty in [
            Type::Void, Type::Bool, Type::Int { bits: 32, signed: true },
            Type::Int { bits: 64, signed: false }, Type::Float64,
            Type::Pointer(Box::new(Type::Int { bits: 8, signed: true })),
            Type::Pointer(Box::new(Type::Void)),
        ] {
            let enc = encode_type(&ty).unwrap();
            assert_eq!(decode_type(&enc), Some(ty));
        }
    }

    #[test]
    fn roundtrip_manifest() {
        let m = ModuleManifest {
            version: 1,
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
        };
        let text = m.to_text();
        let back = ModuleManifest::parse(&text).unwrap();
        assert_eq!(m, back);
    }
}
