//! Generate a binding's `src/generated.rs` from the crate's rustdoc JSON.
//!
//! Every public, non-generic function, struct/enum (with its inherent methods)
//! and constant whose signature uses types the SIC binder maps
//! (crates/sic/src/rust_module.rs) gets a plain-Rust wrapper:
//!
//! * a free function is forwarded (`pub fn shout(s: &str) -> String`); one in a
//!   submodule is named by its path (`text::shout` → `text_shout`);
//! * a type becomes a newtype `pub struct Acc(pub ::krate::Acc);` whose methods
//!   forward to the crate's, converting `Self`/`&Self` arguments and results;
//!   `Display`, `Clone`, `PartialEq` and `Default` impls add `to_string()`,
//!   `clone()`, `eq()` and `default()` (also `new()` when there is none);
//! * a constant becomes a function returning it (`LIMIT` → `limit()`);
//! * a `Result`'s error becomes its `Display` text (else its `Debug` text),
//!   so every error type crosses the boundary;
//! * a method returning `&Self`/`&mut Self` (a builder) returns nothing.
//!
//! Everything else is listed, with the reason, in a comment at the end of the
//! file, so the user can see what to wrap by hand in `lib.rs`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use serde_json::Value;

pub struct Generated {
    pub code: String,
    pub bound: usize,
    pub skipped: usize,
}

/// The rustdoc JSON format versions this generator was written against.
const FORMAT_MIN: u64 = 39;

struct TypeBind {
    /// The wrapper's name.
    wrapper: String,
    /// The crate path of the wrapped type (`::krate::m::Acc`).
    path: String,
}

struct Gen<'a> {
    index: &'a serde_json::Map<String, Value>,
    krate: String,
    /// Bound types, by rustdoc id.
    types: HashMap<String, TypeBind>,
    out: String,
    bound: usize,
    skipped: Vec<String>,
    used_names: HashSet<String>,
    /// Bound types (wrapper names) that implement `Clone`: a by-value use
    /// clones them.
    cloneable: HashSet<String>,
    /// The generic-type instance being emitted: (type id, wrapper).
    inst: Option<(String, String)>,
    /// The crate's public traits: id → path (`::krate::engine::Engine`).
    trait_paths: HashMap<String, String>,
    /// The current function's generic parameters, each replaced by the
    /// concrete type its bound allows (`T: AsRef<[u8]>` → `&[u8]`).
    subst: HashMap<String, Value>,
    /// The enclosing impl's generic parameters, bound by an instance
    /// (`K` → `String` for `HashMap<String, i64>`).
    impl_subst: HashMap<String, Value>,
}

/// One reachable public item: its id, the module path it is reached through
/// (re-exports included) and the name it has there.
struct Entry {
    id: String,
    prefix: Vec<String>,
    name: String,
}

fn id_str(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// `random_range` → `RandomRange` (as the binder names SIC functions).
fn camel(s: &str) -> String {
    let mut out = String::new();
    let mut up = true;
    for c in s.chars() {
        if c == '_' { up = true; continue; }
        if up { out.extend(c.to_uppercase()); up = false; } else { out.push(c); }
    }
    out
}

/// Rust keywords a wrapper parameter may not be named.
const RUST_KW: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
    "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "async",
    "await", "dyn", "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof",
    "unsized", "virtual", "yield", "try", "gen",
];

/// Names a bound type cannot take (SIC's own types and keywords).
const SIC_TYPE_RESERVED: &[&str] = &["Option", "Result", "Iterator", "Fn", "Some", "None", "Ok", "Err"];

/// What a value needs to cross from the crate to the wrapper's result.
type Conv = Box<dyn Fn(&str) -> String>;

impl<'a> Gen<'a> {
    fn item(&self, id: &str) -> Option<&'a Value> {
        self.index.get(id)
    }

    fn skip(&mut self, what: String, why: &str) {
        self.skipped.push(format!("{}: {}", what, why));
    }

    // ── Reachable items ──────────────────────────────────────────────────────

    fn collect(&self, root: &str) -> Vec<Entry> {
        let mut out: Vec<Entry> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut seen_mods: HashSet<String> = HashSet::new();
        let mut queue: std::collections::VecDeque<(String, Vec<String>)> = Default::default();
        queue.push_back((root.to_string(), Vec::new()));
        seen_mods.insert(root.to_string());
        while let Some((mid, prefix)) = queue.pop_front() {
            let Some(m) = self.item(&mid) else { continue };
            let items: Vec<String> = m["inner"]["module"]["items"].as_array().into_iter().flatten()
                .filter_map(id_str).collect();
            for id in items {
                let Some(it) = self.item(&id) else { continue };
                let inner = &it["inner"];
                if let Some(u) = inner.get("use") {
                    let Some(target) = id_str(&u["id"]) else { continue };
                    let Some(t) = self.item(&target) else { continue };
                    let is_mod = t["inner"].get("module").is_some();
                    if u["is_glob"].as_bool() == Some(true) {
                        if is_mod && seen_mods.insert(target.clone()) { queue.push_back((target, prefix.clone())); }
                        continue;
                    }
                    let name = u["name"].as_str().unwrap_or("").to_string();
                    if is_mod {
                        if seen_mods.insert(target.clone()) {
                            let mut p = prefix.clone(); p.push(name); queue.push_back((target, p));
                        }
                    } else if seen.insert(target.clone()) {
                        out.push(Entry { id: target, prefix: prefix.clone(), name });
                    }
                    continue;
                }
                let name = it["name"].as_str().unwrap_or("").to_string();
                if inner.get("module").is_some() {
                    if seen_mods.insert(id.clone()) {
                        let mut p = prefix.clone(); p.push(name); queue.push_back((id, p));
                    }
                } else if seen.insert(id.clone()) {
                    out.push(Entry { id, prefix: prefix.clone(), name });
                }
            }
        }
        out
    }

    fn path_of(&self, e: &Entry) -> String {
        let mut s = format!("::{}", self.krate);
        for p in &e.prefix { s.push_str("::"); s.push_str(p); }
        s.push_str("::");
        s.push_str(&e.name);
        s
    }

    fn display_path(&self, e: &Entry) -> String {
        let mut v = e.prefix.clone();
        v.push(e.name.clone());
        v.join("::")
    }

    // ── Types ────────────────────────────────────────────────────────────────

    /// A bound (wrapper) type: a crate type with a wrapper, or `Self` of `cur`.
    fn own_type(&self, t: &Value, cur: Option<&str>) -> Option<String> {
        if t.get("generic").and_then(|g| g.as_str()) == Some("Self") {
            return cur.map(|c| c.to_string());
        }
        let rp = t.get("resolved_path")?;
        let id = id_str(&rp["id"])?;
        // The generic type of the instance being emitted is that instance.
        if let Some((iid, w)) = &self.inst {
            if *iid == id { return Some(w.clone()); }
        }
        let b = self.types.get(&id)?;
        if has_args(rp) { return None; }
        Some(b.wrapper.clone())
    }

    /// The last path segment of a resolved path (`std::string::String` → `String`).
    fn path_name(t: &Value) -> Option<&str> {
        let p = t.get("resolved_path")?["path"].as_str()?;
        Some(p.rsplit("::").next().unwrap_or(p))
    }

    /// A list element: a scalar (not `str`) or `String`.
    fn elem(&self, t: &Value) -> Option<String> {
        if let Some(p) = t.get("primitive").and_then(|p| p.as_str()) {
            return if p == "str" || p == "never" { None } else { Some(p.to_string()) };
        }
        if Self::path_name(t) == Some("String") && !has_args(&t["resolved_path"]) { return Some("String".into()); }
        None
    }

    fn describe(t: &Value) -> String {
        if let Some(p) = t.get("primitive").and_then(|p| p.as_str()) { return p.to_string(); }
        if let Some(g) = t.get("generic").and_then(|p| p.as_str()) { return g.to_string(); }
        if let Some(rp) = t.get("resolved_path") { return rp["path"].as_str().unwrap_or("?").to_string(); }
        if let Some(r) = t.get("borrowed_ref") {
            return format!("&{}{}", if r["is_mutable"].as_bool() == Some(true) { "mut " } else { "" }, Self::describe(&r["type"]));
        }
        if let Some(s) = t.get("slice") { return format!("[{}]", Self::describe(s)); }
        if t.get("impl_trait").is_some() { return "impl Trait".into(); }
        if t.get("dyn_trait").is_some() { return "dyn Trait".into(); }
        if t.get("function_pointer").is_some() { return "fn(..)".into(); }
        if let Some(tu) = t.get("tuple").and_then(|x| x.as_array()) {
            return format!("({})", tu.iter().map(Self::describe).collect::<Vec<_>>().join(", "));
        }
        if t.get("array").is_some() { return "[T; N]".into(); }
        if t.get("raw_pointer").is_some() { return "*T".into(); }
        if t.get("qualified_path").is_some() { return "<T as Trait>::X".into(); }
        "?".into()
    }

    /// A parameter: (its type in the wrapper, how the argument reaches the crate).
    fn param(&self, t: &Value, cur: Option<&str>) -> Result<(String, Conv), String> {
        let plain = |s: String| -> Result<(String, Conv), String> { Ok((s, Box::new(|x: &str| x.to_string()))) };
        // A generic parameter with a convertible bound, or `impl AsRef<str>`.
        if let Some(g) = t.get("generic").and_then(|g| g.as_str()) {
            if let Some(c) = self.subst.get(g) { return self.param(&c.clone(), cur); }
        }
        if let Some(b) = t.get("impl_trait") {
            if let Some(c) = concrete_for_bounds(b) { return self.param(&c, cur); }
        }
        if let Some(p) = t.get("primitive").and_then(|p| p.as_str()) {
            if p != "str" && p != "never" { return plain(p.to_string()); }
        }
        if let Some(r) = t.get("borrowed_ref") {
            let m = r["is_mutable"].as_bool() == Some(true);
            let inner_c = self.resolved(&r["type"]);
            let inner: &Value = &inner_c;
            if inner.get("primitive").and_then(|p| p.as_str()) == Some("str") && !m { return plain("&str".into()); }
            // `&u64` (a lookup key): SIC passes the value.
            if let Some(p) = inner.get("primitive").and_then(|p| p.as_str()).filter(|p| *p != "str" && *p != "never") {
                if !m { return Ok((p.to_string(), Box::new(|x: &str| format!("&{}", x)))); }
            }
            if let Some(e) = inner.get("slice").and_then(|s| self.elem(s)) {
                // A byte slice is a SIC string, which cannot be written through.
                if m && e == "u8" { return Err("takes a mutable byte buffer (`&mut [u8]`)".into()); }
                return plain(format!("&{}[{}]", if m { "mut " } else { "" }, e));
            }
            if !m && Self::path_name(inner) == Some("String") { return plain("&String".into()); }
            if !m && Self::path_name(inner) == Some("Vec") {
                if let Some(e) = single_arg(inner).and_then(|a| self.elem(a)) { return plain(format!("&Vec<{}>", e)); }
            }
            if let Some(w) = self.own_type(inner, cur) {
                let mm = if m { "mut " } else { "" };
                let pre = format!("&{}", mm);
                return Ok((format!("&{}{}", mm, w), Box::new(move |x: &str| format!("{}{}.0", pre, x))));
            }
            return Err(format!("parameter type `{}`", Self::describe(t)));
        }
        if Self::path_name(t) == Some("String") && !has_args(&t["resolved_path"]) { return plain("String".into()); }
        if Self::path_name(t) == Some("Vec") {
            if let Some(e) = single_arg(t).and_then(|a| self.elem(a)) { return plain(format!("Vec<{}>", e)); }
        }
        if let Some(w) = self.own_type(t, cur) {
            // Taken by value: pass a clone, so the SIC value stays usable.
            if self.is_cloneable(&w) {
                return Ok((format!("&{}", w), Box::new(|x: &str| format!("Clone::clone(&{}.0)", x))));
            }
            return Err(format!("takes `{}` by value (it would be consumed; it is not `Clone`)", Self::describe(t)));
        }
        Err(format!("parameter type `{}`", Self::describe(t)))
    }

    fn is_cloneable(&self, wrapper: &str) -> bool {
        self.cloneable.contains(wrapper)
    }

    /// `t` with the current generic substitution applied at its top.
    fn resolved<'v>(&'v self, t: &'v Value) -> std::borrow::Cow<'v, Value> {
        if let Some(g) = t.get("generic").and_then(|g| g.as_str()) {
            if let Some(c) = self.subst.get(g) { return std::borrow::Cow::Owned(apply(c, &self.subst)); }
        }
        std::borrow::Cow::Borrowed(t)
    }

    /// The `Item` of an iterator result: `impl Iterator<Item = X>`, or a crate
    /// type implementing `Iterator` (its `type Item`, with the result type's
    /// arguments substituted).
    fn iterator_item(&self, t: &Value) -> Option<Value> {
        if let Some(bounds) = t.get("impl_trait").and_then(|b| b.as_array()) {
            for b in bounds {
                let tr = &b["trait_bound"]["trait"];
                if tr["path"].as_str().map(|p| p.rsplit("::").next().unwrap_or(p)) != Some("Iterator") { continue; }
                for c in tr["args"]["angle_bracketed"]["constraints"].as_array().into_iter().flatten() {
                    if c["name"] == "Item" { return c["binding"]["equality"].get("type").map(|t| apply(t, &self.subst)); }
                }
            }
            return None;
        }
        let rp = t.get("resolved_path")?;
        let Some(ty) = id_str(&rp["id"]).and_then(|id| self.item(&id)) else {
            return std_iterator_item(t).map(|i| apply(&i, &self.subst));
        };
        let kind = if ty["inner"].get("struct").is_some() { "struct" } else if ty["inner"].get("enum").is_some() { "enum" } else { return None };
        for i in ty["inner"][kind]["impls"].as_array().into_iter().flatten().filter_map(id_str) {
            let Some(im) = self.item(&i) else { continue };
            let imp = &im["inner"]["impl"];
            if imp["trait"]["path"].as_str().map(|p| p.rsplit("::").next().unwrap_or(p)) != Some("Iterator") { continue; }
            let mut binds = HashMap::new();
            let concrete = apply(t, &self.subst);
            if !unify(&imp["for"], &concrete, &mut binds) { continue; }
            for a in imp["items"].as_array().into_iter().flatten().filter_map(id_str) {
                let Some(ai) = self.item(&a) else { continue };
                if ai["name"] == "Item" {
                    let it = ai["inner"]["assoc_type"]["type"].clone();
                    if it.is_null() { return None; }
                    return Some(apply(&it, &binds));
                }
            }
        }
        None
    }

    /// A result that is not an `Option`/`Result`: (wrapper type, conversion).
    fn ret_plain(&self, t: &Value, cur: Option<&str>) -> Result<(String, Conv), String> {
        let plain = |s: String| -> Result<(String, Conv), String> { Ok((s, Box::new(|x: &str| x.to_string()))) };
        let with = |s: String, f: Conv| -> Result<(String, Conv), String> { Ok((s, f)) };
        if let Some(g) = t.get("generic").and_then(|g| g.as_str()) {
            if let Some(c) = self.subst.get(g) { return self.ret_plain(&apply(c, &self.subst), cur); }
            if g != "Self" { return Err(format!("returns the generic `{}`", g)); }
        }
        // An iterator is collected into a list.
        if let Some(item) = self.iterator_item(t) {
            if item["borrowed_ref"]["is_mutable"].as_bool() == Some(true) {
                return Err("an iterator of mutable references (changes to the copies would be lost)".into());
            }
            let (ety, econv) = self.ret_plain(&item, cur).map_err(|e| format!("an iterator of {}", e))?;
            let ok = matches!(ety.as_str(), "String" | "bool" | "char" | "f32" | "f64")
                || ety.starts_with('i') || ety.starts_with('u');
            if !ok || ety.contains('<') { return Err(format!("an iterator of `{}`", ety)); }
            let inner = econv("__v");
            return with(format!("Vec<{}>", ety), Box::new(move |x: &str| format!("({}).map(|__v| {}).collect::<Vec<_>>()", x, inner)));
        }
        // `std::cmp::Ordering` → -1 / 0 / 1.
        if Self::path_name(t) == Some("Ordering") && !has_args(&t["resolved_path"]) {
            return with("i32".into(), Box::new(|x: &str| format!("({}) as i32", x)));
        }
        if let Some(tu) = t.get("tuple").and_then(|x| x.as_array()) {
            if tu.is_empty() { return plain("()".into()); }
        }
        if let Some(p) = t.get("primitive").and_then(|p| p.as_str()) {
            if p != "str" && p != "never" { return plain(p.to_string()); }
        }
        if let Some(r) = t.get("borrowed_ref") {
            // A copy of a `&mut` result would silently drop the caller's writes.
            if r["is_mutable"].as_bool() == Some(true) {
                return Err(format!("returns a mutable reference (`{}`)", Self::describe(t)));
            }
            let inner_c = self.resolved(&r["type"]);
            let inner: &Value = &inner_c;
            // Borrowed results are copied out (no lifetime crosses into SIC).
            if let Some(p) = inner.get("primitive").and_then(|p| p.as_str()) {
                if p != "str" && p != "never" { return with(p.to_string(), Box::new(|x: &str| format!("*({})", x))); }
            }
            if let Some(w) = self.own_type(inner, cur).filter(|w| self.is_cloneable(w) && Some(w.as_str()) != cur) {
                return with(w.clone(), Box::new(move |x: &str| format!("{}(Clone::clone({}))", w, x)));
            }
            if inner.get("primitive").and_then(|p| p.as_str()) == Some("str") {
                return with("String".into(), Box::new(|x: &str| format!("({}).to_string()", x)));
            }
            if let Some(e) = inner.get("slice").and_then(|s| self.elem(s)) {
                return with(format!("Vec<{}>", e), Box::new(|x: &str| format!("({}).to_vec()", x)));
            }
            if Self::path_name(inner) == Some("String") {
                return with("String".into(), Box::new(|x: &str| format!("({}).clone()", x)));
            }
            if Self::path_name(inner) == Some("Vec") {
                if let Some(e) = single_arg(inner).and_then(|a| self.elem(a)) {
                    return with(format!("Vec<{}>", e), Box::new(|x: &str| format!("({}).clone()", x)));
                }
            }
            return Err(format!("returns a reference (`{}`)", Self::describe(t)));
        }
        if Self::path_name(t) == Some("String") && !has_args(&t["resolved_path"]) { return plain("String".into()); }
        if Self::path_name(t) == Some("Vec") {
            if let Some(a) = single_arg(t) {
                if let Some(e) = self.elem(a) { return plain(format!("Vec<{}>", e)); }
                // `Vec<&str>` → owned strings.
                if a.get("borrowed_ref").map_or(false, |r| r["type"].get("primitive").and_then(|p| p.as_str()) == Some("str")) {
                    return with("Vec<String>".into(), Box::new(|x: &str| format!("({}).into_iter().map(String::from).collect()", x)));
                }
            }
        }
        if let Some(w) = self.own_type(t, cur) {
            return with(w.clone(), Box::new(move |x: &str| format!("{}({})", w, x)));
        }
        Err(format!("result type `{}`", Self::describe(t)))
    }

    /// A function's result: (wrapper type, conversion). `&Self` results (a
    /// builder returning itself) become `()`.
    fn ret(&self, t: &Value, cur: Option<&str>) -> Result<(String, Conv), String> {
        if t.is_null() { return Ok(("()".into(), Box::new(|x: &str| x.to_string()))); }
        if let (Some(r), Some(c)) = (t.get("borrowed_ref"), cur) {
            if self.own_type(&r["type"], cur).as_deref() == Some(c) {
                return Ok(("()".into(), Box::new(|x: &str| format!("{{ let _ = {}; }}", x))));
            }
        }
        match Self::path_name(t) {
            Some("Option") => {
                let a = single_arg(t).ok_or_else(|| "an `Option` without its type".to_string())?;
                let (s, f) = self.ret_plain(a, cur)?;
                if s == "()" { return Err("`Option<()>`".into()); }
                let inner = f("__v");
                Ok((format!("Option<{}>", s), Box::new(move |x: &str| format!("({}).map(|__v| {})", x, inner))))
            }
            Some("Result") => {
                let args = type_args(t);
                let a = args.first().ok_or_else(|| "a `Result` without its type".to_string())?;
                let (s, f) = self.ret_plain(a, cur)?;
                let inner = f("__v");
                Ok((format!("Result<{}, String>", s),
                    Box::new(move |x: &str| format!("({}).map(|__v| {}).map_err(|__e| sic_err!(__e))", x, inner))))
            }
            _ => self.ret_plain(t, cur),
        }
    }

    // ── Functions ────────────────────────────────────────────────────────────

    fn doc_comment(&mut self, it: &Value, indent: &str) {
        let Some(docs) = it["docs"].as_str() else { return };
        // The first paragraph: the summary, without rustdoc's examples.
        for line in docs.lines().take_while(|l| !l.trim().is_empty()) {
            let _ = writeln!(self.out, "{}/// {}", indent, line);
        }
    }

    /// Check a function item; returns its `sig` when it can be wrapped.
    fn fn_sig(&self, it: &Value) -> Result<Value, String> {
        let f = &it["inner"]["function"];
        if f.is_null() { return Err("not a function".into()); }
        let h = &f["header"];
        if h["is_async"].as_bool() == Some(true) { return Err("an `async fn`".into()); }
        if h["is_unsafe"].as_bool() == Some(true) { return Err("an `unsafe fn`".into()); }
        if f["sig"]["is_c_variadic"].as_bool() == Some(true) { return Err("variadic".into()); }
        Ok(f["sig"].clone())
    }

    /// Emit one wrapper fn. `owner`: (wrapper type, wrapped path) for methods
    /// and associated functions. Returns the reason when it cannot be wrapped.
    fn emit_fn(&mut self, it: &Value, name: &str, call_path: &str, owner: Option<(&str, &str)>, indent: &str)
        -> Result<(), String>
    {
        let base = std::mem::take(&mut self.impl_subst);
        let r = self.emit_fn_with(it, name, call_path, owner, indent, &base);
        self.impl_subst = base;
        r
    }

    fn emit_fn_with(&mut self, it: &Value, name: &str, call_path: &str, owner: Option<(&str, &str)>, indent: &str,
        base: &HashMap<String, Value>) -> Result<(), String>
    {
        let sig = self.fn_sig(it)?;
        let mut subst = base.clone();
        subst.extend(generic_subst(&it["inner"]["function"]["generics"], base)?);
        self.subst = subst;
        let cur = owner.map(|o| o.0);
        let mut inputs: Vec<(String, Value)> = sig["inputs"].as_array().into_iter().flatten()
            .filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.clone()))).collect();
        let mut recv = String::new();
        let mut args: Vec<String> = Vec::new();
        if let (Some(first), Some(_)) = (inputs.first(), owner) {
            if first.0 == "self" {
                let t = &first.1;
                match t.get("borrowed_ref") {
                    Some(r) if r["type"].get("generic").and_then(|g| g.as_str()) == Some("Self") => {
                        let m = r["is_mutable"].as_bool() == Some(true);
                        recv = if m { "&mut self".into() } else { "&self".into() };
                        args.push(if m { "&mut self.0".into() } else { "&self.0".into() });
                    }
                    // By value: a `Clone` type is cloned (`with_x(self) -> Self`
                    // builders then return a new value).
                    _ if t.get("generic").and_then(|g| g.as_str()) == Some("Self")
                        && owner.map_or(false, |o| self.is_cloneable(o.0)) => {
                        recv = "&self".into();
                        args.push("Clone::clone(&self.0)".into());
                    }
                    _ => return Err("takes `self` by value (it would be consumed; it is not `Clone`)".into()),
                }
                inputs.remove(0);
            }
        }
        let mut params: Vec<String> = Vec::new();
        if !recv.is_empty() { params.push(recv); }
        for (i, (pname, t)) in inputs.iter().enumerate() {
            let (sty, conv) = self.param(t, cur)?;
            let n = if pname.is_empty() || pname == "_" || !pname.chars().all(|c| c.is_alphanumeric() || c == '_')
                || RUST_KW.contains(&pname.as_str()) { format!("arg{}", i) } else { pname.clone() };
            params.push(format!("{}: {}", n, sty));
            args.push(conv(&n));
        }
        let (rty, rconv) = self.ret(&sig["output"], cur)?;
        let call = rconv(&format!("{}({})", call_path, args.join(", ")));
        self.doc_comment(it, indent);
        let ret = if rty == "()" { String::new() } else { format!(" -> {}", rty) };
        let _ = writeln!(self.out, "{}pub fn {}({}){} {{\n{}    {}\n{}}}", indent, name, params.join(", "), ret, indent, call, indent);
        self.bound += 1;
        Ok(())
    }

    // ── Types ────────────────────────────────────────────────────────────────

    fn trait_impls(&self, it: &Value, kind: &str) -> Vec<String> {
        let mut out = Vec::new();
        for i in it["inner"][kind]["impls"].as_array().into_iter().flatten().filter_map(id_str) {
            let Some(im) = self.item(&i) else { continue };
            let imp = &im["inner"]["impl"];
            if imp["is_synthetic"].as_bool() == Some(true) || !imp["blanket_impl"].is_null() { continue; }
            if let Some(name) = imp["trait"]["path"].as_str() {
                out.push(name.rsplit("::").next().unwrap_or(name).to_string());
            }
        }
        out
    }

    /// Methods of the crate's own public, non-generic traits implemented for a
    /// type: the impl's own items plus the trait's provided methods.
    fn trait_methods(&self, it: &Value, kind: &str) -> Vec<(&'a Value, String)> {
        let mut out = Vec::new();
        for i in it["inner"][kind]["impls"].as_array().into_iter().flatten().filter_map(id_str) {
            let Some(im) = self.item(&i) else { continue };
            let imp = &im["inner"]["impl"];
            if imp["trait"].is_null() || imp["is_synthetic"].as_bool() == Some(true) || !imp["blanket_impl"].is_null() { continue; }
            let Some(tid) = id_str(&imp["trait"]["id"]) else { continue };
            let Some(tpath) = self.trait_paths.get(&tid).cloned() else { continue };
            if has_args(&imp["trait"]) { continue; }
            let Some(tr) = self.item(&tid) else { continue };
            if tr["inner"]["trait"]["generics"]["params"].as_array().map_or(false, |a| !a.is_empty()) { continue; }
            let mut seen: HashSet<String> = HashSet::new();
            for m in imp["items"].as_array().into_iter().flatten().filter_map(id_str) {
                let Some(mi) = self.item(&m) else { continue };
                if mi["inner"].get("function").is_none() { continue; }
                seen.insert(mi["name"].as_str().unwrap_or("").to_string());
                out.push((mi, tpath.clone()));
            }
            let provided: Vec<String> = imp["provided_trait_methods"].as_array().into_iter().flatten()
                .filter_map(|v| v.as_str().map(String::from)).collect();
            for m in tr["inner"]["trait"]["items"].as_array().into_iter().flatten().filter_map(id_str) {
                let Some(mi) = self.item(&m) else { continue };
                let n = mi["name"].as_str().unwrap_or("").to_string();
                if mi["inner"].get("function").is_none() || seen.contains(&n) || !provided.contains(&n) { continue; }
                out.push((mi, tpath.clone()));
            }
        }
        out
    }

    /// The inherent methods of a type, each with its impl's generic bindings.
    /// For an instance (`inst_ty`: the concrete type), only the impls whose
    /// `for` type it matches (`impl<K, V> HashMap<K, V, DefaultHashBuilder>`).
    fn inherent_methods(&self, it: &Value, kind: &str, inst_ty: Option<&Value>) -> Vec<(&'a Value, HashMap<String, Value>)> {
        let mut out = Vec::new();
        for i in it["inner"][kind]["impls"].as_array().into_iter().flatten().filter_map(id_str) {
            let Some(im) = self.item(&i) else { continue };
            let imp = &im["inner"]["impl"];
            if !imp["trait"].is_null() || imp["is_synthetic"].as_bool() == Some(true) { continue; }
            let mut binds = HashMap::new();
            if let Some(c) = inst_ty {
                if !unify(&imp["for"], c, &mut binds) { continue; }
            }
            for m in imp["items"].as_array().into_iter().flatten().filter_map(id_str) {
                let Some(mi) = self.item(&m) else { continue };
                if mi["inner"].get("function").is_none() { continue; }
                if mi["visibility"].as_str() != Some("public") { continue; }
                out.push((mi, binds.clone()));
            }
        }
        out
    }

    fn emit_type(&mut self, it: &Value, kind: &str, w: &str, path: &str, shown: &str, inst_ty: Option<&Value>) {
        self.doc_comment(it, "");
        let _ = writeln!(self.out, "pub struct {}(pub {});\n\nimpl {} {{", w, path, w);
        let methods = self.inherent_methods(it, kind, inst_ty);
        let mut names: HashSet<String> = HashSet::new();
        let mut has_new0 = false;
        for (m, binds) in methods {
            self.impl_subst = binds;
            let mname = m["name"].as_str().unwrap_or("").to_string();
            if m["deprecation"].is_object() { self.skip(format!("fn `{}::{}`", shown, mname), "deprecated"); continue; }
            if names.contains(&mname) { continue; }
            let call = format!("<{}>::{}", path, mname);
            let mark = self.out.len();
            match self.emit_fn(m, &mname, &call, Some((w, path)), "    ") {
                Ok(()) => {
                    names.insert(mname.clone());
                    let ins = m["inner"]["function"]["sig"]["inputs"].as_array().map_or(0, |a| a.len());
                    if mname == "new" && ins == 0 { has_new0 = true; }
                }
                Err(why) => { self.out.truncate(mark); self.skip(format!("fn `{}::{}`", shown, mname), &why); }
            }
        }
        self.impl_subst.clear();
        // Methods of the crate's own traits implemented for the type (with the
        // trait's provided methods): `<T as Trait>::m(...)`.
        for (m, tpath) in self.trait_methods(it, kind) {
            let mname = m["name"].as_str().unwrap_or("").to_string();
            if names.contains(&mname) || m["deprecation"].is_object() { continue; }
            let call = format!("<{} as {}>::{}", path, tpath, mname);
            let mark = self.out.len();
            match self.emit_fn(m, &mname, &call, Some((w, path)), "    ") {
                Ok(()) => { names.insert(mname); }
                Err(why) => { self.out.truncate(mark); self.skip(format!("fn `{}::{}`", shown, mname), &why); }
            }
        }
        // Public fields: a getter, and a setter for scalars and strings.
        if kind == "struct" {
            let fields: Vec<String> = it["inner"]["struct"]["kind"]["plain"]["fields"].as_array().into_iter().flatten()
                .filter_map(id_str).collect();
            for fid in fields {
                let Some(f) = self.item(&fid) else { continue };
                if f["visibility"].as_str() != Some("public") { continue; }
                let fname = f["name"].as_str().unwrap_or("").to_string();
                let fty = &f["inner"]["struct_field"];
                if names.contains(&fname) { continue; }
                let getter = if fty.get("primitive").map_or(false, |p| p != "str") {
                    Some((fty["primitive"].as_str().unwrap().to_string(), format!("self.0.{}", fname)))
                } else if let Some(fw) = self.own_type(fty, Some(w)).filter(|fw| self.is_cloneable(fw)) {
                    Some((fw.clone(), format!("{}(Clone::clone(&self.0.{}))", fw, fname)))
                } else {
                    let r = serde_json::json!({"borrowed_ref": {"lifetime": null, "is_mutable": false, "type": fty}});
                    self.ret_plain(&r, Some(w)).ok().map(|(t, c)| (t, c(&format!("&self.0.{}", fname))))
                };
                match getter {
                    Some((t, e)) => {
                        let _ = writeln!(self.out, "    /// The `{}` field.\n    pub fn {}(&self) -> {} {{\n        {}\n    }}", fname, fname, t, e);
                        names.insert(fname.clone());
                        self.bound += 1;
                    }
                    None => { self.skip(format!("field `{}::{}`", shown, fname), &format!("type `{}`", Self::describe(fty))); continue; }
                }
                let setter = format!("set_{}", fname);
                let settable = fty.get("primitive").map_or(false, |p| p != "str")
                    || (Self::path_name(fty) == Some("String") && !has_args(&fty["resolved_path"]));
                if settable && !names.contains(&setter) {
                    let (t, _) = self.param(fty, Some(w)).unwrap();
                    let _ = writeln!(self.out, "    /// Set the `{}` field.\n    pub fn {}(&mut self, v: {}) {{\n        self.0.{} = v;\n    }}", fname, setter, t, fname);
                    names.insert(setter);
                    self.bound += 1;
                }
            }
        }
        // An enum: a constructor per payload-less variant, and its name.
        if kind == "enum" {
            let mut arms: Vec<String> = Vec::new();
            for vid in it["inner"]["enum"]["variants"].as_array().into_iter().flatten().filter_map(id_str) {
                let Some(v) = self.item(&vid) else { continue };
                let vname = v["name"].as_str().unwrap_or("").to_string();
                let vk = &v["inner"]["variant"]["kind"];
                let pat = if vk.as_str() == Some("plain") { format!("{}::{}", path, vname) }
                    else if vk.get("tuple").is_some() { format!("{}::{}(..)", path, vname) }
                    else { format!("{}::{} {{ .. }}", path, vname) };
                arms.push(format!("            {} => \"{}\",", pat, vname));
                let fname = snake(&vname);
                if vk.as_str() == Some("plain") && !names.contains(&fname) && !RUST_KW.contains(&fname.as_str()) {
                    let _ = writeln!(self.out, "    /// The `{}` variant.\n    pub fn {}() -> {} {{\n        {}({}::{})\n    }}", vname, fname, w, w, path, vname);
                    names.insert(fname);
                    self.bound += 1;
                }
            }
            if !arms.is_empty() && !names.contains("variant_name") {
                let _ = writeln!(self.out, "    /// The variant's name.\n    #[allow(unreachable_patterns)]\n    pub fn variant_name(&self) -> String {{\n        String::from(match &self.0 {{\n{}\n            _ => \"?\",\n        }})\n    }}", arms.join("\n"));
                names.insert("variant_name".into());
                self.bound += 1;
            }
        }
        let traits = self.trait_impls(it, kind);
        let has = |t: &str| traits.iter().any(|x| x == t);
        if has("Ord") && !names.contains("cmp") {
            let _ = writeln!(self.out, "    /// Compare (`Ord`): -1, 0 or 1.\n    pub fn cmp(&self, other: &{w}) -> i32 {{\n        Ord::cmp(&self.0, &other.0) as i32\n    }}");
            self.bound += 1;
        }
        if has("Display") && !names.contains("to_string") {
            let _ = writeln!(self.out, "    /// The `Display` text.\n    pub fn to_string(&self) -> String {{\n        ToString::to_string(&self.0)\n    }}");
            self.bound += 1;
        }
        if has("Clone") && !names.contains("clone") {
            let _ = writeln!(self.out, "    /// An independent copy (`Clone`).\n    pub fn clone(&self) -> {w} {{\n        {w}(Clone::clone(&self.0))\n    }}");
            self.bound += 1;
        }
        if has("PartialEq") && !names.contains("eq") {
            let _ = writeln!(self.out, "    /// `==` (`PartialEq`).\n    pub fn eq(&self, other: &{w}) -> bool {{\n        self.0 == other.0\n    }}");
            self.bound += 1;
        }
        if has("Default") {
            if !names.contains("default") {
                let _ = writeln!(self.out, "    /// The default value (`Default`).\n    pub fn default() -> {w} {{\n        {w}(Default::default())\n    }}");
                self.bound += 1;
            }
            if !has_new0 && !names.contains("new") {
                let _ = writeln!(self.out, "    /// The default value (`Default`); also the SIC constructor.\n    pub fn new() -> {w} {{\n        {w}(Default::default())\n    }}");
                self.bound += 1;
            }
        }
        let _ = writeln!(self.out, "}}\n");
        self.bound += 1;
    }
}

/// `Exact` → `exact`, `NoPadding` → `no_padding`.
fn snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 { out.push('_'); }
            out.extend(c.to_lowercase());
        } else { out.push(c); }
    }
    out
}

/// The concrete argument type a set of trait bounds allows: `AsRef<[u8]>` →
/// `&[u8]`, `AsRef<str>` / `AsRef<Path>` / `Display` → `&str`, `Into<String>` →
/// `String`. None when no bound is one of these.
fn concrete_for_bounds(bounds: &Value) -> Option<Value> {
    let str_ref = serde_json::json!({"borrowed_ref": {"lifetime": null, "is_mutable": false, "type": {"primitive": "str"}}});
    for b in bounds.as_array().into_iter().flatten() {
        let tr = &b["trait_bound"]["trait"];
        let Some(path) = tr["path"].as_str() else { continue };
        let name = path.rsplit("::").next().unwrap_or(path);
        let args: Vec<&Value> = tr["args"]["angle_bracketed"]["args"].as_array().into_iter().flatten()
            .filter_map(|a| a.get("type")).collect();
        let arg = args.first().copied();
        match name {
            "AsRef" => match arg {
                Some(a) if a.get("slice").and_then(|s| s.get("primitive")).and_then(|p| p.as_str()) == Some("u8") =>
                    return Some(serde_json::json!({"borrowed_ref": {"lifetime": null, "is_mutable": false, "type": {"slice": {"primitive": "u8"}}}})),
                Some(a) if a.get("primitive").and_then(|p| p.as_str()) == Some("str") => return Some(str_ref),
                Some(a) if matches!(a.get("resolved_path").and_then(|r| r["path"].as_str()).map(|p| p.rsplit("::").next().unwrap_or(p)), Some("Path" | "OsStr")) =>
                    return Some(str_ref),
                _ => {}
            },
            "Into" if arg.and_then(|a| a.get("resolved_path")).and_then(|r| r["path"].as_str()).map(|p| p.ends_with("String")) == Some(true) =>
                return Some(serde_json::json!({"resolved_path": {"path": "String", "id": null, "args": null}})),
            "Display" | "ToString" => return Some(str_ref),
            _ => {}
        }
    }
    None
}

/// Each generic type parameter of a function, replaced by the concrete type
/// its bounds allow; an error when one has no such bound.
fn generic_subst(generics: &Value, base: &HashMap<String, Value>) -> Result<HashMap<String, Value>, String> {
    let mut out = HashMap::new();
    // The lookup-key pattern (`get<Q>(&self, k: &Q) where K: Borrow<Q>` or
    // `Q: Equivalent<K>`): Q is the bound key type K.
    let lookup_key = |q: &str| -> Option<Value> {
        for w in generics["where_predicates"].as_array().into_iter().flatten() {
            let bp = &w["bound_predicate"];
            let on = bp["type"].get("generic").and_then(|g| g.as_str());
            for b in bp["bounds"].as_array().into_iter().flatten() {
                let tr = &b["trait_bound"]["trait"];
                let name = tr["path"].as_str().map(|p| p.rsplit("::").next().unwrap_or(p).to_string());
                let arg = tr["args"]["angle_bracketed"]["args"].as_array()
                    .and_then(|a| a.first()).and_then(|a| a.get("type")).and_then(|t| t.get("generic")).and_then(|g| g.as_str());
                match (name.as_deref(), on, arg) {
                    (Some("Borrow"), Some(k), Some(a)) if a == q => if let Some(c) = base.get(k) { return Some(c.clone()); },
                    (Some("Equivalent"), Some(o), Some(k)) if o == q => if let Some(c) = base.get(k) { return Some(c.clone()); },
                    _ => {}
                }
            }
        }
        for p in generics["params"].as_array().into_iter().flatten() {
            if p["name"] != q { continue; }
            for b in p["kind"]["type"]["bounds"].as_array().into_iter().flatten() {
                let tr = &b["trait_bound"]["trait"];
                let name = tr["path"].as_str().map(|p| p.rsplit("::").next().unwrap_or(p).to_string());
                let arg = tr["args"]["angle_bracketed"]["args"].as_array()
                    .and_then(|a| a.first()).and_then(|a| a.get("type")).and_then(|t| t.get("generic")).and_then(|g| g.as_str());
                if let (Some("Equivalent"), Some(k)) = (name.as_deref(), arg) {
                    if let Some(c) = base.get(k) { return Some(c.clone()); }
                }
            }
        }
        None
    };
    for p in generics["params"].as_array().into_iter().flatten() {
        let Some(t) = p["kind"].get("type") else {
            if p["kind"].get("lifetime").is_some() { continue; }
            return Err("has a const generic parameter".into());
        };
        let name = p["name"].as_str().unwrap_or("").to_string();
        let mut bounds: Vec<Value> = t["bounds"].as_array().cloned().unwrap_or_default();
        for w in generics["where_predicates"].as_array().into_iter().flatten() {
            let bp = &w["bound_predicate"];
            if bp["type"].get("generic").and_then(|g| g.as_str()) == Some(name.as_str()) {
                bounds.extend(bp["bounds"].as_array().cloned().unwrap_or_default());
            }
        }
        match concrete_for_bounds(&Value::Array(bounds)).or_else(|| lookup_key(&name)) {
            Some(c) => { out.insert(name, c); }
            None => return Err("generic (wrap a concrete instance in lib.rs)".into()),
        }
    }
    Ok(out)
}

/// The `Item` of a standard-library iterator type (not in the crate's index):
/// `slice::Iter<T>` → `&T`, `IntoIter<T>` → `T`, `Chars` → `char`, `Bytes` →
/// `u8`, `Split*`/`Lines` → `&str`, map `Keys<K, V>`/`Values<K, V>` → `&K`/`&V`.
fn std_iterator_item(t: &Value) -> Option<Value> {
    let name = last_seg(t)?;
    let args = type_args(t);
    let r = |v: &Value| serde_json::json!({"borrowed_ref": {"lifetime": null, "is_mutable": false, "type": v}});
    match (name, args.len()) {
        ("Iter", 1) => Some(r(args[0])),
        ("IntoIter", 1) => Some(args[0].clone()),
        ("Keys", 2) => Some(r(args[0])),
        ("Values", 2) => Some(r(args[1])),
        ("Chars", 0) => Some(serde_json::json!({"primitive": "char"})),
        ("Bytes", 0) => Some(serde_json::json!({"primitive": "u8"})),
        ("Lines" | "Split" | "SplitWhitespace" | "SplitTerminator" | "RSplit" | "SplitN" | "SplitAsciiWhitespace", _) =>
            Some(r(&serde_json::json!({"primitive": "str"}))),
        _ => None,
    }
}

/// `t` with every `{"generic": G}` replaced by `binds[G]`.
fn apply(t: &Value, binds: &HashMap<String, Value>) -> Value {
    match t {
        Value::Object(o) => {
            if let Some(g) = o.get("generic").and_then(|g| g.as_str()) {
                if let Some(c) = binds.get(g) { return c.clone(); }
            }
            Value::Object(o.iter().map(|(k, v)| (k.clone(), apply(v, binds))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| apply(v, binds)).collect()),
        other => other.clone(),
    }
}

/// The last segment of a resolved path's name.
fn last_seg(t: &Value) -> Option<&str> {
    t.get("resolved_path")?["path"].as_str().map(|p| p.rsplit("::").next().unwrap_or(p))
}

/// Match the pattern type `pat` (with generics) against `conc`, binding the
/// generics. Paths compare by id when both have one, else by their last name.
fn unify(pat: &Value, conc: &Value, binds: &mut HashMap<String, Value>) -> bool {
    if let Some(g) = pat.get("generic").and_then(|g| g.as_str()) {
        if g == "Self" { return true; }
        if let Some(b) = binds.get(g) { return b == conc || describe_eq(b, conc); }
        binds.insert(g.to_string(), conc.clone());
        return true;
    }
    if let (Some(a), Some(b)) = (pat.get("primitive"), conc.get("primitive")) { return a == b; }
    if let (Some(a), Some(b)) = (pat.get("borrowed_ref"), conc.get("borrowed_ref")) {
        return a["is_mutable"] == b["is_mutable"] && unify(&a["type"], &b["type"], binds);
    }
    if let (Some(a), Some(b)) = (pat.get("slice"), conc.get("slice")) { return unify(a, b, binds); }
    if let (Some(a), Some(b)) = (pat.get("resolved_path"), conc.get("resolved_path")) {
        let same = match (id_str(&a["id"]), id_str(&b["id"])) {
            (Some(x), Some(y)) => x == y,
            _ => last_seg(pat) == last_seg(conc),
        };
        if !same { return false; }
        let pa = type_args(pat);
        let ca = type_args(conc);
        // The concrete side may leave defaulted parameters out.
        for (i, p) in pa.iter().enumerate() {
            match ca.get(i) {
                Some(c) => if !unify(p, c, binds) { return false; },
                None => if p.get("generic").is_none() { continue; } else { binds.entry(p["generic"].as_str().unwrap().to_string()).or_insert(Value::Null); },
            }
        }
        return true;
    }
    if let (Some(a), Some(b)) = (pat.get("tuple"), conc.get("tuple")) { return a == b; }
    false
}

fn describe_eq(a: &Value, b: &Value) -> bool {
    last_seg(a).is_some() && last_seg(a) == last_seg(b)
}

/// Parse a Rust type as written in sic.toml (`HashMap<String, i64>`, `&str`,
/// `Vec<u8>`) into rustdoc's JSON form. `resolve` gives a crate type's id.
fn parse_type(s: &str, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Value, String> {
    fn toks(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        for c in s.chars() {
            if c.is_alphanumeric() || c == '_' || c == ':' { cur.push(c); continue; }
            if !cur.is_empty() { out.push(std::mem::take(&mut cur)); }
            if !c.is_whitespace() { out.push(c.to_string()); }
        }
        if !cur.is_empty() { out.push(cur); }
        out
    }
    fn ty(t: &[String], i: &mut usize, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Value, String> {
        let tok = t.get(*i).cloned().ok_or("unexpected end of type")?;
        *i += 1;
        match tok.as_str() {
            "&" => {
                let m = t.get(*i).map(|s| s == "mut").unwrap_or(false);
                if m { *i += 1; }
                let inner = ty(t, i, resolve)?;
                Ok(serde_json::json!({"borrowed_ref": {"lifetime": null, "is_mutable": m, "type": inner}}))
            }
            "[" => {
                let inner = ty(t, i, resolve)?;
                if t.get(*i).map(|s| s.as_str()) != Some("]") { return Err("expected `]`".into()); }
                *i += 1;
                Ok(serde_json::json!({"slice": inner}))
            }
            "(" => {
                if t.get(*i).map(|s| s.as_str()) != Some(")") { return Err("tuples are not supported".into()); }
                *i += 1;
                Ok(serde_json::json!({"tuple": []}))
            }
            name => {
                let last = name.rsplit("::").next().unwrap_or(name);
                let mut args: Vec<Value> = Vec::new();
                if t.get(*i).map(|s| s.as_str()) == Some("<") {
                    *i += 1;
                    loop {
                        args.push(ty(t, i, resolve)?);
                        match t.get(*i).map(|s| s.as_str()) {
                            Some(",") => *i += 1,
                            Some(">") => { *i += 1; break; }
                            _ => return Err("expected `,` or `>`".into()),
                        }
                    }
                }
                const PRIMS: &[&str] = &["i8", "i16", "i32", "i64", "i128", "u8", "u16", "u32", "u64", "u128",
                    "isize", "usize", "f32", "f64", "bool", "char", "str"];
                if PRIMS.contains(&last) && args.is_empty() { return Ok(serde_json::json!({"primitive": last})); }
                let id = resolve(name).map(|i| Value::String(i)).unwrap_or(Value::Null);
                let a: Vec<Value> = args.into_iter().map(|t| serde_json::json!({"type": t})).collect();
                let args = if a.is_empty() { Value::Null } else { serde_json::json!({"angle_bracketed": {"args": a, "constraints": []}}) };
                Ok(serde_json::json!({"resolved_path": {"path": name, "id": id, "args": args}}))
            }
        }
    }
    let t = toks(s);
    let mut i = 0;
    let v = ty(&t, &mut i, resolve)?;
    if i != t.len() { return Err(format!("unexpected `{}`", t[i])); }
    Ok(v)
}

fn has_args(rp: &Value) -> bool {
    rp["args"]["angle_bracketed"]["args"].as_array().map_or(false, |a| !a.is_empty())
}

fn type_args(t: &Value) -> Vec<&Value> {
    t["resolved_path"]["args"]["angle_bracketed"]["args"].as_array().into_iter().flatten()
        .filter_map(|a| a.get("type")).collect()
}

fn single_arg(t: &Value) -> Option<&Value> {
    let a = type_args(t);
    if a.len() == 1 { Some(a[0]) } else { None }
}

const PRELUDE: &str = r#"#![allow(dead_code, unused_imports, unused_macros, clippy::all)]

// A `Result`'s error as text: its `Display`, else its `Debug`, else "error"
// (picked at compile time by autoref specialization).
struct SicErr<T>(T);
trait SicErrDisplay { fn sic_msg(&self) -> String; }
impl<T: std::fmt::Display> SicErrDisplay for &&SicErr<T> { fn sic_msg(&self) -> String { self.0.to_string() } }
trait SicErrDebug { fn sic_msg(&self) -> String; }
impl<T: std::fmt::Debug> SicErrDebug for &SicErr<T> { fn sic_msg(&self) -> String { format!("{:?}", self.0) } }
trait SicErrAny { fn sic_msg(&self) -> String; }
impl<T> SicErrAny for SicErr<T> { fn sic_msg(&self) -> String { String::from("error") } }
macro_rules! sic_err { ($e:expr) => { (&&&SicErr($e)).sic_msg() } }

"#;

/// A generic type instance requested in sic.toml: the Rust type and the name
/// SIC sees.
pub struct Instance {
    pub ty: String,
    pub name: String,
}

pub fn generate(api: &Value, krate: &str, crate_name: &str, version: &str, instances: &[Instance]) -> Result<Generated, String> {
    let fv = api["format_version"].as_u64().unwrap_or(0);
    if fv < FORMAT_MIN {
        return Err(format!("rustdoc JSON format {} is too old (need {}+); update Rust", fv, FORMAT_MIN));
    }
    let index = api["index"].as_object().ok_or("rustdoc JSON has no index")?;
    let root = id_str(&api["root"]).ok_or("rustdoc JSON has no root")?;
    let mut g = Gen {
        index, krate: krate.to_string(), types: HashMap::new(), out: String::new(),
        bound: 0, skipped: Vec::new(), used_names: HashSet::new(),
        cloneable: HashSet::new(), trait_paths: HashMap::new(), subst: HashMap::new(),
        inst: None, impl_subst: HashMap::new(),
    };
    let entries = g.collect(&root);
    for e in &entries {
        if g.item(&e.id).map_or(false, |it| it["inner"].get("trait").is_some()) {
            let p = g.path_of(e);
            g.trait_paths.insert(e.id.clone(), p);
        }
    }

    // Types first, so signatures can refer to them.
    let mut type_entries: Vec<(&Entry, &str)> = Vec::new();
    let mut tnames: HashSet<String> = HashSet::new();
    for e in &entries {
        let Some(it) = g.item(&e.id) else { continue };
        let kind = if it["inner"].get("struct").is_some() { "struct" }
            else if it["inner"].get("enum").is_some() { "enum" } else { continue };
        let shown = g.display_path(e);
        if it["deprecation"].is_object() { g.skip(format!("type `{}`", shown), "deprecated"); continue; }
        let generic = it["inner"][kind]["generics"]["params"].as_array().into_iter().flatten()
            .any(|p| p["kind"].get("lifetime").is_none());
        if generic || it["inner"][kind]["generics"]["params"].as_array().map_or(false, |a| !a.is_empty()) {
            if !instances.iter().any(|i| i.ty.split('<').next().map(|b| b.trim()) == Some(e.name.as_str())) {
                g.skip(format!("type `{}`", shown), "generic (bind an instance: `instantiate` in sic.toml) or has a lifetime");
            }
            continue;
        }
        let mut w = e.name.clone();
        if tnames.contains(&w) { w = format!("{}{}", e.prefix.iter().map(|p| camel(p)).collect::<String>(), e.name); }
        if tnames.contains(&w) || SIC_TYPE_RESERVED.contains(&w.as_str()) {
            g.skip(format!("type `{}`", shown), "its name is taken");
            continue;
        }
        tnames.insert(w.clone());
        if g.trait_impls(it, kind).iter().any(|t| t == "Clone" || t == "Copy") { g.cloneable.insert(w.clone()); }
        g.types.insert(e.id.clone(), TypeBind { wrapper: w, path: g.path_of(e) });
        type_entries.push((e, kind));
    }
    // Generic types made concrete in sic.toml (`HashMap<String, i64>` as
    // `StrIntMap`): (entry, kind, wrapper, Rust type, its JSON form).
    let mut inst_entries: Vec<(&Entry, &str, String, String, Value)> = Vec::new();
    for ins in instances {
        let base = ins.ty.split('<').next().unwrap_or("").trim().to_string();
        let found = entries.iter().find(|e| {
            let full = { let mut v = e.prefix.clone(); v.push(e.name.clone()); v.join("::") };
            (e.name == base || full == base) && g.item(&e.id).map_or(false, |it| it["inner"].get("struct").is_some() || it["inner"].get("enum").is_some())
        });
        let Some(e) = found else {
            return Err(format!("sic.toml: instance `{}`: no public type `{}` in {}", ins.ty, base, crate_name));
        };
        let it = g.item(&e.id).unwrap();
        let kind = if it["inner"].get("struct").is_some() { "struct" } else { "enum" };
        if tnames.contains(&ins.name) || SIC_TYPE_RESERVED.contains(&ins.name.as_str())
            || !ins.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(format!("sic.toml: instance name `{}` is taken or invalid", ins.name));
        }
        let types_snapshot: HashMap<String, String> = g.types.iter().map(|(id, b)| (b.wrapper.clone(), id.clone())).collect();
        let resolve = |n: &str| -> Option<String> {
            let last = n.rsplit("::").next().unwrap_or(n);
            if last == base.rsplit("::").next().unwrap_or(&base) { return Some(e.id.clone()); }
            types_snapshot.get(last).cloned()
        };
        let mut json = parse_type(&ins.ty, &resolve).map_err(|m| format!("sic.toml: instance `{}`: {}", ins.ty, m))?;
        // Defaulted parameters (`S = DefaultHashBuilder`) take their default.
        let params: Vec<Value> = it["inner"][kind]["generics"]["params"].as_array().cloned().unwrap_or_default();
        let tparams: Vec<&Value> = params.iter().filter(|p| p["kind"].get("type").is_some()).collect();
        let given = type_args(&json).len();
        if given > tparams.len() {
            return Err(format!("sic.toml: instance `{}`: `{}` takes {} type parameter(s)", ins.ty, base, tparams.len()));
        }
        for p in &tparams[given..] {
            let d = &p["kind"]["type"]["default"];
            if d.is_null() {
                return Err(format!("sic.toml: instance `{}`: give `{}` all its type parameters", ins.ty, base));
            }
            let args = json["resolved_path"]["args"].clone();
            let mut list: Vec<Value> = args["angle_bracketed"]["args"].as_array().cloned().unwrap_or_default();
            list.push(serde_json::json!({"type": d}));
            json["resolved_path"]["args"] = serde_json::json!({"angle_bracketed": {"args": list, "constraints": []}});
        }
        let args_text = ins.ty.find('<').map(|i| ins.ty[i..].to_string()).unwrap_or_default();
        let rust = format!("{}{}", g.path_of(e), args_text);
        tnames.insert(ins.name.clone());
        if g.trait_impls(it, kind).iter().any(|t| t == "Clone" || t == "Copy") { g.cloneable.insert(ins.name.clone()); }
        inst_entries.push((e, kind, ins.name.clone(), rust, json));
    }
    // Free functions' SIC names must not collide with a type (its namespace).
    let mut fn_entries: Vec<(&Entry, String)> = Vec::new();
    let mut const_entries: Vec<(&Entry, String)> = Vec::new();
    for e in &entries {
        let Some(it) = g.item(&e.id) else { continue };
        let inner = &it["inner"];
        let shown = g.display_path(e);
        let is_fn = inner.get("function").is_some();
        let is_const = inner.get("constant").is_some();
        if !is_fn && !is_const {
            if inner.get("struct").is_none() && inner.get("enum").is_none() {
                let kind = inner.as_object().and_then(|o| o.keys().next().cloned()).unwrap_or_default();
                if matches!(kind.as_str(), "trait" | "macro" | "static" | "union" | "type_alias" | "proc_macro") {
                    g.skip(format!("{} `{}`", kind.replace('_', " "), shown), "not bindable");
                }
            }
            continue;
        }
        if it["deprecation"].is_object() { g.skip(format!("`{}`", shown), "deprecated"); continue; }
        let mut name: Vec<String> = e.prefix.clone();
        name.push(if is_const { e.name.to_lowercase() } else { e.name.clone() });
        let name = name.join("_");
        if tnames.contains(&camel(&name)) || g.used_names.contains(&name) {
            g.skip(format!("`{}`", shown), "its SIC name collides with a type or another function");
            continue;
        }
        g.used_names.insert(name.clone());
        if is_fn { fn_entries.push((e, name)); } else { const_entries.push((e, name)); }
    }

    g.out.push_str(&format!(
        "// Generated by `cargo sic` from {} {} — regenerated on every build; do not\n\
         // edit. Hand-written wrappers belong in lib.rs.\n", crate_name, version));
    g.out.push_str(PRELUDE);

    for (e, kind) in &type_entries {
        let it = g.item(&e.id).unwrap();
        let tb = g.types.get(&e.id).unwrap();
        let (w, path) = (tb.wrapper.clone(), tb.path.clone());
        let shown = g.display_path(e);
        g.emit_type(it, kind, &w, &path, &shown, None);
    }
    for (e, kind, w, rust, json) in &inst_entries {
        let it = g.item(&e.id).unwrap();
        g.inst = Some((e.id.clone(), w.clone()));
        let shown = w.clone();
        g.emit_type(it, kind, w, rust, &shown, Some(json));
        g.inst = None;
    }
    for (e, name) in &fn_entries {
        let it = g.item(&e.id).unwrap();
        let path = g.path_of(e);
        let mark = g.out.len();
        match g.emit_fn(it, name, &path, None, "") {
            Ok(()) => g.out.push('\n'),
            Err(why) => { g.out.truncate(mark); let s = g.display_path(e); g.skip(format!("fn `{}`", s), &why); }
        }
    }
    for (e, name) in &const_entries {
        let it = g.item(&e.id).unwrap();
        let path = g.path_of(e);
        match g.ret_plain(&it["inner"]["constant"]["type"], None) {
            Ok((ty, conv)) if ty != "()" => {
                g.doc_comment(it, "");
                let _ = writeln!(g.out, "pub fn {}() -> {} {{\n    {}\n}}\n", name, ty, conv(&path));
                g.bound += 1;
            }
            Ok(_) => {}
            Err(why) => { let s = g.display_path(e); g.skip(format!("const `{}`", s), &why); }
        }
    }
    if !g.skipped.is_empty() {
        g.out.push_str("// Not bound (wrap these by hand in lib.rs if you need them):\n");
        for s in &g.skipped { let _ = writeln!(g.out, "//   {}", s); }
    }
    Ok(Generated { code: g.out, bound: g.bound, skipped: g.skipped.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_names() {
        assert_eq!(camel("text_shout"), "TextShout");
    }

    #[test]
    fn small_api() {
        // rustdoc JSON shape (format 61), trimmed to what the generator reads.
        let api: Value = serde_json::from_str(r#"{
          "format_version": 61, "root": 1,
          "index": {
            "1": {"id":1,"name":"k","inner":{"module":{"items":[2,3,4]}}},
            "2": {"id":2,"name":"shout","docs":"Shout it.\n\nMore.","deprecation":null,"inner":{"function":{
                  "sig":{"inputs":[["s",{"borrowed_ref":{"is_mutable":false,"type":{"primitive":"str"}}}]],
                         "output":{"resolved_path":{"path":"String","id":9,"args":null}},"is_c_variadic":false},
                  "generics":{"params":[]},"header":{"is_async":false,"is_unsafe":false}}}},
            "3": {"id":3,"name":"ident","deprecation":null,"inner":{"function":{
                  "sig":{"inputs":[["x",{"generic":"T"}]],"output":{"generic":"T"},"is_c_variadic":false},
                  "generics":{"params":[{"name":"T","kind":{"type":{}}}]},"header":{}}}},
            "4": {"id":4,"name":"LIMIT","deprecation":null,"inner":{"constant":{"type":{"primitive":"u32"}}}}
          }}"#).unwrap();
        let g = generate(&api, "k", "k", "0.1.0", &[]).unwrap();
        assert!(g.code.contains("/// Shout it.\npub fn shout(s: &str) -> String {\n    ::k::shout(s)\n}"), "{}", g.code);
        assert!(g.code.contains("pub fn limit() -> u32 {\n    ::k::LIMIT\n}"), "{}", g.code);
        assert!(g.code.contains("fn `ident`: generic"), "{}", g.code);
        assert_eq!((g.bound, g.skipped), (2, 1));
    }
}
