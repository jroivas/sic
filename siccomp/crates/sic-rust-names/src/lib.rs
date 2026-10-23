//! How sic and `cargo sic` name a Rust generic instance.
//!
//! sic asks for an instance by its Rust type (`hash_map::HashMap<i64, String>`)
//! and expects the binding to define it under `<Generic>__<arguments>`
//! (`hash_map::HashMap__i64__String`); `cargo sic` generates it under that
//! name. Both use these functions, so the two spellings cannot drift apart.

/// An instance's name suffix: each type argument reduced to identifier
/// characters (a run of others becomes one `_`), joined by `__`
/// (`["i64", "String"]` → `i64__String`, `["Vec<u8>"]` → `Vec_u8`).
pub fn args_mangled(args: &[String]) -> String {
    args.iter().map(|a| {
        let mut o = String::new();
        for c in a.chars() {
            if c.is_ascii_alphanumeric() { o.push(c); } else if !o.ends_with('_') { o.push('_'); }
        }
        o.trim_matches('_').to_string()
    }).collect::<Vec<_>>().join("__")
}

/// The top-level type arguments of `Base<A, B<C>>` (`A`, `B<C>`), trimmed.
pub fn type_arg_texts(ty: &str) -> Vec<String> {
    let Some(start) = ty.find('<') else { return Vec::new() };
    let inner = &ty[start + 1..ty.rfind('>').unwrap_or(ty.len())];
    let mut out = Vec::new();
    let (mut depth, mut cur) = (0i32, String::new());
    for c in inner.chars() {
        match c {
            '<' | '(' | '[' => { depth += 1; cur.push(c); }
            '>' | ')' | ']' => { depth -= 1; cur.push(c); }
            ',' if depth == 0 => { out.push(cur.trim().to_string()); cur.clear(); }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() { out.push(cur.trim().to_string()); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangling() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(args_mangled(&v(&["i64", "String"])), "i64__String");
        assert_eq!(args_mangled(&v(&["Vec<u8>"])), "Vec_u8");
        assert_eq!(args_mangled(&v(&["hash_map::Iter"])), "hash_map_Iter");
    }

    #[test]
    fn arguments() {
        assert_eq!(type_arg_texts("HashMap<i64, Vec<String>>"), vec!["i64", "Vec<String>"]);
        assert_eq!(type_arg_texts("Stack<u8>"), vec!["u8"]);
        assert!(type_arg_texts("Version").is_empty());
    }

    /// The round trip sic relies on: the Rust type it writes, split back by
    /// `cargo sic`, names the same instance.
    #[test]
    fn round_trip() {
        let args = vec!["i64".to_string(), "String".to_string()];
        let ty = format!("hash_map::HashMap<{}>", args.join(", "));
        assert_eq!(args_mangled(&type_arg_texts(&ty)), args_mangled(&args));
    }
}
