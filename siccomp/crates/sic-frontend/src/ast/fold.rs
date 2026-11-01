//! Constants of sic's strings: what the runtime computes, computed from literals.

use super::{BinOpKind, Expr, ExprKind};

/// The bytes of a string literal: not always UTF-8 (`"\xff"`).
fn lit(e: &Expr) -> Option<&[u8]> {
    match &e.kind { ExprKind::StringLit(s) => Some(s.as_bytes()), _ => None }
}

fn string_lit(b: &[u8]) -> ExprKind {
    // Bytes of a literal, cut at ASCII or joined: as `lit` found them.
    ExprKind::StringLit(unsafe { String::from_utf8_unchecked(b.to_vec()) })
}

/// C's `isspace`, what `.trim()` removes.
fn is_space(c: u8) -> bool { matches!(c, b' ' | 9..=13) }

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() { return Some(0); }
    h.windows(n.len()).position(|w| w == n)
}

/// What the runtime computes from literals, with its results: `.length` counts
/// UTF-8 code points, `.size` and `.find` are in bytes, `==` compares bytes.
pub fn fold_string(e: &Expr) -> Option<ExprKind> {
    match &e.kind {
        ExprKind::BinOp { op, lhs, rhs } => {
            let (l, r) = (lit(lhs)?, lit(rhs)?);
            match op {
                BinOpKind::Add => Some(string_lit(&[l, r].concat())),
                BinOpKind::Eq => Some(ExprKind::BoolLit(l == r)),
                BinOpKind::Ne => Some(ExprKind::BoolLit(l != r)),
                _ => None,
            }
        }
        ExprKind::Field { base, name } => {
            let s = lit(base)?;
            match name.as_str() {
                "size" => Some(ExprKind::UIntLit(s.len() as u64, true)),
                "length" => Some(ExprKind::UIntLit(s.iter().filter(|b| **b & 0xC0 != 0x80).count() as u64, true)),
                _ => None,
            }
        }
        ExprKind::Call { func, args } => {
            let ExprKind::Field { base, name } = &func.kind else { return None };
            let s = lit(base)?;
            match (name.as_str(), args.as_slice()) {
                ("trim" | "ltrim" | "rtrim", []) => {
                    let start = if name == "rtrim" { 0 } else { s.iter().position(|c| !is_space(*c)).unwrap_or(s.len()) };
                    let end = if name == "ltrim" { s.len() } else { s.iter().rposition(|c| !is_space(*c)).map_or(start, |p| p + 1) };
                    Some(string_lit(&s[start..end.max(start)]))
                }
                ("starts_with", [a]) => Some(ExprKind::BoolLit(s.starts_with(lit(a)?))),
                ("ends_with", [a]) => Some(ExprKind::BoolLit(s.ends_with(lit(a)?))),
                ("contains", [a]) => Some(ExprKind::BoolLit(find(s, lit(a)?).is_some())),
                ("find", [a]) => Some(ExprKind::IntLit(find(s, lit(a)?).map_or(-1, |p| p as i64), true)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `e` with its strings folded, operands first, where a constant is needed before
/// the fold pass runs (an array dimension is part of a type).
pub fn fold_strings(e: &mut Expr) {
    match &mut e.kind {
        ExprKind::BinOp { lhs, rhs, .. } => { fold_strings(lhs); fold_strings(rhs); }
        ExprKind::Field { base, .. } => fold_strings(base),
        ExprKind::Call { func, args } => {
            fold_strings(func);
            args.iter_mut().for_each(fold_strings);
        }
        ExprKind::Cast { expr, .. } | ExprKind::Unary { expr, .. } => fold_strings(expr),
        _ => {}
    }
    if let Some(k) = fold_string(e) { e.kind = k; }
}
