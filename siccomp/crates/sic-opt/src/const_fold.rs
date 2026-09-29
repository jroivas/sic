//! AST-level constant folding: fold operations whose operands are literals into
//! a single literal. Value-preserving and type-neutral, so it is sound on the
//! untyped AST (width-sensitive folding is left to the typed IR `ir-fold` pass).

use sic_frontend::ast::*;
use crate::pass::AstPass;
use crate::visit::{MutVisitor, walk_expr};

#[derive(Default)]
pub struct ConstFold { changed: bool }

impl ConstFold {
    pub fn new() -> Self { ConstFold { changed: false } }
}

impl AstPass for ConstFold {
    fn name(&self) -> &'static str { "const-fold" }
    fn run(&mut self, tu: &mut TranslationUnit) -> bool {
        self.changed = false;
        self.visit_tu(tu);
        self.changed
    }
}

impl MutVisitor for ConstFold {
    fn visit_expr(&mut self, e: &mut Expr) {
        walk_expr(self, e);   // fold children first (bottom-up)
        self.fold(e);
    }
}

/// A signed integer literal value + its 64-bit-ness, from either an `IntLit` or
/// a `CharLit` (whose C type is already `int`).
fn as_int(e: &Expr) -> Option<(i64, bool)> {
    match &e.kind {
        ExprKind::IntLit(v, w) => Some((*v, *w)),
        ExprKind::CharLit(v) => Some((*v as i64, false)),
        _ => None,
    }
}

impl ConstFold {
    fn set(&mut self, e: &mut Expr, kind: ExprKind) {
        e.kind = kind;
        self.changed = true;
    }

    fn fold(&mut self, e: &mut Expr) {
        match &e.kind {
            ExprKind::BinOp { op, lhs, rhs } => {
                let op = *op;
                if let (Some((l, lw)), Some((r, rw))) = (as_int(lhs), as_int(rhs)) {
                    if let Some(k) = fold_int(op, l, r, lw || rw) {
                        self.set(e, k);
                    }
                } else if let (ExprKind::UIntLit(l, lw), ExprKind::UIntLit(r, rw)) =
                    (&lhs.kind, &rhs.kind)
                {
                    if let Some(k) = fold_uint(op, *l, *r, *lw || *rw) {
                        self.set(e, k);
                    }
                } else if let (ExprKind::FloatLit(l), ExprKind::FloatLit(r)) =
                    (&lhs.kind, &rhs.kind)
                {
                    if let Some(k) = fold_float(op, *l, *r) {
                        self.set(e, k);
                    }
                }
            }
            ExprKind::Unary { op, expr: inner } => {
                let op = *op;
                if let Some((v, w)) = as_int(inner) {
                    match op {
                        UnOpKind::Neg => self.set(e, ExprKind::IntLit(v.wrapping_neg(), w)),
                        UnOpKind::BitNot => self.set(e, ExprKind::IntLit(!v, w)),
                        UnOpKind::Not => self.set(e, ExprKind::IntLit(i64::from(v == 0), false)),
                        _ => {}
                    }
                } else if let ExprKind::FloatLit(v) = inner.kind {
                    match op {
                        UnOpKind::Neg => self.set(e, ExprKind::FloatLit(-v)),
                        UnOpKind::Not => self.set(e, ExprKind::IntLit(i64::from(v == 0.0), false)),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Fold a signed-integer binary op. Result of a comparison/logical op is a plain
/// 32-bit `int` `0`/`1` (as in C); arithmetic keeps the wider operand's width.
fn fold_int(op: BinOpKind, l: i64, r: i64, w: bool) -> Option<ExprKind> {
    use BinOpKind::*;
    let arith = |v: i64| {
        // Promote to 64-bit if either operand was, or the result no longer fits
        // a 32-bit type.
        let is64 = w || v < i32::MIN as i64 || v > u32::MAX as i64;
        ExprKind::IntLit(v, is64)
    };
    let boolean = |b: bool| ExprKind::IntLit(i64::from(b), false);
    Some(match op {
        Add => arith(l.wrapping_add(r)),
        Sub => arith(l.wrapping_sub(r)),
        Mul => arith(l.wrapping_mul(r)),
        // `/` and `%` are NOT folded on the untyped AST: their result is
        // type-sensitive — `1/3` is `0` as an integer but `0.333…` once a
        // float/`fixed` context promotes the literals (sic.md §"Built-in fixed
        // point"). Folding here would bake in the integer value before lowering
        // resolves the type, so it is left to the typed `ir-fold` pass, which folds
        // it correctly at the operands' resolved type.
        BitAnd => arith(l & r),
        BitOr => arith(l | r),
        BitXor => arith(l ^ r),
        Shl => arith(l.wrapping_shl((r & 63) as u32)),
        Shr => arith(l.wrapping_shr((r & 63) as u32)),
        Eq => boolean(l == r),
        Ne => boolean(l != r),
        Lt => boolean(l < r),
        Le => boolean(l <= r),
        Gt => boolean(l > r),
        Ge => boolean(l >= r),
        LogAnd => boolean(l != 0 && r != 0),
        LogOr => boolean(l != 0 || r != 0),
        _ => return None,
    })
}

fn fold_uint(op: BinOpKind, l: u64, r: u64, w: bool) -> Option<ExprKind> {
    use BinOpKind::*;
    // Arithmetic wraps at the OPERAND width: two 32-bit `unsigned int`s produce a
    // 32-bit result (C 6.2.5/9 — unsigned overflow is defined modular arithmetic),
    // so `0xFFFFFFFFu + 1u` is `0u`, not the 64-bit `0x100000000`. Only a 64-bit
    // operand (`w`) yields a 64-bit result. (Previously this promoted to 64-bit
    // whenever the value exceeded `u32::MAX`, which silently disagreed with the
    // runtime and could flip a constant-folded branch condition.)
    let arith = |v: u64| {
        if w { ExprKind::UIntLit(v, true) }
        else { ExprKind::UIntLit(v & 0xFFFF_FFFF, false) }
    };
    let boolean = |b: bool| ExprKind::IntLit(i64::from(b), false);
    Some(match op {
        Add => arith(l.wrapping_add(r)),
        Sub => arith(l.wrapping_sub(r)),
        Mul => arith(l.wrapping_mul(r)),
        // `/` and `%` are left to the typed `ir-fold` pass — their value is
        // type-sensitive under float/`fixed` promotion (see `fold_int`).
        BitAnd => arith(l & r),
        BitOr => arith(l | r),
        BitXor => arith(l ^ r),
        Shl => arith(l.wrapping_shl((r & 63) as u32)),
        Shr => arith(l.wrapping_shr((r & 63) as u32)),
        Eq => boolean(l == r),
        Ne => boolean(l != r),
        Lt => boolean(l < r),
        Le => boolean(l <= r),
        Gt => boolean(l > r),
        Ge => boolean(l >= r),
        LogAnd => boolean(l != 0 && r != 0),
        LogOr => boolean(l != 0 || r != 0),
        _ => return None,
    })
}

fn fold_float(op: BinOpKind, l: f64, r: f64) -> Option<ExprKind> {
    use BinOpKind::*;
    let boolean = |b: bool| ExprKind::IntLit(i64::from(b), false);
    Some(match op {
        Add => ExprKind::FloatLit(l + r),
        Sub => ExprKind::FloatLit(l - r),
        Mul => ExprKind::FloatLit(l * r),
        Div if r != 0.0 => ExprKind::FloatLit(l / r),
        Eq => boolean(l == r),
        Ne => boolean(l != r),
        Lt => boolean(l < r),
        Le => boolean(l <= r),
        Gt => boolean(l > r),
        Ge => boolean(l >= r),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visit::MutVisitor;
    use sic_frontend::lexer::Span;

    fn e(k: ExprKind) -> Expr { Expr::new(k, Span::default()) }
    fn int(n: i64) -> Box<Expr> { Box::new(e(ExprKind::IntLit(n, false))) }

    #[test]
    fn folds_nested_arithmetic() {
        // (1 + 2) * 4  =>  12
        let mut cf = ConstFold::new();
        let inner = e(ExprKind::BinOp { op: BinOpKind::Add, lhs: int(1), rhs: int(2) });
        let mut x = e(ExprKind::BinOp { op: BinOpKind::Mul, lhs: Box::new(inner), rhs: int(4) });
        cf.visit_expr(&mut x);
        assert!(matches!(x.kind, ExprKind::IntLit(12, _)));
    }

    #[test]
    fn folds_comparison_to_bool_int() {
        let mut cf = ConstFold::new();
        let mut c = e(ExprKind::BinOp { op: BinOpKind::Lt, lhs: int(5), rhs: int(3) });
        cf.visit_expr(&mut c);
        assert!(matches!(c.kind, ExprKind::IntLit(0, _)));
    }
}
