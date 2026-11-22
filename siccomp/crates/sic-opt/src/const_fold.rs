//! AST-level constant folding: fold operations whose operands are literals into
//! a single literal. Value-preserving and type-neutral, so it is sound on the
//! untyped AST (width-sensitive folding is left to the typed IR `ir-fold` pass).

use sic_frontend::ast::*;
use sic_frontend::ast::fold::fold_string;
use crate::pass::AstPass;
use crate::visit::{MutVisitor, walk_expr};

#[derive(Default)]
pub struct ConstFold { changed: bool, sic: bool }

impl ConstFold {
    pub fn new() -> Self { ConstFold { changed: false, sic: false } }

    /// With sic's strings: what is written with literals only is a literal.
    pub fn for_sic(sic: bool) -> Self { ConstFold { changed: false, sic } }
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
        if self.sic {
            if let Some(k) = fold_string(e) { return self.set(e, k); }
        }
        // A constant condition, when the two sides are of one kind: the usual
        // conversions may otherwise give the result a type neither has.
        if let ExprKind::Ternary { cond, then, else_ } = &e.kind {
            if std::mem::discriminant(&then.kind) == std::mem::discriminant(&else_.kind)
                && matches!(then.kind, ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::FloatLit(_)
                    | ExprKind::CharLit(_) | ExprKind::BoolLit(_) | ExprKind::StringLit(_))
            {
                if let Some(c) = truth(cond) {
                    let k = if c { then.kind.clone() } else { else_.kind.clone() };
                    return self.set(e, k);
                }
            }
        }
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
                        // `-INT_MIN` overflows: left to `ir-fold`, as above.
                        UnOpKind::Neg => if let Some(n) = v.checked_neg().filter(|&n| w || i32::try_from(n).is_ok()) {
                            self.set(e, ExprKind::IntLit(n, w))
                        },
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

fn truth(e: &Expr) -> Option<bool> {
    match &e.kind {
        ExprKind::IntLit(v, _) => Some(*v != 0),
        ExprKind::UIntLit(v, _) => Some(*v != 0),
        ExprKind::CharLit(v) => Some(*v != 0),
        ExprKind::BoolLit(b) => Some(*b),
        _ => None,
    }
}

/// Fold a signed-integer binary op. Result of a comparison/logical op is a plain
/// 32-bit `int` `0`/`1` (as in C); arithmetic keeps the wider operand's width.
fn fold_int(op: BinOpKind, l: i64, r: i64, w: bool) -> Option<ExprKind> {
    use BinOpKind::*;
    // The result has the operands' type: `long` if either is (`w`), else `int`.
    // One that overflows it is not folded — it was made a wider literal, where
    // the operation at run time wraps (and `unsafe` traps it): the typed
    // `ir-fold` pass folds it at the right width, and the guard still sees it.
    let fits = |v: i64| w || i32::try_from(v).is_ok();
    let arith = |v: Option<i64>| v.filter(|&v| fits(v)).map(|v| ExprKind::IntLit(v, w));
    let boolean = |b: bool| ExprKind::IntLit(i64::from(b), false);
    Some(match op {
        Add => arith(l.checked_add(r))?,
        Sub => arith(l.checked_sub(r))?,
        Mul => arith(l.checked_mul(r))?,
        // `/` and `%` are NOT folded on the untyped AST: their result is
        // type-sensitive — `1/3` is `0` as an integer but `0.333…` once a
        // float/`fixed` context promotes the literals (sic.md §"Built-in fixed
        // point"). Folding here would bake in the integer value before lowering
        // resolves the type, so it is left to the typed `ir-fold` pass, which folds
        // it correctly at the operands' resolved type.
        BitAnd => arith(Some(l & r))?,
        BitOr => arith(Some(l | r))?,
        BitXor => arith(Some(l ^ r))?,
        // Shifts are NOT folded here either: the result type is the promoted
        // LEFT operand's (not the wider operand's), and an out-of-range count is
        // language-defined (sic.md §"Rotate and shift") — the typed `ir-fold`
        // pass folds them at the resolved type.
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
    // An unsigned result that wraps is left to `ir-fold` too: C wraps it, but
    // in sic's `unsafe` it traps, which a literal would hide.
    let arith = |v: Option<u64>| v.filter(|&v| w || v <= u32::MAX as u64).map(|v| ExprKind::UIntLit(v, w));
    let boolean = |b: bool| ExprKind::IntLit(i64::from(b), false);
    Some(match op {
        Add => arith(l.checked_add(r))?,
        Sub => arith(l.checked_sub(r))?,
        Mul => arith(l.checked_mul(r))?,
        // `/` and `%` are left to the typed `ir-fold` pass — their value is
        // type-sensitive under float/`fixed` promotion (see `fold_int`).
        BitAnd => arith(Some(l & r))?,
        BitOr => arith(Some(l | r))?,
        BitXor => arith(Some(l ^ r))?,
        // Shifts are NOT folded here either: the result type is the promoted
        // LEFT operand's (not the wider operand's), and an out-of-range count is
        // language-defined (sic.md §"Rotate and shift") — the typed `ir-fold`
        // pass folds them at the resolved type.
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

    #[test]
    fn leaves_overflow_to_the_typed_fold() {
        // `2147483647 * 2` (int) wraps at run time: it was folded to the long
        // 4294967294. Kept, as is `-(-2147483647 - 1)`; what fits still folds.
        let bin = |op, l: i64, r: i64| e(ExprKind::BinOp { op, lhs: int(l), rhs: int(r) });
        let mut cf = ConstFold::new();
        let mut x = bin(BinOpKind::Mul, 2147483647, 2);
        cf.visit_expr(&mut x);
        assert!(matches!(x.kind, ExprKind::BinOp { .. }));
        let mut y = e(ExprKind::Unary { op: UnOpKind::Neg, expr: Box::new(e(ExprKind::IntLit(-2147483648, false))) });
        cf.visit_expr(&mut y);
        assert!(matches!(y.kind, ExprKind::Unary { .. }));
        let mut z = bin(BinOpKind::Sub, -2147483647, 1);
        cf.visit_expr(&mut z);
        assert!(matches!(z.kind, ExprKind::IntLit(-2147483648, false)));
        // `0xFFFFFFFFu + 1u` wraps (and `unsafe` traps it): kept.
        let u = |v| Box::new(e(ExprKind::UIntLit(v, false)));
        let mut w = e(ExprKind::BinOp { op: BinOpKind::Add, lhs: u(0xFFFF_FFFF), rhs: u(1) });
        cf.visit_expr(&mut w);
        assert!(matches!(w.kind, ExprKind::BinOp { .. }));
    }
}
