//! Shared helpers for optimization passes.

use sic_frontend::ast::*;

/// Conservatively decide whether evaluating `e` has no observable side effect,
/// so a pass may safely discard it (e.g. the dropped operand of `x * 0`). When
/// in doubt this returns `false` — a false negative only forgoes an
/// optimization, whereas a false positive would delete a needed effect.
pub fn is_side_effect_free(e: &Expr) -> bool {
    match &e.kind {
        // Pure leaves.
        ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::BoolLit(_)
        | ExprKind::BigIntLit(_) | ExprKind::DecimalLit(_) | ExprKind::FloatLit(_)
        | ExprKind::StringLit(_) | ExprKind::CharLit(_) | ExprKind::Ident(_)
        | ExprKind::Nullptr | ExprKind::EnumVariant { .. } | ExprKind::TypeIdOf(_)
        | ExprKind::SizeofType(_) | ExprKind::AlignofType(_)
        | ExprKind::SizeofExpr(_) | ExprKind::AlignofExpr(_)
        | ExprKind::TypeId(_) | ExprKind::TypesCompatible(..)
        | ExprKind::OffsetOf { .. } => true,

        // Pure iff every sub-expression is pure.
        ExprKind::Unary { expr, .. } | ExprKind::Cast { expr, .. }
        | ExprKind::Field { base: expr, .. } | ExprKind::Arrow { base: expr, .. }
        | ExprKind::OptField { base: expr, .. } => is_side_effect_free(expr),

        ExprKind::BinOp { lhs, rhs, .. } | ExprKind::Comma(lhs, rhs) =>
            is_side_effect_free(lhs) && is_side_effect_free(rhs),
        ExprKind::Index { base, index } =>
            is_side_effect_free(base) && is_side_effect_free(index),
        ExprKind::Ternary { cond, then, else_ }
        | ExprKind::ChooseExpr { cond, then, else_ } =>
            is_side_effect_free(cond) && is_side_effect_free(then) && is_side_effect_free(else_),
        ExprKind::Elvis { cond, else_ } =>
            is_side_effect_free(cond) && is_side_effect_free(else_),
        ExprKind::TupleExpr(items) => items.iter().all(is_side_effect_free),
        ExprKind::Slice { base, lo, hi } =>
            is_side_effect_free(base)
                && lo.as_deref().map_or(true, is_side_effect_free)
                && hi.as_deref().map_or(true, is_side_effect_free),
        ExprKind::Generic { controlling, assocs } =>
            is_side_effect_free(controlling) && assocs.iter().all(|(_, e)| is_side_effect_free(e)),

        // Anything that writes, calls, allocates, or has unknown effect: impure.
        // (Assign, Swap, Pre/PostInc, Call, New, Ref, StmtExpr, Guard, Match,
        // Va*, CompoundLiteral.)
        _ => false,
    }
}
