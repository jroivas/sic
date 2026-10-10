//! C-mode warnings on constant operands, gcc's on-by-default
//! `-Wdiv-by-zero`, `-Wshift-count-overflow` and `-Wshift-count-negative`.
//! (SIC defines `x / 0` and over-wide shifts, so they do not warn there.)

use crate::ast::{BinOpKind, Expr};
use crate::diag;
use super::super::func::FuncCtx;
use super::*;

impl<'m> FuncCtx<'m> {
    /// Check `lhs op rhs` (also `lhs op= rhs`) for a constant divisor of zero or
    /// a constant shift count outside `0..width` of the promoted left operand.
    pub(crate) fn warn_const_operand(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr, at: &crate::lexer::Span) {
        if self.is_sic() { return; }
        let (is_div, is_shift) = match op {
            BinOpKind::Div | BinOpKind::Rem => (true, false),
            BinOpKind::Shl | BinOpKind::Shr => (false, true),
            _ => return,
        };
        let int_bits = |t: &Type| match t {
            Type::Int { bits, .. } => Some(*bits),
            Type::Bool => Some(1),
            _ => None,
        };
        // An integer constant operand only (`x / 0.0` is a well-defined infinity).
        if self.infer_expr_type(rhs).ok().as_ref().and_then(int_bits).is_none() { return; }
        let Ok(k) = crate::lower::eval_const_expr(rhs, &self.lowerer.enum_consts) else { return };
        let file = at.file.as_deref();
        if is_div {
            if k == 0 && self.infer_expr_type(lhs).ok().as_ref().and_then(int_bits).is_some() {
                diag::warn("div-by-zero", file, at.line, at.col, "division by zero");
            }
        } else if is_shift {
            let Some(lbits) = self.infer_expr_type(lhs).ok().as_ref().and_then(int_bits) else { return };
            let width = lbits.max(32) as i64; // after the integer promotions
            let dir = if op == BinOpKind::Shl { "left" } else { "right" };
            if k < 0 {
                diag::warn("shift-count-negative", file, at.line, at.col, &format!("{} shift count is negative", dir));
            } else if k >= width {
                diag::warn("shift-count-overflow", file, at.line, at.col, &format!("{} shift count >= width of type", dir));
            }
        }
    }
}
