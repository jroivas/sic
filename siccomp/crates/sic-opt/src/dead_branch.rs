//! Constant-condition / dead-code elimination. When a condition folds to a
//! compile-time constant (run after `const-fold`, via the manager's fixpoint),
//! the un-taken branch is removed: `if (0)`, `while (0)`, `1 ? a : b`, and the
//! short-circuit cases of `&&`/`||`/`?:`.
//!
//! Only branches are dropped, never anything evaluated: a constant condition is
//! itself side-effect-free, and `&&`/`||`/`?:` never evaluate the discarded arm
//! (short-circuit), so removal is always sound.

use sic_frontend::ast::*;
use sic_frontend::lexer::Span;
use crate::pass::AstPass;
use crate::visit::{MutVisitor, walk_stmt, walk_expr};

#[derive(Default)]
pub struct DeadBranch { changed: bool }

impl DeadBranch {
    pub fn new() -> Self { DeadBranch { changed: false } }
}

impl AstPass for DeadBranch {
    fn name(&self) -> &'static str { "dead-branch" }
    fn run(&mut self, tu: &mut TranslationUnit) -> bool {
        self.changed = false;
        self.visit_tu(tu);
        self.changed
    }
}

impl MutVisitor for DeadBranch {
    fn visit_stmt(&mut self, s: &mut Stmt) {
        walk_stmt(self, s);          // simplify children first
        self.fold_stmt(s);
    }
    fn visit_expr(&mut self, e: &mut Expr) {
        walk_expr(self, e);
        self.fold_expr(e);
    }
}

/// Truthiness of a compile-time-constant expression, else `None`.
fn as_bool(e: &Expr) -> Option<bool> {
    Some(match &e.kind {
        ExprKind::IntLit(v, _) => *v != 0,
        ExprKind::UIntLit(v, _) => *v != 0,
        ExprKind::CharLit(v) => *v != 0,
        ExprKind::FloatLit(v) => *v != 0.0,
        ExprKind::BoolLit(b) => *b,
        ExprKind::Nullptr => false,
        _ => return None,
    })
}

fn dummy(span: &Span) -> Expr { Expr::new(ExprKind::Nullptr, span.clone()) }

impl DeadBranch {
    fn fold_stmt(&mut self, s: &mut Stmt) {
        let repl: Option<Stmt> = match s {
            Stmt::If { cond, then, else_, span } => as_bool(cond).map(|b| {
                // Keep a scope boundary around the surviving branch so a bare
                // declaration in it can't leak into the parent scope.
                let taken = if b {
                    std::mem::replace(then.as_mut(), Stmt::Null(span.clone()))
                } else {
                    else_.take().map(|e| *e).unwrap_or(Stmt::Null(span.clone()))
                };
                Stmt::Block(vec![taken], span.clone())
            }),
            // `while (0) body` never runs.
            Stmt::While { cond, span, .. } if as_bool(cond) == Some(false) =>
                Some(Stmt::Null(span.clone())),
            // `do body while (0)` runs the body exactly once.
            Stmt::DoWhile { body, cond, span } if as_bool(cond) == Some(false) =>
                Some(Stmt::Block(
                    vec![std::mem::replace(body.as_mut(), Stmt::Null(span.clone()))],
                    span.clone(),
                )),
            _ => None,
        };
        if let Some(r) = repl {
            *s = r;
            self.changed = true;
        }
    }

    fn fold_expr(&mut self, e: &mut Expr) {
        let span = e.span.clone();
        let taken: Option<Expr> = match &mut e.kind {
            ExprKind::Ternary { cond, then, else_ } => match as_bool(cond) {
                Some(true) => Some(std::mem::replace(then.as_mut(), dummy(&span))),
                Some(false) => Some(std::mem::replace(else_.as_mut(), dummy(&span))),
                None => None,
            },
            // `c ?: b`: `c` is evaluated once — a constant `c` picks a side.
            ExprKind::Elvis { cond, else_ } => match as_bool(cond) {
                Some(true) => Some(std::mem::replace(cond.as_mut(), dummy(&span))),
                Some(false) => Some(std::mem::replace(else_.as_mut(), dummy(&span))),
                None => None,
            },
            // Short-circuit: the determined side wins and the other is never
            // evaluated, so dropping it is safe regardless of its effects.
            ExprKind::BinOp { op: BinOpKind::LogAnd, lhs, .. }
                if as_bool(lhs) == Some(false) =>
                Some(Expr::new(ExprKind::IntLit(0, false), span.clone())),
            ExprKind::BinOp { op: BinOpKind::LogOr, lhs, .. }
                if as_bool(lhs) == Some(true) =>
                Some(Expr::new(ExprKind::IntLit(1, false), span.clone())),
            _ => None,
        };
        if let Some(t) = taken {
            *e = t;
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visit::MutVisitor;

    fn e(k: ExprKind) -> Expr { Expr::new(k, Span::default()) }
    fn int(n: i64) -> Box<Expr> { Box::new(e(ExprKind::IntLit(n, false))) }

    #[test]
    fn constant_ternary_picks_arm() {
        let mut db = DeadBranch::new();
        // 1 ? 7 : 8  =>  7
        let mut t = e(ExprKind::Ternary { cond: int(1), then: int(7), else_: int(8) });
        db.visit_expr(&mut t);
        assert!(matches!(t.kind, ExprKind::IntLit(7, _)));
        // 0 ? 7 : 8  =>  8
        let mut f = e(ExprKind::Ternary { cond: int(0), then: int(7), else_: int(8) });
        db.visit_expr(&mut f);
        assert!(matches!(f.kind, ExprKind::IntLit(8, _)));
    }

    #[test]
    fn short_circuit_false_and() {
        let mut db = DeadBranch::new();
        // 0 && x  =>  0   (x dropped safely by short-circuit)
        let mut a = e(ExprKind::BinOp { op: BinOpKind::LogAnd, lhs: int(0),
            rhs: Box::new(e(ExprKind::Ident("x".into()))) });
        db.visit_expr(&mut a);
        assert!(matches!(a.kind, ExprKind::IntLit(0, _)));
    }
}
