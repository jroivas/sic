/// AST-level constant folding pass.
/// Mirrors the Python optimizer: folds literal binary ops and unary negation.

use sic_frontend::ast::*;

pub struct ConstFold;

impl ConstFold {
    pub fn fold_tu(tu: &mut TranslationUnit) {
        for decl in &mut tu.decls {
            Self::fold_decl(decl);
        }
    }

    fn fold_decl(decl: &mut Decl) {
        match decl {
            Decl::Func { body: Some(stmts), .. } => {
                for s in stmts { Self::fold_stmt(s); }
            }
            Decl::Var { declarators, .. } => {
                for d in declarators {
                    if let Some(init) = &mut d.init {
                        Self::fold_init(init);
                    }
                }
            }
            Decl::ExprStmt(e, _) => { Self::fold_expr(e); }
            _ => {}
        }
    }

    fn fold_stmt(s: &mut Stmt) {
        match s {
            Stmt::Expr(e, _) => { Self::fold_expr(e); }
            Stmt::Block(stmts, _) => { for s in stmts { Self::fold_stmt(s); } }
            Stmt::If { cond, then, else_, .. } => {
                Self::fold_expr(cond);
                Self::fold_stmt(then);
                if let Some(e) = else_ { Self::fold_stmt(e); }
            }
            Stmt::While { cond, body, .. } => { Self::fold_expr(cond); Self::fold_stmt(body); }
            Stmt::DoWhile { body, cond, .. } => { Self::fold_stmt(body); Self::fold_expr(cond); }
            Stmt::For { init, cond, post, body, .. } => {
                if let Some(ForInit::Expr(e)) = init { Self::fold_expr(e); }
                if let Some(c) = cond { Self::fold_expr(c); }
                if let Some(p) = post { Self::fold_expr(p); }
                Self::fold_stmt(body);
            }
            Stmt::Return(Some(e), _) => { Self::fold_expr(e); }
            Stmt::Decl(d) => { Self::fold_decl(d); }
            Stmt::Label(_, inner, _) => { Self::fold_stmt(inner); }
            Stmt::Case(e, inner, _) => { Self::fold_expr(e); Self::fold_stmt(inner); }
            Stmt::Switch { val, body, .. } => { Self::fold_expr(val); Self::fold_stmt(body); }
            _ => {}
        }
    }

    fn fold_init(init: &mut Initializer) {
        match init {
            Initializer::Expr(e) => { Self::fold_expr(e); }
            Initializer::List(items) => { for i in items { Self::fold_init(i); } }
        }
    }

    pub fn fold_expr(e: &mut Expr) {
        match &mut e.kind {
            ExprKind::BinOp { op, lhs, rhs } => {
                Self::fold_expr(lhs);
                Self::fold_expr(rhs);
                let op = *op;
                if let (ExprKind::IntLit(l, lw), ExprKind::IntLit(r, rw)) = (&lhs.kind, &rhs.kind) {
                    let l = *l; let r = *r; let operand_64 = *lw || *rw;
                    let result = match op {
                        BinOpKind::Add => Some(l.wrapping_add(r)),
                        BinOpKind::Sub => Some(l.wrapping_sub(r)),
                        BinOpKind::Mul => Some(l.wrapping_mul(r)),
                        BinOpKind::Div if r != 0 => Some(l / r),
                        BinOpKind::Rem if r != 0 => Some(l % r),
                        BinOpKind::BitAnd => Some(l & r),
                        BinOpKind::BitOr  => Some(l | r),
                        BinOpKind::BitXor => Some(l ^ r),
                        BinOpKind::Shl    => Some(l << (r & 63)),
                        BinOpKind::Shr    => Some(l >> (r & 63)),
                        _ => None,
                    };
                    if let Some(v) = result {
                        // The folded literal is 64-bit if either operand was, or
                        // the result no longer fits in a 32-bit type.
                        let is64 = operand_64 || v < i32::MIN as i64 || v > u32::MAX as i64;
                        e.kind = ExprKind::IntLit(v, is64);
                    }
                } else if let (ExprKind::FloatLit(l), ExprKind::FloatLit(r)) = (&lhs.kind, &rhs.kind) {
                    let l = *l; let r = *r;
                    let result = match op {
                        BinOpKind::Add => Some(l + r),
                        BinOpKind::Sub => Some(l - r),
                        BinOpKind::Mul => Some(l * r),
                        BinOpKind::Div if r != 0.0 => Some(l / r),
                        _ => None,
                    };
                    if let Some(v) = result {
                        e.kind = ExprKind::FloatLit(v);
                    }
                }
            }
            ExprKind::Unary { op, expr: inner } => {
                Self::fold_expr(inner);
                let op = *op;
                if let ExprKind::IntLit(v, w) = inner.kind {
                    match op {
                        UnOpKind::Neg    => { e.kind = ExprKind::IntLit(v.wrapping_neg(), w); }
                        UnOpKind::BitNot => { e.kind = ExprKind::IntLit(!v, w); }
                        UnOpKind::Not    => { e.kind = ExprKind::IntLit(if v == 0 { 1 } else { 0 }, false); }
                        _ => {}
                    }
                }
            }
            ExprKind::Cast { expr: inner, .. } => { Self::fold_expr(inner); }
            ExprKind::Call { func, args } => {
                Self::fold_expr(func);
                for a in args { Self::fold_expr(a); }
            }
            ExprKind::Assign { lhs, rhs, .. } => { Self::fold_expr(lhs); Self::fold_expr(rhs); }
            ExprKind::Ternary { cond, then, else_ } => {
                Self::fold_expr(cond); Self::fold_expr(then); Self::fold_expr(else_);
            }
            ExprKind::Index { base, index } => { Self::fold_expr(base); Self::fold_expr(index); }
            ExprKind::Field { base, .. } | ExprKind::Arrow { base, .. } => { Self::fold_expr(base); }
            ExprKind::PreInc { expr, .. } | ExprKind::PostInc { expr, .. } => { Self::fold_expr(expr); }
            ExprKind::Comma(l, r) => { Self::fold_expr(l); Self::fold_expr(r); }
            _ => {}
        }
    }
}
