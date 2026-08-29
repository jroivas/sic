//! Static borrow-checker for sic `@` references (sic.md §"References").
//!
//! Enforces, at compile time and only in sic mode:
//!   * multiple readers XOR one writer — a variable may have several shared `@`
//!     borrows or a single exclusive `@mut` borrow, never both;
//!   * no returning a freshly-formed reference to a local (`return @x`);
//!   * no reference to NULL.
//!
//! Borrow lifetimes are block-lexical, which matches the runtime model (a `@expr`
//! retains its referent until the enclosing scope exits via `Cleanup::RefRelease`),
//! so the checker forbids exactly what would alias at run time.

use crate::ast::*;
use crate::lexer::Span;
use crate::{Result, CompileError};

#[derive(Clone, Copy, PartialEq)]
enum BorrowKind { Shared, Mut }

struct Ctx {
    /// One frame per open block; each holds the borrows formed in that block.
    /// A frame is popped (its borrows end) when the block exits.
    scopes: Vec<Vec<(String, BorrowKind)>>,
}

impl Ctx {
    fn new() -> Self { Ctx { scopes: vec![Vec::new()] } }
    fn push(&mut self) { self.scopes.push(Vec::new()); }
    fn pop(&mut self) { self.scopes.pop(); }

    /// (shared count, mut count) of live borrows of `var`.
    fn live(&self, var: &str) -> (u32, u32) {
        let mut sh = 0;
        let mut mu = 0;
        for frame in &self.scopes {
            for (v, k) in frame {
                if v == var {
                    match k { BorrowKind::Shared => sh += 1, BorrowKind::Mut => mu += 1 }
                }
            }
        }
        (sh, mu)
    }

    fn borrow(&mut self, var: String, kind: BorrowKind, span: &Span) -> Result<()> {
        let (sh, mu) = self.live(&var);
        match kind {
            BorrowKind::Mut if sh > 0 || mu > 0 => {
                return Err(CompileError::at(
                    format!("cannot mutably borrow `{}` with `@mut`: it is already borrowed", var),
                    span.file.clone(), span.line, span.col));
            }
            BorrowKind::Shared if mu > 0 => {
                return Err(CompileError::at(
                    format!("cannot borrow `{}` with `@`: it is already mutably borrowed", var),
                    span.file.clone(), span.line, span.col));
            }
            _ => {}
        }
        self.scopes.last_mut().unwrap().push((var, kind));
        Ok(())
    }
}

/// Borrow-check one function body.
pub fn check(body: &[Stmt]) -> Result<()> {
    let mut ctx = Ctx::new();
    for s in body {
        check_stmt(s, &mut ctx)?;
    }
    Ok(())
}

/// The root variable name of an lvalue chain (`x`, `x.f`, `x[i]`, `*x` → `x`).
fn root_var(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Field { base, .. } | ExprKind::Arrow { base, .. } => root_var(base),
        ExprKind::Index { base, .. } => root_var(base),
        ExprKind::Unary { op: UnOpKind::Deref, expr } => root_var(expr),
        ExprKind::Cast { expr, .. } => root_var(expr),
        _ => None,
    }
}

/// Whether `e` is a null pointer constant (`0`, `NULL` → `(void*)0`, `nullptr`).
fn is_null(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::IntLit(0, _) | ExprKind::UIntLit(0, _) | ExprKind::Nullptr => true,
        ExprKind::Cast { expr, .. } => is_null(expr),
        _ => false,
    }
}

fn check_stmt(s: &Stmt, ctx: &mut Ctx) -> Result<()> {
    match s {
        Stmt::Block(ss, _) => {
            ctx.push();
            for s in ss { check_stmt(s, ctx)?; }
            ctx.pop();
        }
        Stmt::Decl(Decl::Var { declarators, .. }) => {
            for d in declarators {
                match &d.init {
                    // `r = @expr;` binds the reference to the named variable `r`,
                    // so the borrow is block-scoped (lives until this block exits):
                    // record it in the current block frame.
                    Some(Initializer::Expr(e)) if matches!(&e.kind, ExprKind::Ref { .. }) => {
                        check_expr(e, ctx)?;
                    }
                    // Any other initializer forms only temporary references.
                    Some(init) => check_temp(ctx, |ctx| check_init(init, ctx))?,
                    None => {}
                }
            }
        }
        Stmt::Decl(_) => {}
        Stmt::Expr(e, _) => check_temp(ctx, |ctx| check_expr(e, ctx))?,
        Stmt::Return(Some(e), _) => {
            if matches!(&e.kind, ExprKind::Ref { .. }) {
                return Err(CompileError::at(
                    "cannot return a reference to a local variable".to_string(),
                    e.span.file.clone(), e.span.line, e.span.col));
            }
            check_temp(ctx, |ctx| check_expr(e, ctx))?;
        }
        Stmt::If { cond, then, else_, .. } => {
            check_temp(ctx, |ctx| check_expr(cond, ctx))?;
            ctx.push(); check_stmt(then, ctx)?; ctx.pop();
            if let Some(e) = else_ { ctx.push(); check_stmt(e, ctx)?; ctx.pop(); }
        }
        Stmt::While { cond, body, .. } => {
            check_temp(ctx, |ctx| check_expr(cond, ctx))?;
            ctx.push(); check_stmt(body, ctx)?; ctx.pop();
        }
        Stmt::DoWhile { body, cond, .. } => {
            ctx.push(); check_stmt(body, ctx)?; ctx.pop();
            check_temp(ctx, |ctx| check_expr(cond, ctx))?;
        }
        Stmt::For { init, cond, post, body, .. } => {
            ctx.push();
            match init {
                Some(ForInit::Expr(e)) => check_temp(ctx, |ctx| check_expr(e, ctx))?,
                Some(ForInit::Decl(d)) => check_stmt(&Stmt::Decl(d.clone()), ctx)?,
                _ => {}
            }
            if let Some(e) = cond { check_temp(ctx, |ctx| check_expr(e, ctx))?; }
            if let Some(e) = post { check_temp(ctx, |ctx| check_expr(e, ctx))?; }
            check_stmt(body, ctx)?;
            ctx.pop();
        }
        Stmt::Switch { val, body, .. } => {
            check_temp(ctx, |ctx| check_expr(val, ctx))?;
            ctx.push(); check_stmt(body, ctx)?; ctx.pop();
        }
        Stmt::Case(v, body, _) => { check_temp(ctx, |ctx| check_expr(v, ctx))?; check_stmt(body, ctx)?; }
        Stmt::CaseRange(lo, hi, body, _) => {
            check_temp(ctx, |ctx| { check_expr(lo, ctx)?; check_expr(hi, ctx) })?;
            check_stmt(body, ctx)?;
        }
        Stmt::Default(body, _) | Stmt::Label(_, body, _) | Stmt::Defer(body, _) => check_stmt(body, ctx)?,
        Stmt::Delete(e, _) => check_temp(ctx, |ctx| check_expr(e, ctx))?,
        Stmt::Match { scrutinee, arms, .. } => {
            check_temp(ctx, |ctx| check_expr(scrutinee, ctx))?;
            for a in arms { ctx.push(); check_stmt(&a.body, ctx)?; ctx.pop(); }
        }
        _ => {}
    }
    Ok(())
}

/// Run `f` inside a transient frame, so any borrows it forms are statement-scoped
/// (temporary references) and are dropped afterwards.
fn check_temp<F: FnOnce(&mut Ctx) -> Result<()>>(ctx: &mut Ctx, f: F) -> Result<()> {
    ctx.push();
    let r = f(ctx);
    ctx.pop();
    r
}

fn check_init(init: &Initializer, ctx: &mut Ctx) -> Result<()> {
    match init {
        Initializer::Expr(e) => check_expr(e, ctx),
        Initializer::List(items) => {
            for it in items { check_init(&it.init, ctx)?; }
            Ok(())
        }
    }
}

fn check_expr(e: &Expr, ctx: &mut Ctx) -> Result<()> {
    use ExprKind::*;
    // Handle a reference-forming node first, then recurse into its operand.
    if let Ref { mutable, expr } = &e.kind {
        if is_null(expr) {
            return Err(CompileError::at(
                "reference to NULL is not allowed".to_string(),
                e.span.file.clone(), e.span.line, e.span.col));
        }
        if let Some(root) = root_var(expr) {
            let kind = if *mutable { BorrowKind::Mut } else { BorrowKind::Shared };
            ctx.borrow(root, kind, &e.span)?;
        }
        return check_expr(expr, ctx);
    }
    // Recurse into all sub-expressions (mirrors `collect_expr_names`).
    match &e.kind {
        BinOp { lhs, rhs, .. } | Comma(lhs, rhs) | Assign { lhs, rhs, .. } | Swap { lhs, rhs } => {
            check_expr(lhs, ctx)?; check_expr(rhs, ctx)?;
        }
        Unary { expr, .. } | PreInc { expr, .. } | PostInc { expr, .. }
        | SizeofExpr(expr) | AlignofExpr(expr) | Cast { expr, .. } => check_expr(expr, ctx)?,
        Ternary { cond, then, else_ } | ChooseExpr { cond, then, else_ } => {
            check_expr(cond, ctx)?; check_expr(then, ctx)?; check_expr(else_, ctx)?;
        }
        Elvis { cond, else_ } => { check_expr(cond, ctx)?; check_expr(else_, ctx)?; }
        Call { func, args } => { check_expr(func, ctx)?; for a in args { check_expr(a, ctx)?; } }
        Index { base, index } => { check_expr(base, ctx)?; check_expr(index, ctx)?; }
        Slice { base, lo, hi } => {
            check_expr(base, ctx)?;
            if let Some(x) = lo { check_expr(x, ctx)?; }
            if let Some(x) = hi { check_expr(x, ctx)?; }
        }
        New { args, .. } => { for x in args { check_expr(x, ctx)?; } }
        Field { base, .. } | Arrow { base, .. } => check_expr(base, ctx)?,
        Generic { controlling, assocs } => { check_expr(controlling, ctx)?; for (_, x) in assocs { check_expr(x, ctx)?; } }
        StmtExpr(stmts) => { ctx.push(); for s in stmts { check_stmt(s, ctx)?; } ctx.pop(); }
        CompoundLiteral { init, .. } => { for it in init { check_init(&it.init, ctx)?; } }
        VaStart { list, last } => { check_expr(list, ctx)?; check_expr(last, ctx)?; }
        VaArg { list, .. } | VaEnd { list } => check_expr(list, ctx)?,
        VaCopy { dst, src } => { check_expr(dst, ctx)?; check_expr(src, ctx)?; }
        _ => {}
    }
    Ok(())
}
