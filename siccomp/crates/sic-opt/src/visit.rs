//! A reusable *mutable* AST visitor for optimization passes.
//!
//! `MutVisitor` provides overridable `visit_expr`/`visit_stmt`/`visit_decl`
//! hooks; the default of each just recurses via the free `walk_*` functions,
//! which do the structural traversal and call back into the visitor. A pass that
//! rewrites expressions bottom-up is therefore:
//!
//! ```ignore
//! impl MutVisitor for MyPass {
//!     fn visit_expr(&mut self, e: &mut Expr) {
//!         walk_expr(self, e);   // rewrite children first
//!         self.rewrite(e);      // then this node
//!     }
//! }
//! ```
//!
//! The walk covers every AST node that can contain a sub-expression or
//! statement, so a pass never has to hand-write the traversal.

use sic_frontend::ast::*;

pub trait MutVisitor: Sized {
    fn visit_expr(&mut self, e: &mut Expr) { walk_expr(self, e); }
    fn visit_stmt(&mut self, s: &mut Stmt) { walk_stmt(self, s); }
    fn visit_decl(&mut self, d: &mut Decl) { walk_decl(self, d); }
    fn visit_tu(&mut self, tu: &mut TranslationUnit) { walk_tu(self, tu); }
}

pub fn walk_tu<V: MutVisitor>(v: &mut V, tu: &mut TranslationUnit) {
    for d in &mut tu.decls {
        v.visit_decl(d);
    }
}

pub fn walk_decl<V: MutVisitor>(v: &mut V, d: &mut Decl) {
    match d {
        Decl::Func { body: Some(stmts), .. } => {
            for s in stmts { v.visit_stmt(s); }
        }
        Decl::Func { body: None, .. } => {}
        Decl::Var { declarators, .. } => {
            for decl in declarators {
                if let Some(init) = &mut decl.init { walk_init(v, init); }
            }
        }
        Decl::ExprStmt(e, _) => v.visit_expr(e),
        Decl::Namespace { decls, .. } => {
            for d in decls { v.visit_decl(d); }
        }
        // Type declarations, module/import: no expressions to rewrite. (sic
        // struct-method bodies are hoisted and lowered separately; passes that
        // want them can extend this arm.)
        _ => {}
    }
}

pub fn walk_init<V: MutVisitor>(v: &mut V, init: &mut Initializer) {
    match init {
        Initializer::Expr(e) => v.visit_expr(e),
        Initializer::List(items) => {
            for it in items { walk_init(v, &mut it.init); }
        }
    }
}

pub fn walk_stmt<V: MutVisitor>(v: &mut V, s: &mut Stmt) {
    match s {
        Stmt::Decl(d) => v.visit_decl(d),
        Stmt::Expr(e, _) => v.visit_expr(e),
        Stmt::Block(stmts, _) | Stmt::Unsafe(stmts, _) => {
            for s in stmts { v.visit_stmt(s); }
        }
        Stmt::If { cond, then, else_, .. } => {
            v.visit_expr(cond);
            v.visit_stmt(then);
            if let Some(e) = else_ { v.visit_stmt(e); }
        }
        Stmt::While { cond, body, .. } => { v.visit_expr(cond); v.visit_stmt(body); }
        Stmt::DoWhile { body, cond, .. } => { v.visit_stmt(body); v.visit_expr(cond); }
        Stmt::For { init, cond, post, body, .. } => {
            match init {
                Some(ForInit::Decl(d)) => v.visit_decl(d),
                Some(ForInit::Expr(e)) => v.visit_expr(e),
                None => {}
            }
            if let Some(c) = cond { v.visit_expr(c); }
            if let Some(p) = post { v.visit_expr(p); }
            v.visit_stmt(body);
        }
        Stmt::ForEach { iterable, body, .. } => { v.visit_expr(iterable); v.visit_stmt(body); }
        Stmt::Return(Some(e), _) => v.visit_expr(e),
        Stmt::Return(None, _) | Stmt::Break(_) | Stmt::Continue(_)
        | Stmt::Fallthrough(_) | Stmt::Goto(_, _) | Stmt::Null(_) => {}
        Stmt::Defer(inner, _) => v.visit_stmt(inner),
        Stmt::Delete(e, _) => v.visit_expr(e),
        Stmt::Label(_, inner, _) => v.visit_stmt(inner),
        Stmt::Case(e, inner, _) => { v.visit_expr(e); v.visit_stmt(inner); }
        Stmt::CaseRange(lo, hi, inner, _) => {
            v.visit_expr(lo); v.visit_expr(hi); v.visit_stmt(inner);
        }
        Stmt::Default(inner, _) => v.visit_stmt(inner),
        Stmt::Switch { val, body, .. } => { v.visit_expr(val); v.visit_stmt(body); }
        Stmt::Match { scrutinee, arms, .. } => {
            v.visit_expr(scrutinee);
            for a in arms { v.visit_stmt(&mut a.body); }
        }
        Stmt::Guard { cond, else_body, .. } => { v.visit_expr(cond); v.visit_stmt(else_body); }
    }
}

pub fn walk_expr<V: MutVisitor>(v: &mut V, e: &mut Expr) {
    match &mut e.kind {
        // Leaves.
        ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::BoolLit(_)
        | ExprKind::BigIntLit(_) | ExprKind::DecimalLit(_) | ExprKind::FloatLit(_)
        | ExprKind::StringLit(_) | ExprKind::CharLit(_) | ExprKind::Ident(_)
        | ExprKind::Nullptr | ExprKind::EnumVariant { .. } | ExprKind::TypeIdOf(_)
        | ExprKind::SizeofType(_) | ExprKind::AlignofType(_)
        | ExprKind::GenericRef { .. }
        | ExprKind::TypesCompatible(..) => {}

        ExprKind::TypeId(inner) | ExprKind::Ref { expr: inner, .. }
        | ExprKind::Unary { expr: inner, .. } | ExprKind::PreInc { expr: inner, .. }
        | ExprKind::PostInc { expr: inner, .. } | ExprKind::Cast { expr: inner, .. }
        | ExprKind::SizeofExpr(inner) | ExprKind::AlignofExpr(inner)
        | ExprKind::Field { base: inner, .. } | ExprKind::Arrow { base: inner, .. }
        | ExprKind::NamedArg { value: inner, .. }
        | ExprKind::Await(inner)
        | ExprKind::OptField { base: inner, .. } => v.visit_expr(inner),

        ExprKind::BinOp { lhs, rhs, .. } | ExprKind::Assign { lhs, rhs, .. }
        | ExprKind::Swap { lhs, rhs } | ExprKind::Comma(lhs, rhs) => {
            v.visit_expr(lhs); v.visit_expr(rhs);
        }
        ExprKind::Index { base, index } => { v.visit_expr(base); v.visit_expr(index); }
        ExprKind::Slice { base, lo, hi } => {
            v.visit_expr(base);
            if let Some(e) = lo { v.visit_expr(e); }
            if let Some(e) = hi { v.visit_expr(e); }
        }
        ExprKind::New { args, .. } | ExprKind::TupleExpr(args) => {
            for a in args { v.visit_expr(a); }
        }
        ExprKind::Ternary { cond, then, else_ }
        | ExprKind::ChooseExpr { cond, then, else_ } => {
            v.visit_expr(cond); v.visit_expr(then); v.visit_expr(else_);
        }
        ExprKind::Elvis { cond, else_ } => { v.visit_expr(cond); v.visit_expr(else_); }
        ExprKind::Call { func, args } => {
            v.visit_expr(func);
            for a in args { v.visit_expr(a); }
        }
        ExprKind::Match { scrutinee, arms } => {
            v.visit_expr(scrutinee);
            for a in arms { v.visit_stmt(&mut a.body); }
        }
        ExprKind::Generic { controlling, assocs } => {
            v.visit_expr(controlling);
            for (_, e) in assocs { v.visit_expr(e); }
        }
        ExprKind::OffsetOf { designators, .. } => {
            for d in designators {
                if let OffsetDesignator::Index(e) = d { v.visit_expr(e); }
            }
        }
        ExprKind::StmtExpr(stmts) | ExprKind::Guard { body: stmts, .. } => {
            for s in stmts { v.visit_stmt(s); }
        }
        ExprKind::CompoundLiteral { init, .. } => {
            for it in init { walk_init(v, &mut it.init); }
        }
        ExprKind::VaStart { list, last } => { v.visit_expr(list); v.visit_expr(last); }
        ExprKind::VaArg { list, .. } => v.visit_expr(list),
        ExprKind::VaEnd { list } => v.visit_expr(list),
        ExprKind::VaCopy { dst, src } => { v.visit_expr(dst); v.visit_expr(src); }
    }
}
