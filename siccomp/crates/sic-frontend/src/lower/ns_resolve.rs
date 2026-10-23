//! sic namespaces (sic.md §"Namespace"): resolve BARE references to namespace
//! members from inside the namespace.
//!
//! `flatten_namespaces` hoists `namespace N { int g; int f(void) { return g; } }`
//! to the mangled top-level symbols `N__g` / `N__f`. A bare `g` inside `N`'s own
//! code must then name `N__g` — it was left as `g`, so `&g_stdin` in
//! `namespace File` failed ("'g_stdin' is not an lvalue") and sibling calls had
//! no target. This pass renames such identifiers, with C scoping: a parameter or
//! a local declared in an enclosing block shadows the member (`int g = …;` inside
//! a function keeps referring to the local, from its own initializer on).
//!
//! The walk matches every expression and statement kind exhaustively so a newly
//! added one cannot silently skip resolution.

use std::collections::HashSet;
use crate::ast::*;

pub(crate) struct NsRenamer<'a> {
    /// Member name → mangled symbol for the namespace chain of the code being
    /// renamed (innermost scope first), or `None` when not a member.
    resolve: &'a dyn Fn(&str) -> Option<String>,
    /// Bare enum type name → its mangled registry name (`Status` → `N__Status`).
    resolve_type: &'a dyn Fn(&str) -> Option<String>,
    /// Names declared in the enclosing function scopes (innermost last).
    scopes: Vec<HashSet<String>>,
}

impl<'a> NsRenamer<'a> {
    pub(crate) fn new(resolve: &'a dyn Fn(&str) -> Option<String>,
                      resolve_type: &'a dyn Fn(&str) -> Option<String>) -> Self {
        NsRenamer { resolve, resolve_type, scopes: Vec::new() }
    }

    /// A bare (unqualified) type or enum name naming a namespace enum.
    fn rename_type(&self, name: &mut String) {
        if name.contains("::") { return; }
        if let Some(m) = (self.resolve_type)(name) { *name = m; }
    }

    fn shadowed(&self, name: &str) -> bool {
        self.scopes.iter().any(|s| s.contains(name))
    }

    fn declare(&mut self, name: &str) {
        if let Some(s) = self.scopes.last_mut() { s.insert(name.to_string()); }
    }

    fn rename(&self, name: &mut String) {
        if self.shadowed(name) { return; }
        if let Some(m) = (self.resolve)(name) { *name = m; }
    }

    /// A function (or method/lambda) body with its parameters in scope.
    pub(crate) fn function(&mut self, params: &mut [Param], body: &mut [Stmt]) {
        self.scopes.push(HashSet::new());
        for p in params.iter_mut() {
            self.qual_type(&mut p.ty);
            if let Some(d) = &mut p.default { self.expr(d); }
            if let Some(n) = &p.name { let n = n.clone(); self.declare(&n); }
        }
        self.scopes.push(HashSet::new());
        for s in body.iter_mut() { self.stmt(s); }
        self.scopes.pop();
        self.scopes.pop();
    }

    /// A top-level (namespace member) declaration other than a function body:
    /// initializers and types of globals, struct method bodies.
    pub(crate) fn top_decl(&mut self, d: &mut Decl) {
        match d {
            Decl::Func { ret_ty, params, body, .. } => {
                self.qual_type(ret_ty);
                match body {
                    Some(b) => self.function(params, b),
                    None => for p in params.iter_mut() { self.qual_type(&mut p.ty); },
                }
            }
            Decl::Var { base_ty, declarators, .. } => {
                self.qual_type(base_ty);
                for de in declarators.iter_mut() {
                    self.qual_type(&mut de.ty);
                    if let Some(i) = &mut de.init { self.init(i); }
                }
            }
            Decl::TypeDef { names, .. } => for (_, t) in names.iter_mut() { self.qual_type(t); },
            Decl::StructDecl(sd) => self.struct_def(sd),
            Decl::UnionDecl(ud) => self.fields(ud.fields.as_mut()),
            Decl::EnumDecl(ed) => self.enum_def(ed),
            Decl::ExprStmt(e, _) => self.expr(e),
            Decl::Module(..) | Decl::Import { .. } | Decl::Namespace { .. } => {}
        }
    }

    fn struct_def(&mut self, sd: &mut StructDef) {
        self.fields(sd.fields.as_mut());
        for m in sd.methods.iter_mut() {
            self.qual_type(&mut m.ret_ty);
            self.function(&mut m.params, &mut m.body);
        }
    }

    fn fields(&mut self, fields: Option<&mut Vec<FieldDecl>>) {
        for f in fields.into_iter().flatten() {
            self.qual_type(&mut f.ty);
            if let Some(w) = &mut f.bit_width { self.expr(w); }
        }
    }

    fn enum_def(&mut self, ed: &mut EnumDef) {
        for v in ed.variants.iter_mut().flatten() {
            if let Some(e) = &mut v.value { self.expr(e); }
            if let Some(t) = &mut v.payload { self.qual_type(t); }
        }
    }

    /// Expressions inside types: `typeof(member)`, array bounds.
    fn qual_type(&mut self, qt: &mut QualType) { self.ast_type(&mut qt.ty); }

    fn ast_type(&mut self, t: &mut AstType) {
        match t {
            AstType::Pointer { base, .. } | AstType::Weak(base) => self.qual_type(base),
            AstType::Array { base, size } => {
                self.qual_type(base);
                if let Some(s) = size { self.expr(s); }
            }
            AstType::Function { ret, params, .. } => {
                self.qual_type(ret);
                for p in params.iter_mut() { self.qual_type(&mut p.ty); }
            }
            AstType::Typeof(e) => self.expr(e),
            AstType::Struct(sd) => {
                // `struct S *p` names a namespace struct (a body is a definition,
                // already renamed when hoisted).
                if sd.fields.is_none() { if let Some(n) = &mut sd.name { self.rename_type(n); } }
                self.struct_def(sd)
            }
            AstType::Union(ud) => {
                if ud.fields.is_none() { if let Some(n) = &mut ud.name { self.rename_type(n); } }
                self.fields(ud.fields.as_mut())
            }
            AstType::Enum(ed) => {
                // `enum Status x` names a namespace enum (a body is a definition,
                // already renamed when hoisted).
                if ed.variants.is_none() { if let Some(n) = &mut ed.name { self.rename_type(n); } }
                self.enum_def(ed)
            }
            AstType::Named(n) => self.rename_type(n),
            AstType::Generic { args, .. } => for a in args.iter_mut() { self.qual_type(a); },
            AstType::Closure { ret, params } => {
                self.qual_type(ret);
                for p in params.iter_mut() { self.qual_type(p); }
            }
            AstType::Void | AstType::Char { .. } | AstType::Short { .. } | AstType::Int { .. }
            | AstType::Long { .. } | AstType::LongLong { .. } | AstType::Float | AstType::Double
            | AstType::LongDouble | AstType::Bool | AstType::Complex | AstType::Bitfield(_)
            | AstType::Builtin(_) | AstType::Tuple | AstType::Fixed { .. }
            | AstType::Auto => {}
        }
    }

    fn init(&mut self, i: &mut Initializer) {
        match i {
            Initializer::Expr(e) => self.expr(e),
            Initializer::List(items) => for it in items.iter_mut() { self.init_item(it); },
        }
    }

    fn init_item(&mut self, it: &mut InitItem) {
        for d in it.designators.iter_mut() {
            match d {
                Designator::Field(_) => {}
                Designator::Index(e) => self.expr(e),
                Designator::IndexRange(a, b) => { self.expr(a); self.expr(b); }
            }
        }
        self.init(&mut it.init);
    }

    /// A declaration inside a function body: its names shadow from their own
    /// initializer on (`int x = x;` reads the new `x`, as in C).
    fn local_decl(&mut self, d: &mut Decl) {
        match d {
            Decl::Var { base_ty, declarators, .. } => {
                self.qual_type(base_ty);
                for de in declarators.iter_mut() {
                    self.qual_type(&mut de.ty);
                    let n = de.name.clone();
                    self.declare(&n);
                    if let Some(i) = &mut de.init { self.init(i); }
                }
            }
            Decl::Func { name, .. } => { let n = name.clone(); self.declare(&n); }
            other => self.top_decl(other),
        }
    }

    fn block(&mut self, stmts: &mut [Stmt]) {
        self.scopes.push(HashSet::new());
        for s in stmts.iter_mut() { self.stmt(s); }
        self.scopes.pop();
    }

    fn scoped_stmt(&mut self, s: &mut Stmt) {
        self.scopes.push(HashSet::new());
        self.stmt(s);
        self.scopes.pop();
    }

    fn stmt(&mut self, s: &mut Stmt) {
        match s {
            Stmt::Decl(d) => self.local_decl(d),
            Stmt::Expr(e, _) | Stmt::Delete(e, _) => self.expr(e),
            Stmt::Block(ss, _) | Stmt::Unsafe(ss, _) => self.block(ss),
            Stmt::If { cond, then, else_, .. } => {
                self.expr(cond);
                self.scoped_stmt(then);
                if let Some(e) = else_ { self.scoped_stmt(e); }
            }
            Stmt::While { cond, body, .. } => { self.expr(cond); self.scoped_stmt(body); }
            Stmt::DoWhile { body, cond, .. } => { self.scoped_stmt(body); self.expr(cond); }
            Stmt::For { init, cond, post, body, .. } => {
                self.scopes.push(HashSet::new());
                match init {
                    Some(ForInit::Decl(d)) => self.local_decl(d),
                    Some(ForInit::Expr(e)) => self.expr(e),
                    None => {}
                }
                if let Some(c) = cond { self.expr(c); }
                if let Some(p) = post { self.expr(p); }
                self.scoped_stmt(body);
                self.scopes.pop();
            }
            Stmt::ForEach { ty, name, iterable, body, .. } => {
                self.qual_type(ty);
                self.expr(iterable);
                self.scopes.push(HashSet::new());
                let n = name.clone();
                self.declare(&n);
                self.scoped_stmt(body);
                self.scopes.pop();
            }
            Stmt::Return(e, _) => if let Some(e) = e { self.expr(e); },
            Stmt::Defer(inner, _) | Stmt::Label(_, inner, _) | Stmt::Default(inner, _) => self.stmt(inner),
            Stmt::Case(e, inner, _) => { self.expr(e); self.stmt(inner); }
            Stmt::CaseRange(a, b, inner, _) => { self.expr(a); self.expr(b); self.stmt(inner); }
            Stmt::Switch { val, body, .. } => { self.expr(val); self.scoped_stmt(body); }
            Stmt::Match { scrutinee, arms, .. } => { self.expr(scrutinee); self.arms(arms); }
            Stmt::Guard { binding, cond, else_body, .. } => {
                self.expr(cond);
                self.scoped_stmt(else_body);
                // The bind form adds its name to the CURRENT scope.
                if let Some((ty, n)) = binding {
                    if let Some(t) = ty { self.qual_type(t); }
                    let n = n.clone();
                    self.declare(&n);
                }
            }
            Stmt::Asm(a) => for o in a.outputs.iter_mut().chain(a.inputs.iter_mut()) { self.expr(&mut o.expr); },
            Stmt::Break(_) | Stmt::Continue(_) | Stmt::Fallthrough(_) | Stmt::Goto(..)
            | Stmt::Fence { .. } | Stmt::UnknownType(..) | Stmt::Null(_) => {}
        }
    }

    fn arms(&mut self, arms: &mut [MatchArm]) {
        for a in arms.iter_mut() {
            self.scopes.push(HashSet::new());
            if let Some(b) = &a.binding { let b = b.clone(); self.declare(&b); }
            self.stmt(&mut a.body);
            self.scopes.pop();
        }
    }

    fn expr(&mut self, e: &mut Expr) {
        match &mut e.kind {
            ExprKind::Ident(name) => self.rename(name),
            ExprKind::TypeMember { ty, .. } => self.qual_type(ty),
            ExprKind::GenericRef { name, type_args } => {
                self.rename(name);
                for t in type_args.iter_mut() { self.qual_type(t); }
            }
            ExprKind::Lambda { params, ret, body, .. } => {
                if let Some(r) = ret { self.qual_type(r); }
                self.function(params, body);
            }
            ExprKind::BinOp { lhs, rhs, .. } | ExprKind::Assign { lhs, rhs, .. }
            | ExprKind::Swap { lhs, rhs } | ExprKind::Comma(lhs, rhs) => { self.expr(lhs); self.expr(rhs); }
            ExprKind::Unary { expr, .. } | ExprKind::PreInc { expr, .. } | ExprKind::PostInc { expr, .. }
            | ExprKind::SizeofExpr(expr) | ExprKind::AlignofExpr(expr) | ExprKind::Ref { expr, .. }
            | ExprKind::Await(expr) | ExprKind::TypeId(expr) => self.expr(expr),
            ExprKind::Cast { ty, expr } => { self.qual_type(ty); self.expr(expr); }
            ExprKind::Field { base, .. } | ExprKind::Arrow { base, .. } | ExprKind::OptField { base, .. } => self.expr(base),
            ExprKind::Index { base, index } => { self.expr(base); self.expr(index); }
            ExprKind::Slice { base, lo, hi } => {
                self.expr(base);
                if let Some(x) = lo { self.expr(x); }
                if let Some(x) = hi { self.expr(x); }
            }
            ExprKind::New { ty, args, .. } => { self.qual_type(ty); for a in args.iter_mut() { self.expr(a); } }
            ExprKind::TupleExpr(args) => for a in args.iter_mut() { self.expr(a); },
            ExprKind::Ternary { cond, then, else_ } | ExprKind::ChooseExpr { cond, then, else_ } => {
                self.expr(cond); self.expr(then); self.expr(else_);
            }
            ExprKind::Elvis { cond, else_ } => { self.expr(cond); self.expr(else_); }
            ExprKind::Match { scrutinee, arms } => { self.expr(scrutinee); self.arms(arms); }
            ExprKind::Call { func, args } => { self.expr(func); for a in args.iter_mut() { self.expr(a); } }
            ExprKind::NamedArg { value, .. } => self.expr(value),
            ExprKind::Guard { body, .. } | ExprKind::StmtExpr(body) => self.block(body),
            ExprKind::Generic { controlling, assocs } => {
                self.expr(controlling);
                for (t, x) in assocs.iter_mut() {
                    if let Some(t) = t { self.qual_type(t); }
                    self.expr(x);
                }
            }
            ExprKind::CompoundLiteral { ty, init } => {
                self.qual_type(ty);
                for it in init.iter_mut() { self.init_item(it); }
            }
            ExprKind::OffsetOf { ty, designators } => {
                self.qual_type(ty);
                for d in designators.iter_mut() {
                    if let OffsetDesignator::Index(x) = d { self.expr(x); }
                }
            }
            ExprKind::SizeofType(t) | ExprKind::AlignofType(t) | ExprKind::TypeIdOf(t) => self.qual_type(t),
            ExprKind::TypesCompatible(a, b) => { self.qual_type(a); self.qual_type(b); }
            ExprKind::VaStart { list, last } => { self.expr(list); self.expr(last); }
            ExprKind::VaArg { list, ty } => { self.expr(list); self.qual_type(ty); }
            ExprKind::VaEnd { list } => self.expr(list),
            ExprKind::VaCopy { dst, src } => { self.expr(dst); self.expr(src); }
            ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::BoolLit(_) | ExprKind::BigIntLit(_)
            | ExprKind::DecimalLit(_) | ExprKind::FloatLit(_) | ExprKind::StringLit(_) | ExprKind::WideStringLit(..)
            | ExprKind::CharLit(_) | ExprKind::Nullptr => {}
            // `Status::Joined` inside the namespace that defines `Status`.
            ExprKind::EnumVariant { enum_name, .. } => self.rename_type(enum_name),
        }
    }
}
