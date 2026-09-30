//! Loop-invariant code motion for SIC fat arrays (AST stage).
//!
//! A counting loop that reads `arr[E]` where `E` does not vary with the loop
//! recomputes that load every iteration; hoisting it to a guarded preheader
//! computes it once. The classic case is a DP inner loop reading `A[i-1]` (a value
//! fixed for the whole inner loop over `j`), which the back end otherwise reloads
//! each step.
//!
//! Hoisting a memory read out of a loop is only sound if nothing in the loop can
//! write the memory it reads. Rather than general alias analysis, this exploits a
//! SIC guarantee: a local initialized with `new T[…]` is a fresh heap allocation,
//! and if its pointer *never escapes* the function (it only ever appears as the
//! base of an index, never copied to another variable, passed to a call, or
//! address-taken) then no other pointer can alias it — so its memory can only be
//! written through `arr[…] = …`. We hoist `arr[E]` when:
//!   * `arr` is such a non-escaping `new[]` local,
//!   * the loop body never writes `arr` (no `arr[..] =`, `arr[..]++`, or `del arr`),
//!   * `E` is a pure scalar expression over locals/params that the loop does not
//!     modify and whose variables are never address-taken (so no call or pointer
//!     write can change them either).
//!
//! The rewrite pulls the loop init out and guards the preload with the loop-entry
//! test, so a zero-trip loop never speculatively performs the (bounds-checked)
//! read:
//!
//! ```text
//!   for (T j = LO; cond; post)  … arr[E] …
//! =>
//!   { T j = LO;
//!     if (cond) { auto _licm0 = arr[E];
//!                 for (; cond; post) … _licm0 … } }
//! ```
//!
//! In C mode there are no `new[]` locals, so the pass finds nothing.

use std::collections::{HashMap, HashSet};
use sic_frontend::ast::*;
use crate::pass::AstPass;
use crate::visit::{MutVisitor, walk_expr, walk_stmt, walk_decl};

#[derive(Default)]
pub struct Licm { changed: bool }
impl Licm { pub fn new() -> Self { Licm::default() } }

impl AstPass for Licm {
    fn name(&self) -> &'static str { "licm" }
    fn run(&mut self, tu: &mut TranslationUnit) -> bool {
        self.changed = false;
        for d in &mut tu.decls {
            if let Decl::Func { params, body: Some(stmts), .. } = d {
                // Whole-function facts: non-escaping `new[]` locals + declared
                // locals/params + address-taken names.
                let mut fs = FnScan::default();
                for p in params.iter() { if let Some(n) = &p.name { fs.locals.insert(n.clone()); } }
                for s in stmts.iter_mut() { fs.visit_stmt(s); }
                let safe_arrays: HashSet<String> =
                    fs.new_arrays.difference(&fs.disq).cloned().collect();
                if safe_arrays.is_empty() { continue; }
                let mut h = Hoister {
                    safe_arrays, locals: fs.locals, addr_taken: fs.addr_taken,
                    counter: 0, changed: false,
                };
                for s in stmts.iter_mut() { h.visit_stmt(s); }
                self.changed |= h.changed;
            }
        }
        self.changed
    }
}

// ---- whole-function scan: new[] arrays, escapes, locals, address-taken --------

#[derive(Default)]
struct FnScan {
    new_arrays: HashSet<String>,
    disq: HashSet<String>,       // names whose pointer escapes (can't be proven unaliased)
    addr_taken: HashSet<String>,
    locals: HashSet<String>,     // declared locals + params
}

impl MutVisitor for FnScan {
    fn visit_stmt(&mut self, s: &mut Stmt) {
        // `del arr` / `defer del arr` frees the array by name — that is a known,
        // non-escaping use (the pointer does not flow to arbitrary code), so don't
        // let the bare identifier disqualify it. A `del` of a compound expression is
        // walked normally.
        if let Stmt::Delete(e, _) = s {
            if matches!(&e.kind, ExprKind::Ident(_)) { return; }
        }
        walk_stmt(self, s);
    }
    fn visit_decl(&mut self, d: &mut Decl) {
        if let Decl::Var { declarators, .. } = d {
            for de in declarators.iter() {
                self.locals.insert(de.name.clone());
                if let Some(Initializer::Expr(e)) = &de.init {
                    if matches!(&e.kind, ExprKind::New { array: true, .. }) {
                        self.new_arrays.insert(de.name.clone());
                    }
                }
            }
        }
        walk_decl(self, d);
    }
    fn visit_expr(&mut self, e: &mut Expr) {
        match &mut e.kind {
            // Indexing `arr[idx]` does NOT escape `arr` — it is exactly the safe use.
            // Recurse into the index only (unless the base is itself compound).
            ExprKind::Index { base, index } => {
                if !matches!(&base.kind, ExprKind::Ident(_)) { self.visit_expr(base); }
                self.visit_expr(index);
            }
            // Address-of escapes the target (and any array it indexes into).
            ExprKind::Ref { expr, .. } | ExprKind::Unary { op: UnOpKind::Addr, expr } => {
                match &mut expr.kind {
                    ExprKind::Ident(n) => { self.disq.insert(n.clone()); self.addr_taken.insert(n.clone()); }
                    ExprKind::Index { base, index } => {
                        if let ExprKind::Ident(n) = &base.kind {
                            self.disq.insert(n.clone()); self.addr_taken.insert(n.clone());
                        } else { self.visit_expr(base); }
                        self.visit_expr(index);
                    }
                    _ => self.visit_expr(expr),
                }
            }
            // A bare identifier used anywhere else means its value/pointer flows out
            // of a plain index — treat it as an escape (conservative for arrays;
            // harmless for scalars, which are not array candidates).
            ExprKind::Ident(n) => { self.disq.insert(n.clone()); }
            _ => walk_expr(self, e),
        }
    }
}

// ---- per-loop write/mod scan --------------------------------------------------

#[derive(Default)]
struct WriteScan {
    written_arrays: HashSet<String>, // arr in `arr[..] = ` / `arr[..]++`
    mods: HashSet<String>,           // scalar names assigned / inc'd / declared
    dels: HashSet<String>,           // names appearing in a `del`
}

impl WriteScan {
    fn note_lhs(&mut self, lhs: &Expr) {
        match &lhs.kind {
            ExprKind::Ident(n) => { self.mods.insert(n.clone()); }
            ExprKind::Index { base, .. } => {
                if let ExprKind::Ident(a) = &base.kind { self.written_arrays.insert(a.clone()); }
            }
            _ => {}
        }
    }
}

impl MutVisitor for WriteScan {
    fn visit_decl(&mut self, d: &mut Decl) {
        if let Decl::Var { declarators, .. } = d {
            for de in declarators.iter() { self.mods.insert(de.name.clone()); }
        }
        walk_decl(self, d);
    }
    fn visit_stmt(&mut self, s: &mut Stmt) {
        if let Stmt::Delete(e, _) = s { collect_idents(e, &mut self.dels); }
        walk_stmt(self, s);
    }
    fn visit_expr(&mut self, e: &mut Expr) {
        match &e.kind {
            ExprKind::Assign { lhs, .. } => self.note_lhs(lhs),
            ExprKind::PreInc { expr, .. } | ExprKind::PostInc { expr, .. } => self.note_lhs(expr),
            _ => {}
        }
        walk_expr(self, e);
    }
}

// ---- candidate collection -----------------------------------------------------

struct CandScan<'a> {
    safe_arrays: &'a HashSet<String>,
    out: Vec<(String, String, Expr)>, // (arr, key(E), the arr[E] Index expr)
}
impl<'a> MutVisitor for CandScan<'a> {
    fn visit_expr(&mut self, e: &mut Expr) {
        if let ExprKind::Index { base, index } = &e.kind {
            if let ExprKind::Ident(arr) = &base.kind {
                if self.safe_arrays.contains(arr) {
                    if let Some(k) = pure_scalar_key(index) {
                        self.out.push((arr.clone(), k, e.clone()));
                    }
                }
            }
        }
        walk_expr(self, e);
    }
}

// ---- replacement of arr[E] with a temp ----------------------------------------

struct Replacer { keys: HashMap<(String, String), String> } // (arr,key(E)) -> temp
impl MutVisitor for Replacer {
    fn visit_expr(&mut self, e: &mut Expr) {
        walk_expr(self, e);
        let repl = if let ExprKind::Index { base, index } = &e.kind {
            if let ExprKind::Ident(arr) = &base.kind {
                pure_scalar_key(index)
                    .and_then(|k| self.keys.get(&(arr.clone(), k)).cloned())
            } else { None }
        } else { None };
        if let Some(name) = repl { e.kind = ExprKind::Ident(name); }
    }
}

// ---- the hoisting visitor -----------------------------------------------------

struct Hoister {
    safe_arrays: HashSet<String>,
    locals: HashSet<String>,
    addr_taken: HashSet<String>,
    counter: usize,
    changed: bool,
}

impl MutVisitor for Hoister {
    fn visit_stmt(&mut self, s: &mut Stmt) {
        walk_stmt(self, s); // hoist inner loops first
        if let Some(rewritten) = self.try_hoist(s) {
            *s = rewritten;
            self.changed = true;
        }
    }
}

impl Hoister {
    fn try_hoist(&mut self, s: &Stmt) -> Option<Stmt> {
        let (init, cond, post, body, span) = match s {
            Stmt::For { init: Some(i), cond: Some(c), post: Some(p), body, span } =>
                (i, c, p, body, span),
            _ => return None,
        };

        // What the loop writes / modifies (body + post).
        let mut ws = WriteScan::default();
        { let mut b = body.clone(); ws.visit_stmt(&mut b);
          let mut pe = post.clone(); ws.visit_expr(&mut pe); }

        // Collect candidate `arr[E]` reads over the body.
        let mut cs = CandScan { safe_arrays: &self.safe_arrays, out: Vec::new() };
        { let mut b = body.clone(); cs.visit_stmt(&mut b); }
        if cs.out.is_empty() { return None; }

        // Filter to genuinely invariant, non-aliased reads and assign temp names.
        let mut keys: HashMap<(String, String), String> = HashMap::new();
        let mut hoists: Vec<(String, Expr)> = Vec::new(); // (tempname, arr[E])
        for (arr, k, idx_expr) in cs.out {
            if ws.written_arrays.contains(&arr) || ws.dels.contains(&arr) { continue; }
            let key = (arr.clone(), k);
            if keys.contains_key(&key) { continue; }
            // E's variables must be loop-invariant locals/params, never address-taken.
            let e_ids = match &idx_expr.kind {
                ExprKind::Index { index, .. } => { let mut s = HashSet::new(); collect_idents(index, &mut s); s }
                _ => continue,
            };
            let invariant = e_ids.iter().all(|n|
                self.locals.contains(n) && !self.addr_taken.contains(n) && !ws.mods.contains(n));
            if !invariant { continue; }
            let name = format!("__licm_{}", self.counter);
            self.counter += 1;
            keys.insert(key, name.clone());
            hoists.push((name, idx_expr));
        }
        if hoists.is_empty() { return None; }

        // Rewrite the body to read the temps instead of `arr[E]`.
        let mut body2 = body.clone();
        { let mut r = Replacer { keys }; r.visit_stmt(&mut body2); }

        // Build:  { <init>; if (cond) { auto _licmN = arr[E]; …; for(;cond;post) body2 } }
        let init_stmt = match init {
            ForInit::Decl(d) => Stmt::Decl(d.clone()),
            ForInit::Expr(e) => Stmt::Expr(e.clone(), span.clone()),
        };
        let mut then_body: Vec<Stmt> = Vec::with_capacity(hoists.len() + 1);
        for (name, arr_e) in hoists {
            let decl = Decl::Var {
                base_ty: QualType::new(AstType::Typeof(Box::new(arr_e.clone()))),
                declarators: vec![Declarator {
                    name, ty: QualType::new(AstType::Typeof(Box::new(arr_e.clone()))),
                    init: Some(Initializer::Expr(arr_e)), cleanup: None, span: span.clone(),
                }],
                weak: false, thread_local: false, span: span.clone(),
            };
            then_body.push(Stmt::Decl(decl));
        }
        then_body.push(Stmt::For {
            init: None, cond: Some(cond.clone()), post: Some(post.clone()),
            body: body2, span: span.clone(),
        });
        let guard = Stmt::If {
            cond: cond.clone(),
            then: Box::new(Stmt::Block(then_body, span.clone())),
            else_: None, span: span.clone(),
        };
        Some(Stmt::Block(vec![init_stmt, guard], span.clone()))
    }
}

// ---- small helpers ------------------------------------------------------------

/// A canonical key for a pure scalar expression (names, literals, and pure
/// non-trapping arithmetic over them), or `None` if `e` is not such an expression
/// — the only shape we hoist an index on.
fn pure_scalar_key(e: &Expr) -> Option<String> {
    use ExprKind as E;
    Some(match &e.kind {
        E::IntLit(v, _) => format!("i{}", v),
        E::UIntLit(v, _) => format!("u{}", v),
        E::CharLit(v) => format!("c{}", v),
        E::BoolLit(b) => format!("b{}", b),
        E::Ident(n) => format!("n:{}", n),
        E::Cast { expr, .. } => format!("(cast {})", pure_scalar_key(expr)?),
        E::Unary { op: op @ (UnOpKind::Neg | UnOpKind::Not | UnOpKind::BitNot), expr } =>
            format!("(u{:?} {})", op, pure_scalar_key(expr)?),
        E::BinOp { op, lhs, rhs } if is_pure_binop(op) =>
            format!("({:?} {} {})", op, pure_scalar_key(lhs)?, pure_scalar_key(rhs)?),
        _ => return None,
    })
}

fn is_pure_binop(op: &BinOpKind) -> bool {
    use BinOpKind as B;
    matches!(op, B::Add | B::Sub | B::Mul | B::BitAnd | B::BitOr | B::BitXor | B::Shl | B::Shr
        | B::Eq | B::Ne | B::Lt | B::Le | B::Gt | B::Ge)
}

/// Collect every identifier name referenced anywhere in `e`.
fn collect_idents(e: &Expr, out: &mut HashSet<String>) {
    struct C<'a>(&'a mut HashSet<String>);
    impl<'a> MutVisitor for C<'a> {
        fn visit_expr(&mut self, e: &mut Expr) {
            if let ExprKind::Ident(n) = &e.kind { self.0.insert(n.clone()); }
            walk_expr(self, e);
        }
    }
    let mut tmp = e.clone();
    C(out).visit_expr(&mut tmp);
}
