//! Strict mode (sic.md §"Strict mode"): variables are immutable unless declared
//! `mut`. An immutable local declared without an initializer may still be
//! assigned once — its "late initialization" — when no path through the
//! function assigns it twice. (Until then it reads as zero, like any SIC
//! variable.) This pass finds those first-and-only assignments; the lowering
//! rejects every other write to an immutable binding.
//!
//! It walks the function body in order, tracking for each such local whether it
//! is unassigned, assigned, or maybe assigned on the paths reaching each point.
//! A loop body is walked twice — the second time also entered from its own
//! back edge — so an assignment repeated by the loop is caught. A function with
//! `goto` gets no late initialization (its paths are not followed).

use std::collections::{HashMap, HashSet};
use crate::ast::*;

/// The declared object may be changed: `mut` on its declaration (`mut int x`,
/// `mut char *p`).
pub(crate) fn qt_is_mut(qt: &QualType) -> bool {
    let mut cur = qt;
    loop {
        if cur.qualifiers.contains(&TypeQual::Mut) { return true; }
        match &cur.ty {
            AstType::Pointer { base, .. } | AstType::Array { base, .. } => cur = base,
            _ => return false,
        }
    }
}

/// The declaration is marked `strict` (`strict int f()`).
pub(crate) fn qt_is_strict(qt: &QualType) -> bool {
    let mut cur = qt;
    loop {
        if cur.qualifiers.contains(&TypeQual::Strict) { return true; }
        match &cur.ty {
            AstType::Pointer { base, .. } | AstType::Array { base, .. } => cur = base,
            _ => return false,
        }
    }
}

/// Where an assignment is: its target's span.
pub(crate) type Site = (Option<String>, u32, u32);

pub(crate) fn site_of(e: &Expr) -> Site { (e.span.file.clone(), e.span.line, e.span.col) }

#[derive(Clone, Copy, PartialEq, Debug)]
enum St { No, Yes, Maybe }

type State = Vec<St>;

fn get(s: &State, id: usize) -> St { s.get(id).copied().unwrap_or(St::No) }

fn merge(a: Option<State>, b: Option<State>) -> Option<State> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => {
            let n = a.len().max(b.len());
            Some((0..n).map(|i| match (get(&a, i), get(&b, i)) {
                (x, y) if x == y => x,
                _ => St::Maybe,
            }).collect())
        }
    }
}

struct Walk {
    scopes: Vec<HashMap<String, Option<usize>>>,
    next: usize,
    ok: HashSet<Site>,
    bad: HashSet<Site>,
    breaks: Vec<Option<State>>,
    conts: Vec<Option<State>>,
    cases: Vec<Option<State>>,
    in_defer: bool,
}

/// The first-and-only assignments of the uninitialized immutable locals of a
/// strict function's `body`.
pub(crate) fn late_init_sites(params: &[Param], body: &[Stmt]) -> HashSet<Site> {
    if body.iter().any(stmt_has_goto) { return HashSet::new(); }
    let mut w = Walk {
        scopes: vec![params.iter().filter_map(|p| p.name.clone().map(|n| (n, None))).collect()],
        next: 0, ok: HashSet::new(), bad: HashSet::new(),
        breaks: vec![], conts: vec![], cases: vec![], in_defer: false,
    };
    w.block(body, Some(vec![]));
    w.ok.retain(|s| !w.bad.contains(s));
    w.ok
}

fn stmt_has_goto(s: &Stmt) -> bool {
    let mut found = false;
    visit_stmts(s, &mut |x| if matches!(x, Stmt::Goto(..)) { found = true; });
    found
}

fn visit_stmts(s: &Stmt, f: &mut dyn FnMut(&Stmt)) {
    f(s);
    match s {
        Stmt::Block(v, _) | Stmt::Unsafe(v, _) => for x in v { visit_stmts(x, f); },
        Stmt::If { then, else_, .. } => { visit_stmts(then, f); if let Some(e) = else_ { visit_stmts(e, f); } }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. }
        | Stmt::ForEach { body, .. } | Stmt::Switch { body, .. } | Stmt::Defer(body, _)
        | Stmt::Label(_, body, _) | Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _)
        | Stmt::Default(body, _) => visit_stmts(body, f),
        Stmt::Match { arms, .. } => for a in arms { visit_stmts(&a.body, f); },
        Stmt::Guard { else_body, .. } => visit_stmts(else_body, f),
        _ => {}
    }
}

impl Walk {
    fn lookup(&self, n: &str) -> Option<usize> {
        for s in self.scopes.iter().rev() {
            if let Some(v) = s.get(n) { return *v; }
        }
        None
    }

    fn bind(&mut self, n: &str, tracked: bool, st: &mut Option<State>) {
        let id = if tracked {
            let id = self.next;
            self.next += 1;
            if let Some(s) = st {
                if s.len() <= id { s.resize(id + 1, St::No); }
                s[id] = St::No;
            }
            Some(id)
        } else { None };
        self.scopes.last_mut().unwrap().insert(n.to_string(), id);
    }

    fn block(&mut self, v: &[Stmt], mut st: Option<State>) -> Option<State> {
        self.scopes.push(HashMap::new());
        for s in v { st = self.stmt(s, st); }
        self.scopes.pop();
        st
    }

    fn decl(&mut self, d: &Decl, mut st: Option<State>) -> Option<State> {
        if let Decl::Var { base_ty, declarators, .. } = d {
            let local = !matches!(base_ty.storage, Some(StorageClass::Static | StorageClass::Extern));
            for dc in declarators {
                if let Some(i) = &dc.init { st = self.init(i, st); }
                let tracked = local && dc.init.is_none() && !qt_is_mut(&dc.ty)
                    && !matches!(dc.ty.ty, AstType::Function { .. });
                self.bind(&dc.name, tracked, &mut st);
            }
        }
        st
    }

    fn init(&mut self, i: &Initializer, mut st: Option<State>) -> Option<State> {
        match i {
            Initializer::Expr(e) => self.expr(e, st),
            Initializer::List(items) => { for it in items { st = self.init(&it.init, st); } st }
        }
    }

    /// One pass over a loop: `(state on the back edge, state on exit)`.
    fn loop_once(&mut self, cond: Option<&Expr>, body: &Stmt, post: Option<&Expr>, do_while: bool,
        st: Option<State>) -> (Option<State>, Option<State>) {
        let forever = cond.map_or(true, |c| matches!(c.kind, ExprKind::IntLit(n, _) if n != 0));
        let mut s = st;
        let mut exit = None;
        if !do_while {
            if let Some(c) = cond { s = self.expr(c, s); }
            if !forever { exit = s.clone(); }
        }
        self.breaks.push(None);
        self.conts.push(None);
        let b = self.stmt(body, s);
        let brk = self.breaks.pop().unwrap();
        let cnt = self.conts.pop().unwrap();
        let mut back = merge(b, cnt);
        if let Some(p) = post { back = self.expr(p, back); }
        if do_while {
            if let Some(c) = cond { back = self.expr(c, back); }
            if !forever { exit = back.clone(); }
        }
        (back, merge(exit, brk))
    }

    fn looped(&mut self, cond: Option<&Expr>, body: &Stmt, post: Option<&Expr>, do_while: bool,
        st: Option<State>) -> Option<State> {
        let (back, exit1) = self.loop_once(cond, body, post, do_while, st.clone());
        let (_, exit2) = self.loop_once(cond, body, post, do_while, merge(st, back));
        merge(exit1, exit2)
    }

    fn stmt(&mut self, s: &Stmt, st: Option<State>) -> Option<State> {
        match s {
            Stmt::Decl(d) => self.decl(d, st),
            Stmt::Expr(e, _) => self.expr(e, st),
            Stmt::Block(v, _) | Stmt::Unsafe(v, _) => self.block(v, st),
            Stmt::If { cond, then, else_, .. } => {
                let st = self.expr(cond, st);
                let a = self.block(std::slice::from_ref(then), st.clone());
                let b = match else_ { Some(e) => self.block(std::slice::from_ref(e), st), None => st };
                merge(a, b)
            }
            Stmt::While { cond, body, .. } => self.looped(Some(cond), body, None, false, st),
            Stmt::DoWhile { body, cond, .. } => self.looped(Some(cond), body, None, true, st),
            Stmt::For { init, cond, post, body, .. } => {
                self.scopes.push(HashMap::new());
                let st = match init {
                    Some(ForInit::Decl(d)) => self.decl(d, st),
                    Some(ForInit::Expr(e)) => self.expr(e, st),
                    None => st,
                };
                let r = self.looped(cond.as_ref(), body, post.as_ref(), false, st);
                self.scopes.pop();
                r
            }
            Stmt::ForEach { name, iterable, body, .. } => {
                let mut st = self.expr(iterable, st);
                self.scopes.push(HashMap::new());
                self.bind(name, false, &mut st);
                let r = self.looped(None, body, None, false, st.clone());
                self.scopes.pop();
                // The iterable may be empty: the body may not run at all.
                merge(st, r)
            }
            Stmt::Return(e, _) => { if let Some(e) = e { self.expr(e, st); } None }
            Stmt::Break(_) => {
                if let Some(b) = self.breaks.last_mut() { *b = merge(b.take(), st); }
                None
            }
            Stmt::Continue(_) => {
                if let Some(c) = self.conts.last_mut() { *c = merge(c.take(), st); }
                None
            }
            Stmt::Fallthrough(_) => st,
            Stmt::Goto(..) => None,
            Stmt::Defer(body, _) => {
                // Runs at scope exit, after anything: no assignment in it is a first one.
                let prev = std::mem::replace(&mut self.in_defer, true);
                self.stmt(body, st.clone());
                self.in_defer = prev;
                st
            }
            Stmt::Delete(e, _) => self.expr(e, st),
            Stmt::Label(_, body, _) => self.stmt(body, st),
            Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) | Stmt::Default(body, _) => {
                let entry = self.cases.last().cloned().flatten();
                let st = merge(st, entry);
                self.stmt(body, st)
            }
            Stmt::Switch { val, body, .. } => {
                let st = self.expr(val, st);
                let has_default = match body.as_ref() {
                    Stmt::Block(v, _) => v.iter().any(|x| matches!(x, Stmt::Default(..))),
                    other => matches!(other, Stmt::Default(..)),
                };
                self.cases.push(st.clone());
                self.breaks.push(None);
                // The body is entered only at a case label.
                let end = self.stmt(body, None);
                let brk = self.breaks.pop().unwrap();
                self.cases.pop();
                let out = merge(end, brk);
                if has_default { out } else { merge(out, st) }
            }
            Stmt::Match { scrutinee, arms, .. } => {
                let st = self.expr(scrutinee, st);
                let mut out = None;
                for a in arms {
                    self.scopes.push(HashMap::new());
                    let mut s = st.clone();
                    if let Some(b) = &a.binding { self.bind(b, false, &mut s); }
                    let r = self.stmt(&a.body, s);
                    self.scopes.pop();
                    out = merge(out, r);
                }
                if arms.is_empty() { st } else { out }
            }
            Stmt::Guard { binding, cond, else_body, .. } => {
                let mut st = self.expr(cond, st);
                let e = self.block(std::slice::from_ref(else_body), st.clone());
                if let Some((_, n)) = binding { self.bind(n, false, &mut st); }
                merge(st, e)
            }
            _ => st,
        }
    }

    /// A write to the tracked local `e` names (`None` if it names none).
    fn tracked(&self, e: &Expr) -> Option<usize> {
        match &e.kind { ExprKind::Ident(n) => self.lookup(n), _ => None }
    }

    fn expr(&mut self, e: &Expr, st: Option<State>) -> Option<State> {
        use ExprKind::*;
        match &e.kind {
            Assign { op, lhs, rhs } => {
                let mut st = self.expr(rhs, st);
                match self.tracked(lhs) {
                    Some(id) => {
                        let first = op.is_none() && !self.in_defer
                            && st.as_ref().map_or(true, |s| get(s, id) == St::No);
                        if first { self.ok.insert(site_of(lhs)); } else { self.bad.insert(site_of(lhs)); }
                        if let Some(s) = &mut st {
                            if s.len() <= id { s.resize(id + 1, St::No); }
                            s[id] = St::Yes;
                        }
                        st
                    }
                    None => self.expr(lhs, st),
                }
            }
            PreInc { expr, .. } | PostInc { expr, .. } => {
                if self.tracked(expr).is_some() { self.bad.insert(site_of(expr)); }
                self.expr(expr, st)
            }
            Swap { lhs, rhs } => {
                for x in [lhs, rhs] { if self.tracked(x).is_some() { self.bad.insert(site_of(x)); } }
                let st = self.expr(lhs, st);
                self.expr(rhs, st)
            }
            Ternary { cond, then, else_ } => {
                let st = self.expr(cond, st);
                let a = self.expr(then, st.clone());
                let b = self.expr(else_, st);
                merge(a, b)
            }
            Elvis { cond, else_ } => {
                let st = self.expr(cond, st);
                let b = self.expr(else_, st.clone());
                merge(st, b)
            }
            BinOp { op: BinOpKind::LogAnd | BinOpKind::LogOr, lhs, rhs } => {
                let st = self.expr(lhs, st);
                let b = self.expr(rhs, st.clone());
                merge(st, b)
            }
            // A lambda body is its own function.
            Lambda { .. } => st,
            StmtExpr(v) => self.block(v, st),
            Guard { body, .. } => {
                let b = self.block(body, st.clone());
                merge(st, b)
            }
            Match { scrutinee, arms } => {
                let st = self.expr(scrutinee, st);
                let mut out = None;
                for a in arms {
                    self.scopes.push(HashMap::new());
                    let mut s = st.clone();
                    if let Some(b) = &a.binding { self.bind(b, false, &mut s); }
                    let r = self.stmt(&a.body, s);
                    self.scopes.pop();
                    out = merge(out, r);
                }
                if arms.is_empty() { st } else { out }
            }
            BinOp { lhs, rhs, .. } | Comma(lhs, rhs) | Index { base: lhs, index: rhs }
            | VaStart { list: lhs, last: rhs } => {
                let st = self.expr(lhs, st);
                self.expr(rhs, st)
            }
            ChooseExpr { cond, then, else_ } => {
                let st = self.expr(cond, st);
                let st = self.expr(then, st);
                self.expr(else_, st)
            }
            Unary { expr, .. } | Ref { expr, .. } | Cast { expr, .. } | SizeofExpr(expr) | AlignofExpr(expr)
            | Await(expr) | TypeId(expr) | Field { base: expr, .. } | Arrow { base: expr, .. }
            | OptField { base: expr, .. } | NamedArg { value: expr, .. } | VaArg { list: expr, .. }
            | VaEnd { list: expr } => self.expr(expr, st),
            Call { func, args } => {
                let mut st = self.expr(func, st);
                for a in args { st = self.expr(a, st); }
                st
            }
            New { args, .. } | TupleExpr(args) => {
                let mut st = st;
                for a in args { st = self.expr(a, st); }
                st
            }
            Slice { base, lo, hi } => {
                let mut st = self.expr(base, st);
                if let Some(x) = lo { st = self.expr(x, st); }
                if let Some(x) = hi { st = self.expr(x, st); }
                st
            }
            Generic { controlling, .. } => self.expr(controlling, st),
            CompoundLiteral { init, .. } => {
                let mut st = st;
                for it in init { st = self.init(&it.init, st); }
                st
            }
            _ => st,
        }
    }
}
