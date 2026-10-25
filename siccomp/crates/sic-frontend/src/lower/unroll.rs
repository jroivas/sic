//! Full unrolling of small counted loops (-O2+): `for (int j = A; j < B; j++)`
//! with constant bounds and a short trip count is lowered as one copy of the
//! body per iteration, with `j` a constant in each. Array indices built from
//! `j` become constant offsets, which lets arrays of SIMD vectors (ggml's
//! `__m256 sum[4]` accumulators) stay in registers.
//!
//! The body must not change or take the address of `j`, declare another `j`,
//! leave the loop by `break`/`continue`, jump (`goto`, labels, `case`), keep
//! state across copies (`static` locals), defer work, or contain inline
//! assembly or lambdas; every construct is checked against a list of the
//! known-safe ones, so anything new is simply not unrolled.

use crate::ast::{BinOpKind, Decl, Expr, ExprKind, ForInit, Initializer, Stmt, StorageClass, UnOpKind};

/// Iterations at most, and AST nodes at most after unrolling.
const MAX_TRIPS: i64 = 16;
const MAX_NODES: usize = 600;

pub(crate) struct Plan {
    pub var: String,
    pub values: Vec<i64>,
}

/// The loop's counter and its value in each iteration, when it qualifies.
/// `konst` folds a constant expression; `is_int` says whether the declared
/// counter type is plain `int`.
pub(crate) fn plan(
    init: &Option<ForInit>, cond: &Option<Expr>, post: &Option<Expr>, body: &Stmt,
    konst: &dyn Fn(&Expr) -> Option<i64>, is_int: &dyn Fn(&Decl) -> bool,
) -> Option<Plan> {
    let Some(ForInit::Decl(d @ Decl::Var { base_ty, declarators, .. })) = init else { return None };
    if base_ty.storage.is_some() || declarators.len() != 1 || !is_int(d) { return None; }
    let dc = &declarators[0];
    if dc.cleanup.is_some() { return None; }
    let var = dc.name.clone();
    let start = match &dc.init { Some(Initializer::Expr(e)) => konst(e)?, _ => return None };
    let (op, bound) = match &cond.as_ref()?.kind {
        ExprKind::BinOp { op, lhs, rhs } if is_var(lhs, &var) => (*op, konst(rhs)?),
        _ => return None,
    };
    let step = match &post.as_ref()?.kind {
        ExprKind::PostInc { inc, expr } | ExprKind::PreInc { inc, expr } if is_var(expr, &var) => if *inc { 1 } else { -1 },
        ExprKind::Assign { op: Some(BinOpKind::Add), lhs, rhs } if is_var(lhs, &var) => konst(rhs)?,
        ExprKind::Assign { op: Some(BinOpKind::Sub), lhs, rhs } if is_var(lhs, &var) => -konst(rhs)?,
        _ => return None,
    };
    if step == 0 { return None; }
    let holds = |j: i64| match op {
        BinOpKind::Lt => j < bound, BinOpKind::Le => j <= bound,
        BinOpKind::Gt => j > bound, BinOpKind::Ge => j >= bound,
        BinOpKind::Ne => j != bound,
        _ => false,
    };
    if !matches!(op, BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge | BinOpKind::Ne) { return None; }
    let mut values = Vec::new();
    let mut j = start;
    while holds(j) {
        if values.len() as i64 >= MAX_TRIPS { return None; }
        values.push(j);
        j += step;
        if j < i32::MIN as i64 || j > i32::MAX as i64 { return None; }
    }
    if values.is_empty() { return None; }
    let mut nodes = 0usize;
    if !stmt_ok(body, &var, 0, &mut nodes) || nodes * values.len() > MAX_NODES { return None; }
    Some(Plan { var, values })
}

fn is_var(e: &Expr, var: &str) -> bool { matches!(&e.kind, ExprKind::Ident(n) if n == var) }

/// `loops` counts the loops and switches around `s` inside the body (a
/// `break` there leaves them, not the unrolled loop).
fn stmt_ok(s: &Stmt, var: &str, loops: usize, nodes: &mut usize) -> bool {
    *nodes += 1;
    match s {
        Stmt::Expr(e, _) => expr_ok(e, var, nodes),
        Stmt::Block(v, _) => v.iter().all(|x| stmt_ok(x, var, loops, nodes)),
        Stmt::Decl(Decl::Var { base_ty, declarators, .. }) => {
            !matches!(base_ty.storage, Some(StorageClass::Static) | Some(StorageClass::Extern))
                && declarators.iter().all(|d| d.name != var && d.cleanup.is_none() && match &d.init {
                    None => true,
                    Some(i) => init_ok(i, var, nodes),
                })
        }
        Stmt::If { cond, then, else_, .. } => expr_ok(cond, var, nodes) && stmt_ok(then, var, loops, nodes)
            && else_.as_ref().map_or(true, |e| stmt_ok(e, var, loops, nodes)),
        Stmt::While { cond, body, .. } | Stmt::DoWhile { body, cond, .. } =>
            expr_ok(cond, var, nodes) && stmt_ok(body, var, loops + 1, nodes),
        Stmt::For { init, cond, post, body, .. } => {
            let init_ok = match init {
                None => true,
                Some(ForInit::Expr(e)) => expr_ok(e, var, nodes),
                Some(ForInit::Decl(d)) => stmt_ok(&Stmt::Decl(d.clone()), var, loops, nodes),
            };
            init_ok && cond.as_ref().map_or(true, |e| expr_ok(e, var, nodes))
                && post.as_ref().map_or(true, |e| expr_ok(e, var, nodes))
                && stmt_ok(body, var, loops + 1, nodes)
        }
        Stmt::Return(e, _) => e.as_ref().map_or(true, |e| expr_ok(e, var, nodes)),
        Stmt::Break(_) | Stmt::Continue(_) => loops > 0,
        _ => false,
    }
}

fn init_ok(i: &Initializer, var: &str, nodes: &mut usize) -> bool {
    match i {
        Initializer::Expr(e) => expr_ok(e, var, nodes),
        Initializer::List(items) => items.iter().all(|it| it.designators.is_empty() && init_ok(&it.init, var, nodes)),
    }
}

fn expr_ok(e: &Expr, var: &str, nodes: &mut usize) -> bool {
    use ExprKind::*;
    *nodes += 1;
    let go = |x: &Expr, nodes: &mut usize| expr_ok(x, var, nodes);
    match &e.kind {
        IntLit(..) | UIntLit(..) | FloatLit(_) | CharLit(_) | StringLit(_) | BoolLit(_) | Nullptr
        | Ident(_) | SizeofType(_) | AlignofType(_) => true,
        // `j` itself must never be written or have its address taken.
        Assign { lhs, rhs, .. } => !is_var(lhs, var) && go(lhs, nodes) && go(rhs, nodes),
        PreInc { expr, .. } | PostInc { expr, .. } => !is_var(expr, var) && go(expr, nodes),
        Unary { op: UnOpKind::Addr, expr } => !is_var(expr, var) && go(expr, nodes),
        Unary { expr, .. } | Cast { expr, .. } | SizeofExpr(expr) | AlignofExpr(expr)
        | Field { base: expr, .. } | Arrow { base: expr, .. } => go(expr, nodes),
        BinOp { lhs, rhs, .. } | Index { base: lhs, index: rhs } | Comma(lhs, rhs) => go(lhs, nodes) && go(rhs, nodes),
        Ternary { cond, then, else_ } => go(cond, nodes) && go(then, nodes) && go(else_, nodes),
        Call { func, args } => go(func, nodes) && args.iter().all(|a| go(a, nodes)),
        _ => false,
    }
}
