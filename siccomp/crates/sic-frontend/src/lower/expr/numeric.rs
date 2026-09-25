use crate::ast::{Expr, ExprKind, BinOpKind, UnOpKind};
use crate::{Result, CompileError};
use sic_ir::*;
use super::super::func::FuncCtx;
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    /// Call a bigint runtime function that returns a fresh `bigint` temporary, and
    /// record it for freeing at the end of the current statement (so a value
    /// re-evaluated each loop iteration does not leak). The result stays valid for
    /// the rest of the statement.
    pub(crate) fn call_bigint_new(&mut self, name: &str, args: Vec<Val>) -> Result<Val> {
        let bt = super::super::types::bigint_type();
        let v = self.emit_bigint_call(name, args, bt)?;
        self.bigint_temps.push(v.clone());
        Ok(v)
    }

    /// Free every `bigint` temporary created during the current statement. Called
    /// at statement boundaries in `lower_stmt`. Straight-line by construction (a
    /// statement's temps are produced in the block reaching its end).
    pub(crate) fn flush_bigint_temps(&mut self) {
        // sic `va_dict` (sic.md §"Named parameters"): free each per-call va_dict
        // packed in this statement (the callee only borrowed it for the call).
        if !self.va_dict_temps.is_empty() {
            let vds = std::mem::take(&mut self.va_dict_temps);
            let free = self.dict_runtime_fn("__sic_dict_free");
            for h in vds {
                self.push_instr(Instr::Call { dest: None, func: free, args: vec![h], ret_ty: Type::Void });
            }
        }
        // sic `.keys`/`.values` (sic.md §"Iterators"): free each materialized list
        // that wasn't taken over by a binding.
        if !self.list_temps.is_empty() {
            let ls = std::mem::take(&mut self.list_temps);
            let free = self.list_runtime_fn("__sic_list_free");
            for h in ls {
                self.push_instr(Instr::Call { dest: None, func: free, args: vec![h], ret_ty: Type::Void });
            }
        }
        // sic container producers (sic.md §"List"/§"Dict"): release each `new`/call
        // container whose owned reference no binding took over (`mk();`, `f(mk())`,
        // `l.add(mk())` — the last retained its own ref, so this frees the producer's).
        if !self.container_temps.is_empty() {
            let cs = std::mem::take(&mut self.container_temps);
            for (h, ty) in cs {
                let _ = self.container_release(h, &ty);
            }
        }
        if self.bigint_temps.is_empty() { return; }
        let temps = std::mem::take(&mut self.bigint_temps);
        for t in temps {
            let f = self.temp_free_fn(&t);
            let _ = self.emit_bigint_call(f, vec![t], Type::Void);
        }
    }

    /// The runtime free function for a bigint/fixed temporary: a `fixed` value is
    /// an exact rational (`__sic_rat*`) freed via `__sic_rat_free`; a `bigint` (or
    /// any other) temp is freed via `__sic_bi_free`. Dispatched on the recorded
    /// value type so a mixed temp list frees each correctly.
    fn temp_free_fn(&self, v: &Val) -> &'static str {
        if let Val::Local(id) = v {
            if matches!(self.val_types.get(&id.0), Some(t) if super::super::types::is_fixed(t)) {
                return "__sic_rat_free";
            }
        }
        "__sic_bi_free"
    }

    /// Free only the bigint/fixed temporaries recorded since `mark` (in the current
    /// block). Used to free a conditionally-evaluated sub-expression's temps (a
    /// `||`/`&&` right operand, a ternary arm) where they are created, since they
    /// don't dominate the statement-end flush.
    pub(crate) fn flush_bigint_temps_from(&mut self, mark: usize) {
        if self.bigint_temps.len() <= mark { return; }
        let temps: Vec<Val> = self.bigint_temps.split_off(mark);
        for t in temps {
            let f = self.temp_free_fn(&t);
            let _ = self.emit_bigint_call(f, vec![t], Type::Void);
        }
    }

    /// A snapshot of the pending statement-temp counts (bigint/fixed, `.keys`/
    /// `.values` list temps, and per-call `va_dict` temps), for freeing a
    /// conditionally-evaluated sub-expression's temps where they were created (they
    /// don't dominate the statement-end flush — e.g. a call in an `if` condition).
    pub(crate) fn temp_mark(&self) -> (usize, usize, usize, usize) {
        (self.bigint_temps.len(), self.list_temps.len(), self.va_dict_temps.len(),
         self.container_temps.len())
    }

    /// Free every bigint/fixed, materialized-`list`, `va_dict`, and container-producer
    /// temp recorded since `mark`.
    pub(crate) fn flush_temps_from(&mut self, mark: (usize, usize, usize, usize)) {
        self.flush_bigint_temps_from(mark.0);
        if self.list_temps.len() > mark.1 {
            let ls: Vec<Val> = self.list_temps.split_off(mark.1);
            let free = self.list_runtime_fn("__sic_list_free");
            for h in ls {
                self.push_instr(Instr::Call { dest: None, func: free, args: vec![h], ret_ty: Type::Void });
            }
        }
        if self.va_dict_temps.len() > mark.2 {
            let vds: Vec<Val> = self.va_dict_temps.split_off(mark.2);
            let free = self.dict_runtime_fn("__sic_dict_free");
            for h in vds {
                self.push_instr(Instr::Call { dest: None, func: free, args: vec![h], ret_ty: Type::Void });
            }
        }
        // sic container producers (sic.md §"List"/§"Dict"): free — with the right
        // per-type runtime — each producer created in a conditionally-evaluated
        // sub-expression (a ternary arm, a `&&`/`||` right operand) since `mark`,
        // where it dominates (the statement-end flush would not).
        if self.container_temps.len() > mark.3 {
            let cs: Vec<(Val, Type)> = self.container_temps.split_off(mark.3);
            for (h, ty) in cs {
                let _ = self.container_release(h, &ty);
            }
        }
    }

    /// A binding is transferring ownership of a freshly-produced container out of the
    /// statement temps (into a local or a reassignment slot): drop it from
    /// `container_temps` so it is not also released at statement end.
    pub(crate) fn take_container_temp(&mut self, v: &Val) {
        if let Some(pos) = self.container_temps.iter().position(|(t, _)| t == v) {
            self.container_temps.remove(pos);
        }
    }

    /// Evaluate `e` as a `bigint` value for use as a *borrowed operand* (of an
    /// arithmetic/compare op): an existing bigint is used directly (no copy); a
    /// big literal parses via the runtime; any integer is widened to a bigint.
    pub(crate) fn to_bigint(&mut self, e: &Expr) -> Result<Val> {
        if let ExprKind::BigIntLit(digits) = &e.kind {
            let s = self.emit_cstring(digits);
            return self.call_bigint_new("__sic_bi_from_str", vec![s]);
        }
        // An existing bigint value (variable, arith result temp) is borrowed as-is.
        if matches!(self.infer_expr_type(e), Ok(t) if super::super::types::is_bigint(&t)) {
            return self.lower_expr(e);
        }
        // An integer expression → widen to a temporary bigint.
        let v = self.lower_expr(e)?;
        let i64v = self.coerce(v, &Type::i64())?;
        self.call_bigint_new("__sic_bi_from_i64", vec![i64v])
    }

    /// Evaluate `e` into an OWNED `bigint` block to store into a slot (a `bigint`
    /// local/target — value semantics). The result is a fresh `__sic_bi_clone`
    /// emitted *raw* (no scope-exit free of its own): it is owned solely by the
    /// slot it is stored into, whose `BigintFree` cleanup frees it. `to_bigint`
    /// yields the borrowed source (and registers frees for any temporaries it
    /// materialises), so this never double-frees.
    pub(crate) fn eval_bigint_owned(&mut self, e: &Expr) -> Result<Val> {
        let src = self.to_bigint(e)?;
        self.emit_bigint_call("__sic_bi_clone", vec![src], super::super::types::bigint_type())
    }

    /// Lower a `bigint` arithmetic binary op `+ - *` (sic.md §"Integer sizes"):
    /// coerce each operand to a bigint and call the runtime, yielding a fresh
    /// owned result.
    pub(crate) fn lower_bigint_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        // Shifts take an integer shift count on the right, not a bigint.
        if matches!(op, BinOpKind::Shl | BinOpKind::Shr) {
            let a = self.to_bigint(lhs)?;
            let cnt = self.lower_expr(rhs)?;
            let cnt = self.coerce(cnt, &Type::u32())?;
            let f = if op == BinOpKind::Shl { "__sic_bi_shl" } else { "__sic_bi_shr" };
            return self.call_bigint_new(f, vec![a, cnt]);
        }
        let fname = match op {
            BinOpKind::Add => "__sic_bi_add",
            BinOpKind::Sub => "__sic_bi_sub",
            BinOpKind::Mul => "__sic_bi_mul",
            BinOpKind::Div => "__sic_bi_div",
            BinOpKind::Rem => "__sic_bi_mod",
            BinOpKind::BitAnd => "__sic_bi_and",
            BinOpKind::BitOr  => "__sic_bi_or",
            BinOpKind::BitXor => "__sic_bi_xor",
            _ => return Err(CompileError::new(
                format!("bigint does not support this operator"))),
        };
        let a = self.to_bigint(lhs)?;
        let b = self.to_bigint(rhs)?;
        self.call_bigint_new(fname, vec![a, b])
    }

    /// `to_bigint`, tracking whether the result is an OWNED temp (literal/int) vs a
    /// borrowed variable — so a caller can free it in-block.
    fn to_bigint_owned(&mut self, e: &Expr) -> Result<(Val, bool)> {
        if let ExprKind::BigIntLit(digits) = &e.kind {
            let s = self.emit_cstring(digits);
            let m = self.emit_bigint_call("__sic_bi_from_str", vec![s], super::super::types::bigint_type())?;
            return Ok((m, true));
        }
        if matches!(self.infer_expr_type(e), Ok(t) if super::super::types::is_bigint(&t)) {
            return Ok((self.lower_expr(e)?, false));
        }
        let v = self.lower_expr(e)?;
        let i64v = self.coerce(v, &Type::i64())?;
        let m = self.emit_bigint_call("__sic_bi_from_i64", vec![i64v], super::super::types::bigint_type())?;
        Ok((m, true))
    }

    /// Lower a `bigint` comparison (all six), via `__sic_bi_cmp` → {-1,0,1} then
    /// the relational operator against 0. Yields an `i32`; operand temps are freed
    /// in-block (safe inside `||`/`&&`).
    pub(crate) fn lower_bigint_cmp(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (a, oa) = self.to_bigint_owned(lhs)?;
        let (b, ob) = self.to_bigint_owned(rhs)?;
        let cmp = self.emit_bigint_call("__sic_bi_cmp", vec![a.clone(), b.clone()], Type::i32())?;
        if oa { self.bi_free_now(a)?; }
        if ob { self.bi_free_now(b)?; }
        self.emit_binop(op, cmp, Constant::int(0))
    }

    /// Whether `e` is (statically) a `bigint`-typed operand — used to route `+`,
    /// comparisons, etc. A `BigIntLit` counts; an integer literal does not.
    pub(crate) fn is_bigint_operand(&self, e: &Expr) -> bool {
        if matches!(&e.kind, ExprKind::BigIntLit(_)) { return true; }
        matches!(self.infer_expr_type(e), Ok(t) if super::super::types::is_bigint(&t))
    }

    // ─── fixed-point (sic.md §"Built-in fixed point") ──────────────────────────
    //
    // A `fixed<I,F>` value is, at runtime, a `bigint` mantissa equal to the real
    // value × 10^F; the scale F (and integral width I) live in the compile-time
    // type. Arithmetic harmonizes scales by rescaling a mantissa (× or ÷ 10^diff,
    // all on bigints — never a float), then reuses the bigint ops. Memory is
    // managed exactly like a bigint.

    /// Whether `e` genuinely has a `fixed` type (a bare decimal literal does NOT —
    /// `3.5 + 2.5` on their own are `double`; they turn fixed only next to a real
    /// `fixed`). Used to *trigger* fixed lowering.
    pub(crate) fn is_fixed_typed(&self, e: &Expr) -> bool {
        matches!(self.infer_expr_type(e), Ok(t) if super::super::types::is_fixed(&t))
    }

    /// Whether `e` is a fixed *operand* in a fixed context: a `fixed`-typed value
    /// OR a bare decimal literal. Unlike `is_fixed_typed`, a decimal literal counts
    /// — so `1.0 / 3.0` on the RHS of a `fixed` binding is computed as an exact
    /// rational rather than truncated `double` division.
    fn is_fixed_operand(&self, e: &Expr) -> bool {
        matches!(&e.kind, ExprKind::DecimalLit(_)) || self.is_fixed_typed(e)
    }

    /// Whether `e` is a `+ - * / %` arithmetic op whose operands are fixed operands
    /// — evaluated exactly (num/den) when materialized in a fixed context.
    fn is_fixed_binop(&self, e: &Expr) -> bool {
        use BinOpKind::*;
        matches!(&e.kind, ExprKind::BinOp { op: Add | Sub | Mul | Div | Rem, lhs, rhs }
            if self.is_fixed_operand(lhs) || self.is_fixed_operand(rhs))
    }

    /// Split a decimal literal's exact text into `(mantissa_digits, integral,
    /// fraction)` — the digits with the point removed, and the digit counts.
    pub(crate) fn decimal_lit_parts(text: &str) -> (String, u32, u32) {
        let (neg, body) = match text.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, text.trim_start_matches('+')),
        };
        let (int_part, frac_part) = match body.split_once('.') {
            Some((i, f)) => (i, f),
            None => (body, ""),
        };
        let mut mant = String::new();
        if neg { mant.push('-'); }
        mant.push_str(int_part);
        mant.push_str(frac_part);
        let integral = (int_part.len().max(1)) as u32;
        let fraction = frac_part.len() as u32;
        (mant, integral, fraction)
    }

    /// Default display precision (fraction digits) for a `fixed` whose `F` is
    /// unspecified (`fixed`, `fixed<,>`, `fixed<I,>`). ~fits a small-integral value
    /// in 64 bits (sic.md's guidance) and is plenty for most uses.
    pub(crate) const FIXED_DEFAULT_F: u32 = 18;

    /// Emit a rational-runtime call yielding a `fixed` value (a `__sic_rat*`),
    /// tagging its type so memory management frees it via `__sic_rat_free`.
    pub(crate) fn emit_rat_call(&mut self, name: &str, args: Vec<Val>) -> Result<Val> {
        self.emit_bigint_call(name, args, super::super::types::fixed_type(0, 0))
    }

    /// Free a `fixed` rational temporary immediately (in the current block).
    fn rat_free_now(&mut self, v: Val) -> Result<()> {
        self.emit_bigint_call("__sic_rat_free", vec![v], Type::Void)?;
        Ok(())
    }

    /// Evaluate `e` as a `fixed` rational → `(rat_ptr, integral, fraction, owned)`.
    /// A fixed variable is borrowed (`owned=false`); a decimal literal / integer
    /// builds a fresh owned rational. `integral`/`fraction` are the display digit
    /// widths for `typestr` and `.str`.
    fn fixed_operand_owned(&mut self, e: &Expr) -> Result<(Val, u32, u32, bool)> {
        // A fixed arithmetic binop (incl. bare-literal ops like `1.0/3.0`) is
        // computed exactly here — its result temp is statement-managed, so it is
        // handed back as a "borrowed" (not caller-freed-in-block) operand.
        if self.is_fixed_binop(e) {
            let ExprKind::BinOp { op, lhs, rhs } = &e.kind else { unreachable!() };
            let (i, f) = self.fixed_expr_dims(e).unwrap_or((0, 0));
            let r = self.lower_fixed_binop(*op, lhs, rhs)?;
            return Ok((r, i, f, false));
        }
        if let ExprKind::DecimalLit(text) = &e.kind {
            let (digits, i, f) = Self::decimal_lit_parts(text);
            let s = self.emit_cstring(&digits);
            let scale = self.coerce(Constant::int(f as i64), &Type::i32())?;
            let r = self.emit_rat_call("__sic_rat_from_decimal", vec![s, scale])?;
            return Ok((r, i, f, true));
        }
        let ty = self.infer_expr_type(e).unwrap_or_else(|_| Type::i32());
        if let Some((i, f)) = super::super::types::fixed_dims(&ty) {
            let r = self.lower_expr(e)?; // borrowed rational pointer
            return Ok((r, i, f, false));
        }
        // An integer → an exact rational with denominator 1.
        let v = self.lower_expr(e)?;
        let i64v = self.coerce(v, &Type::i64())?;
        let r = self.emit_rat_call("__sic_rat_from_i64", vec![i64v])?;
        Ok((r, 19, 0, true))
    }

    /// Like `fixed_operand_owned` but registers an owned temp for statement-end
    /// freeing (used where the operand isn't consumed immediately in-block).
    pub(crate) fn fixed_operand(&mut self, e: &Expr) -> Result<(Val, u32, u32)> {
        let (r, i, f, owned) = self.fixed_operand_owned(e)?;
        if owned { self.bigint_temps.push(r.clone()); }
        Ok((r, i, f))
    }

    /// Lower a fixed `+ - * / %` as EXACT rational arithmetic (sic.md §"Built-in
    /// fixed point") — no scale, no rounding until display. Operand temps are freed
    /// in-block; the fresh result is registered for statement-end freeing.
    pub(crate) fn lower_fixed_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let fname = match op {
            BinOpKind::Add => "__sic_rat_add",
            BinOpKind::Sub => "__sic_rat_sub",
            BinOpKind::Mul => "__sic_rat_mul",
            BinOpKind::Div => "__sic_rat_div",
            BinOpKind::Rem => "__sic_rat_mod",
            _ => return Err(CompileError::new("fixed supports only + - * / % here".to_string())),
        };
        let (a, _, _, oa) = self.fixed_operand_owned(lhs)?;
        let (b, _, _, ob) = self.fixed_operand_owned(rhs)?;
        let r = self.emit_rat_call(fname, vec![a.clone(), b.clone()])?;
        if oa { self.rat_free_now(a)?; }
        if ob { self.rat_free_now(b)?; }
        self.bigint_temps.push(r.clone());
        Ok(r)
    }

    /// Lower a fixed comparison (all six) as an exact rational compare. Operand
    /// temps are freed in-block (so a compare inside `||`/`&&` leaves nothing
    /// behind); the result is a plain `i32`.
    pub(crate) fn lower_fixed_cmp(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (a, _, _, oa) = self.fixed_operand_owned(lhs)?;
        let (b, _, _, ob) = self.fixed_operand_owned(rhs)?;
        let cmp = self.emit_bigint_call("__sic_rat_cmp", vec![a.clone(), b.clone()], Type::i32())?;
        if oa { self.rat_free_now(a)?; }
        if ob { self.rat_free_now(b)?; }
        self.emit_binop(op, cmp, Constant::int(0))
    }

    /// Result `(integral, fraction)` digit widths of a fixed op, for `typestr` and
    /// `.str` display precision (the value itself is an exact rational): `+`/`-`/`%`
    /// take the larger of each; `*` sums them; `/` keeps the larger fraction (a
    /// non-terminating quotient like 1/3 is shown to that many digits, rounded).
    pub(crate) fn fixed_result_dims(op: BinOpKind, a: (u32, u32), b: (u32, u32)) -> (u32, u32) {
        match op {
            BinOpKind::Mul => (a.0 + b.0, a.1 + b.1),
            BinOpKind::Div => (a.0 + b.1, a.1.max(b.1)),
            _ => (a.0.max(b.0), a.1.max(b.1)),
        }
    }

    /// Compile-time `(integral, fraction)` display widths of a fixed expression.
    pub(crate) fn fixed_expr_dims(&self, e: &Expr) -> Option<(u32, u32)> {
        if let ExprKind::DecimalLit(text) = &e.kind {
            let (_, i, f) = Self::decimal_lit_parts(text);
            return Some((i, f));
        }
        match &e.kind {
            ExprKind::IntLit(v, _) => return Some((v.unsigned_abs().to_string().len().max(1) as u32, 0)),
            ExprKind::UIntLit(v, _) => return Some((v.to_string().len().max(1) as u32, 0)),
            _ => {}
        }
        match self.infer_expr_type(e) {
            Ok(t) => super::super::types::fixed_dims(&t).or({
                if matches!(t, Type::Int { .. }) { Some((19, 0)) } else { None }
            }),
            _ => None,
        }
    }

    /// Materialize `e` as an OWNED `fixed` rational for storing into a slot (value
    /// semantics). The rational is exact; the target's `F` is display precision, so
    /// nothing is rounded here. Clones so the binding owns an independent block.
    pub(crate) fn eval_fixed_owned(&mut self, e: &Expr, _to_f: u32) -> Result<Val> {
        // A `fixed` target puts the RHS in a fixed numeric context: bare integer
        // literals adopt `fixed`, so `fixed a = 1/3` is the exact rational ⅓
        // rather than integer-divided to 0 (sic.md §"Built-in fixed point").
        let pe = Self::promote_numeric_literals(e);
        let (r, _, _) = self.fixed_operand(&pe)?;
        self.emit_rat_call("__sic_rat_clone", vec![r])
    }

    /// sic numeric-context literal promotion (sic.md §"Built-in fixed point"): in
    /// `T v = <expr>` with a float/double/fixed target, a bare integer literal in
    /// an arithmetic position adopts the target type — so `fixed a = 1/3` is the
    /// exact rational ⅓ and `float b = 1/3` is 0.333…, not integer-divided to 0.
    /// Rewrites `IntLit(_, false)` → `DecimalLit`, descending only through `+ - * /`,
    /// unary `-`, and ternary arms. Suffixed / unsigned literals (`1U`, `1L`),
    /// explicit casts (`(int)1`), calls, and subscripts keep their own type.
    pub(crate) fn promote_numeric_literals(e: &Expr) -> Expr {
        use BinOpKind::*;
        let kind = match &e.kind {
            // Only a bare (un-suffixed, 32-bit) integer literal is promoted; the
            // `bool=true` form marks an `L`/`LL`/oversized literal, left as-is.
            ExprKind::IntLit(v, false) => ExprKind::DecimalLit(v.to_string()),
            // An arithmetic op where either operand is explicitly typed (a suffixed
            // literal or a cast) keeps standard C semantics — no operand is promoted
            // — so `1U / 3` and `(int)1 / 3` still integer-divide.
            ExprKind::BinOp { op: op @ (Add | Sub | Mul | Div), lhs, rhs }
                if !Self::is_type_anchored(lhs) && !Self::is_type_anchored(rhs) => ExprKind::BinOp {
                op: *op,
                lhs: Box::new(Self::promote_numeric_literals(lhs)),
                rhs: Box::new(Self::promote_numeric_literals(rhs)),
            },
            ExprKind::Unary { op: UnOpKind::Neg, expr } if !Self::is_type_anchored(expr) =>
                ExprKind::Unary {
                    op: UnOpKind::Neg,
                    expr: Box::new(Self::promote_numeric_literals(expr)),
                },
            ExprKind::Ternary { cond, then, else_ } => ExprKind::Ternary {
                cond: cond.clone(),
                then: Box::new(Self::promote_numeric_literals(then)),
                else_: Box::new(Self::promote_numeric_literals(else_)),
            },
            _ => return e.clone(),
        };
        Expr { kind, span: e.span.clone() }
    }

    /// Whether `e` pins an explicit numeric type that suppresses literal promotion
    /// (sic.md §"Built-in fixed point"): a suffixed / unsigned literal (`1U`, `1L`)
    /// or an explicit cast (`(int)1`). Propagates through arithmetic, so `(1U+2)/3`
    /// stays integer. Bare literals, variables, calls, etc. do not anchor.
    fn is_type_anchored(e: &Expr) -> bool {
        use BinOpKind::*;
        match &e.kind {
            ExprKind::IntLit(_, true) | ExprKind::UIntLit(_, _) => true,
            ExprKind::Cast { .. } => true,
            ExprKind::BinOp { op: Add | Sub | Mul | Div | Rem, lhs, rhs } =>
                Self::is_type_anchored(lhs) || Self::is_type_anchored(rhs),
            ExprKind::Unary { op: UnOpKind::Neg, expr } => Self::is_type_anchored(expr),
            _ => false,
        }
    }

    /// Free a bigint/fixed temporary immediately (in the current block).
    fn bi_free_now(&mut self, m: Val) -> Result<()> {
        self.emit_bigint_call("__sic_bi_free", vec![m], Type::Void)?;
        Ok(())
    }

    /// If `pty` is a bigint or fixed parameter type, set `*pval` to the argument
    /// built as that bignum value and return true. A same-type/scale argument is
    /// passed as-is (the callee borrows it); a literal/int lowered as a scalar is
    /// (re)built here — safe because such mismatched args are pure. Temps are freed
    /// at statement end (after the call).
    pub(crate) fn build_bignum_arg(&mut self, pval: &mut Val, pty: &Type, arg: &Expr) -> Result<bool> {
        if !self.is_sic() { return Ok(false); }
        let at = self.infer_expr_type(arg).unwrap_or_else(|_| Type::i32());
        if super::super::types::is_bigint(pty) {
            if !super::super::types::is_bigint(&at) {
                *pval = self.to_bigint(arg)?;
            }
            return Ok(true);
        }
        if super::super::types::is_fixed(pty) {
            // A `fixed` value is an exact rational (`__sic_rat*`) regardless of its
            // declared `<I,F>` (display-only), so a fixed argument is borrowed as-is;
            // a decimal literal / integer is (re)built into a fresh rational temp.
            if !super::super::types::is_fixed(&at) {
                let (m, _, _) = self.fixed_operand(arg)?; // registers the owned temp
                *pval = m;
            }
            return Ok(true);
        }
        Ok(false)
    }
}
