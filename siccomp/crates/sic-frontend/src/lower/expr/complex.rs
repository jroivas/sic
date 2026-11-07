//! `_Complex T` values (C99 6.2.5, GNU extensions): a `{ re, im }` struct that
//! flows by address like any aggregate. Arithmetic is lowered here part by part;
//! `*` and `/` of two complex floating values call libgcc's `__mul?c3` and
//! `__div?c3`, as GCC does, for their Annex G infinity and NaN results.
use crate::ast::{BinOpKind, Expr, ExprKind, UnOpKind};
use crate::{CompileError, Result};
use super::super::func::FuncCtx;
use super::super::types::{complex_elem, complex_type, is_complex};
#[allow(unused_imports)]
use super::*;

/// An operand of a complex operation, its parts converted to the operation's
/// element type: a real operand has no imaginary part (it is not `+ 0i`: GCC keeps
/// `x * (a + bi)` as `xa + xbi`, so an infinite `b` stays out of a `0 * inf`).
#[derive(Clone)]
pub(crate) enum COp {
    C(Val, Val),
    R(Val),
}

/// What a GCC complex builtin is: `__real__`, `__imag__`, or `~` (conjugate).
fn builtin_part(name: &str) -> Option<&'static str> {
    let base = name.strip_suffix('f').or_else(|| name.strip_suffix('l')).filter(|b| b.ends_with("creal")
        || b.ends_with("cimag") || b.ends_with("conj")).unwrap_or(name);
    match base {
        "__builtin_creal" => Some("__real__"),
        "__builtin_cimag" => Some("__imag__"),
        "__builtin_conj" => Some("~"),
        _ => None,
    }
}

/// The operations a complex operand allows.
fn complex_op(op: BinOpKind) -> bool {
    matches!(op, BinOpKind::Add | BinOpKind::Sub | BinOpKind::Mul | BinOpKind::Div | BinOpKind::Eq | BinOpKind::Ne)
}

impl<'m> FuncCtx<'m> {
    /// The type of `e` if it is complex.
    pub(crate) fn complex_type_of(&self, e: &Expr) -> Option<Type> {
        if !super::super::types::complex_seen() { return None; }
        self.infer_expr_type(e).ok().filter(is_complex)
    }

    /// The type of `a op b` when either is complex: complex of the usual
    /// arithmetic conversion of the element (or real) types.
    pub(crate) fn complex_result(lt: &Type, rt: &Type) -> Option<Type> {
        if !is_complex(lt) && !is_complex(rt) { return None; }
        let real = |t: &Type| complex_elem(t).cloned().unwrap_or_else(|| t.clone());
        let (l, r) = (real(lt), real(rt));
        let arith = |t: &Type| matches!(t, Type::Int { .. } | Type::Bool | Type::Float32 | Type::Float64 | Type::Float80);
        if !arith(&l) || !arith(&r) { return None; }
        Some(complex_type(sic_ir::types::usual_arith_conv(&l, &r)))
    }

    fn complex_at(&mut self, p: &Val, off: u64) -> Val {
        if off == 0 { return p.clone(); }
        let d = self.alloc_val();
        self.push_instr(Instr::PtrOffset { dest: d, base: p.clone(), offset: Constant::int(off as i64) });
        Val::Local(d)
    }

    /// The real and imaginary parts of the complex value at `p`.
    pub(crate) fn complex_load(&mut self, p: &Val, ty: &Type) -> (Val, Val) {
        let elem = complex_elem(ty).unwrap().clone();
        let esz = elem.size_of(self.ptr_size());
        let part = |s: &mut Self, off| {
            let a = s.complex_at(p, off);
            let d = s.alloc_val();
            s.push_instr(Instr::Load { dest: d, ptr: a, ty: elem.clone() });
            Val::Local(d)
        };
        let re = part(self, 0);
        let im = part(self, esz);
        (re, im)
    }

    /// Store the parts into the complex object at `p`.
    pub(crate) fn complex_store(&mut self, p: &Val, ty: &Type, re: Val, im: Val) -> Result<()> {
        let elem = complex_elem(ty).unwrap().clone();
        let esz = elem.size_of(self.ptr_size());
        let re = self.coerce(re, &elem)?;
        let im = self.coerce(im, &elem)?;
        self.push_instr(Instr::Store { val: re, ptr: p.clone() });
        let a = self.complex_at(p, esz);
        self.push_instr(Instr::Store { val: im, ptr: a });
        Ok(())
    }

    /// A fresh complex value of `ty` from its parts.
    pub(crate) fn complex_make(&mut self, ty: &Type, re: Val, im: Val) -> Result<Val> {
        let d = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: d, ty: ty.clone(), align: None });
        let p = Val::Local(d);
        self.complex_store(&p, ty, re, im)?;
        Ok(p)
    }

    fn zero_of(&mut self, t: &Type) -> Result<Val> {
        let z = if t.is_float() { Constant::float(0.0) } else { Constant::zero() };
        self.coerce(z, t)
    }

    /// The value `v` of type `src` (complex or real) as a complex `target`.
    pub(crate) fn complex_convert(&mut self, v: Val, src: &Type, target: &Type) -> Result<Val> {
        let elem = complex_elem(target).unwrap().clone();
        let (re, im) = if is_complex(src) {
            let (re, im) = self.complex_load(&v, src);
            (re, im)
        } else {
            let re = self.coerce(v, &elem)?;
            let im = self.zero_of(&elem)?;
            (re, im)
        };
        self.complex_make(target, re, im)
    }

    /// The complex value `v` of type `src` as the scalar `target`: its real part,
    /// or for `_Bool` whether either part is nonzero.
    pub(crate) fn complex_to_scalar(&mut self, v: Val, src: &Type, target: &Type) -> Result<Val> {
        let (re, im) = self.complex_load(&v, src);
        if *target == Type::Bool {
            let elem = complex_elem(src).unwrap().clone();
            let z = self.zero_of(&elem)?;
            let a = self.emit_binop(BinOpKind::Ne, re, z.clone())?;
            let b = self.emit_binop(BinOpKind::Ne, im, z)?;
            let t = self.emit_binop(BinOpKind::BitOr, a, b)?;
            return self.coerce(t, target);
        }
        self.coerce(re, target)
    }

    /// `e` converted to the complex type `target` (C's conversion as if by
    /// assignment).
    pub(crate) fn lower_complex_as(&mut self, e: &Expr, target: &Type) -> Result<Val> {
        let src = self.infer_expr_type(e)?;
        if is_complex(&src) {
            let p = self.lower_aggregate_ptr(e)?;
            if &src == target { return Ok(p); }
            return self.complex_convert(p, &src, target);
        }
        if matches!(src, Type::Struct(_) | Type::Union(_) | Type::Array { .. } | Type::Pointer(_)) {
            return Err(CompileError::at("a complex value needs an arithmetic operand",
                e.span.file.clone(), e.span.line, e.span.col));
        }
        let v = self.lower_expr(e)?;
        self.complex_convert(v, &src, target)
    }

    /// A value `v` of the expression type `src` passed or stored where `target` is
    /// expected, when either is complex; else None.
    pub(crate) fn complex_coerce(&mut self, v: Val, src: &Type, target: &Type) -> Result<Option<Val>> {
        match (is_complex(src), is_complex(target)) {
            (false, false) => Ok(None),
            (_, true) if src == target => Ok(Some(v)),
            (_, true) if matches!(src, Type::Int { .. } | Type::Bool | Type::Float32 | Type::Float64 | Type::Float80) || is_complex(src)
                => self.complex_convert(v, src, target).map(Some),
            (true, false) if matches!(target, Type::Int { .. } | Type::Bool | Type::Float32 | Type::Float64 | Type::Float80)
                => self.complex_to_scalar(v, src, target).map(Some),
            _ => Ok(None),
        }
    }

    /// The argument `v` (of the expression `arg`) for a parameter of type `pty`,
    /// when either is complex.
    pub(crate) fn complex_arg(&mut self, v: &Val, arg: Option<&Expr>, pty: &Type) -> Result<Option<Val>> {
        let Some(arg) = arg else { return Ok(None) };
        if !super::super::types::complex_seen() { return Ok(None); }
        if !is_complex(pty) && self.complex_type_of(arg).is_none() { return Ok(None); }
        let Ok(src) = self.infer_expr_type(arg) else { return Ok(None) };
        self.complex_coerce(v.clone(), &src, pty)
    }

    /// An operand of a complex operation on `elem`.
    fn complex_operand(&mut self, e: &Expr, elem: &Type) -> Result<COp> {
        let t = self.infer_expr_type(e)?;
        if is_complex(&t) {
            let p = self.lower_aggregate_ptr(e)?;
            let (re, im) = self.complex_load(&p, &t);
            return Ok(COp::C(self.coerce(re, elem)?, self.coerce(im, elem)?));
        }
        let v = self.lower_expr(e)?;
        Ok(COp::R(self.coerce(v, elem)?))
    }

    fn complex_parts(&mut self, o: COp, elem: &Type) -> Result<(Val, Val)> {
        Ok(match o { COp::C(re, im) => (re, im), COp::R(re) => (re, self.zero_of(elem)?) })
    }

    /// libgcc's `__mul?c3`/`__div?c3` for the floating element type: `long double`
    /// takes the `double` one, as sic computes `long double` in double precision.
    fn complex_libcall(&mut self, mul: bool, elem: &Type, a: (Val, Val), b: (Val, Val)) -> Result<(Val, Val)> {
        let (k, t) = match elem { Type::Float32 => ('s', Type::Float32), _ => ('d', Type::Float64) };
        let name = format!("__{}{}c3", if mul { "mul" } else { "div" }, k);
        let cty = complex_type(t.clone());
        let fr = match self.lowerer.module.func_ref_by_name(&name) {
            Some(f) => f,
            None => {
                let sig = super::super::build_fn_sig(cty.clone(), vec![t.clone(); 4], false, self.ptr_size());
                self.lowerer.module.add_extern(sic_ir::ExternFunc { name, sig })
            }
        };
        let mut args = Vec::new();
        for v in [a.0, a.1, b.0, b.1] { args.push(self.coerce(v, &t)?); }
        let d = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(d), func: fr, args, ret_ty: cty.clone() });
        let (re, im) = self.complex_load(&Val::Local(d), &cty);
        Ok((self.coerce(re, elem)?, self.coerce(im, elem)?))
    }

    /// `a op b` on complex operands of element type `elem`: a fresh complex value,
    /// or for `==`/`!=` an `int`.
    pub(crate) fn complex_binop(&mut self, op: BinOpKind, a: COp, b: COp, ty: &Type) -> Result<Val> {
        use BinOpKind::*;
        let elem = complex_elem(ty).unwrap().clone();
        let float = elem.is_float();
        let (re, im) = match (op, a, b) {
            (Eq | Ne, a, b) => {
                let (ar, ai) = self.complex_parts(a, &elem)?;
                let (br, bi) = self.complex_parts(b, &elem)?;
                let r = self.emit_binop(op, ar, br)?;
                let i = self.emit_binop(op, ai, bi)?;
                let v = self.emit_binop(if op == Eq { BitAnd } else { BitOr }, r, i)?;
                return self.coerce(v, &Type::i32());
            }
            (Add | Sub, a, b) => {
                let re_of = |o: &COp| match o { COp::C(r, _) | COp::R(r) => r.clone() };
                let re = self.emit_binop(op, re_of(&a), re_of(&b))?;
                let im = match (&a, &b) {
                    (COp::C(_, x), COp::C(_, y)) => self.emit_binop(op, x.clone(), y.clone())?,
                    (COp::C(_, x), COp::R(_)) => x.clone(),
                    (COp::R(_), COp::C(_, y)) if op == Add => y.clone(),
                    (COp::R(_), COp::C(_, y)) => self.lower_neg_val(y.clone(), &elem)?,
                    (COp::R(_), COp::R(_)) => self.zero_of(&elem)?,
                };
                (re, im)
            }
            (Mul, COp::R(x), COp::C(r, i)) | (Mul, COp::C(r, i), COp::R(x)) => {
                (self.emit_binop(Mul, r, x.clone())?, self.emit_binop(Mul, i, x)?)
            }
            (Div, COp::C(r, i), COp::R(x)) => {
                (self.emit_binop(Div, r, x.clone())?, self.emit_binop(Div, i, x)?)
            }
            (Mul | Div, a, b) if float => {
                let a = self.complex_parts(a, &elem)?;
                let b = self.complex_parts(b, &elem)?;
                self.complex_libcall(op == Mul, &elem, a, b)?
            }
            (Mul, a, b) => {
                let (ar, ai) = self.complex_parts(a, &elem)?;
                let (br, bi) = self.complex_parts(b, &elem)?;
                let rr = self.emit_binop(Mul, ar.clone(), br.clone())?;
                let ii = self.emit_binop(Mul, ai.clone(), bi.clone())?;
                let ri = self.emit_binop(Mul, ar, bi)?;
                let ir = self.emit_binop(Mul, ai, br)?;
                (self.emit_binop(Sub, rr, ii)?, self.emit_binop(Add, ri, ir)?)
            }
            (Div, a, b) => {
                // Integer complex division (GCC's straightforward formula).
                let (ar, ai) = self.complex_parts(a, &elem)?;
                let (br, bi) = self.complex_parts(b, &elem)?;
                let cc = self.emit_binop(Mul, br.clone(), br.clone())?;
                let dd = self.emit_binop(Mul, bi.clone(), bi.clone())?;
                let den = self.emit_binop(Add, cc, dd)?;
                let ac = self.emit_binop(Mul, ar.clone(), br.clone())?;
                let bd = self.emit_binop(Mul, ai.clone(), bi.clone())?;
                let bc = self.emit_binop(Mul, ai, br)?;
                let ad = self.emit_binop(Mul, ar, bi)?;
                let n1 = self.emit_binop(Add, ac, bd)?;
                let n2 = self.emit_binop(Sub, bc, ad)?;
                (self.emit_binop(Div, n1, den.clone())?, self.emit_binop(Div, n2, den)?)
            }
            _ => return Err(CompileError::new(format!("invalid operands to `{}` on a complex value", super::super::func::op_symbol(op)))),
        };
        self.complex_make(ty, re, im)
    }

    fn lower_neg_val(&mut self, v: Val, elem: &Type) -> Result<Val> {
        let v = self.coerce(v, elem)?;
        let dest = self.alloc_val();
        let op = if elem.is_float() { sic_ir::UnOp::FNeg } else { sic_ir::UnOp::Neg };
        self.push_instr(Instr::UnaryOp { dest, op, val: v, ty: elem.clone() });
        Ok(Val::Local(dest))
    }

    /// Lower `e` here when it is an operation on complex values; else None.
    pub(crate) fn try_lower_complex(&mut self, e: &Expr) -> Result<Option<Val>> {
        if !super::super::types::complex_seen() { return Ok(None); }
        let at = |m: String| CompileError::at(m, e.span.file.clone(), e.span.line, e.span.col);
        match &e.kind {
            ExprKind::BinOp { op, lhs, rhs } if complex_op(*op) => {
                let (Ok(lt), Ok(rt)) = (self.infer_expr_type(lhs), self.infer_expr_type(rhs)) else { return Ok(None) };
                let Some(ty) = Self::complex_result(&lt, &rt) else { return Ok(None) };
                let elem = complex_elem(&ty).unwrap().clone();
                let a = self.complex_operand(lhs, &elem)?;
                let b = self.complex_operand(rhs, &elem)?;
                self.complex_binop(*op, a, b, &ty).map(Some)
            }
            ExprKind::BinOp { op, lhs, rhs } if !matches!(op, BinOpKind::LogAnd | BinOpKind::LogOr) => {
                if self.complex_type_of(lhs).is_some() || self.complex_type_of(rhs).is_some() {
                    return Err(at(format!("invalid operands to binary `{}` (a complex value)", super::super::func::op_symbol(*op))));
                }
                Ok(None)
            }
            ExprKind::Unary { op: op @ (UnOpKind::Neg | UnOpKind::BitNot | UnOpKind::Not), expr } => {
                let Some(ty) = self.complex_type_of(expr) else { return Ok(None) };
                let p = self.lower_aggregate_ptr(expr)?;
                if *op == UnOpKind::Not {
                    let t = self.complex_to_scalar(p, &ty, &Type::Bool)?;
                    let z = Constant::bool_val(false);
                    let r = self.emit_binop(BinOpKind::Eq, t, z)?;
                    return self.coerce(r, &Type::i32()).map(Some);
                }
                let elem = complex_elem(&ty).unwrap().clone();
                let (re, im) = self.complex_load(&p, &ty);
                // `~z` is the conjugate (GNU).
                let re = if *op == UnOpKind::Neg { self.lower_neg_val(re, &elem)? } else { re };
                let im = self.lower_neg_val(im, &elem)?;
                self.complex_make(&ty, re, im).map(Some)
            }
            ExprKind::Cast { ty, expr } => {
                let Ok(target) = self.lower_type(ty) else { return Ok(None) };
                if is_complex(&target) { return self.lower_complex_as(expr, &target).map(Some); }
                let Some(src) = self.complex_type_of(expr) else { return Ok(None) };
                if target == Type::Void {
                    self.lower_aggregate_ptr(expr)?;
                    return Ok(Some(Constant::zero()));
                }
                let p = self.lower_aggregate_ptr(expr)?;
                match self.complex_coerce(p, &src, &target)? {
                    Some(v) => Ok(Some(v)),
                    None => Err(at(format!("cannot convert a complex value to `{}`", target))),
                }
            }
            ExprKind::Assign { op, lhs, rhs } => {
                let (Ok(lt), Ok(rt)) = (self.infer_expr_type(lhs), self.infer_expr_type(rhs)) else { return Ok(None) };
                if !is_complex(&lt) && !is_complex(&rt) { return Ok(None); }
                let lv = self.lower_lvalue(lhs)?;
                let value = match op {
                    None => {
                        let v = if is_complex(&rt) { self.lower_aggregate_ptr(rhs)? } else { self.lower_expr(rhs)? };
                        match self.complex_coerce(v, &rt, &lt)? {
                            Some(v) => v,
                            None => return Err(at("incompatible types in assignment of a complex value".into())),
                        }
                    }
                    Some(bop) => {
                        let Some(ty) = Self::complex_result(&lt, &rt) else {
                            return Err(at("invalid operands to a compound assignment of a complex value".into()));
                        };
                        if !complex_op(*bop) || matches!(bop, BinOpKind::Eq | BinOpKind::Ne) {
                            return Err(at(format!("invalid operands to `{}=` (a complex value)", super::super::func::op_symbol(*bop))));
                        }
                        let elem = complex_elem(&ty).unwrap().clone();
                        let a = if is_complex(&lt) {
                            let (re, im) = self.complex_load(&lv.ptr, &lt);
                            COp::C(self.coerce(re, &elem)?, self.coerce(im, &elem)?)
                        } else {
                            let cur = self.load_lvalue(&lv)?;
                            COp::R(self.coerce(cur, &elem)?)
                        };
                        let b = self.complex_operand(rhs, &elem)?;
                        let r = self.complex_binop(*bop, a, b, &ty)?;
                        self.complex_coerce(r, &ty, &lt)?.unwrap_or(Constant::zero())
                    }
                };
                if is_complex(&lt) {
                    let size = lt.size_of(self.ptr_size());
                    let align = lt.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: lv.ptr.clone(), src: value, size, align });
                    return Ok(Some(lv.ptr));
                }
                self.store_lvalue(&lv, value.clone())?;
                Ok(Some(value))
            }
            // `z++`, `--z` (GNU): the real part steps by one.
            ExprKind::PreInc { inc, expr } | ExprKind::PostInc { inc, expr } => {
                let Some(ty) = self.complex_type_of(expr) else { return Ok(None) };
                let elem = complex_elem(&ty).unwrap().clone();
                let lv = self.lower_lvalue(expr)?;
                let (re, im) = self.complex_load(&lv.ptr, &ty);
                let old = if matches!(e.kind, ExprKind::PostInc { .. }) {
                    Some(self.complex_make(&ty, re.clone(), im.clone())?)
                } else { None };
                let one = if elem.is_float() { Constant::float(1.0) } else { Constant::int(1) };
                let one = self.coerce(one, &elem)?;
                let re = self.emit_binop(if *inc { BinOpKind::Add } else { BinOpKind::Sub }, re, one)?;
                self.complex_store(&lv.ptr, &ty, re, im)?;
                Ok(Some(old.unwrap_or(lv.ptr)))
            }
            ExprKind::Ternary { cond, then, else_ } => {
                let (Ok(tt), Ok(et)) = (self.infer_expr_type(then), self.infer_expr_type(else_)) else { return Ok(None) };
                let Some(ty) = Self::complex_result(&tt, &et) else { return Ok(None) };
                if tt == ty && et == ty { return Ok(None); }
                let then = Expr::new(ExprKind::Cast { ty: crate::ast::QualType::new(crate::ast::AstType::Lowered(ty.clone())), expr: then.clone() }, then.span.clone());
                let else_ = Expr::new(ExprKind::Cast { ty: crate::ast::QualType::new(crate::ast::AstType::Lowered(ty)), expr: else_.clone() }, else_.span.clone());
                self.lower_ternary(cond, &then, &else_).map(Some)
            }
            ExprKind::Call { func, args } => {
                let ExprKind::Ident(name) = &func.kind else { return Ok(None) };
                if self.lookup(name).is_some() { return Ok(None); }
                // GCC's `__builtin_creal`/`cimag`/`conj` (and `f`/`l` forms).
                let gnu = builtin_part(name);
                if let Some(part) = gnu {
                    if args.len() != 1 { return Err(at(format!("`{}` takes one argument", name))); }
                    let f = Expr::new(ExprKind::Ident(part.to_string()), func.span.clone());
                    let call = Expr::new(ExprKind::Call { func: Box::new(f), args: args.clone() }, e.span.clone());
                    let call = if part == "~" {
                        Expr::new(ExprKind::Unary { op: UnOpKind::BitNot, expr: Box::new(args[0].clone()) }, e.span.clone())
                    } else { call };
                    return self.try_lower_complex(&call);
                }
                match name.as_str() {
                    "__sic_imaginary" => {
                        let t = self.infer_expr_type(&args[0])?;
                        let ty = complex_type(t.clone());
                        let im = self.lower_expr(&args[0])?;
                        let re = self.zero_of(&t)?;
                        self.complex_make(&ty, re, im).map(Some)
                    }
                    "__builtin_complex" => {
                        if args.len() != 2 { return Err(at("__builtin_complex takes two arguments".into())); }
                        let t = self.infer_expr_type(&args[0])?;
                        if !t.is_float() || self.infer_expr_type(&args[1])? != t {
                            return Err(at("__builtin_complex needs two arguments of the same floating type".into()));
                        }
                        let ty = complex_type(t);
                        let re = self.lower_expr(&args[0])?;
                        let im = self.lower_expr(&args[1])?;
                        self.complex_make(&ty, re, im).map(Some)
                    }
                    "__real__" | "__imag__" => {
                        let t = self.infer_expr_type(&args[0])?;
                        if is_complex(&t) {
                            let p = self.lower_aggregate_ptr(&args[0])?;
                            let (re, im) = self.complex_load(&p, &t);
                            return Ok(Some(if name == "__real__" { re } else { im }));
                        }
                        // Of a real value: the value itself, or a zero.
                        let v = self.lower_expr(&args[0])?;
                        if name == "__real__" { return Ok(Some(v)); }
                        self.zero_of(&t).map(Some)
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    /// The truth value of `e` (a complex value is true when either part is).
    pub(crate) fn lower_truth(&mut self, e: &Expr) -> Result<Val> {
        if let Some(t) = self.complex_type_of(e) {
            let p = self.lower_aggregate_ptr(e)?;
            return self.complex_to_scalar(p, &t, &Type::Bool);
        }
        let v = self.lower_expr(e)?;
        self.to_bool(v)
    }

    /// `__real__ z` / `__imag__ z` of a complex lvalue as an lvalue.
    pub(crate) fn complex_part_lvalue(&mut self, e: &Expr) -> Result<Option<LValue>> {
        let ExprKind::Call { func, args } = &e.kind else { return Ok(None) };
        let ExprKind::Ident(name) = &func.kind else { return Ok(None) };
        if !matches!(name.as_str(), "__real__" | "__imag__") || args.len() != 1 || self.lookup(name).is_some() {
            return Ok(None);
        }
        let Some(ty) = self.complex_type_of(&args[0]) else { return Ok(None) };
        let lv = self.lower_lvalue(&args[0])?;
        let elem = complex_elem(&ty).unwrap().clone();
        let off = if name == "__real__" { 0 } else { elem.size_of(self.ptr_size()) };
        let p = self.complex_at(&lv.ptr, off);
        Ok(Some(LValue::plain(p, elem)))
    }

    /// The result type of a complex builtin.
    pub(crate) fn complex_builtin_type(&self, name: &str, args: &[Expr]) -> Option<Type> {
        let arg = |i: usize| args.get(i).and_then(|a| self.infer_expr_type(a).ok());
        let name = match builtin_part(name) { Some("~") => return arg(0), Some(p) => p, None => name };
        match name {
            "__sic_imaginary" | "__builtin_complex" => arg(0).map(complex_type),
            "__real__" | "__imag__" => arg(0).map(|t| complex_elem(&t).cloned().unwrap_or(t)),
            _ => None,
        }
    }
}
