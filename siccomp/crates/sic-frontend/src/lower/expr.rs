use crate::ast::{self, Expr, ExprKind, BinOpKind, UnOpKind};
use crate::{Result, CompileError};
use sic_ir::*;
use super::func::{FuncCtx, LookupResult};

/// The result of lowering a "location" (lvalue) — a pointer to the storage.
struct LValue {
    ptr: Val,
    ty: Type,    // type of the pointee
    /// Set when the location is a bit-field: (bit offset within the storage unit
    /// pointed to by `ptr`, width in bits, whether the field is signed). Reads
    /// and writes go through masked load/store.
    bitfield: Option<BitField>,
}

#[derive(Clone, Copy)]
pub(super) struct BitField {
    bit_offset: u32,
    width: u32,
    signed: bool,
}

impl LValue {
    fn plain(ptr: Val, ty: Type) -> Self { LValue { ptr, ty, bitfield: None } }
}

impl<'m> FuncCtx<'m> {
    /// Emit a NUL-terminated string as a private global and return a pointer to
    /// its first element (the decayed `char *` value).
    pub fn emit_cstring(&mut self, s: &str) -> Val {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // null terminate
        let name = format!(".str.{}", self.lowerer.module.globals.len());
        let len = bytes.len();
        let g = Global {
            name,
            ty: Type::Array { elem: Box::new(Type::i8()), len },
            init: Some(Constant::Bytes(bytes)),
            linkage: Linkage::Private,
            constant: true,
        };
        let gref = self.lowerer.module.add_global(g);
        let ptr_id = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: ptr_id,
            base: Val::Global(gref),
            index: Constant::zero(),
            elem_size: 1,
            result_ty: Type::char_ptr(),
        });
        Val::Local(ptr_id)
    }

    /// Lower an expression, returning its rvalue.
    pub fn lower_expr(&mut self, expr: &Expr) -> Result<Val> {
        match &expr.kind {
            ExprKind::Generic { controlling, assocs } => {
                let idx = self.select_generic(controlling, assocs)?;
                self.lower_expr(&assocs[idx].1)
            }
            ExprKind::OffsetOf { ty, designators } => {
                let off = self.compute_offsetof(ty, designators)?;
                self.coerce(Constant::int(off as i64), &Type::u64())
            }
            // Widen a 64-bit literal to its declared width so its runtime type
            // isn't the default 32-bit (needed for e.g. `1LL << 40`). For a
            // large-magnitude value `val_type` already reports 64-bit, so the
            // coercion is a no-op there and only kicks in for small-valued but
            // suffix-typed literals.
            ExprKind::IntLit(v, is64) => {
                let c = Constant::int(*v);
                if *is64 { self.coerce(c, &Type::i64()) } else { Ok(c) }
            }
            ExprKind::UIntLit(v, is64) => {
                let c = Constant::uint(*v);
                if *is64 { self.coerce(c, &Type::Int { bits: 64, signed: false }) } else { Ok(c) }
            }
            ExprKind::FloatLit(v) => Ok(Val::Const(Constant::Float(*v))),
            ExprKind::CharLit(v) => Ok(Constant::int(*v as i64)),
            ExprKind::StringLit(s) => Ok(self.emit_cstring(s)),
            ExprKind::Nullptr => Ok(Constant::null()),

            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, vid)) => {
                        let ty = ty.clone();
                        // Arrays and structs decay to pointer-to-first-element in rvalue context
                        if matches!(ty, Type::Array { .. }) {
                            return Ok(Val::Local(vid));
                        }
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Load { dest, ptr: Val::Local(vid), ty });
                        Ok(Val::Local(dest))
                    }
                    Some(LookupResult::Global(ty, gref)) => {
                        let ty = ty.clone();
                        // Arrays decay to pointer in rvalue context
                        if matches!(ty, Type::Array { .. }) {
                            return Ok(Val::Global(gref));
                        }
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Load { dest, ptr: Val::Global(gref), ty });
                        Ok(Val::Local(dest))
                    }
                    Some(LookupResult::EnumConst(v)) => Ok(Constant::int(v)),
                    Some(LookupResult::Func(fref)) => Ok(Val::Func(fref)),
                    None => {
                        // Compiler-provided predefined identifiers that expand to a
                        // string literal naming the enclosing function. Unlike
                        // __FILE__/__LINE__ these are not preprocessor macros, so we
                        // synthesize them here natively.
                        match name.as_str() {
                            "__func__" | "__FUNCTION__" => {
                                let fname = self.func_ref().name.clone();
                                return Ok(self.emit_cstring(&fname));
                            }
                            "__PRETTY_FUNCTION__" => {
                                let pretty = self.pretty_func.clone();
                                return Ok(self.emit_cstring(&pretty));
                            }
                            _ => {}
                        }
                        Err(CompileError::at(
                            format!("undefined name '{}'", name),
                            expr.span.file.clone(), expr.span.line, expr.span.col,
                        ))
                    }
                }
            }

            ExprKind::BinOp { op, lhs, rhs } => self.lower_binop(*op, lhs, rhs),

            ExprKind::Assign { op, lhs, rhs } => self.lower_assign(*op, lhs, rhs),

            ExprKind::Unary { op, expr: inner } => self.lower_unary(*op, inner),

            ExprKind::PreInc { inc, expr: inner } => self.lower_pre_inc(*inc, inner),
            ExprKind::PostInc { inc, expr: inner } => self.lower_post_inc(*inc, inner),

            ExprKind::Ternary { cond, then, else_ } => self.lower_ternary(cond, then, else_),
            ExprKind::Elvis { cond, else_ } => self.lower_elvis(cond, else_),

            ExprKind::Call { func, args } => self.lower_call(func, args, &expr.span),

            ExprKind::Index { base, index } => {
                let lv = self.lower_lvalue_index(base, index)?;
                // An array element that is itself an array decays to a pointer to
                // its first element (`a[i]` in `a[i][j]` yields the row address,
                // not a load of the whole row).
                if matches!(lv.ty, Type::Array { .. }) {
                    return Ok(lv.ptr);
                }
                let dest = self.alloc_val();
                let ty = lv.ty.clone();
                self.push_instr(Instr::Load { dest, ptr: lv.ptr, ty });
                Ok(Val::Local(dest))
            }

            ExprKind::Field { base, name } => {
                let lv = self.lower_lvalue_field(base, name)?;
                // An array member decays to a pointer to its first element.
                if matches!(lv.ty, Type::Array { .. }) {
                    return Ok(lv.ptr);
                }
                self.load_lvalue(&lv)
            }

            ExprKind::Arrow { base, name } => {
                let lv = self.lower_lvalue_arrow(base, name)?;
                if matches!(lv.ty, Type::Array { .. }) {
                    return Ok(lv.ptr);
                }
                self.load_lvalue(&lv)
            }

            ExprKind::Cast { ty, expr: inner } => {
                let v = self.lower_expr(inner)?;
                let target = self.lower_type(ty)?;
                self.coerce(v, &target)
            }

            ExprKind::SizeofType(ty) => {
                let ir_ty = self.lower_type(ty)?;
                let size = ir_ty.size_of(self.ptr_size());
                Ok(Constant::uint(size))
            }

            ExprKind::SizeofExpr(inner) => {
                // We need the type of the expression without evaluating it.
                // Simplified: just return a placeholder for now.
                let ty = self.infer_expr_type(inner)?;
                let size = ty.size_of(self.ptr_size());
                Ok(Constant::uint(size))
            }

            ExprKind::ChooseExpr { cond, then, else_ } => {
                // Compile-time selection: only the chosen branch is lowered.
                if self.eval_choose_cond(cond) != 0 { self.lower_expr(then) }
                else { self.lower_expr(else_) }
            }
            ExprKind::TypesCompatible(t1, t2) => {
                let compat = match (self.lower_type(t1), self.lower_type(t2)) {
                    (Ok(a), Ok(b)) => self.types_equal(&a, &b),
                    _ => false,
                };
                Ok(Constant::int(if compat { 1 } else { 0 }))
            }

            ExprKind::AlignofType(ty) => {
                let a = self.lower_type(ty)?.align_of(self.ptr_size());
                Ok(Constant::uint(a))
            }
            ExprKind::AlignofExpr(inner) => {
                let a = self.infer_expr_type(inner)?.align_of(self.ptr_size());
                Ok(Constant::uint(a))
            }

            ExprKind::Comma(lhs, rhs) => {
                self.lower_expr(lhs)?;
                self.lower_expr(rhs)
            }

            ExprKind::StmtExpr(stmts) => {
                // GCC statement expression: the value is that of the last
                // statement when it is an expression statement, else void (0).
                self.enter_scope();
                let mut result = Constant::zero();
                let n = stmts.len();
                for (i, stmt) in stmts.iter().enumerate() {
                    if self.is_terminated() { break; }
                    if i + 1 == n {
                        if let ast::Stmt::Expr(e, _) = stmt {
                            result = self.lower_expr(e)?;
                            continue;
                        }
                    }
                    self.lower_stmt(stmt)?;
                }
                self.exit_scope();
                Ok(result)
            }

            ExprKind::CompoundLiteral { ty, init } => {
                let ir_ty = self.lower_type(ty)?;
                let vid = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: vid, ty: ir_ty.clone(), align: None });
                // Zero first
                let size = ir_ty.size_of(self.ptr_size());
                if size > 0 {
                    self.push_instr(Instr::MemSet {
                        dst: Val::Local(vid), val: Constant::zero(), size,
                        align: ir_ty.align_of(self.ptr_size()),
                    });
                }
                let ptr = Val::Local(vid);
                // Reuse the full brace-initializer lowering (handles designators,
                // nested aggregates, and cursor positioning).
                let list = crate::ast::Initializer::List(init.clone());
                self.lower_initializer(&list, ptr.clone(), &ir_ty)?;
                // A compound literal decays to a pointer to its temporary.
                Ok(ptr)
            }

            ExprKind::VaStart { list, last } => {
                let _ = last;
                let list_ptr = self.lower_va_list_ptr(list)?;
                self.push_instr(Instr::VaStart { list_ptr });
                Ok(Constant::zero())
            }

            ExprKind::VaArg { list, ty } => {
                let list_ptr = self.lower_va_list_ptr(list)?;
                let ir_ty = self.lower_type(ty)?;
                let dest = self.alloc_val();
                self.push_instr(Instr::VaArg { dest, list_ptr, ty: ir_ty });
                Ok(Val::Local(dest))
            }

            ExprKind::VaEnd { list } => {
                let list_ptr = self.lower_va_list_ptr(list)?;
                self.push_instr(Instr::VaEnd { list_ptr });
                Ok(Constant::zero())
            }

            ExprKind::VaCopy { dst, src } => {
                // va_copy(d, s): duplicate the whole va_list state.
                let dptr = self.lower_va_list_ptr(dst)?;
                let sptr = self.lower_va_list_ptr(src)?;
                let vl = super::types::va_list_type();
                let size = vl.size_of(self.ptr_size());
                let align = vl.align_of(self.ptr_size());
                self.push_instr(Instr::MemCopy { dst: dptr, src: sptr, size, align });
                Ok(Constant::zero())
            }
        }
    }

    fn lower_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        // Short-circuit for logical ops
        if op == BinOpKind::LogAnd || op == BinOpKind::LogOr {
            return self.lower_logical(op == BinOpKind::LogAnd, lhs, rhs);
        }

        let l = self.lower_expr(lhs)?;
        let r = self.lower_expr(rhs)?;
        self.emit_binop(op, l, r)
    }

    pub fn emit_binop(&mut self, op: BinOpKind, l: Val, r: Val) -> Result<Val> {
        let lt = self.val_type(&l);
        let rt = self.val_type(&r);

        // Handle pointer arithmetic: ptr + int, int + ptr, ptr - int
        if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
            match (&lt, &rt) {
                (Type::Pointer(elem), _) if !matches!(rt, Type::Pointer(_)) => {
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => *e.clone(), t => t.clone() };
                    // Resolve an opaque pointee aggregate so the element stride is
                    // its real size, not 0/1 (pointer pointees are stored opaque).
                    let inner = super::types::resolve_aggregate(&inner, &self.lowerer.struct_types);
                    let elem_size = inner.size_of(self.ptr_size()) as i64;
                    let idx = self.coerce(r, &Type::i64())?;
                    let idx = if op == BinOpKind::Sub {
                        let neg = self.alloc_val();
                        self.push_instr(Instr::UnaryOp { dest: neg, op: UnOp::Neg, val: idx, ty: Type::i64() });
                        Val::Local(neg)
                    } else { idx };
                    let dest = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest, base: l, index: idx, elem_size: elem_size.unsigned_abs(), result_ty: Type::Pointer(Box::new(inner.clone())) });
                    self.val_types.insert(dest.0, Type::Pointer(Box::new(inner)));
                    return Ok(Val::Local(dest));
                }
                (_, Type::Pointer(elem)) if op == BinOpKind::Add => {
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => *e.clone(), t => t.clone() };
                    let inner = super::types::resolve_aggregate(&inner, &self.lowerer.struct_types);
                    let elem_size = inner.size_of(self.ptr_size());
                    let idx = self.coerce(l, &Type::i64())?;
                    let dest = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest, base: r, index: idx, elem_size, result_ty: Type::Pointer(Box::new(inner.clone())) });
                    self.val_types.insert(dest.0, Type::Pointer(Box::new(inner)));
                    return Ok(Val::Local(dest));
                }
                (Type::Pointer(elem), Type::Pointer(_)) if op == BinOpKind::Sub => {
                    // ptr - ptr → (ptr - ptr) / elem_size
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => (**e).clone(), t => t.clone() };
                    let inner = super::types::resolve_aggregate(&inner, &self.lowerer.struct_types);
                    let elem_size = inner.size_of(self.ptr_size()) as i64;
                    let lp = self.coerce(l, &Type::i64())?;
                    let rp = self.coerce(r, &Type::i64())?;
                    let diff = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: diff, op: BinOp::Sub, lhs: lp, rhs: rp, ty: Type::i64() });
                    if elem_size > 1 {
                        let elem_size_val = Constant::int(elem_size);
                        let quot = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: quot, op: BinOp::SDiv, lhs: Val::Local(diff), rhs: elem_size_val, ty: Type::i64() });
                        return Ok(Val::Local(quot));
                    }
                    return Ok(Val::Local(diff));
                }
                _ => {}
            }
        }

        let common = usual_arith_conv(&lt, &rt);

        let lc = self.coerce(l, &common)?;
        let rc = self.coerce(r, &common)?;

        let is_float = common.is_float();
        let is_signed = common.is_signed();

        let (ir_op, result_ty) = match op {
            BinOpKind::Add => (if is_float { BinOp::FAdd } else { BinOp::Add }, common.clone()),
            BinOpKind::Sub => (if is_float { BinOp::FSub } else { BinOp::Sub }, common.clone()),
            BinOpKind::Mul => (if is_float { BinOp::FMul } else { BinOp::Mul }, common.clone()),
            BinOpKind::Div => {
                let op = if is_float { BinOp::FDiv } else if is_signed { BinOp::SDiv } else { BinOp::UDiv };
                (op, common.clone())
            }
            BinOpKind::Rem => {
                let op = if is_float { BinOp::FRem } else if is_signed { BinOp::SRem } else { BinOp::URem };
                (op, common.clone())
            }
            BinOpKind::BitAnd => (BinOp::And, common.clone()),
            BinOpKind::BitOr  => (BinOp::Or,  common.clone()),
            BinOpKind::BitXor => (BinOp::Xor, common.clone()),
            BinOpKind::Shl    => (BinOp::Shl,  common.clone()),
            BinOpKind::Shr    => (if is_signed { BinOp::AShr } else { BinOp::LShr }, common.clone()),
            // Comparisons return i32 (C convention: 0 or 1)
            BinOpKind::Eq | BinOpKind::Ne | BinOpKind::Lt | BinOpKind::Le |
            BinOpKind::Gt | BinOpKind::Ge => {
                let cmp_op = if is_float {
                    match op {
                        BinOpKind::Eq => CmpOp::FOEq, BinOpKind::Ne => CmpOp::FONe,
                        BinOpKind::Lt => CmpOp::FOLt, BinOpKind::Le => CmpOp::FOLe,
                        BinOpKind::Gt => CmpOp::FOGt, BinOpKind::Ge => CmpOp::FOGe,
                        _ => unreachable!()
                    }
                } else if is_signed {
                    match op {
                        BinOpKind::Eq => CmpOp::IEq,  BinOpKind::Ne => CmpOp::INe,
                        BinOpKind::Lt => CmpOp::ISLt, BinOpKind::Le => CmpOp::ISLe,
                        BinOpKind::Gt => CmpOp::ISGt, BinOpKind::Ge => CmpOp::ISGe,
                        _ => unreachable!()
                    }
                } else {
                    // Unsigned ints AND pointers: pointer relational comparisons
                    // are unsigned (addresses like 0xffff... must compare above
                    // real heap/stack addresses, not as a negative number).
                    match op {
                        BinOpKind::Eq => CmpOp::IEq,  BinOpKind::Ne => CmpOp::INe,
                        BinOpKind::Lt => CmpOp::IULt, BinOpKind::Le => CmpOp::IULe,
                        BinOpKind::Gt => CmpOp::IUGt, BinOpKind::Ge => CmpOp::IUGe,
                        _ => unreachable!()
                    }
                };
                let cmp_dest = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: cmp_dest, op: cmp_op, lhs: lc, rhs: rc, ty: common.clone() });
                // Extend bool to i32
                let ext_dest = self.alloc_val();
                self.push_instr(Instr::Cast { dest: ext_dest, op: CastOp::ZExt, val: Val::Local(cmp_dest), to_ty: Type::i32() });
                return Ok(Val::Local(ext_dest));
            }
            BinOpKind::LogAnd | BinOpKind::LogOr => unreachable!(),
        };

        let dest = self.alloc_val();
        self.push_instr(Instr::BinOp { dest, op: ir_op, lhs: lc, rhs: rc, ty: result_ty });
        Ok(Val::Local(dest))
    }

    fn lower_logical(&mut self, is_and: bool, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: Type::i32(), align: None });
        let zero = Constant::zero();
        let one = Constant::int(1);

        let lhs_val = self.lower_expr(lhs)?;
        let lhs_bool = self.to_bool(lhs_val)?;

        let rhs_bb = self.new_block_after_current();
        let end_bb  = self.new_block_after_current();

        if is_and {
            // if lhs is false → result=0, else evaluate rhs
            let false_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: lhs_bool, then_bb: rhs_bb, else_bb: false_bb });

            self.switch_to_block(false_bb);
            self.push_instr(Instr::Store { val: zero.clone(), ptr: Val::Local(result_ptr) });
            self.set_terminator(Terminator::Jump(end_bb));
        } else {
            // if lhs is true → result=1, else evaluate rhs
            let true_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: lhs_bool, then_bb: true_bb, else_bb: rhs_bb });

            self.switch_to_block(true_bb);
            self.push_instr(Instr::Store { val: one.clone(), ptr: Val::Local(result_ptr) });
            self.set_terminator(Terminator::Jump(end_bb));
        }

        self.switch_to_block(rhs_bb);
        let rhs_val = self.lower_expr(rhs)?;
        let rhs_bool = self.to_bool(rhs_val)?;
        // Store 0 or 1 based on rhs bool
        let rhs_ext = self.alloc_val();
        self.push_instr(Instr::Cast { dest: rhs_ext, op: CastOp::ZExt, val: rhs_bool, to_ty: Type::i32() });
        self.push_instr(Instr::Store { val: Val::Local(rhs_ext), ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(end_bb));

        self.switch_to_block(end_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: Type::i32() });
        Ok(Val::Local(dest))
    }

    fn lower_assign(&mut self, op: Option<BinOpKind>, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(lhs)?;

        // Aggregate (struct/union) assignment is a byte copy, not a scalar
        // load/store — the latter would truncate anything wider than a register.
        if op.is_none() && matches!(lv.ty, Type::Struct(_) | Type::Union(_)) {
            // Copy the whole object, whether the RHS is an lvalue or an aggregate
            // rvalue (e.g. a compound literal `(T){...}` or a struct return).
            let src = self.lower_aggregate_ptr(rhs)?;
            let size = lv.ty.size_of(self.ptr_size());
            let align = lv.ty.align_of(self.ptr_size());
            self.push_instr(Instr::MemCopy { dst: lv.ptr.clone(), src, size, align });
            return Ok(lv.ptr);
        }

        let rhs_val = self.lower_expr(rhs)?;

        let store_val = if let Some(bin_op) = op {
            // Load current value (bit-field aware), apply op, store result.
            let cur = self.load_lvalue(&lv)?;
            self.emit_binop(bin_op, cur, rhs_val)?
        } else {
            rhs_val
        };

        self.store_lvalue(&lv, store_val)
    }

    fn lower_unary(&mut self, op: UnOpKind, inner: &Expr) -> Result<Val> {
        match op {
            UnOpKind::Addr => {
                // `&func` yields a function pointer — functions aren't lvalues
                // but are addressable, and `&func` is equivalent to `func`.
                if let ExprKind::Ident(name) = &inner.kind {
                    if let Some(LookupResult::Func(fref)) = self.lookup(name) {
                        return Ok(Val::Func(fref));
                    }
                }
                let lv = self.lower_lvalue(inner)?;
                Ok(lv.ptr)
            }
            UnOpKind::Deref => {
                let ptr = self.lower_expr(inner)?;
                // Determine pointee type
                let ptr_ty = self.val_type(&ptr);
                let inner_ty = self.pointee_of(&ptr_ty);
                // Dereferencing a function pointer yields a function designator
                // that immediately decays back to the pointer — emit no load
                // (so `(*fp)(args)` calls `fp` directly rather than a garbage
                // value loaded from the function's code).
                if matches!(inner_ty, Type::Function(_)) {
                    return Ok(ptr);
                }
                let dest = self.alloc_val();
                self.push_instr(Instr::Load { dest, ptr, ty: inner_ty });
                Ok(Val::Local(dest))
            }
            UnOpKind::Neg => {
                let v = self.lower_expr(inner)?;
                let ty = self.val_type(&v);
                let dest = self.alloc_val();
                let un_op = if ty.is_float() { UnOp::FNeg } else { UnOp::Neg };
                self.push_instr(Instr::UnaryOp { dest, op: un_op, val: v, ty: ty.clone() });
                Ok(Val::Local(dest))
            }
            UnOpKind::Not => {
                let v = self.lower_expr(inner)?;
                let b = self.to_bool(v)?;
                // Flip the bool
                let dest = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest, op: UnOp::BoolNot, val: b, ty: Type::Bool });
                // Extend to i32
                let ext = self.alloc_val();
                self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: Val::Local(dest), to_ty: Type::i32() });
                Ok(Val::Local(ext))
            }
            UnOpKind::BitNot => {
                let v = self.lower_expr(inner)?;
                let ty = self.val_type(&v);
                let dest = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest, op: UnOp::Not, val: v, ty: ty.clone() });
                Ok(Val::Local(dest))
            }
        }
    }

    /// Read an lvalue's value, extracting a bit-field with shifts/masking.
    fn load_lvalue(&mut self, lv: &LValue) -> Result<Val> {
        if let Some(bf) = lv.bitfield {
            let ty = lv.ty.clone();
            let bits = ty.int_bits().unwrap_or(32);
            let raw = self.alloc_val();
            self.push_instr(Instr::Load { dest: raw, ptr: lv.ptr.clone(), ty: ty.clone() });
            // Shift the field to the top, then back down: masks and (for signed
            // fields) sign-extends in one pair of shifts.
            let left = bits.saturating_sub(bf.bit_offset + bf.width);
            let right = bits.saturating_sub(bf.width);
            let hi = if left > 0 {
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: BinOp::Shl, lhs: Val::Local(raw), rhs: Constant::int(left as i64), ty: ty.clone() });
                Val::Local(d)
            } else { Val::Local(raw) };
            let op = if bf.signed { BinOp::AShr } else { BinOp::LShr };
            let res = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: res, op, lhs: hi, rhs: Constant::int(right as i64), ty });
            return Ok(Val::Local(res));
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: lv.ptr.clone(), ty: lv.ty.clone() });
        Ok(Val::Local(dest))
    }

    /// Store `val` into an lvalue, performing a read-modify-write for bit-fields.
    /// Returns the value actually stored (for use as the assignment's value).
    fn store_lvalue(&mut self, lv: &LValue, val: Val) -> Result<Val> {
        if let Some(bf) = lv.bitfield {
            let ty = lv.ty.clone();
            let val = self.coerce(val, &ty)?;
            let mask: i64 = if bf.width >= 64 { -1 } else { ((1u64 << bf.width) - 1) as i64 };
            let vm = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: vm, op: BinOp::And, lhs: val.clone(), rhs: Constant::int(mask), ty: ty.clone() });
            let vs = if bf.bit_offset > 0 {
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: BinOp::Shl, lhs: Val::Local(vm), rhs: Constant::int(bf.bit_offset as i64), ty: ty.clone() });
                Val::Local(d)
            } else { Val::Local(vm) };
            let raw = self.alloc_val();
            self.push_instr(Instr::Load { dest: raw, ptr: lv.ptr.clone(), ty: ty.clone() });
            let clear_mask = !(mask as u64).wrapping_shl(bf.bit_offset) as i64;
            let cleared = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: cleared, op: BinOp::And, lhs: Val::Local(raw), rhs: Constant::int(clear_mask), ty: ty.clone() });
            let newv = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: newv, op: BinOp::Or, lhs: Val::Local(cleared), rhs: vs, ty: ty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(newv), ptr: lv.ptr.clone() });
            return Ok(val);
        }
        let coerced = self.coerce(val, &lv.ty)?;
        self.push_instr(Instr::Store { val: coerced.clone(), ptr: lv.ptr.clone() });
        Ok(coerced)
    }

    fn lower_pre_inc(&mut self, inc: bool, inner: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(inner)?;
        let cur = self.load_lvalue(&lv)?;
        let op = if inc { BinOpKind::Add } else { BinOpKind::Sub };
        let result = self.emit_binop(op, cur, Constant::int(1))?;
        self.store_lvalue(&lv, result)
    }

    fn lower_post_inc(&mut self, inc: bool, inner: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(inner)?;
        let old = self.load_lvalue(&lv)?;
        let op = if inc { BinOpKind::Add } else { BinOpKind::Sub };
        let result = self.emit_binop(op, old.clone(), Constant::int(1))?;
        self.store_lvalue(&lv, result)?;
        Ok(old)
    }

    fn lower_ternary(&mut self, cond: &Expr, then: &Expr, else_: &Expr) -> Result<Val> {
        let cond_val = self.lower_expr(cond)?;
        let cond_bool = self.to_bool(cond_val)?;

        // Result type of `a ? b : c`: prefer a pointer/float/wider branch so the
        // value (and its type — needed for a following `->`, `*`, arithmetic)
        // survives. Both branches are coerced to it.
        let tty = self.infer_expr_type(then).unwrap_or_else(|_| Type::i32());
        let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());
        let ty = match (&tty, &ety) {
            (Type::Pointer(_), _) | (Type::Void, _) => tty.clone(),
            (_, Type::Pointer(_)) => ety.clone(),
            _ if tty.is_float() => tty.clone(),
            _ if ety.is_float() => ety.clone(),
            _ if ety.size_of(self.ptr_size()) > tty.size_of(self.ptr_size()) => ety.clone(),
            _ => tty.clone(),
        };

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: ty.clone(), align: None });

        let then_bb  = self.new_block_after_current();
        let else_bb  = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();

        self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

        self.switch_to_block(then_bb);
        let tv = self.lower_expr(then)?;
        let tv = self.coerce(tv, &ty)?;
        self.push_instr(Instr::Store { val: tv, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(else_bb);
        let ev = self.lower_expr(else_)?;
        let ev = self.coerce(ev, &ty)?;
        self.push_instr(Instr::Store { val: ev, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: ty.clone() });
        Ok(Val::Local(dest))
    }

    /// Lower GNU `a ?: b`. `a` is evaluated exactly once (its SSA value is reused
    /// both as the condition and as the "then" result).
    fn lower_elvis(&mut self, cond: &Expr, else_: &Expr) -> Result<Val> {
        let cond_val = self.lower_expr(cond)?;
        let cty = self.infer_expr_type(cond).unwrap_or_else(|_| Type::i32());
        let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());
        let ty = match (&cty, &ety) {
            (Type::Pointer(_), _) | (Type::Void, _) => cty.clone(),
            (_, Type::Pointer(_)) => ety.clone(),
            _ if cty.is_float() => cty.clone(),
            _ if ety.is_float() => ety.clone(),
            _ if ety.size_of(self.ptr_size()) > cty.size_of(self.ptr_size()) => ety.clone(),
            _ => cty.clone(),
        };
        let cond_bool = self.to_bool(cond_val.clone())?;

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: ty.clone(), align: None });

        let then_bb  = self.new_block_after_current();
        let else_bb  = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();

        self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

        self.switch_to_block(then_bb);
        let tv = self.coerce(cond_val, &ty)?;
        self.push_instr(Instr::Store { val: tv, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(else_bb);
        let ev = self.lower_expr(else_)?;
        let ev = self.coerce(ev, &ty)?;
        self.push_instr(Instr::Store { val: ev, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: ty.clone() });
        Ok(Val::Local(dest))
    }

    /// Lower a call argument. Struct/union arguments are passed by value using
    /// the pointer ABI: the callee receives a pointer to the value and copies it
    /// into its own local, so passing the argument's address is sufficient.
    fn lower_arg(&mut self, a: &Expr) -> Result<Val> {
        let aty = self.infer_expr_type(a).unwrap_or_else(|_| Type::i32());
        if matches!(aty, Type::Struct(_) | Type::Union(_)) {
            if let Ok(lv) = self.lower_lvalue(a) {
                return Ok(lv.ptr);
            }
            // Non-lvalue aggregate (e.g. a struct returned by value): its rvalue
            // lowering already yields a pointer to the temporary.
            return self.lower_expr(a);
        }
        self.lower_expr(a)
    }

    /// Pointee type of a pointer value (resolving opaque aggregates).
    fn pointee_ty(&self, ptr: &Val) -> Type {
        match self.val_type(ptr) {
            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
            other => other,
        }
    }

    /// `T __atomic_exchange_n(ptr, val)`: old = *ptr; *ptr = val; return old.
    fn lower_atomic_exchange(&mut self, ptr_expr: &Expr, val_expr: &Expr) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = self.pointee_ty(&ptr);
        let old = self.alloc_val();
        self.push_instr(Instr::Load { dest: old, ptr: ptr.clone(), ty: ty.clone() });
        let val = self.lower_expr(val_expr)?;
        let val = self.coerce(val, &ty)?;
        self.push_instr(Instr::Store { val, ptr });
        Ok(Val::Local(old))
    }

    /// `__sync_{val,bool}_compare_and_swap(ptr, oldv, newv)`: if `*ptr == oldv`
    /// set `*ptr = newv`. Returns the prior value (`ret_bool == false`) or whether
    /// the swap happened. Non-atomic (single-thread) emulation.
    fn lower_atomic_cas(&mut self, ptr_expr: &Expr, old_expr: &Expr, new_expr: &Expr, ret_bool: bool) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = self.pointee_ty(&ptr);
        let cur = self.alloc_val();
        self.push_instr(Instr::Load { dest: cur, ptr: ptr.clone(), ty: ty.clone() });
        let oldv = self.lower_expr(old_expr)?; let oldv = self.coerce(oldv, &ty)?;
        let newv = self.lower_expr(new_expr)?; let newv = self.coerce(newv, &ty)?;
        let matched = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: matched, op: CmpOp::IEq, lhs: Val::Local(cur), rhs: oldv, ty: ty.clone() });
        let sel = self.alloc_val();
        self.push_instr(Instr::Select { dest: sel, cond: Val::Local(matched), on_true: newv, on_false: Val::Local(cur), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(sel), ptr });
        if ret_bool {
            let ext = self.alloc_val();
            self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: Val::Local(matched), to_ty: Type::i32() });
            Ok(Val::Local(ext))
        } else {
            Ok(Val::Local(cur))
        }
    }

    /// `bool __atomic_compare_exchange_n(ptr, expected_ptr, desired, ...)`: like
    /// CAS, but on failure writes the current value back through `expected_ptr`.
    fn lower_atomic_compare_exchange(&mut self, ptr_expr: &Expr, exp_ptr_expr: &Expr, des_expr: &Expr) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = self.pointee_ty(&ptr);
        let eptr = self.lower_expr(exp_ptr_expr)?;
        let cur = self.alloc_val();
        self.push_instr(Instr::Load { dest: cur, ptr: ptr.clone(), ty: ty.clone() });
        let expected = self.alloc_val();
        self.push_instr(Instr::Load { dest: expected, ptr: eptr.clone(), ty: ty.clone() });
        let desired = self.lower_expr(des_expr)?; let desired = self.coerce(desired, &ty)?;
        let matched = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: matched, op: CmpOp::IEq, lhs: Val::Local(cur), rhs: Val::Local(expected), ty: ty.clone() });
        // *ptr = matched ? desired : cur
        let sel = self.alloc_val();
        self.push_instr(Instr::Select { dest: sel, cond: Val::Local(matched), on_true: desired, on_false: Val::Local(cur), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(sel), ptr });
        // *expected_ptr = matched ? expected : cur  (write current back on failure)
        let esel = self.alloc_val();
        self.push_instr(Instr::Select { dest: esel, cond: Val::Local(matched), on_true: Val::Local(expected), on_false: Val::Local(cur), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(esel), ptr: eptr });
        let ext = self.alloc_val();
        self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: Val::Local(matched), to_ty: Type::i32() });
        Ok(Val::Local(ext))
    }

    /// Whether two IR types are the same for `__builtin_types_compatible_p`
    /// (sic already drops qualifiers; opaque aggregates compare by name).
    fn types_equal(&self, a: &Type, b: &Type) -> bool {
        super::types::resolve_aggregate(a, &self.lowerer.struct_types)
            == super::types::resolve_aggregate(b, &self.lowerer.struct_types)
    }

    /// Evaluate the (constant) controlling condition of a `__builtin_choose_expr`,
    /// understanding `__builtin_types_compatible_p` and the `||`/`&&`/`!` that
    /// glib/QEMU macros build them from. Unknown → 0 (pick the else branch).
    fn eval_choose_cond(&self, e: &Expr) -> i64 {
        match &e.kind {
            ExprKind::TypesCompatible(t1, t2) => {
                match (self.lower_type(t1), self.lower_type(t2)) {
                    (Ok(a), Ok(b)) => if self.types_equal(&a, &b) { 1 } else { 0 },
                    _ => 0,
                }
            }
            ExprKind::ChooseExpr { cond, then, else_ } => {
                if self.eval_choose_cond(cond) != 0 { self.eval_choose_cond(then) }
                else { self.eval_choose_cond(else_) }
            }
            ExprKind::BinOp { op: BinOpKind::LogOr, lhs, rhs } =>
                (self.eval_choose_cond(lhs) != 0 || self.eval_choose_cond(rhs) != 0) as i64,
            ExprKind::BinOp { op: BinOpKind::LogAnd, lhs, rhs } =>
                (self.eval_choose_cond(lhs) != 0 && self.eval_choose_cond(rhs) != 0) as i64,
            ExprKind::Unary { op: UnOpKind::Not, expr } =>
                (self.eval_choose_cond(expr) == 0) as i64,
            _ => crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0),
        }
    }

    /// Lower `__builtin_{clz,ctz,popcount,ffs}[l|ll]` on a `bits`-wide operand.
    /// The result is an `int`.
    fn lower_bit_count(&mut self, arg: &Expr, bits: u32, kind: BitOp) -> Result<Val> {
        let ty = Type::Int { bits, signed: false };
        let v = self.lower_expr(arg)?;
        let v = self.coerce(v, &ty)?;
        let result = match kind {
            BitOp::Clz | BitOp::Ctz | BitOp::Popcnt => {
                let op = match kind {
                    BitOp::Clz => UnOp::Clz,
                    BitOp::Ctz => UnOp::Ctz,
                    _ => UnOp::Popcnt,
                };
                let d = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: d, op, val: v, ty: ty.clone() });
                Val::Local(d)
            }
            BitOp::Parity => {
                // parity(x) = popcount(x) & 1
                let pc = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: pc, op: UnOp::Popcnt, val: v, ty: ty.clone() });
                let res = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: res, op: BinOp::And, lhs: Val::Local(pc), rhs: Constant::int(1), ty: ty.clone() });
                Val::Local(res)
            }
            BitOp::Clrsb => {
                // clrsb(x) = clz(x ^ (x >>arith (bits-1))) - 1: leading redundant
                // sign bits. The `x ^ sign` maps the leading sign run to zeros.
                let sign = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: sign, op: BinOp::AShr, lhs: v.clone(), rhs: Constant::int((bits - 1) as i64), ty: ty.clone() });
                let y = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: y, op: BinOp::Xor, lhs: v, rhs: Val::Local(sign), ty: ty.clone() });
                let clz = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: clz, op: UnOp::Clz, val: Val::Local(y), ty: ty.clone() });
                let res = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: res, op: BinOp::Sub, lhs: Val::Local(clz), rhs: Constant::int(1), ty: ty.clone() });
                Val::Local(res)
            }
            BitOp::Ffs => {
                // ffs(x) = x == 0 ? 0 : ctz(x) + 1
                let ctz = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: ctz, op: UnOp::Ctz, val: v.clone(), ty: ty.clone() });
                let ctzp1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: ctzp1, op: BinOp::Add, lhs: Val::Local(ctz), rhs: Constant::int(1), ty: ty.clone() });
                let iszero = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: iszero, op: CmpOp::IEq, lhs: v, rhs: Constant::int(0), ty: ty.clone() });
                let sel = self.alloc_val();
                self.push_instr(Instr::Select { dest: sel, cond: Val::Local(iszero), on_true: Constant::int(0), on_false: Val::Local(ctzp1), ty: ty.clone() });
                Val::Local(sel)
            }
        };
        self.coerce(result, &Type::i32())
    }

    /// Lower an atomic read-modify-write as a non-atomic load/op/store, returning
    /// either the old value (`ret_new == false`) or the new value.
    fn lower_atomic_rmw(&mut self, ptr_expr: &Expr, val_expr: &Expr, op: BinOp, ret_new: bool) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = match self.val_type(&ptr) {
            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
            other => other,
        };
        let old = self.alloc_val();
        self.push_instr(Instr::Load { dest: old, ptr: ptr.clone(), ty: ty.clone() });
        let rhs = self.lower_expr(val_expr)?;
        let rhs = self.coerce(rhs, &ty)?;
        let newv = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newv, op, lhs: Val::Local(old), rhs, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(newv), ptr });
        Ok(Val::Local(if ret_new { newv } else { old }))
    }

    /// Pointer to the storage of a struct/union-typed expression. Lvalues yield
    /// their address; aggregate rvalues (compound literals, struct-returning
    /// calls) already lower to a pointer to their temporary.
    pub(crate) fn lower_aggregate_ptr(&mut self, e: &Expr) -> Result<Val> {
        if let Ok(lv) = self.lower_lvalue(e) {
            Ok(lv.ptr)
        } else {
            self.lower_expr(e)
        }
    }

    fn lower_call(&mut self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // A `_Generic(...)` selection used as the callee resolves to the chosen
        // association's expression, which may itself be a builtin name (e.g.
        // QEMU's `bswaps` macro: `_Generic(x, uint16_t: __builtin_bswap16, ...)(x)`).
        if let ExprKind::Generic { controlling, assocs } = &func_expr.kind {
            let idx = self.select_generic(controlling, assocs)?;
            return self.lower_call(&assocs[idx].1, args, sp);
        }

        // Handle __builtin_bswap* before evaluating args
        if let ExprKind::Ident(name) = &func_expr.kind {
            let bits: Option<u32> = match name.as_str() {
                "__builtin_bswap16" => Some(16),
                "__builtin_bswap32" => Some(32),
                "__builtin_bswap64" => Some(64),
                _ => None,
            };
            if let Some(bits) = bits {
                if let Some(arg) = args.first() {
                    let v = self.lower_expr(arg)?;
                    let ty = Type::Int { bits, signed: false };
                    let dest = self.alloc_val();
                    self.push_instr(Instr::BSwap { dest, val: v, ty });
                    return Ok(Val::Local(dest));
                }
            }

            // Overflow-checked arithmetic builtins:
            //   bool __builtin_{add,mul}_overflow(a, b, *res)
            // Compute `a op b`, store the wrapped result through `*res`, and
            // return whether the mathematical result overflowed the result type.
            let ovf_op = match name.as_str() {
                "__builtin_add_overflow" => Some(BinOp::Add),
                "__builtin_sub_overflow" => Some(BinOp::Sub),
                "__builtin_mul_overflow" => Some(BinOp::Mul),
                _ => None,
            };
            if let (Some(op), [a_expr, b_expr, res_expr]) = (ovf_op, args) {
                return self.lower_overflow_builtin(op, a_expr, b_expr, res_expr);
            }

            // Atomic builtins. We lower these to plain (non-atomic) load/store
            // and treat fences as no-ops. This is functionally correct for
            // single-threaded execution and the relaxed-ordering uses sqlite
            // makes; it is not a true multi-threaded atomic implementation.
            match name.as_str() {
                // T __atomic_load_n(const T *ptr, int memorder)
                "__atomic_load_n" => {
                    if let Some(ptr_expr) = args.first() {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => *t,
                            _ => Type::i32(),
                        };
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Load { dest, ptr, ty });
                        return Ok(Val::Local(dest));
                    }
                }
                // void __atomic_store_n(T *ptr, T val, int memorder)
                "__atomic_store_n" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let val = self.lower_expr(val_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => *t,
                            _ => self.val_type(&val),
                        };
                        let cv = self.coerce(val, &ty)?;
                        self.push_instr(Instr::Store { val: cv, ptr });
                        return Ok(Constant::zero());
                    }
                }
                // void __sync_synchronize(void) — full memory barrier; no-op here.
                "__sync_synchronize" => return Ok(Constant::zero()),
                // Atomic read-modify-write builtins. sic has no real atomics, so
                // these lower to a plain load / op / store (correct for a single
                // thread, which is enough to compile and run the code).
                //   __atomic_fetch_OP(ptr, val, order)  -> returns OLD value
                //   __atomic_OP_fetch(ptr, val, order)  -> returns NEW value
                //   __sync_fetch_and_OP(ptr, val)       -> returns OLD value
                //   __sync_OP_and_fetch(ptr, val)       -> returns NEW value
                n if atomic_rmw_op(n).is_some() => {
                    let (op, ret_new) = atomic_rmw_op(n).unwrap();
                    if let [ptr_expr, val_expr, ..] = args {
                        return self.lower_atomic_rmw(ptr_expr, val_expr, op, ret_new);
                    }
                }
                // Fences / barriers: no-ops for a single thread.
                "__atomic_thread_fence" | "__atomic_signal_fence" => return Ok(Constant::zero()),
                // T __atomic_exchange_n(ptr, val, order) / __sync_lock_test_and_set(ptr, val)
                "__atomic_exchange_n" | "__sync_lock_test_and_set" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        return self.lower_atomic_exchange(ptr_expr, val_expr);
                    }
                }
                // void __sync_lock_release(ptr): *ptr = 0
                "__sync_lock_release" => {
                    if let [ptr_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ty = self.pointee_ty(&ptr);
                        let z = self.coerce(Constant::zero(), &ty)?;
                        self.push_instr(Instr::Store { val: z, ptr });
                        return Ok(Constant::zero());
                    }
                }
                // Compare-and-swap.
                "__sync_val_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, false); }
                }
                "__sync_bool_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, true); }
                }
                "__atomic_compare_exchange_n" | "__atomic_compare_exchange" => {
                    if let [p, eptr, d, ..] = args { return self.lower_atomic_compare_exchange(p, eptr, d); }
                }
                // Branch-prediction hints: the value is just the first argument.
                "__builtin_expect" | "__builtin_expect_with_probability" => {
                    if let Some(e) = args.first() { return self.lower_expr(e); }
                }
                // Optimizer hints with no runtime effect for us.
                "__builtin_prefetch" | "__builtin_unreachable"
                | "__builtin_assume_aligned" => {
                    // `assume_aligned(p, ...)` returns its pointer; the rest are void.
                    if name.as_str() == "__builtin_assume_aligned" {
                        if let Some(e) = args.first() { return self.lower_expr(e); }
                    }
                    return Ok(Constant::zero());
                }
                "__builtin_constant_p" => return Ok(Constant::int(0)),
                // Bit-count builtins: clz/ctz/popcount/ffs (32- and 64-bit).
                n if builtin_bit_op(n).is_some() => {
                    let (kind, bits) = builtin_bit_op(n).unwrap();
                    if let Some(arg) = args.first() {
                        return self.lower_bit_count(arg, bits, kind);
                    }
                }
                // Static assertions: accepted, not evaluated (compile-time only).
                "_Static_assert" | "static_assert" => return Ok(Constant::zero()),
                // Type-compat query: conservatively false (only affects _Generic-
                // style dispatch we don't otherwise need).
                "__builtin_types_compatible_p" => return Ok(Constant::int(0)),
                _ => {}
            }
        }

        // Evaluate arguments
        let mut arg_vals = Vec::new();
        for a in args {
            arg_vals.push(self.lower_arg(a)?);
        }

        // Resolve function reference
        let fref = match &func_expr.kind {
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Func(fr)) => fr,
                    Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)) => {
                        // local/global function pointer variable: fall through to indirect call
                        let fptr = self.lower_expr(func_expr)?;
                        let fptr_ty = self.val_type(&fptr);
                        let func_ty = match &fptr_ty {
                            Type::Pointer(inner) => match inner.as_ref() {
                                Type::Function(ft) => *ft.clone(),
                                _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                            },
                            _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                        };
                        let ret_ty = func_ty.ret.clone();
                        let is_void = ret_ty == Type::Void;
                        let dest = if !is_void { Some(self.alloc_val()) } else { None };
                        self.push_instr(Instr::CallIndirect {
                            dest,
                            fptr,
                            args: arg_vals,
                            ret_ty: ret_ty.clone(),
                            func_ty: Box::new(func_ty),
                        });
                        return Ok(if let Some(d) = dest { Val::Local(d) } else { Constant::zero() });
                    }
                    _ => {
                        return Err(CompileError::at(
                            format!("unknown function '{}'", name),
                            sp.file.clone(), sp.line, sp.col,
                        ));
                    }
                }
            }
            _ => {
                // Indirect call through function pointer expression
                let fptr = self.lower_expr(func_expr)?;
                let fptr_ty = self.val_type(&fptr);
                let func_ty = match &fptr_ty {
                    Type::Pointer(inner) => match inner.as_ref() {
                        Type::Function(ft) => *ft.clone(),
                        _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                    },
                    _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                };
                let ret_ty = func_ty.ret.clone();
                let is_void = ret_ty == Type::Void;
                let dest = if !is_void { Some(self.alloc_val()) } else { None };
                self.push_instr(Instr::CallIndirect {
                    dest,
                    fptr,
                    args: arg_vals,
                    ret_ty: ret_ty.clone(),
                    func_ty: Box::new(func_ty),
                });
                return Ok(if let Some(d) = dest { Val::Local(d) } else { Constant::zero() });
            }
        };

        let ret_ty = self.lowerer.module.func_sig(fref).ret.clone();
        let is_void = ret_ty == Type::Void;

        // Coerce arguments to expected param types
        let param_tys: Vec<Type> = self.lowerer.module.func_sig(fref).params.clone();
        for (i, pval) in arg_vals.iter_mut().enumerate() {
            if let Some(pty) = param_tys.get(i) {
                // Struct/union args are already lowered to a pointer to the value
                // (by-value ABI); leave them as-is.
                if matches!(pty, Type::Struct(_) | Type::Union(_)) { continue; }
                let coerced = self.coerce(pval.clone(), pty)?;
                *pval = coerced;
            }
        }

        if is_void {
            self.push_instr(Instr::Call { dest: None, func: fref, args: arg_vals, ret_ty });
            Ok(Constant::zero())
        } else {
            let dest = self.alloc_val();
            self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: arg_vals, ret_ty });
            Ok(Val::Local(dest))
        }
    }

    /// Lower `__builtin_{add,mul}_overflow(a, b, *res)`: compute `a op b` in the
    /// result type, store the wrapped value through `*res`, and return an i1
    /// indicating whether the true result overflowed that type.
    fn lower_overflow_builtin(
        &mut self,
        op: BinOp,
        a_expr: &Expr,
        b_expr: &Expr,
        res_expr: &Expr,
    ) -> Result<Val> {
        let a = self.lower_expr(a_expr)?;
        let b = self.lower_expr(b_expr)?;
        let res_ptr = self.lower_expr(res_expr)?;

        // The result type is whatever `*res` points at.
        let ty = match self.val_type(&res_ptr) {
            Type::Pointer(inner) => *inner,
            _ => self.val_type(&a),
        };
        let signed = matches!(ty, Type::Int { signed: true, .. });

        // Coerce operands to the result type so the arithmetic is well-typed.
        let a = self.coerce(a, &ty)?;
        let b = self.coerce(b, &ty)?;

        // result = a op b (wrapping), stored through *res.
        let result = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: result, op, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        let result = Val::Local(result);
        self.push_instr(Instr::Store { val: result.clone(), ptr: res_ptr });

        let zero = Constant::zero();
        let ovf = self.alloc_val();
        match op {
            BinOp::Add if signed => {
                // Overflow iff a and b share a sign that differs from the sum:
                // ((a ^ sum) & (b ^ sum)) < 0.
                let t1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t1, op: BinOp::Xor, lhs: a.clone(), rhs: result.clone(), ty: ty.clone() });
                let t2 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t2, op: BinOp::Xor, lhs: b.clone(), rhs: result.clone(), ty: ty.clone() });
                let t3 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t3, op: BinOp::And, lhs: Val::Local(t1), rhs: Val::Local(t2), ty: ty.clone() });
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::ISLt, lhs: Val::Local(t3), rhs: zero, ty: ty.clone() });
            }
            BinOp::Add => {
                // Unsigned add overflows iff the sum wrapped below an operand.
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::IULt, lhs: result.clone(), rhs: a.clone(), ty: ty.clone() });
            }
            BinOp::Sub if signed => {
                // Signed sub overflows iff the operands differ in sign and the
                // result's sign differs from the minuend: ((a^b) & (a^diff)) < 0.
                let t1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t1, op: BinOp::Xor, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
                let t2 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t2, op: BinOp::Xor, lhs: a.clone(), rhs: result.clone(), ty: ty.clone() });
                let t3 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t3, op: BinOp::And, lhs: Val::Local(t1), rhs: Val::Local(t2), ty: ty.clone() });
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::ISLt, lhs: Val::Local(t3), rhs: zero, ty: ty.clone() });
            }
            BinOp::Sub => {
                // Unsigned sub overflows (borrows) iff a < b.
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::IULt, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
            }
            _ => {
                // Multiply: overflow iff a != 0 and result / a != b.
                let a_nz = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: a_nz, op: CmpOp::INe, lhs: a.clone(), rhs: zero, ty: ty.clone() });
                let quot = self.alloc_val();
                let div = if signed { BinOp::SDiv } else { BinOp::UDiv };
                self.push_instr(Instr::BinOp { dest: quot, op: div, lhs: result.clone(), rhs: a.clone(), ty: ty.clone() });
                let mism = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: mism, op: CmpOp::INe, lhs: Val::Local(quot), rhs: b.clone(), ty: ty.clone() });
                // ovf = a_nz ? mism : false
                self.push_instr(Instr::Select {
                    dest: ovf,
                    cond: Val::Local(a_nz),
                    on_true: Val::Local(mism),
                    on_false: Val::Const(Constant::Bool(false)),
                    ty: Type::Bool,
                });
            }
        }
        Ok(Val::Local(ovf))
    }

    // ─── LValue lowering ─────────────────────────────────────────────────────

    /// Extract a pointer's pointee type, resolving an opaque pointee aggregate
    /// to its full definition. Pointees are stored opaque (see `lower_ast_type`);
    /// dereferencing needs the real layout for loads/stores/copies.
    fn pointee_of(&self, ptr_ty: &Type) -> Type {
        match ptr_ty {
            Type::Pointer(t) => super::types::resolve_aggregate(t, &self.lowerer.struct_types),
            _ => Type::i32(),
        }
    }

    fn lower_lvalue(&mut self, expr: &Expr) -> Result<LValue> {
        match &expr.kind {
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, vid)) => {
                        let ty = ty.clone();
                        Ok(LValue::plain(Val::Local(vid), ty))
                    }
                    Some(LookupResult::Global(ty, gref)) => {
                        let ty = ty.clone();
                        Ok(LValue::plain(Val::Global(gref), ty))
                    }
                    _ => Err(CompileError::at(
                        format!("'{}' is not an lvalue", name),
                        expr.span.file.clone(), expr.span.line, expr.span.col,
                    ))
                }
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let ptr = self.lower_expr(inner)?;
                let ptr_ty = self.val_type(&ptr);
                let inner_ty = self.pointee_of(&ptr_ty);
                Ok(LValue::plain(ptr, inner_ty))
            }
            ExprKind::Index { base, index } => self.lower_lvalue_index(base, index),
            ExprKind::Field { base, name } => self.lower_lvalue_field(base, name),
            ExprKind::Arrow { base, name }  => self.lower_lvalue_arrow(base, name),
            ExprKind::CompoundLiteral { ty, .. } => {
                // A compound literal is an lvalue: materialize the temporary and
                // use its address (its rvalue lowering already yields that pointer).
                let ir_ty = self.lower_type(ty)?;
                let ptr = self.lower_expr(expr)?;
                Ok(LValue::plain(ptr, ir_ty))
            }
            _ => {
                // Not a simple lvalue.
                Err(CompileError::at(
                    "expression is not an lvalue",
                    expr.span.file.clone(), expr.span.line, expr.span.col,
                ))
            }
        }
    }

    fn lower_lvalue_index(&mut self, base: &Expr, index: &Expr) -> Result<LValue> {
        let base_val = self.lower_expr(base)?;
        let idx_val = self.lower_expr(index)?;
        let idx_i64 = self.coerce(idx_val, &Type::i64())?;

        let base_ty = self.val_type(&base_val);
        // Unwrap the pointer target; if it's an array (alloca of array), take the element type
        let elem_ty = match &base_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { elem, .. } => *elem.clone(),
                other => super::types::resolve_aggregate(other, &self.lowerer.struct_types),
            },
            Type::Array { elem, .. } => *elem.clone(),
            _ => Type::i32(),
        };

        let elem_size = elem_ty.size_of(self.ptr_size());
        let dest = self.alloc_val();
        let result_ty = Type::Pointer(Box::new(elem_ty.clone()));
        self.push_instr(Instr::GetElemPtr { dest, base: base_val, index: idx_i64, elem_size, result_ty });
        Ok(LValue::plain(Val::Local(dest), elem_ty))
    }

    fn lower_lvalue_field(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base must be a struct lvalue
        let lv = self.lower_lvalue(base)?;
        self.field_ptr_from(lv, name, false, &base.span)
    }

    fn lower_lvalue_arrow(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base is a pointer to struct — or an array, which decays to a pointer
        // to its first element (`arr->field` ≡ `arr[0].field`).
        let ptr = self.lower_expr(base)?;
        let ptr_ty = self.val_type(&ptr);
        let struct_ty = match &ptr_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { elem, .. } => (**elem).clone(),
                _ => (**t).clone(),
            },
            Type::Array { elem, .. } => (**elem).clone(),
            _ => return Err(CompileError::at(
                format!("-> applied to non-pointer (field '{}')", name),
                base.span.file.clone(), base.span.line, base.span.col)),
        };
        let lv = LValue::plain(ptr, struct_ty);
        self.field_ptr_from(lv, name, true, &base.span)
    }

    fn field_ptr_from(&mut self, lv: LValue, field_name: &str, via_ptr: bool, sp: &crate::lexer::Span) -> Result<LValue> {
        let struct_ty = if via_ptr {
            match &lv.ty {
                Type::Pointer(t) => *t.clone(),
                other => other.clone(),
            }
        } else {
            lv.ty.clone()
        };

        // Resolve the member — including through anonymous struct/union members —
        // to a cumulative byte offset, type, and (if any) bit-field descriptor.
        let (byte_offset, field_ty, bitfield) =
            resolve_field_access(&struct_ty, field_name, self.ptr_size(), &self.lowerer.struct_types)
                .ok_or_else(|| CompileError::at(
                    format!("no field '{}' in type", field_name),
                    sp.file.clone(), sp.line, sp.col,
                ))?;

        let base_ptr = lv.ptr;
        let dest = self.alloc_val();
        let result_ty = Type::Pointer(Box::new(field_ty.clone()));
        self.push_instr(Instr::GetFieldPtr {
            dest, base: base_ptr, field_idx: 0, struct_name: None, byte_offset, result_ty,
        });
        Ok(LValue { ptr: Val::Local(dest), ty: field_ty, bitfield })
    }

    // ─── Type inference ───────────────────────────────────────────────────────

    /// Resolve a `_Generic` selection to the index of the matching association.
    /// The controlling expression's type undergoes lvalue conversion (array /
    /// function decay); it is compared against each association's lowered type,
    /// falling back to the `default` association. Matching is done on the IR
    /// `Type`, which is qualifier-insensitive — adequate because only the
    /// selected branch is ever lowered.
    fn select_generic(&self, controlling: &Expr, assocs: &[(Option<crate::ast::QualType>, Box<Expr>)]) -> Result<usize> {
        fn decay(t: Type) -> Type {
            match t {
                Type::Array { elem, .. } => Type::Pointer(elem),
                Type::Function(_) => Type::void_ptr(),
                other => other,
            }
        }
        let ctrl_ty = decay(self.infer_expr_type(controlling)?);
        let mut default_idx = None;
        for (i, (aty, _)) in assocs.iter().enumerate() {
            match aty {
                None => default_idx = Some(i),
                Some(qt) => {
                    if decay(self.lower_type(qt)?) == ctrl_ty {
                        return Ok(i);
                    }
                }
            }
        }
        let sp = &controlling.span;
        default_idx.ok_or_else(|| CompileError::at(
            "no matching association in _Generic selection",
            sp.file.clone(), sp.line, sp.col,
        ))
    }

    /// Compute the byte offset of a member designator within a type, for
    /// `__builtin_offsetof`. Walks `.field` (struct/union) and `[index]` (array)
    /// steps, summing struct field offsets and array element strides.
    fn compute_offsetof(&self, ty: &crate::ast::QualType, designators: &[crate::ast::OffsetDesignator]) -> Result<u64> {
        use crate::ast::OffsetDesignator;
        let mut cur = self.lower_type(ty)?;
        let mut offset: u64 = 0;
        for d in designators {
            match d {
                OffsetDesignator::Field(name) => {
                    let resolved = super::types::resolve_aggregate(&cur, &self.lowerer.struct_types);
                    let (idx, fty, _) = find_field(&resolved, name, &self.lowerer.struct_types)
                        .ok_or_else(|| CompileError::new(format!("no field '{}' in offsetof", name)))?;
                    if let Type::Struct(st) = &resolved {
                        offset += st.field_offset(idx, self.ptr_size());
                    }
                    // union members are all at offset 0
                    cur = fty;
                }
                OffsetDesignator::Index(e) => {
                    let i = super::eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0);
                    let elem = match &cur {
                        Type::Array { elem, .. } => *elem.clone(),
                        Type::Pointer(t) => *t.clone(),
                        other => other.clone(),
                    };
                    offset += (i as u64).wrapping_mul(elem.size_of(self.ptr_size()));
                    cur = elem;
                }
            }
        }
        Ok(offset)
    }

    pub fn infer_expr_type(&self, expr: &Expr) -> Result<Type> {
        match &expr.kind {
            ExprKind::Generic { controlling, assocs } => {
                let idx = self.select_generic(controlling, assocs)?;
                self.infer_expr_type(&assocs[idx].1)
            }
            ExprKind::OffsetOf { .. } => Ok(Type::u64()),
            ExprKind::CharLit(_) => Ok(Type::i32()),
            ExprKind::IntLit(_, is64) => Ok(if *is64 { Type::i64() } else { Type::i32() }),
            ExprKind::UIntLit(_, is64) => Ok(if *is64 { Type::Int { bits: 64, signed: false } } else { Type::u32() }),
            ExprKind::FloatLit(_) => Ok(Type::Float64),
            ExprKind::StringLit(_) => Ok(Type::char_ptr()),
            ExprKind::Nullptr => Ok(Type::void_ptr()),
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, _)) => Ok(ty.clone()),
                    Some(LookupResult::Global(ty, _)) => Ok(ty.clone()),
                    Some(LookupResult::EnumConst(_)) => Ok(Type::i32()),
                    Some(LookupResult::Func(_)) => Ok(Type::void_ptr()),
                    None => Ok(Type::i32()),
                }
            }
            ExprKind::Cast { ty, .. } => self.lower_type(ty),
            ExprKind::ChooseExpr { cond, then, else_ } => {
                if self.eval_choose_cond(cond) != 0 { self.infer_expr_type(then) }
                else { self.infer_expr_type(else_) }
            }
            ExprKind::TypesCompatible(..) => Ok(Type::i32()),
            ExprKind::SizeofType(_) | ExprKind::SizeofExpr(_)
            | ExprKind::AlignofType(_) | ExprKind::AlignofExpr(_) => Ok(Type::u64()),
            ExprKind::Unary { op: UnOpKind::Addr, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                Ok(Type::Pointer(Box::new(inner_ty)))
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                Ok(match inner_ty {
                    Type::Pointer(t) => self.pointee_of(&Type::Pointer(t)),
                    _ => Type::i32(),
                })
            }
            ExprKind::Field { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                if let Some((_, fty, _)) = resolve_field_access(&base_ty, name, self.ptr_size(), &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            ExprKind::Arrow { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                let struct_ty = match base_ty {
                    Type::Pointer(t) => *t,
                    other => other,
                };
                if let Some((_, fty, _)) = resolve_field_access(&struct_ty, name, self.ptr_size(), &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            ExprKind::Index { base, .. } => {
                let bt = self.infer_expr_type(base)?;
                let elem = match bt {
                    Type::Pointer(t) => match *t {
                        Type::Array { elem, .. } => *elem,
                        other => other,
                    },
                    Type::Array { elem, .. } => *elem,
                    _ => Type::i32(),
                };
                // The element of a pointer-to-opaque-aggregate (e.g. `p->aCol[0]`
                // where `aCol` is `Column*`) must be resolved to its full
                // definition, or `sizeof` sees an empty struct and returns 0.
                Ok(super::types::resolve_aggregate(&elem, &self.lowerer.struct_types))
            }
            ExprKind::Call { func, .. } => {
                // Return type of the callee. A direct call resolves via the
                // module signature; an indirect call takes the pointee function
                // type's return. Without this a call defaults to i32 and a
                // pointer-returning call in a ternary gets truncated to 32 bits.
                if let ExprKind::Ident(name) = &func.kind {
                    if let Some(LookupResult::Func(fref)) = self.lookup(name) {
                        return Ok(self.lowerer.module.func_sig(fref).ret.clone());
                    }
                }
                let fty = self.infer_expr_type(func)?;
                Ok(match fty {
                    Type::Pointer(inner) => match *inner {
                        Type::Function(ft) => ft.ret.clone(),
                        _ => Type::i32(),
                    },
                    Type::Function(ft) => ft.ret.clone(),
                    _ => Type::i32(),
                })
            }
            ExprKind::Ternary { then, else_, .. }
            | ExprKind::Elvis { cond: then, else_ } => {
                // Mirror lower_ternary/lower_elvis's result-type selection.
                let tty = self.infer_expr_type(then).unwrap_or_else(|_| Type::i32());
                let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());
                Ok(match (&tty, &ety) {
                    (Type::Pointer(_), _) | (Type::Void, _) => tty,
                    (_, Type::Pointer(_)) => ety,
                    _ if tty.is_float() => tty,
                    _ if ety.is_float() => ety,
                    _ if ety.size_of(self.ptr_size()) > tty.size_of(self.ptr_size()) => ety,
                    _ => tty,
                })
            }
            _ => Ok(Type::i32()),
        }
    }

    /// Lower a `va_list` operand to the address of its `__va_list_tag`. A local
    /// `va_list` (the builtin array, or a user-defined struct aliased to
    /// `va_list`) needs its own address; a `va_list` *parameter* has already
    /// decayed to a `__va_list_tag*`, so its value is that address.
    fn lower_va_list_ptr(&mut self, list: &Expr) -> Result<Val> {
        let ty = self.infer_expr_type(list).unwrap_or_else(|_| Type::void_ptr());
        if matches!(ty, Type::Array { .. } | Type::Struct(_) | Type::Union(_)) {
            if let Ok(lv) = self.lower_lvalue(list) {
                return Ok(lv.ptr);
            }
        }
        self.lower_expr(list)
    }

    /// Lower an expression expecting it to produce a pointer (for va_list etc).
    #[allow(dead_code)]
    fn lower_expr_as_ptr(&mut self, expr: &Expr) -> Result<Val> {
        match self.lower_lvalue(expr) {
            Ok(lv) => Ok(lv.ptr),
            Err(_) => self.lower_expr(expr),
        }
    }
}

fn inc_op(ty: &Type, inc: bool) -> BinOp {
    if ty.is_float() {
        if inc { BinOp::FAdd } else { BinOp::FSub }
    } else {
        if inc { BinOp::Add } else { BinOp::Sub }
    }
}

/// A resolved member access: cumulative byte offset from the start of the
/// aggregate, the member's type, and bit-field info if it is one. Drills through
/// anonymous (unnamed) struct/union members, whose fields are accessed as if they
/// were members of the enclosing aggregate (C11 anonymous struct/union).
pub(super) fn resolve_field_access(
    ty: &Type,
    name: &str,
    ptr_size: u32,
    named: &std::collections::HashMap<String, Type>,
) -> Option<(u64, Type, Option<BitField>)> {
    let resolved = super::types::resolve_aggregate(ty, named);
    match &resolved {
        Type::Struct(st) => {
            let (offs, bit_offs, _) = st.layout_full(ptr_size);
            // Direct member.
            for (i, (fname, fty)) in st.fields.iter().enumerate() {
                if fname == name {
                    let bf = st.bitfields.get(i).copied().flatten().map(|w| BitField {
                        bit_offset: *bit_offs.get(i).unwrap_or(&0),
                        width: w,
                        signed: fty.is_signed(),
                    });
                    return Some((*offs.get(i).unwrap_or(&0), fty.clone(), bf));
                }
            }
            // Anonymous member: recurse, adding that member's byte offset.
            for (i, (fname, fty)) in st.fields.iter().enumerate() {
                if fname.is_empty() && matches!(fty, Type::Struct(_) | Type::Union(_)) {
                    if let Some((sub_off, sub_ty, sub_bf)) = resolve_field_access(fty, name, ptr_size, named) {
                        return Some((offs.get(i).copied().unwrap_or(0) + sub_off, sub_ty, sub_bf));
                    }
                }
            }
            None
        }
        Type::Union(u) => {
            // All union members live at offset 0.
            for (fname, fty) in &u.fields {
                if fname == name {
                    return Some((0, fty.clone(), None));
                }
            }
            for (fname, fty) in &u.fields {
                if fname.is_empty() && matches!(fty, Type::Struct(_) | Type::Union(_)) {
                    if let Some(r) = resolve_field_access(fty, name, ptr_size, named) {
                        return Some(r);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum BitOp { Clz, Ctz, Popcnt, Ffs, Clrsb, Parity }

/// Classify `__builtin_{clz,ctz,popcount,ffs}[l|ll]` into (kind, operand bits).
fn builtin_bit_op(name: &str) -> Option<(BitOp, u32)> {
    let (base, bits) = if let Some(b) = name.strip_suffix("ll") { (b, 64) }
        else if let Some(b) = name.strip_suffix('l') { (b, 64) }
        else { (name, 32) };
    let kind = match base {
        "__builtin_clz"      => BitOp::Clz,
        "__builtin_ctz"      => BitOp::Ctz,
        "__builtin_popcount" => BitOp::Popcnt,
        "__builtin_ffs"      => BitOp::Ffs,
        "__builtin_clrsb"    => BitOp::Clrsb,
        "__builtin_parity"   => BitOp::Parity,
        _ => return None,
    };
    Some((kind, bits))
}

/// Classify an atomic/sync read-modify-write builtin into its arithmetic op and
/// whether it returns the new value (vs the old). Returns `None` for names that
/// aren't of this family (or use an op we don't special-case, e.g. `nand`).
fn atomic_rmw_op(name: &str) -> Option<(BinOp, bool)> {
    let (op_name, ret_new) = if let Some(rest) = name.strip_prefix("__atomic_fetch_") {
        (rest, false)
    } else if let Some(rest) = name.strip_prefix("__atomic_").and_then(|r| r.strip_suffix("_fetch")) {
        (rest, true)
    } else if let Some(rest) = name.strip_prefix("__sync_fetch_and_") {
        (rest, false)
    } else if let Some(rest) = name.strip_prefix("__sync_").and_then(|r| r.strip_suffix("_and_fetch")) {
        (rest, true)
    } else {
        return None;
    };
    let op = match op_name {
        "add" => BinOp::Add,
        "sub" => BinOp::Sub,
        "or"  => BinOp::Or,
        "and" => BinOp::And,
        "xor" => BinOp::Xor,
        _ => return None,
    };
    Some((op, ret_new))
}

pub(super) fn find_field(ty: &Type, name: &str, named: &std::collections::HashMap<String, Type>) -> Option<(usize, Type, Option<String>)> {
    // A pointee aggregate is stored opaque (no fields); recover its definition.
    let resolved = super::types::resolve_aggregate(ty, named);
    match &resolved {
        Type::Struct(st) => {
            for (i, (fname, fty)) in st.fields.iter().enumerate() {
                if fname == name {
                    return Some((i, fty.clone(), st.name.clone()));
                }
            }
            None
        }
        Type::Union(u) => {
            for (i, (fname, fty)) in u.fields.iter().enumerate() {
                if fname == name {
                    return Some((i, fty.clone(), u.name.clone()));
                }
            }
            None
        }
        _ => None,
    }
}
