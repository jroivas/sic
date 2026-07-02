use crate::ast::{self, Expr, ExprKind, BinOpKind, UnOpKind, Initializer, QualType, AstType};
use crate::{Result, CompileError};
use sic_ir::*;
use super::func::{FuncCtx, LookupResult};
use super::lower_type;

/// The result of lowering a "location" (lvalue) — a pointer to the storage.
struct LValue {
    ptr: Val,
    ty: Type,    // type of the pointee
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
        });
        Val::Local(ptr_id)
    }

    /// Lower an expression, returning its rvalue.
    pub fn lower_expr(&mut self, expr: &Expr) -> Result<Val> {
        match &expr.kind {
            ExprKind::IntLit(v) => Ok(Constant::int(*v)),
            ExprKind::UIntLit(v) => Ok(Constant::uint(*v)),
            ExprKind::FloatLit(v) => Ok(Val::Const(Constant::Float(*v))),
            ExprKind::CharLit(v) => Ok(Constant::int(*v as i64)),
            ExprKind::StringLit(s) => Ok(self.emit_cstring(s)),

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

            ExprKind::Call { func, args } => self.lower_call(func, args, &expr.span),

            ExprKind::Index { base, index } => {
                let lv = self.lower_lvalue_index(base, index)?;
                let dest = self.alloc_val();
                let ty = lv.ty.clone();
                self.push_instr(Instr::Load { dest, ptr: lv.ptr, ty });
                Ok(Val::Local(dest))
            }

            ExprKind::Field { base, name } => {
                let lv = self.lower_lvalue_field(base, name)?;
                let dest = self.alloc_val();
                let ty = lv.ty.clone();
                self.push_instr(Instr::Load { dest, ptr: lv.ptr, ty });
                Ok(Val::Local(dest))
            }

            ExprKind::Arrow { base, name } => {
                let lv = self.lower_lvalue_arrow(base, name)?;
                let dest = self.alloc_val();
                let ty = lv.ty.clone();
                self.push_instr(Instr::Load { dest, ptr: lv.ptr, ty });
                Ok(Val::Local(dest))
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

            ExprKind::Comma(lhs, rhs) => {
                self.lower_expr(lhs)?;
                self.lower_expr(rhs)
            }

            ExprKind::CompoundLiteral { ty, init } => {
                let ir_ty = self.lower_type(ty)?;
                let vid = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: vid, ty: ir_ty.clone() });
                // Zero first
                let size = ir_ty.size_of(self.ptr_size());
                if size > 0 {
                    self.push_instr(Instr::MemSet {
                        dst: Val::Local(vid), val: Constant::zero(), size,
                        align: ir_ty.align_of(self.ptr_size()),
                    });
                }
                let ptr = Val::Local(vid);
                use crate::lower::func::FuncCtx;
                // lower each initializer
                for (i, item) in init.iter().enumerate() {
                    match &ir_ty.clone() {
                        Type::Struct(st) if i < st.fields.len() => {
                            let fty = st.fields[i].1.clone();
                            let byte_offset = st.field_offset(i, self.ptr_size());
                            let fptr = self.alloc_val();
                            self.push_instr(Instr::GetFieldPtr {
                                dest: fptr, base: ptr.clone(), field_idx: i,
                                struct_name: st.name.clone(), byte_offset,
                            });
                            self.lower_init_item(item, Val::Local(fptr), &fty)?;
                        }
                        Type::Array { elem, len } if i < *len || *len == 0 => {
                            let eptr = self.alloc_val();
                            let elem = *elem.clone();
                            let elem_size = elem.size_of(self.ptr_size());
                            self.push_instr(Instr::GetElemPtr {
                                dest: eptr, base: ptr.clone(), index: Constant::int(i as i64), elem_size,
                            });
                            self.lower_init_item(item, Val::Local(eptr), &elem)?;
                        }
                        _ => {}
                    }
                }
                // Return as pointer (compound literals decay to pointer)
                Ok(ptr)
            }

            ExprKind::VaStart { list, last } => {
                let list_ptr = self.lower_expr_as_ptr(list)?;
                self.push_instr(Instr::VaStart { list_ptr });
                Ok(Constant::zero())
            }

            ExprKind::VaArg { list, ty } => {
                let list_ptr = self.lower_expr_as_ptr(list)?;
                let ir_ty = self.lower_type(ty)?;
                let dest = self.alloc_val();
                self.push_instr(Instr::VaArg { dest, list_ptr, ty: ir_ty });
                Ok(Val::Local(dest))
            }

            ExprKind::VaEnd { list } => {
                let list_ptr = self.lower_expr_as_ptr(list)?;
                self.push_instr(Instr::VaEnd { list_ptr });
                Ok(Constant::zero())
            }
        }
    }

    fn lower_init_item(&mut self, item: &crate::ast::Initializer, ptr: Val, ty: &Type) -> Result<()> {
        match item {
            crate::ast::Initializer::Expr(e) => {
                let v = self.lower_expr(e)?;
                let cv = self.coerce(v, ty)?;
                self.push_instr(Instr::Store { val: cv, ptr });
            }
            crate::ast::Initializer::List(items) => {
                for (i, it) in items.iter().enumerate() {
                    match ty {
                        Type::Struct(st) if i < st.fields.len() => {
                            let fty = st.fields[i].1.clone();
                            let byte_offset = st.field_offset(i, self.ptr_size());
                            let fptr = self.alloc_val();
                            self.push_instr(Instr::GetFieldPtr {
                                dest: fptr, base: ptr.clone(), field_idx: i,
                                struct_name: st.name.clone(), byte_offset,
                            });
                            self.lower_init_item(it, Val::Local(fptr), &fty)?;
                        }
                        Type::Array { elem, .. } => {
                            let elem_size = elem.size_of(self.ptr_size());
                            let eptr = self.alloc_val();
                            self.push_instr(Instr::GetElemPtr {
                                dest: eptr, base: ptr.clone(), index: Constant::int(i as i64), elem_size,
                            });
                            self.lower_init_item(it, Val::Local(eptr), elem)?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
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
                    let elem_size = inner.size_of(self.ptr_size()) as i64;
                    let idx = self.coerce(r, &Type::i64())?;
                    let idx = if op == BinOpKind::Sub {
                        let neg = self.alloc_val();
                        self.push_instr(Instr::UnaryOp { dest: neg, op: UnOp::Neg, val: idx, ty: Type::i64() });
                        Val::Local(neg)
                    } else { idx };
                    let dest = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest, base: l, index: idx, elem_size: elem_size.unsigned_abs() });
                    self.val_types.insert(dest.0, Type::Pointer(Box::new(inner)));
                    return Ok(Val::Local(dest));
                }
                (_, Type::Pointer(elem)) if op == BinOpKind::Add => {
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => *e.clone(), t => t.clone() };
                    let elem_size = inner.size_of(self.ptr_size());
                    let idx = self.coerce(l, &Type::i64())?;
                    let dest = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest, base: r, index: idx, elem_size });
                    self.val_types.insert(dest.0, Type::Pointer(Box::new(inner)));
                    return Ok(Val::Local(dest));
                }
                (Type::Pointer(elem), Type::Pointer(_)) if op == BinOpKind::Sub => {
                    // ptr - ptr → (ptr - ptr) / elem_size
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => e.as_ref(), t => t };
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
                } else if is_signed || matches!(common, Type::Pointer(_)) {
                    match op {
                        BinOpKind::Eq => CmpOp::IEq,  BinOpKind::Ne => CmpOp::INe,
                        BinOpKind::Lt => CmpOp::ISLt, BinOpKind::Le => CmpOp::ISLe,
                        BinOpKind::Gt => CmpOp::ISGt, BinOpKind::Ge => CmpOp::ISGe,
                        _ => unreachable!()
                    }
                } else {
                    match op {
                        BinOpKind::Eq => CmpOp::IEq,  BinOpKind::Ne => CmpOp::INe,
                        BinOpKind::Lt => CmpOp::IULt, BinOpKind::Le => CmpOp::IULe,
                        BinOpKind::Gt => CmpOp::IUGt, BinOpKind::Ge => CmpOp::IUGe,
                        _ => unreachable!()
                    }
                };
                let cmp_dest = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: cmp_dest, op: cmp_op, lhs: lc, rhs: rc });
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
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: Type::i32() });
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
        let rhs_val = self.lower_expr(rhs)?;

        let store_val = if let Some(bin_op) = op {
            // Load current value, apply op, store result
            let cur = self.alloc_val();
            let ty = lv.ty.clone();
            self.push_instr(Instr::Load { dest: cur, ptr: lv.ptr.clone(), ty });
            self.emit_binop(bin_op, Val::Local(cur), rhs_val)?
        } else {
            rhs_val
        };

        let coerced = self.coerce(store_val, &lv.ty)?;
        self.push_instr(Instr::Store { val: coerced.clone(), ptr: lv.ptr });
        Ok(coerced)
    }

    fn lower_unary(&mut self, op: UnOpKind, inner: &Expr) -> Result<Val> {
        match op {
            UnOpKind::Addr => {
                let lv = self.lower_lvalue(inner)?;
                Ok(lv.ptr)
            }
            UnOpKind::Deref => {
                let ptr = self.lower_expr(inner)?;
                let dest = self.alloc_val();
                // Determine pointee type
                let ptr_ty = self.val_type(&ptr);
                let inner_ty = match &ptr_ty {
                    Type::Pointer(t) => *t.clone(),
                    _ => Type::i32(), // fallback
                };
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

    fn lower_pre_inc(&mut self, inc: bool, inner: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(inner)?;
        let cur = self.alloc_val();
        let ty = lv.ty.clone();
        self.push_instr(Instr::Load { dest: cur, ptr: lv.ptr.clone(), ty: ty.clone() });
        let op = if inc { BinOpKind::Add } else { BinOpKind::Sub };
        let result = self.emit_binop(op, Val::Local(cur), Constant::int(1))?;
        self.push_instr(Instr::Store { val: result.clone(), ptr: lv.ptr });
        Ok(result)
    }

    fn lower_post_inc(&mut self, inc: bool, inner: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(inner)?;
        let old = self.alloc_val();
        let ty = lv.ty.clone();
        self.push_instr(Instr::Load { dest: old, ptr: lv.ptr.clone(), ty: ty.clone() });
        let op = if inc { BinOpKind::Add } else { BinOpKind::Sub };
        let result = self.emit_binop(op, Val::Local(old), Constant::int(1))?;
        self.push_instr(Instr::Store { val: result, ptr: lv.ptr });
        Ok(Val::Local(old))
    }

    fn lower_ternary(&mut self, cond: &Expr, then: &Expr, else_: &Expr) -> Result<Val> {
        let cond_val = self.lower_expr(cond)?;
        let cond_bool = self.to_bool(cond_val)?;

        let result_ptr = self.alloc_val();
        // Defer type until we know both branches — use i32 for now
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: Type::i32() });

        let then_bb  = self.new_block_after_current();
        let else_bb  = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();

        self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

        self.switch_to_block(then_bb);
        let tv = self.lower_expr(then)?;
        self.push_instr(Instr::Store { val: tv, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(else_bb);
        let ev = self.lower_expr(else_)?;
        self.push_instr(Instr::Store { val: ev, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: Type::i32() });
        Ok(Val::Local(dest))
    }

    fn lower_call(&mut self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
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
        }

        // Evaluate arguments
        let mut arg_vals = Vec::new();
        for a in args {
            arg_vals.push(self.lower_expr(a)?);
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

    // ─── LValue lowering ─────────────────────────────────────────────────────

    fn lower_lvalue(&mut self, expr: &Expr) -> Result<LValue> {
        match &expr.kind {
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, vid)) => {
                        let ty = ty.clone();
                        Ok(LValue { ptr: Val::Local(vid), ty })
                    }
                    Some(LookupResult::Global(ty, gref)) => {
                        let ty = ty.clone();
                        Ok(LValue { ptr: Val::Global(gref), ty })
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
                let inner_ty = match ptr_ty {
                    Type::Pointer(t) => *t,
                    _ => Type::i32(),
                };
                Ok(LValue { ptr, ty: inner_ty })
            }
            ExprKind::Index { base, index } => self.lower_lvalue_index(base, index),
            ExprKind::Field { base, name } => self.lower_lvalue_field(base, name),
            ExprKind::Arrow { base, name }  => self.lower_lvalue_arrow(base, name),
            _ => {
                // Not a simple lvalue — could be compound literal etc.
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
                other => other.clone(),
            },
            Type::Array { elem, .. } => *elem.clone(),
            _ => Type::i32(),
        };

        let elem_size = elem_ty.size_of(self.ptr_size());
        let dest = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest, base: base_val, index: idx_i64, elem_size });
        Ok(LValue { ptr: Val::Local(dest), ty: elem_ty })
    }

    fn lower_lvalue_field(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base must be a struct lvalue
        let lv = self.lower_lvalue(base)?;
        self.field_ptr_from(lv, name, false, &base.span)
    }

    fn lower_lvalue_arrow(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base is a pointer to struct
        let ptr = self.lower_expr(base)?;
        let ptr_ty = self.val_type(&ptr);
        let struct_ty = match &ptr_ty {
            Type::Pointer(t) => *t.clone(),
            _ => return Err(CompileError::new("-> applied to non-pointer")),
        };
        let lv = LValue { ptr, ty: struct_ty };
        self.field_ptr_from(lv, name, true, &crate::lexer::Span::default())
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

        // Look up field index and type
        let (field_idx, field_ty, struct_name) = find_field(&struct_ty, field_name, &self.lowerer.struct_types)
            .ok_or_else(|| CompileError::at(
                format!("no field '{}' in type", field_name),
                sp.file.clone(), sp.line, sp.col,
            ))?;

        let base_ptr = if via_ptr {
            // base is already a pointer to struct
            lv.ptr
        } else {
            lv.ptr
        };

        let byte_offset = match &struct_ty {
            Type::Struct(st) => st.field_offset(field_idx, self.ptr_size()),
            _ => 0,
        };

        let dest = self.alloc_val();
        self.push_instr(Instr::GetFieldPtr {
            dest, base: base_ptr, field_idx, struct_name, byte_offset,
        });
        Ok(LValue { ptr: Val::Local(dest), ty: field_ty })
    }

    // ─── Type inference ───────────────────────────────────────────────────────

    pub fn infer_expr_type(&self, expr: &Expr) -> Result<Type> {
        match &expr.kind {
            ExprKind::IntLit(_) | ExprKind::CharLit(_) => Ok(Type::i32()),
            ExprKind::UIntLit(_) => Ok(Type::u32()),
            ExprKind::FloatLit(_) => Ok(Type::Float64),
            ExprKind::StringLit(_) => Ok(Type::char_ptr()),
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
            ExprKind::SizeofType(_) | ExprKind::SizeofExpr(_) => Ok(Type::u64()),
            ExprKind::Unary { op: UnOpKind::Addr, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                Ok(Type::Pointer(Box::new(inner_ty)))
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                Ok(match inner_ty {
                    Type::Pointer(t) => *t,
                    _ => Type::i32(),
                })
            }
            ExprKind::Field { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                if let Some((_, fty, _)) = find_field(&base_ty, name, &self.lowerer.struct_types) {
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
                if let Some((_, fty, _)) = find_field(&struct_ty, name, &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            ExprKind::Index { base, .. } => {
                let bt = self.infer_expr_type(base)?;
                Ok(match bt {
                    Type::Pointer(t) => match *t {
                        Type::Array { elem, .. } => *elem,
                        other => other,
                    },
                    Type::Array { elem, .. } => *elem,
                    _ => Type::i32(),
                })
            }
            _ => Ok(Type::i32()),
        }
    }

    /// Lower an expression expecting it to produce a pointer (for va_list etc).
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

fn find_field(ty: &Type, name: &str, _named: &std::collections::HashMap<String, Type>) -> Option<(usize, Type, Option<String>)> {
    match ty {
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
