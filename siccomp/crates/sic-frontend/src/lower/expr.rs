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
    pub(super) bit_offset: u32,
    pub(super) width: u32,
    pub(super) signed: bool,
}

impl BitField {
    pub(super) fn new(bit_offset: u32, width: u32, signed: bool) -> Self {
        BitField { bit_offset, width, signed }
    }
}

/// Which AES-NI round intrinsic to emulate.
#[derive(Clone, Copy)]
enum AesMode { Enc, EncLast, Dec, DecLast, Imc }

/// AES forward S-box.
static AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// AES inverse S-box.
static AES_INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

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
            thread_local: false,
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
                self.lower_offsetof(ty, designators)
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

            ExprKind::Swap { lhs, rhs } => self.lower_swap(lhs, rhs),

            ExprKind::Slice { base, lo, hi } => self.lower_slice(base, lo.as_deref(), hi.as_deref()),

            ExprKind::New { ty, count } => self.lower_new(ty, count.as_deref()),

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
                // sic native-string computed accessors (sic.md §"Built-in string").
                // `.size` / `.data` are ordinary struct fields and fall through.
                if self.is_sic() && (name == "ptr" || name == "length") {
                    if let Ok(bt) = self.infer_expr_type(base) {
                        if super::types::is_sic_string(&bt) {
                            return if name == "ptr" {
                                self.emit_string_cptr(base)
                            } else {
                                self.emit_string_length(base)
                            };
                        }
                    }
                }
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
                Ok(self.size_t_val(size))
            }

            ExprKind::SizeofExpr(inner) => {
                // We need the type of the expression without evaluating it.
                // Simplified: just return a placeholder for now.
                let ty = self.infer_expr_type(inner)?;
                let size = ty.size_of(self.ptr_size());
                Ok(self.size_t_val(size))
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
                Ok(self.size_t_val(a))
            }
            ExprKind::AlignofExpr(inner) => {
                let a = self.infer_expr_type(inner)?.align_of(self.ptr_size());
                Ok(self.size_t_val(a))
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
                let mut ir_ty = self.lower_type(ty)?;
                // An implicit-length array literal `(T[]){ a, b, c }` lowers to
                // `[T; 0]`; size it from the initializer element count so the
                // alloca reserves the full array. Otherwise the element stores
                // overflow a 1-byte slot into neighboring stack storage (QEMU's
                // virtio_pci_types_register `.interfaces = (const InterfaceInfo[])
                // { {..}, {..}, {} }` got clobbered by a later g_strdup_printf).
                if let Type::Array { len, .. } = &mut ir_ty {
                    if *len == 0 { *len = self.lowerer.infer_array_len(init); }
                }
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

        // GCC vector extension: when both operands are vector (array) types an
        // arithmetic/bitwise/comparison operator is element-wise, not scalar.
        // Regular arrays decay to pointers before this point, so two array
        // operands here means a `vector_size` type.
        if !matches!(op, BinOpKind::LogAnd | BinOpKind::LogOr) {
            if let (Ok(lt @ Type::Array { .. }), Ok(Type::Array { .. })) =
                (self.infer_expr_type(lhs), self.infer_expr_type(rhs))
            {
                return self.lower_vector_binop(op, lhs, rhs, lt);
            }
        }

        // sic string concatenation `a + b` (sic.md §"Built-in string"): if either
        // side is a `string`, build a fresh joined string.
        if self.is_sic() && op == BinOpKind::Add
            && (self.is_string_operand(lhs) || self.is_string_operand(rhs))
        {
            return self.lower_string_concat(lhs, rhs);
        }

        let l = self.lower_expr(lhs)?;
        let r = self.lower_expr(rhs)?;
        self.emit_binop(op, l, r)
    }

    /// Whether `e` is an actual `string`-typed expression. Used to decide that a
    /// `+` is string concatenation. A bare string literal does NOT count here (so
    /// `"abc" + 1` stays pointer arithmetic); the literal is still accepted as the
    /// *other* operand once concatenation is triggered by a real string.
    fn is_string_operand(&self, e: &Expr) -> bool {
        matches!(self.infer_expr_type(e), Ok(t) if super::types::is_sic_string(&t))
    }

    /// Load a `string`/literal operand of `+` as a `(data, size)` pair (size as
    /// i64). A `string` reads its slice fields; a literal uses a fresh cstring
    /// global and its compile-time byte length.
    fn string_operand_parts(&mut self, e: &Expr) -> Result<(Val, Val)> {
        if let ExprKind::StringLit(s) = &e.kind {
            let data = self.emit_cstring(s);
            return Ok((data, Constant::int(s.len() as i64)));
        }
        let ty = self.infer_expr_type(e)?;
        if !super::types::is_sic_string(&ty) {
            return Err(CompileError::at(
                "operand of string `+` is neither a string nor a string literal".to_string(),
                e.span.file.clone(), e.span.line, e.span.col,
            ));
        }
        let data_lv = self.lower_lvalue_field(e, "data")?;
        let data = self.load_lvalue(&data_lv)?;
        let size_lv = self.lower_lvalue_field(e, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let size = self.coerce(size, &Type::i64())?;
        Ok((data, size))
    }

    /// sic `a + b` on strings: `malloc(a.size + b.size + 1)`, copy both halves,
    /// NUL-terminate, and return the joined `string`. The buffer is not freed
    /// yet (reclaimed later by the ownership/refcount milestone).
    fn lower_string_concat(&mut self, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (d1, s1) = self.string_operand_parts(lhs)?;
        let (d2, s2) = self.string_operand_parts(rhs)?;

        // total = s1 + s2 ; buf = malloc(total + 1)
        let total = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: total, op: BinOp::Add, lhs: s1.clone(), rhs: s2.clone(), ty: Type::i64() });
        let bufsize = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: bufsize, op: BinOp::Add, lhs: Val::Local(total), rhs: Constant::int(1), ty: Type::i64() });
        let buf = self.emit_malloc(Val::Local(bufsize))?;

        // memcpy(buf, d1, s1); memcpy(buf + s1, d2, s2)
        self.emit_memcpy(buf.clone(), d1, s1.clone())?;
        let mid = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: mid, base: buf.clone(), index: s1, elem_size: 1, result_ty: Type::char_ptr() });
        self.emit_memcpy(Val::Local(mid), d2, s2)?;

        // buf[total] = 0
        let endp = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: endp, base: buf.clone(), index: Val::Local(total), elem_size: 1, result_ty: Type::char_ptr() });
        self.push_instr(Instr::MemSet { dst: Val::Local(endp), val: Constant::zero(), size: 1, align: 1 });

        self.make_string_val(buf, Val::Local(total))
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
            BinOpKind::RotL   => (BinOp::Rotl, common.clone()),
            BinOpKind::RotR   => (BinOp::Rotr, common.clone()),
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

        // SIC defines integer `÷0` and `%0` as 0 (sic.md §"Integer overflow"),
        // rather than C's undefined behavior / hardware trap.
        if self.is_sic()
            && matches!(ir_op, BinOp::SDiv | BinOp::UDiv | BinOp::SRem | BinOp::URem)
        {
            return Ok(self.guarded_div_rem(ir_op, lc, rc, result_ty));
        }
        // SIC defines out-of-range shifts (sic.md §"Rotate and shift"): count ≥
        // width → 0 (signed `>>` → sign-fill); count ≤ 0 → value unchanged.
        if self.is_sic() && matches!(ir_op, BinOp::Shl | BinOp::AShr | BinOp::LShr) {
            return Ok(self.guarded_shift(ir_op, lc, rc, result_ty));
        }
        if let Some(v) = self.emit_div_rem_libcall(ir_op, lc.clone(), rc.clone(), &result_ty) {
            return Ok(v);
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::BinOp { dest, op: ir_op, lhs: lc, rhs: rc, ty: result_ty });
        Ok(Val::Local(dest))
    }

    /// SIC integer `÷0`/`%0` → 0. Force the divisor to a nonzero value so the
    /// trapping div/rem never sees 0, then select 0 when the real divisor was 0.
    fn guarded_div_rem(&mut self, op: BinOp, lc: Val, rc: Val, ty: Type) -> Val {
        let is_zero = self.alloc_val();
        self.push_instr(Instr::Cmp {
            dest: is_zero, op: CmpOp::IEq, lhs: rc.clone(), rhs: Constant::int(0), ty: ty.clone(),
        });
        let safe_rhs = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: safe_rhs, cond: Val::Local(is_zero),
            on_true: Constant::int(1), on_false: rc, ty: ty.clone(),
        });
        let q = if let Some(v) =
            self.emit_div_rem_libcall(op, lc.clone(), Val::Local(safe_rhs), &ty)
        {
            v
        } else {
            let d = self.alloc_val();
            self.push_instr(Instr::BinOp {
                dest: d, op, lhs: lc, rhs: Val::Local(safe_rhs), ty: ty.clone(),
            });
            Val::Local(d)
        };
        let result = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: result, cond: Val::Local(is_zero),
            on_true: Constant::int(0), on_false: q, ty,
        });
        Val::Local(result)
    }

    /// SIC out-of-range shift semantics (sic.md §"Rotate and shift"). Cranelift
    /// masks the shift count to the operand width; SIC instead defines count ≥
    /// width → 0 (arithmetic `>>` → sign fill) and count ≤ 0 → value unchanged.
    /// The in-range shift is only *used* for 0<count<width (where masking is a
    /// no-op); the out-of-range cases are picked with `select`.
    fn guarded_shift(&mut self, op: BinOp, lc: Val, rc: Val, ty: Type) -> Val {
        let bits = ty.int_bits().unwrap_or(32) as i64;

        let normal = self.alloc_val();
        self.push_instr(Instr::BinOp {
            dest: normal, op, lhs: lc.clone(), rhs: rc.clone(), ty: ty.clone(),
        });
        // Value when count ≥ width: 0, except signed `>>` fills the sign bit
        // (= arithmetic-shift the value by width-1).
        let overflow_val = if matches!(op, BinOp::AShr) {
            let d = self.alloc_val();
            self.push_instr(Instr::BinOp {
                dest: d, op: BinOp::AShr, lhs: lc.clone(),
                rhs: Constant::int(bits - 1), ty: ty.clone(),
            });
            Val::Local(d)
        } else {
            Constant::int(0)
        };
        // The count is compared as signed: a shift amount is conceptually signed
        // ("zero or negative → unchanged"), and realistic counts are tiny, so a
        // high-bit-set count means "negative", not "> 2 billion".
        let ge_w = self.alloc_val();
        self.push_instr(Instr::Cmp {
            dest: ge_w, op: CmpOp::ISGe, lhs: rc.clone(), rhs: Constant::int(bits), ty: ty.clone(),
        });
        let inner = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: inner, cond: Val::Local(ge_w),
            on_true: overflow_val, on_false: Val::Local(normal), ty: ty.clone(),
        });
        // count ≤ 0 → value unchanged.
        let le0 = self.alloc_val();
        self.push_instr(Instr::Cmp {
            dest: le0, op: CmpOp::ISLe, lhs: rc, rhs: Constant::int(0), ty: ty.clone(),
        });
        let result = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: result, cond: Val::Local(le0),
            on_true: lc, on_false: Val::Local(inner), ty,
        });
        Val::Local(result)
    }

    /// If `op` is an integer divide/remainder on a 128-bit type, emit a call to
    /// the compiler-rt helper (`__divti3`/`__udivti3`/`__modti3`/`__umodti3`) and
    /// return its result — Cranelift's x64 backend can't lower `udiv.i128` etc.
    /// natively. Otherwise return None so the caller emits a plain `BinOp`.
    fn emit_div_rem_libcall(&mut self, op: BinOp, lhs: Val, rhs: Val, ty: &Type) -> Option<Val> {
        if !matches!(ty, Type::Int { bits: 128, .. }) { return None; }
        let name = match op {
            BinOp::SDiv => "__divti3",
            BinOp::UDiv => "__udivti3",
            BinOp::SRem => "__modti3",
            BinOp::URem => "__umodti3",
            _ => return None,
        };
        let fref = self.lowerer.module.func_ref_by_name(name).unwrap_or_else(|| {
            self.lowerer.module.add_extern(sic_ir::ExternFunc {
                name: name.to_string(),
                sig: sic_ir::FunctionType {
                    ret: ty.clone(),
                    params: vec![ty.clone(), ty.clone()],
                    variadic: false,
                },
            })
        });
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![lhs, rhs], ret_ty: ty.clone() });
        Some(Val::Local(dest))
    }

    /// Emit `malloc(n)` and return the result typed as `char*`. Used by the
    /// native-string ops (`.ptr` copy, concat); the block is not freed yet —
    /// reclamation waits on the ownership/refcount milestone.
    fn emit_malloc(&mut self, n: Val) -> Result<Val> {
        let voidp = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("malloc").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "malloc".to_string(),
                sig: FunctionType { ret: voidp.clone(), params: vec![Type::u64()], variadic: false },
            })
        });
        let sz = self.coerce(n, &Type::u64())?;
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![sz], ret_ty: voidp });
        self.val_types.insert(dest.0, Type::char_ptr());
        Ok(Val::Local(dest))
    }

    /// Emit `free(p)`.
    fn emit_free(&mut self, p: Val) -> Result<()> {
        let voidp = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("free").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "free".to_string(),
                sig: FunctionType { ret: Type::Void, params: vec![voidp.clone()], variadic: false },
            })
        });
        let p = self.coerce(p, &voidp)?;
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![p], ret_ty: Type::Void });
        Ok(())
    }

    /// sic `new T` / `new T(count)` (sic.md §"Scopes and automatic release"):
    /// allocate a block with a `{ usize size; usize refcount }` header before the
    /// data, `refcount = 1`, and return the data pointer typed `T*`. `del` frees
    /// via the header; the header also carries the size for future bounds checks.
    pub(crate) fn lower_new(&mut self, ty: &crate::ast::QualType, count: Option<&Expr>) -> Result<Val> {
        let elem_ty = self.lower_type(ty)?;
        let elem_size = elem_ty.size_of(self.ptr_size()).max(1);
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let header = (2 * self.ptr_size()) as i64;

        let count_val = match count {
            Some(e) => { let v = self.lower_expr(e)?; self.coerce(v, &usize_ty)? }
            None => self.coerce(Constant::int(1), &usize_ty)?,
        };
        let esz = self.coerce(Constant::uint(elem_size), &usize_ty)?;
        let data_size = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: data_size, op: BinOp::Mul, lhs: count_val, rhs: esz, ty: usize_ty.clone() });
        let header_c = self.coerce(Constant::int(header), &usize_ty)?;
        let total = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: total, op: BinOp::Add, lhs: Val::Local(data_size), rhs: header_c, ty: usize_ty.clone() });
        let block = self.emit_malloc(Val::Local(total))?; // char*

        // header[0] = data_size ; header[1] (at +ptr_size) = refcount = 1
        self.push_instr(Instr::Store { val: Val::Local(data_size), ptr: block.clone() });
        let rc_ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rc_ptr, base: block.clone(), index: Constant::int(self.ptr_size() as i64), elem_size: 1, result_ty: Type::char_ptr() });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: Val::Local(rc_ptr) });

        let ptr_ty = Type::Pointer(Box::new(elem_ty));
        let data = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: data, base: block, index: Constant::int(header), elem_size: 1, result_ty: ptr_ty.clone() });
        self.val_types.insert(data.0, ptr_ty);
        Ok(Val::Local(data))
    }

    /// sic `del p;` — decrement the header refcount of a `new`-allocated pointer
    /// and `free` the block when it reaches 0. A NULL pointer is a no-op.
    pub(crate) fn lower_delete(&mut self, e: &Expr) -> Result<()> {
        let p = self.lower_expr(e)?;
        let pc = self.coerce(p, &Type::char_ptr())?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };

        let is_null = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: pc.clone(), rhs: Constant::zero(), ty: Type::char_ptr() });
        let body_bb = self.new_block_after_current();
        let free_bb = self.new_block_after_current();
        let done_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done_bb, else_bb: body_bb });

        // body: refcount field is at p - ptr_size (block + ptr_size). Decrement.
        self.switch_to_block(body_bb);
        let rc_ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rc_ptr, base: pc.clone(), index: Constant::int(-(self.ptr_size() as i64)), elem_size: 1, result_ty: Type::char_ptr() });
        let rc = self.alloc_val();
        self.push_instr(Instr::Load { dest: rc, ptr: Val::Local(rc_ptr), ty: usize_ty.clone() });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        let newrc = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newrc, op: BinOp::Sub, lhs: Val::Local(rc), rhs: one, ty: usize_ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(newrc), ptr: Val::Local(rc_ptr) });
        let zero = self.coerce(Constant::int(0), &usize_ty)?;
        let is_zero = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::IEq, lhs: Val::Local(newrc), rhs: zero, ty: usize_ty });
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_zero), then_bb: free_bb, else_bb: done_bb });

        // free: block = p - 2*ptr_size
        self.switch_to_block(free_bb);
        let block = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: block, base: pc, index: Constant::int(-(2 * self.ptr_size() as i64)), elem_size: 1, result_ty: Type::char_ptr() });
        self.emit_free(Val::Local(block))?;
        self.set_terminator(Terminator::Jump(done_bb));

        self.switch_to_block(done_bb);
        Ok(())
    }

    /// Emit `memcpy(dst, src, n)`.
    fn emit_memcpy(&mut self, dst: Val, src: Val, n: Val) -> Result<()> {
        let voidp = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("memcpy").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "memcpy".to_string(),
                sig: FunctionType { ret: voidp.clone(), params: vec![voidp.clone(), voidp.clone(), Type::u64()], variadic: false },
            })
        });
        let dstp = self.coerce(dst, &voidp)?;
        let srcp = self.coerce(src, &voidp)?;
        let n = self.coerce(n, &Type::u64())?;
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![dstp, srcp, n], ret_ty: voidp });
        Ok(())
    }

    /// Materialize a `string` slice descriptor `{ data, size }` in a fresh temp
    /// and return the pointer to it (the aggregate-by-pointer convention used for
    /// struct rvalues, e.g. compound literals).
    pub(crate) fn make_string_val(&mut self, data: Val, size: Val) -> Result<Val> {
        let sty = super::types::sic_string_type(self.ptr_size());
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: sty.clone(), align: None });
        let base = Val::Local(slot);
        if let Some((dptr, dty, _)) = self.member_at(&base, &sty, 0) {
            let v = self.coerce(data, &dty)?;
            self.push_instr(Instr::Store { val: v, ptr: dptr });
        }
        if let Some((sptr, sfty, _)) = self.member_at(&base, &sty, 1) {
            let v = self.coerce(size, &sfty)?;
            self.push_instr(Instr::Store { val: v, ptr: sptr });
        }
        Ok(base)
    }

    /// sic substring slice `s[lo:hi]` (sic.md §"Built-in string"): a half-open,
    /// byte-offset **view** into `s` — no copy. `{ s.data + lo, hi - lo }`.
    /// Omitted bounds default to `lo=0`, `hi=s.size`.
    fn lower_slice(&mut self, base: &Expr, lo: Option<&Expr>, hi: Option<&Expr>) -> Result<Val> {
        let bt = self.infer_expr_type(base)?;
        if !super::types::is_sic_string(&bt) {
            return Err(CompileError::at(
                "slice `[a:b]` applies only to a `string`".to_string(),
                base.span.file.clone(), base.span.line, base.span.col,
            ));
        }
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;                 // char*
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let size = self.coerce(size, &Type::i64())?;

        let lo_v = match lo {
            Some(e) => { let v = self.lower_expr(e)?; self.coerce(v, &Type::i64())? }
            None => Constant::int(0),
        };
        let hi_v = match hi {
            Some(e) => { let v = self.lower_expr(e)?; self.coerce(v, &Type::i64())? }
            None => size.clone(),
        };

        // new data = base data + lo
        let new_data = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: new_data, base: data, index: lo_v.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        // new size = hi - lo
        let new_size = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: new_size, op: BinOp::Sub, lhs: hi_v, rhs: lo_v, ty: Type::i64() });
        self.make_string_val(Val::Local(new_data), Val::Local(new_size))
    }

    /// sic `s.length`: number of UTF-8 code points in the slice (sic.md
    /// §"Built-in string"). Delegates to a synthesized once-per-module helper
    /// `__sic_str_length(data, size)` — keeping the counting loop in its own
    /// function avoids emitting multiple expression-level loops into one caller
    /// (which the -O0 backend miscompiles) and keeps call sites small.
    fn emit_string_length(&mut self, base: &Expr) -> Result<Val> {
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let size = self.coerce(size, &usize_ty)?;
        let fref = self.lowerer.ensure_str_length_fn();
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![data, size], ret_ty: usize_ty });
        Ok(Val::Local(dest))
    }

    /// sic `s.ptr`: yield a `const char*` usable as a C string, copying only when
    /// necessary (sic.md §"Built-in string"). If the byte just past the slice
    /// (`data[size]`) is already NUL, the slice is a valid C string and `data` is
    /// returned as-is; otherwise a NUL-terminated `malloc` copy is made.
    fn emit_string_cptr(&mut self, base: &Expr) -> Result<Val> {
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;                 // char*
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let size = self.coerce(size, &Type::i64())?;

        // Probe data[size]; in-bounds because backing buffers are NUL-terminated.
        let last = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: last, base: data.clone(), index: size.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        let byte = self.alloc_val();
        self.push_instr(Instr::Load { dest: byte, ptr: Val::Local(last), ty: Type::i8() });
        let is_term = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_term, op: CmpOp::IEq, lhs: Val::Local(byte), rhs: Constant::zero(), ty: Type::i8() });

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: Type::char_ptr(), align: None });

        let copy_bb = self.new_block_after_current();
        let term_bb = self.new_block_after_current();
        let end_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_term), then_bb: term_bb, else_bb: copy_bb });

        // Already NUL-terminated: use data directly.
        self.switch_to_block(term_bb);
        self.push_instr(Instr::Store { val: data.clone(), ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(end_bb));

        // Not terminated: malloc(size+1), copy, append NUL.
        self.switch_to_block(copy_bb);
        let n = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: n, op: BinOp::Add, lhs: size.clone(), rhs: Constant::int(1), ty: Type::i64() });
        let buf = self.emit_malloc(Val::Local(n))?;
        self.emit_memcpy(buf.clone(), data.clone(), size.clone())?;
        let bend = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: bend, base: buf.clone(), index: size.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        self.push_instr(Instr::MemSet { dst: Val::Local(bend), val: Constant::zero(), size: 1, align: 1 });
        self.push_instr(Instr::Store { val: buf, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(end_bb));

        self.switch_to_block(end_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: Type::char_ptr() });
        self.val_types.insert(dest.0, Type::char_ptr());
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
        // For an array-typed lvalue this only applies to a genuine aggregate RHS
        // (a vector produced by an operator/intrinsic); a scalar RHS to an
        // array-typed lvalue is a deref like `*arr = 1` (an array decayed to a
        // pointer whose element type sic surfaces as the array), a scalar store.
        let aggregate_assign = op.is_none() && match &lv.ty {
            Type::Struct(_) | Type::Union(_) => true,
            Type::Array { .. } => matches!(
                self.infer_expr_type(rhs),
                Ok(Type::Array { .. } | Type::Struct(_) | Type::Union(_))
            ),
            _ => false,
        };
        if aggregate_assign {
            // Copy the whole object, whether the RHS is an lvalue or an aggregate
            // rvalue (e.g. a compound literal `(T){...}`, a struct return, or a
            // vector produced by an element-wise operator/intrinsic).
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

    /// SIC swap `a <> b` (sic.md §"Swap"): exchange the contents of two lvalues.
    /// Both operands must denote storage of the same size — swap exchanges bytes,
    /// it never converts. Scalars go through a crossed load/store; aggregates are
    /// exchanged byte-wise via a temporary.
    fn lower_swap(&mut self, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let lv_a = self.lower_lvalue(lhs)?;
        let lv_b = self.lower_lvalue(rhs)?;

        let size = lv_a.ty.size_of(self.ptr_size());
        if size != lv_b.ty.size_of(self.ptr_size()) {
            return Err(CompileError::at(
                "`<>` swap requires both operands to have the same type".to_string(),
                lhs.span.file.clone(), lhs.span.line, lhs.span.col,
            ));
        }

        match &lv_a.ty {
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => {
                // Aggregate swap: exchange the bytes through a temporary buffer.
                let align = lv_a.ty.align_of(self.ptr_size());
                let tmp_slot = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: tmp_slot, ty: lv_a.ty.clone(), align: None });
                let tmp = Val::Local(tmp_slot);
                self.push_instr(Instr::MemCopy { dst: tmp.clone(), src: lv_a.ptr.clone(), size, align });
                self.push_instr(Instr::MemCopy { dst: lv_a.ptr.clone(), src: lv_b.ptr.clone(), size, align });
                self.push_instr(Instr::MemCopy { dst: lv_b.ptr.clone(), src: tmp, size, align });
            }
            _ => {
                // Scalar (including bit-field) swap: load both, store crossed.
                let va = self.load_lvalue(&lv_a)?;
                let vb = self.load_lvalue(&lv_b)?;
                self.store_lvalue(&lv_a, vb)?;
                self.store_lvalue(&lv_b, va)?;
            }
        }
        Ok(Constant::zero())
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
                // value loaded from the function's code). The same holds for an
                // array: `*(T(*)[N])p` is an array lvalue that decays to its own
                // address (== `p`), so emit no load — else a scalar is read from
                // the first element. QEMU's coroutine trampoline relies on this:
                // `siglongjmp(*(sigjmp_buf *)co->entry_arg, 1)` where sigjmp_buf is
                // `struct __jmp_buf_tag[1]` — a stray load passed the saved rbx as
                // the jmp_buf and crashed __longjmp.
                if matches!(inner_ty, Type::Function(_) | Type::Array { .. }) {
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
            // The extraction shifts operate on the loaded STORAGE unit's width,
            // not the field type's semantic value width. These differ for a
            // `_Bool` bitfield: `int_bits(_Bool)` is 1, but the field is loaded
            // as a byte (8 bits). Using 1 made the shift/mask a no-op, so a
            // `_Bool:1` read its neighbour's bit too (QEMU's decode_insn loops on
            // `while (e->is_decode)` where is_decode is a `_Bool:1` — an infinite
            // loop that stalled guest translation).
            let bits = ty.size_of(self.ptr_size()).max(1) as u32 * 8;
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
            return self.store_bitfield(&lv.ptr, &lv.ty, bf, val);
        }
        let coerced = self.coerce(val, &lv.ty)?;
        self.push_instr(Instr::Store { val: coerced.clone(), ptr: lv.ptr.clone() });
        Ok(coerced)
    }

    /// Store `val` into a bit-field via read-modify-write: `*ptr = (*ptr & ~mask)
    /// | ((val & field_mask) << bit_offset)`. Needed both for `s.bf = v` and for
    /// a designated initializer of a bit-field, so adjacent bit-fields sharing
    /// the storage unit are preserved (QEMU's `PhysPageEntry{ .ptr=NIL, .skip=1 }`
    /// where `ptr:26`/`skip:6` share one word).
    pub(super) fn store_bitfield(&mut self, ptr: &Val, ty: &Type, bf: BitField, val: Val) -> Result<Val> {
        let ty = ty.clone();
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
        self.push_instr(Instr::Load { dest: raw, ptr: ptr.clone(), ty: ty.clone() });
        let clear_mask = !(mask as u64).wrapping_shl(bf.bit_offset) as i64;
        let cleared = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: cleared, op: BinOp::And, lhs: Val::Local(raw), rhs: Constant::int(clear_mask), ty: ty.clone() });
        let newv = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newv, op: BinOp::Or, lhs: Val::Local(cleared), rhs: vs, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(newv), ptr: ptr.clone() });
        Ok(val)
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
        // Constant-fold a compile-time-constant condition to just the taken arm,
        // like gcc/clang. QEMU's `dup_const`/tcg macros nest
        // `__builtin_constant_p(x) ? <fold> : <runtime>`; sic returns 0 for
        // `__builtin_constant_p`, so the dead `<fold>` arm (which ends in an
        // exhaustiveness `qemu_build_not_reached_always()`) must not be lowered —
        // else it emits a call to that deliberately-undefined symbol.
        if let Ok(v) = crate::lower::eval_const_expr(cond, &self.lowerer.enum_consts) {
            let taken = if v != 0 { then } else { else_ };
            // An aggregate-valued arm flows as a pointer, so return its aggregate
            // pointer rather than a (truncated) scalar load. Matches the runtime
            // path below and the non-folded aggregate case.
            if matches!(self.infer_expr_type(taken), Ok(Type::Struct(_) | Type::Union(_) | Type::Array { .. })) {
                return self.lower_aggregate_ptr(taken);
            }
            return self.lower_expr(taken);
        }
        let cond_val = self.lower_expr(cond)?;
        let cond_bool = self.to_bool(cond_val)?;

        // Result type of `a ? b : c`: prefer a pointer/float/wider branch so the
        // value (and its type — needed for a following `->`, `*`, arithmetic)
        // survives. Both branches are coerced to it.
        let tty = self.infer_expr_type(then).unwrap_or_else(|_| Type::i32());
        let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());

        // Aggregate result (`cond ? struct_a : struct_b`): each arm yields a
        // pointer to a struct/union/array; copy the selected one into a result
        // slot and yield that slot's pointer (how aggregate values flow in the
        // IR). A scalar Store/Load would truncate the aggregate to a register.
        // QEMU's decoder does `*entry = repz ? pause : nop;` (X86OpEntry copy).
        let agg_ty = match (&tty, &ety) {
            (Type::Struct(_) | Type::Union(_) | Type::Array { .. }, _) => Some(tty.clone()),
            (_, Type::Struct(_) | Type::Union(_) | Type::Array { .. }) => Some(ety.clone()),
            _ => None,
        };
        if let Some(aty) = agg_ty {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: aty.clone(), align: None });
            let size = aty.size_of(self.ptr_size());
            let align = aty.align_of(self.ptr_size());
            let then_bb  = self.new_block_after_current();
            let else_bb  = self.new_block_after_current();
            let merge_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

            self.switch_to_block(then_bb);
            let tp = self.lower_aggregate_ptr(then)?;
            self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: tp, size, align });
            self.set_terminator(Terminator::Jump(merge_bb));

            self.switch_to_block(else_bb);
            let ep = self.lower_aggregate_ptr(else_)?;
            self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: ep, size, align });
            self.set_terminator(Terminator::Jump(merge_bb));

            self.switch_to_block(merge_bb);
            return Ok(Val::Local(slot));
        }
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

    /// Lower a floating-point classification builtin (`isnan`/`isinf`/`isfinite`/
    /// `isnormal`) to an `int` (0/1) using ordered comparisons: `x == x` is false
    /// only for NaN, and `x - x == 0` is true only for finite values.
    fn lower_fp_classify(&mut self, name: &str, arg: &Expr) -> Result<Val> {
        let x = self.lower_expr(arg)?;
        let fty = match self.val_type(&x) {
            t if t.is_float() => t,
            _ => Type::Float64,
        };
        let x = self.coerce(x, &fty)?;
        let zero = Val::Const(Constant::Float(0.0));
        // self_eq = (x == x): 1 unless NaN.
        let self_eq = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: self_eq, op: CmpOp::FOEq, lhs: x.clone(), rhs: x.clone(), ty: fty.clone() });
        // diff = x - x; finite = (diff == 0): 1 only for finite x.
        let diff = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: diff, op: BinOp::FSub, lhs: x.clone(), rhs: x.clone(), ty: fty.clone() });
        let finite = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: finite, op: CmpOp::FOEq, lhs: Val::Local(diff), rhs: zero.clone(), ty: fty.clone() });

        let res = match name {
            "__builtin_isnan" => {
                // !self_eq
                let r = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: r, op: UnOp::BoolNot, val: Val::Local(self_eq), ty: Type::Bool });
                Val::Local(r)
            }
            "__builtin_isfinite" => Val::Local(finite),
            "__builtin_isinf" | "__builtin_isinf_sign" => {
                // self_eq && !finite  (not NaN, not finite → infinite)
                let nfin = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: nfin, op: UnOp::BoolNot, val: Val::Local(finite), ty: Type::Bool });
                let r = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: r, op: BinOp::And, lhs: Val::Local(self_eq), rhs: Val::Local(nfin), ty: Type::Bool });
                Val::Local(r)
            }
            // isnormal ≈ finite && x != 0 (ignores the subnormal boundary).
            _ => {
                let nz = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: nz, op: CmpOp::FONe, lhs: x, rhs: zero, ty: fty });
                let r = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: r, op: BinOp::And, lhs: Val::Local(finite), rhs: Val::Local(nz), ty: Type::Bool });
                Val::Local(r)
            }
        };
        self.coerce(res, &Type::i32())
    }

    /// Lower a floating-point comparison builtin (`isgreater` etc.) — like the
    /// bare operator but without raising an invalid exception on NaN (which sic
    /// does not model anyway), yielding `int` 0/1.
    fn lower_fp_compare(&mut self, name: &str, a: &Expr, b: &Expr) -> Result<Val> {
        let av = self.lower_expr(a)?;
        let bv = self.lower_expr(b)?;
        let fty = match self.val_type(&av) {
            t if t.is_float() => t,
            _ => Type::Float64,
        };
        let av = self.coerce(av, &fty)?;
        let bv = self.coerce(bv, &fty)?;
        if name == "__builtin_isunordered" {
            // NaN in either operand: !(a == a) || !(b == b).
            let ae = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: ae, op: CmpOp::FOEq, lhs: av.clone(), rhs: av, ty: fty.clone() });
            let be = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: be, op: CmpOp::FOEq, lhs: bv.clone(), rhs: bv, ty: fty });
            let both = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: both, op: BinOp::And, lhs: Val::Local(ae), rhs: Val::Local(be), ty: Type::Bool });
            let r = self.alloc_val();
            self.push_instr(Instr::UnaryOp { dest: r, op: UnOp::BoolNot, val: Val::Local(both), ty: Type::Bool });
            return self.coerce(Val::Local(r), &Type::i32());
        }
        let op = match name {
            "__builtin_isgreater" => CmpOp::FOGt,
            "__builtin_isgreaterequal" => CmpOp::FOGe,
            "__builtin_isless" => CmpOp::FOLt,
            "__builtin_islessequal" => CmpOp::FOLe,
            _ /* islessgreater */ => CmpOp::FONe,
        };
        let r = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: r, op, lhs: av, rhs: bv, ty: fty });
        self.coerce(Val::Local(r), &Type::i32())
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
            // `__builtin_constant_p(E)` is 1 when E folds to a compile-time
            // constant. `__builtin_choose_expr` needs this accurate (unlike the
            // runtime `?:` fold, which conservatively treats it as 0): QEMU's
            // MIN_CONST/MAX_CONST (e.g. `BDRV_REQUEST_MAX_SECTORS` defaults in
            // virtio_blk_properties) do
            //   __builtin_choose_expr(__builtin_constant_p(a) && ..., min, (void)0)
            // — a 0 here selects the `(void)0` arm, which can't be lowered and
            // zeroed the whole property table.
            ExprKind::Call { func, args }
                if matches!(&func.kind, ExprKind::Ident(n) if n == "__builtin_constant_p") =>
            {
                match args.first() {
                    Some(a) if self.lowerer.eval_const_int(a).is_some() => 1,
                    _ => 0,
                }
            }
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

    // ---- SIMD vector intrinsics (scalar-emulated over the byte aggregate) ----

    /// Address of `base + off` bytes (off is a compile-time constant).
    fn vec_at(&mut self, base: &Val, off: i64) -> Val {
        if off == 0 { return base.clone(); }
        let d = self.alloc_val();
        self.push_instr(Instr::PtrOffset { dest: d, base: base.clone(), offset: Constant::int(off) });
        Val::Local(d)
    }

    /// Load a scalar of `ty` at `base + off`.
    fn vec_load(&mut self, base: &Val, off: i64, ty: Type) -> Val {
        let addr = self.vec_at(base, off);
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: addr, ty });
        Val::Local(d)
    }

    /// Store `val` at `base + off`.
    fn vec_store(&mut self, base: &Val, off: i64, val: Val) {
        let addr = self.vec_at(base, off);
        self.push_instr(Instr::Store { val, ptr: addr });
    }

    fn vec_bin(&mut self, op: BinOp, lhs: Val, rhs: Val, ty: Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: d, op, lhs, rhs, ty });
        Val::Local(d)
    }

    /// Fresh stack slot holding a vector of type `vty`; returns a pointer to it.
    fn vec_alloca(&mut self, vty: Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: d, ty: vty, align: None });
        Val::Local(d)
    }

    /// Element-wise binary op on two vector (`vector_size`) operands. Operates
    /// lane-by-lane over the vector's element type into a fresh result vector.
    /// Comparisons yield an all-ones (`-1`) / all-zeros lane per GCC semantics.
    fn lower_vector_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr, vty: Type) -> Result<Val> {
        let (elem, lanes) = match &vty {
            Type::Array { elem, len } => ((**elem).clone(), *len),
            _ => return Err(CompileError::new("vector binop on non-array type")),
        };
        let signed = matches!(&elem, Type::Int { signed: true, .. });
        // Either an arithmetic/bitwise op, or a comparison predicate.
        let arith = match op {
            BinOpKind::BitOr => Some(BinOp::Or),
            BinOpKind::BitAnd => Some(BinOp::And),
            BinOpKind::BitXor => Some(BinOp::Xor),
            BinOpKind::Add => Some(BinOp::Add),
            BinOpKind::Sub => Some(BinOp::Sub),
            BinOpKind::Mul => Some(BinOp::Mul),
            BinOpKind::Div => Some(if signed { BinOp::SDiv } else { BinOp::UDiv }),
            BinOpKind::Rem => Some(if signed { BinOp::SRem } else { BinOp::URem }),
            BinOpKind::Shl => Some(BinOp::Shl),
            BinOpKind::Shr => Some(if signed { BinOp::AShr } else { BinOp::LShr }),
            _ => None,
        };
        let cmp = match op {
            BinOpKind::Eq => Some(CmpOp::IEq),
            BinOpKind::Ne => Some(CmpOp::INe),
            BinOpKind::Lt => Some(if signed { CmpOp::ISLt } else { CmpOp::IULt }),
            BinOpKind::Le => Some(if signed { CmpOp::ISLe } else { CmpOp::IULe }),
            BinOpKind::Gt => Some(if signed { CmpOp::ISGt } else { CmpOp::IUGt }),
            BinOpKind::Ge => Some(if signed { CmpOp::ISGe } else { CmpOp::IUGe }),
            _ => None,
        };
        if arith.is_none() && cmp.is_none() {
            return Err(CompileError::new(format!("unsupported vector operator {:?}", op)));
        }
        let lp = self.lower_aggregate_ptr(lhs)?;
        let rp = self.lower_aggregate_ptr(rhs)?;
        let rp_out = self.vec_alloca(vty.clone());
        let esz = elem.size_of(self.ptr_size()) as i64;
        for i in 0..lanes {
            let off = i as i64 * esz;
            let x = self.vec_load(&lp, off, elem.clone());
            let y = self.vec_load(&rp, off, elem.clone());
            let v = if let Some(irop) = arith {
                self.vec_bin(irop, x, y, elem.clone())
            } else {
                let c = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: c, op: cmp.unwrap(), lhs: x, rhs: y, ty: elem.clone() });
                let s = self.alloc_val();
                self.push_instr(Instr::Select { dest: s, cond: Val::Local(c), on_true: Constant::int(-1), on_false: Constant::int(0), ty: elem.clone() });
                Val::Local(s)
            };
            self.vec_store(&rp_out, off, v);
        }
        Ok(rp_out)
    }

    /// `__builtin_ia32_pmovmskb128/256`: pack the high bit of each byte into an int.
    fn lower_vec_pmovmskb(&mut self, arg: &Expr, n: usize) -> Result<Val> {
        let vp = self.lower_aggregate_ptr(arg)?;
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut mask = Constant::int(0);
        for i in 0..n {
            let b = self.vec_load(&vp, i as i64, u8t.clone());
            let b32 = self.coerce(b, &i32t)?;
            let sh = self.vec_bin(BinOp::LShr, b32, Constant::int(7), i32t.clone());
            let bit = self.vec_bin(BinOp::And, sh, Constant::int(1), i32t.clone());
            let shifted = self.vec_bin(BinOp::Shl, bit, Constant::int(i as i64), i32t.clone());
            mask = self.vec_bin(BinOp::Or, mask, shifted, i32t.clone());
        }
        Ok(mask)
    }

    /// `__builtin_ia32_pcmpeqb128/256`: per-byte equality → 0xFF/0x00 lanes.
    fn lower_vec_pcmpeqb(&mut self, a: &Expr, b: &Expr, n: usize) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let vty = self.infer_expr_type(a)?;
        let rp = self.vec_alloca(vty);
        let u8t = Type::u8();
        for i in 0..n {
            let x = self.vec_load(&ap, i as i64, u8t.clone());
            let y = self.vec_load(&bp, i as i64, u8t.clone());
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: x, rhs: y, ty: u8t.clone() });
            let val = self.alloc_val();
            self.push_instr(Instr::Select { dest: val, cond: Val::Local(eq), on_true: Constant::int(0xFF), on_false: Constant::int(0), ty: u8t.clone() });
            self.vec_store(&rp, i as i64, Val::Local(val));
        }
        Ok(rp)
    }

    /// `__builtin_ia32_pshufb128`: byte shuffle `r[i] = (b[i]&0x80) ? 0 : a[b[i]&0x0F]`.
    fn lower_vec_pshufb(&mut self, a: &Expr, b: &Expr, n: usize) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let vty = self.infer_expr_type(a)?;
        let rp = self.vec_alloca(vty);
        let u8t = Type::u8();
        let i64t = Type::i64();
        for i in 0..n {
            let idx = self.vec_load(&bp, i as i64, u8t.clone());
            let idx64 = self.coerce(idx, &i64t)?;
            // lo = idx & 0x0F  → offset into `a`
            let lo = self.vec_bin(BinOp::And, idx64.clone(), Constant::int(0x0F), i64t.clone());
            let srcaddr = self.alloc_val();
            self.push_instr(Instr::PtrOffset { dest: srcaddr, base: ap.clone(), offset: lo });
            let src = self.alloc_val();
            self.push_instr(Instr::Load { dest: src, ptr: Val::Local(srcaddr), ty: u8t.clone() });
            // high bit set → zero the lane
            let hib = self.vec_bin(BinOp::And, idx64, Constant::int(0x80), i64t.clone());
            let clr = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: clr, op: CmpOp::INe, lhs: hib, rhs: Constant::int(0), ty: i64t.clone() });
            let val = self.alloc_val();
            self.push_instr(Instr::Select { dest: val, cond: Val::Local(clr), on_true: Constant::int(0), on_false: Val::Local(src), ty: u8t.clone() });
            self.vec_store(&rp, i as i64, Val::Local(val));
        }
        Ok(rp)
    }

    /// `__builtin_ia32_pclmulqdq128`: carry-less multiply of two selected 64-bit
    /// halves → a 128-bit result. `imm` selects which halves (bit0 of a, bit4 of b).
    fn lower_vec_pclmulqdq(&mut self, a: &Expr, b: &Expr, imm: &Expr) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let immv = crate::lower::eval_const_expr(imm, &self.lowerer.enum_consts).unwrap_or(0);
        let u64t = Type::u64();
        let i128t = Type::Int { bits: 128, signed: false };
        let a_off = if immv & 0x01 != 0 { 8 } else { 0 };
        let b_off = if immv & 0x10 != 0 { 8 } else { 0 };
        let x = self.vec_load(&ap, a_off, u64t.clone());
        let y = self.vec_load(&bp, b_off, u64t.clone());
        let xext = self.coerce(x, &i128t)?;
        let mut res = Constant::int(0);
        for j in 0..64 {
            // bit j of y set?  term = bit ? (xext << j) : 0 ; res ^= term
            let yj = self.vec_bin(BinOp::LShr, y.clone(), Constant::int(j), u64t.clone());
            let ybit = self.vec_bin(BinOp::And, yj, Constant::int(1), u64t.clone());
            let set = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: set, op: CmpOp::INe, lhs: ybit, rhs: Constant::int(0), ty: u64t.clone() });
            let shifted = self.vec_bin(BinOp::Shl, xext.clone(), Constant::int(j), i128t.clone());
            let term = self.alloc_val();
            self.push_instr(Instr::Select { dest: term, cond: Val::Local(set), on_true: shifted, on_false: Constant::int(0), ty: i128t.clone() });
            res = self.vec_bin(BinOp::Xor, res, Val::Local(term), i128t.clone());
        }
        let vty = self.infer_expr_type(a).unwrap_or(Type::Array { elem: Box::new(Type::i64()), len: 2 });
        let rp = self.vec_alloca(vty);
        self.vec_store(&rp, 0, res);
        Ok(rp)
    }

    /// Pointer to the first byte of the (lazily-created) AES S-box / inverse
    /// S-box global constant.
    fn aes_sbox_ptr(&mut self, inverse: bool) -> Val {
        let name = if inverse { ".sic_aes_inv_sbox" } else { ".sic_aes_sbox" };
        let gref = if let Some(i) = self.lowerer.module.globals.iter().position(|g| g.name == name) {
            sic_ir::GlobalRef(i as u32)
        } else {
            let bytes = if inverse { AES_INV_SBOX.to_vec() } else { AES_SBOX.to_vec() };
            self.lowerer.module.add_global(sic_ir::Global {
                name: name.to_string(),
                ty: Type::Array { elem: Box::new(Type::u8()), len: 256 },
                init: Some(Constant::Bytes(bytes)),
                linkage: Linkage::Private,
                constant: true,
                thread_local: false,
            })
        };
        let ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: ptr, base: Val::Global(gref), index: Constant::zero(),
            elem_size: 1, result_ty: Type::ptr(Type::u8()),
        });
        Val::Local(ptr)
    }

    /// GF(2^8) `xtime` (multiply by 2 modulo the AES polynomial 0x11B), on a
    /// byte held in an i32.
    fn aes_xtime(&mut self, x: Val) -> Val {
        let i32t = Type::i32();
        let sh = self.vec_bin(BinOp::Shl, x.clone(), Constant::int(1), i32t.clone());
        let hi = self.vec_bin(BinOp::LShr, x, Constant::int(7), i32t.clone());
        let hi1 = self.vec_bin(BinOp::And, hi, Constant::int(1), i32t.clone());
        let red = self.vec_bin(BinOp::Mul, hi1, Constant::int(0x1b), i32t.clone());
        let xored = self.vec_bin(BinOp::Xor, sh, red, i32t.clone());
        self.vec_bin(BinOp::And, xored, Constant::int(0xff), i32t)
    }

    /// GF(2^8) multiply of byte `x` by a compile-time constant `c`.
    fn aes_gmul(&mut self, x: Val, c: u8) -> Val {
        let i32t = Type::i32();
        let mut pow = x;                 // xtime^0(x) = x
        let mut acc: Option<Val> = None;
        let mut cc = c;
        while cc != 0 {
            if cc & 1 != 0 {
                acc = Some(match acc {
                    None => pow.clone(),
                    Some(a) => self.vec_bin(BinOp::Xor, a, pow.clone(), i32t.clone()),
                });
            }
            cc >>= 1;
            if cc != 0 { pow = self.aes_xtime(pow); }
        }
        acc.unwrap_or(Constant::int(0))
    }

    /// SubBytes / InvSubBytes: replace each byte with its S-box image.
    fn aes_sub_bytes(&mut self, s: Vec<Val>, inverse: bool) -> Result<Vec<Val>> {
        let tbl = self.aes_sbox_ptr(inverse);
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut out = Vec::with_capacity(16);
        for b in s {
            let idx = self.coerce(b, &Type::i64())?;
            let addr = self.alloc_val();
            self.push_instr(Instr::PtrOffset { dest: addr, base: tbl.clone(), offset: idx });
            let v = self.alloc_val();
            self.push_instr(Instr::Load { dest: v, ptr: Val::Local(addr), ty: u8t.clone() });
            out.push(self.coerce(Val::Local(v), &i32t)?);
        }
        Ok(out)
    }

    /// MixColumns / InvMixColumns over the four 4-byte columns.
    fn aes_mix_columns(&mut self, s: Vec<Val>, inverse: bool) -> Vec<Val> {
        let m: [[u8; 4]; 4] = if inverse {
            [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
        } else {
            [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        };
        let i32t = Type::i32();
        let mut out: Vec<Val> = vec![Constant::int(0); 16];
        for col in 0..4 {
            let a = [
                s[col * 4].clone(), s[col * 4 + 1].clone(),
                s[col * 4 + 2].clone(), s[col * 4 + 3].clone(),
            ];
            for r in 0..4 {
                let mut acc: Option<Val> = None;
                for j in 0..4 {
                    let term = self.aes_gmul(a[j].clone(), m[r][j]);
                    acc = Some(match acc {
                        None => term,
                        Some(x) => self.vec_bin(BinOp::Xor, x, term, i32t.clone()),
                    });
                }
                out[col * 4 + r] = acc.unwrap();
            }
        }
        out
    }

    /// Emulate an AES-NI round intrinsic over the 16-byte state.
    fn lower_aes(&mut self, state: &Expr, key: Option<&Expr>, mode: AesMode) -> Result<Val> {
        // Byte permutations for (Inv)ShiftRows: out[i] = in[MAP[i]].
        const SHR: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        const INV_SHR: [usize; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

        let sp = self.lower_aggregate_ptr(state)?;
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut s: Vec<Val> = Vec::with_capacity(16);
        for i in 0..16 {
            let b = self.vec_load(&sp, i as i64, u8t.clone());
            s.push(self.coerce(b, &i32t)?);
        }
        match mode {
            AesMode::Enc | AesMode::EncLast => {
                s = SHR.iter().map(|&j| s[j].clone()).collect();
                s = self.aes_sub_bytes(s, false)?;
                if matches!(mode, AesMode::Enc) { s = self.aes_mix_columns(s, false); }
            }
            AesMode::Dec | AesMode::DecLast => {
                s = INV_SHR.iter().map(|&j| s[j].clone()).collect();
                s = self.aes_sub_bytes(s, true)?;
                if matches!(mode, AesMode::Dec) { s = self.aes_mix_columns(s, true); }
            }
            AesMode::Imc => {
                s = self.aes_mix_columns(s, true);
            }
        }
        if let Some(k) = key {
            let kp = self.lower_aggregate_ptr(k)?;
            for i in 0..16 {
                let kb = self.vec_load(&kp, i as i64, u8t.clone());
                let kb32 = self.coerce(kb, &i32t)?;
                s[i] = self.vec_bin(BinOp::Xor, s[i].clone(), kb32, i32t.clone());
            }
        }
        let vty = self.infer_expr_type(state)
            .unwrap_or(Type::Array { elem: Box::new(Type::i64()), len: 2 });
        let rp = self.vec_alloca(vty);
        for i in 0..16 {
            let b = self.coerce(s[i].clone(), &u8t)?;
            self.vec_store(&rp, i as i64, b);
        }
        Ok(rp)
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

            // Multiprecision add/subtract with carry:
            //   T __builtin_{add,sub}c[l|ll](T a, T b, T carryin, T *carryout)
            // Returns `a ± b ± carryin` (wrapped) and stores the outgoing
            // carry/borrow (0 or 1) through `*carryout`.
            let carry_sub = match name.as_str() {
                "__builtin_addc" | "__builtin_addcl" | "__builtin_addcll" => Some(false),
                "__builtin_subc" | "__builtin_subcl" | "__builtin_subcll" => Some(true),
                _ => None,
            };
            if let (Some(is_sub), [a_expr, b_expr, cin_expr, cout_expr]) = (carry_sub, args) {
                return self.lower_carry_builtin(is_sub, a_expr, b_expr, cin_expr, cout_expr);
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
                // void __atomic_load(const T *ptr, T *ret, int memorder): *ret = *ptr.
                "__atomic_load" => {
                    if let [ptr_expr, ret_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ret = self.lower_expr(ret_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        let size = ty.size_of(self.ptr_size());
                        let align = ty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: ret, src: ptr, size, align });
                        return Ok(Constant::zero());
                    }
                }
                // void __atomic_store(T *ptr, T *val, int memorder): *ptr = *val.
                "__atomic_store" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let val = self.lower_expr(val_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        let size = ty.size_of(self.ptr_size());
                        let align = ty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: ptr, src: val, size, align });
                        return Ok(Constant::zero());
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
                // x86 scalar bit-scan intrinsics (from <ia32intrin.h>):
                //   bsr = index of the most-significant set bit = (bits-1) - clz
                //   bsf = index of the least-significant set bit = ctz
                "__builtin_ia32_bsrsi" | "__builtin_ia32_bsrdi"
                | "__builtin_ia32_bsfsi" | "__builtin_ia32_bsfdi" => {
                    if let Some(arg) = args.first() {
                        let bits = if name.ends_with("di") { 64 } else { 32 };
                        if name.contains("bsf") {
                            return self.lower_bit_count(arg, bits, BitOp::Ctz);
                        }
                        // bsr: (bits-1) - clz
                        let clz = self.lower_bit_count(arg, bits, BitOp::Clz)?;
                        let res = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: res, op: BinOp::Sub, lhs: Constant::int((bits - 1) as i64), rhs: clz, ty: Type::i32() });
                        return Ok(Val::Local(res));
                    }
                }
                // x86 SIMD vector intrinsics — scalar-emulated over the byte/lane
                // aggregate that a `vector_size` type lowers to.
                "__builtin_ia32_pmovmskb128" | "__builtin_ia32_pmovmskb256" => {
                    if let [v] = args {
                        let n = if name.ends_with("256") { 32 } else { 16 };
                        return self.lower_vec_pmovmskb(v, n);
                    }
                }
                "__builtin_ia32_pcmpeqb128" | "__builtin_ia32_pcmpeqb256" => {
                    if let [a, b] = args {
                        let n = if name.ends_with("256") { 32 } else { 16 };
                        return self.lower_vec_pcmpeqb(a, b, n);
                    }
                }
                "__builtin_ia32_pshufb128" => {
                    if let [a, b] = args { return self.lower_vec_pshufb(a, b, 16); }
                }
                "__builtin_ia32_pclmulqdq128" => {
                    if let [a, b, imm] = args { return self.lower_vec_pclmulqdq(a, b, imm); }
                }
                // AES-NI round intrinsics (from <wmmintrin.h>, used by QEMU's
                // host/crypto/aes-round.h). Each is a full AES round emulated with
                // the S-box tables + GF(2^8) MixColumns.
                "__builtin_ia32_aesenc128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::Enc); }
                }
                "__builtin_ia32_aesenclast128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::EncLast); }
                }
                "__builtin_ia32_aesdec128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::Dec); }
                }
                "__builtin_ia32_aesdeclast128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::DecLast); }
                }
                "__builtin_ia32_aesimc128" => {
                    if let [s] = args { return self.lower_aes(s, None, AesMode::Imc); }
                }
                // `alloca(n)` / `__builtin_alloca(n)`: sic has no dynamic stack
                // allocation (cranelift stack slots are static-size). Emulate with
                // `malloc` so the code links and yields correct storage. NOTE:
                // this leaks (the block is not freed on function return); adequate
                // for bounded uses, but a proper dynamic stack alloca is a TODO.
                "__builtin_alloca" | "alloca" | "__builtin_alloca_with_align" => {
                    if let [size_expr, ..] = args {
                        let voidp = Type::void_ptr();
                        let fref = match self.lowerer.module.func_ref_by_name("malloc") {
                            Some(f) => f,
                            None => self.lowerer.module.add_extern(ExternFunc {
                                name: "malloc".to_string(),
                                sig: FunctionType { ret: voidp.clone(), params: vec![Type::u64()], variadic: false },
                            }),
                        };
                        let sz = self.lower_expr(size_expr)?;
                        let sz = self.coerce(sz, &Type::u64())?;
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![sz], ret_ty: voidp.clone() });
                        self.val_types.insert(dest.0, voidp);
                        return Ok(Val::Local(dest));
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
                // Compare-and-swap. GCC exposes both the type-generic form and the
                // width-suffixed `_1/_2/_4/_8/_16` forms (QEMU's atomic128 host
                // path uses `_16` for 128-bit CAS). `lower_atomic_cas` is width-
                // agnostic (it works off the pointee type, incl. i128).
                n if sync_builtin_base(n) == "__sync_val_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, false); }
                }
                n if sync_builtin_base(n) == "__sync_bool_compare_and_swap" => {
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
                // sic does no object-size analysis; return the "size unknown"
                // sentinel so any _FORTIFY / size check falls through to the plain
                // path: type 0/1 -> (size_t)-1, type 2/3 -> 0.
                "__builtin_object_size" | "__builtin_dynamic_object_size" => {
                    let ty = args.get(1)
                        .and_then(|e| crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok())
                        .unwrap_or(0);
                    let v: u64 = if ty & 2 != 0 { 0 } else { u64::MAX };
                    return self.coerce(Constant::uint(v), &Type::Int { bits: 64, signed: false });
                }
                // `__builtin_return_address(0)` = the current function's return
                // address. Critical for QEMU's GETPC(): a faulting helper uses it
                // to restart the TB at the right guest PC. Level 0 maps to
                // Cranelift's get_return_address; deeper levels (stack walking) and
                // frame/CFA queries fall back to null (diagnostics degrade).
                "__builtin_return_address" => {
                    let level0 = args.first()
                        .and_then(|e| crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok())
                        .map(|v| v == 0)
                        .unwrap_or(true);
                    if level0 {
                        let d = self.alloc_val();
                        self.push_instr(Instr::ReturnAddress { dest: d });
                        self.val_types.insert(d.0, Type::void_ptr());
                        return Ok(Val::Local(d));
                    }
                    return Ok(Constant::zero());
                }
                "__builtin_frame_address" | "__builtin_dwarf_cfa"
                    => return Ok(Constant::zero()),
                // These identity/no-op address adjusters return their argument.
                "__builtin_extract_return_addr" | "__builtin_frob_return_addr" => {
                    if let Some(e) = args.first() { return self.lower_expr(e); }
                    return Ok(Constant::zero());
                }
                // Floating-point classification / comparison builtins.
                "__builtin_isnan" | "__builtin_isinf" | "__builtin_isinf_sign"
                | "__builtin_isfinite" | "__builtin_isnormal" => {
                    if let Some(arg) = args.first() {
                        return self.lower_fp_classify(name, arg);
                    }
                }
                "__builtin_isgreater" | "__builtin_isgreaterequal" | "__builtin_isless"
                | "__builtin_islessequal" | "__builtin_islessgreater" | "__builtin_isunordered" => {
                    if let [a, b, ..] = args {
                        return self.lower_fp_compare(name, a, b);
                    }
                }
                // __builtin_fpclassify(NAN, INF, NORMAL, SUBNORMAL, ZERO, x):
                // pick the category constant matching x. Subnormals are treated
                // as normal (sic doesn't distinguish the boundary).
                "__builtin_fpclassify" => {
                    if let [nan_v, inf_v, normal_v, _subnormal_v, zero_v, x] = args {
                        let is_nan = self.lower_fp_classify("__builtin_isnan", x)?;
                        let is_inf = self.lower_fp_classify("__builtin_isinf", x)?;
                        let xv = self.lower_expr(x)?;
                        let fty = match self.val_type(&xv) { t if t.is_float() => t, _ => Type::Float64 };
                        let xv = self.coerce(xv, &fty)?;
                        let is_zero = self.alloc_val();
                        self.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::FOEq, lhs: xv, rhs: Val::Const(Constant::Float(0.0)), ty: fty });
                        // result = isnan ? NAN : isinf ? INF : iszero ? ZERO : NORMAL
                        let nan_v = self.lower_expr(nan_v)?;
                        let inf_v = self.lower_expr(inf_v)?;
                        let normal_v = self.lower_expr(normal_v)?;
                        let zero_v = self.lower_expr(zero_v)?;
                        let ity = Type::i32();
                        let (nan_v, inf_v, normal_v, zero_v) = (
                            self.coerce(nan_v, &ity)?, self.coerce(inf_v, &ity)?,
                            self.coerce(normal_v, &ity)?, self.coerce(zero_v, &ity)?);
                        let is_nan = self.coerce(is_nan, &Type::Bool)?;
                        let is_inf = self.coerce(is_inf, &Type::Bool)?;
                        let sel_zn = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel_zn, cond: Val::Local(is_zero), on_true: zero_v, on_false: normal_v, ty: ity.clone() });
                        let sel_inf = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel_inf, cond: is_inf, on_true: inf_v, on_false: Val::Local(sel_zn), ty: ity.clone() });
                        let sel = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel, cond: is_nan, on_true: nan_v, on_false: Val::Local(sel_inf), ty: ity });
                        return Ok(Val::Local(sel));
                    }
                }
                // Infinity / huge-value constants.
                "__builtin_inf" | "__builtin_inff" | "__builtin_infl"
                | "__builtin_huge_val" | "__builtin_huge_valf" | "__builtin_huge_vall" =>
                    return Ok(Val::Const(Constant::Float(f64::INFINITY))),
                "__builtin_nan" | "__builtin_nanf" | "__builtin_nanl" =>
                    return Ok(Val::Const(Constant::Float(f64::NAN))),
                // signbit(x): nonzero iff the sign bit is set. Type-pun the float
                // through a stack slot and test the top bit (correct for -0.0).
                "__builtin_signbit" | "__builtin_signbitf" | "__builtin_signbitl" => {
                    if let Some(arg) = args.first() {
                        let v = self.lower_expr(arg)?;
                        let fty = self.val_type(&v);
                        let (fty, ity, shift) = match fty {
                            Type::Float32 => (Type::Float32, Type::Int { bits: 32, signed: false }, 31),
                            _ => (Type::Float64, Type::Int { bits: 64, signed: false }, 63),
                        };
                        let v = self.coerce(v, &fty)?;
                        let slot = self.alloc_val();
                        self.push_instr(Instr::Alloca { dest: slot, ty: ity.clone(), align: None });
                        self.push_instr(Instr::Store { val: v, ptr: Val::Local(slot) });
                        let iv = self.alloc_val();
                        self.push_instr(Instr::Load { dest: iv, ptr: Val::Local(slot), ty: ity.clone() });
                        let sh = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: sh, op: BinOp::LShr, lhs: Val::Local(iv), rhs: Constant::int(shift), ty: ity.clone() });
                        let masked = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: masked, op: BinOp::And, lhs: Val::Local(sh), rhs: Constant::int(1), ty: ity });
                        return self.coerce(Val::Local(masked), &Type::i32());
                    }
                }
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
                            // A function-typed parameter does not decay to a
                            // pointer type in sic's IR; accept it directly.
                            Type::Function(ft) => *ft.clone(),
                            _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                        };
                        let ret_ty = func_ty.ret.clone();
                        if super::ret_is_sret(&ret_ty, self.ptr_size()) {
                            return self.lower_indirect_sret(fptr, func_ty, arg_vals);
                        }
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
                        // Many `__builtin_<fn>` calls (memcpy, memmove, strlen, …)
                        // are just the libc function; retry resolution with the
                        // prefix stripped.
                        if let Some(libc) = name.strip_prefix("__builtin_") {
                            if let Some(LookupResult::Func(fr)) = self.lookup(libc) {
                                fr
                            } else {
                                return Err(CompileError::at(
                                    format!("unknown function '{}'", name),
                                    sp.file.clone(), sp.line, sp.col,
                                ));
                            }
                        } else {
                            return Err(CompileError::at(
                                format!("unknown function '{}'", name),
                                sp.file.clone(), sp.line, sp.col,
                            ));
                        }
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
                    Type::Function(ft) => *ft.clone(),
                    _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                };
                let ret_ty = func_ty.ret.clone();
                if super::ret_is_sret(&ret_ty, self.ptr_size()) {
                    return self.lower_indirect_sret(fptr, func_ty, arg_vals);
                }
                // Coerce fixed args to their param types and apply the default
                // argument promotions to any `...` args (same as the direct path).
                for (i, pval) in arg_vals.iter_mut().enumerate() {
                    if let Some(pty) = func_ty.params.get(i) {
                        if matches!(pty, Type::Struct(_) | Type::Union(_)) { continue; }
                        let c = self.coerce(pval.clone(), pty)?;
                        *pval = c;
                    } else if func_ty.variadic {
                        let p = self.promote_vararg(pval.clone())?;
                        *pval = p;
                    }
                }
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

        // Aggregate return (sret ABI): allocate the result slot, pass its pointer
        // as the hidden first argument, and yield that pointer as the call value.
        if super::ret_is_sret(&ret_ty, self.ptr_size()) {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: ret_ty.clone(), align: None });
            let slot = Val::Local(slot);
            let param_tys: Vec<Type> = self.lowerer.module.func_sig(fref).params.clone();
            // Coerce user args against params[1..] (params[0] is the sret ptr).
            for (i, pval) in arg_vals.iter_mut().enumerate() {
                if let Some(pty) = param_tys.get(i + 1) {
                    if matches!(pty, Type::Struct(_) | Type::Union(_)) { continue; }
                    let coerced = self.coerce(pval.clone(), pty)?;
                    *pval = coerced;
                }
            }
            let mut args = Vec::with_capacity(arg_vals.len() + 1);
            args.push(slot.clone());
            args.extend(arg_vals);
            self.push_instr(Instr::Call { dest: None, func: fref, args, ret_ty });
            return Ok(slot);
        }

        // Coerce arguments to expected param types
        let param_tys: Vec<Type> = self.lowerer.module.func_sig(fref).params.clone();
        let is_variadic = self.lowerer.module.func_sig(fref).variadic;
        for (i, pval) in arg_vals.iter_mut().enumerate() {
            if let Some(pty) = param_tys.get(i) {
                // Struct/union args are already lowered to a pointer to the value
                // (by-value ABI); leave them as-is.
                if matches!(pty, Type::Struct(_) | Type::Union(_)) { continue; }
                let coerced = self.coerce(pval.clone(), pty)?;
                *pval = coerced;
            } else if is_variadic {
                // Arguments in the `...` part undergo the default argument
                // promotions (char/short→int, float→double). Without this a
                // small integer passed on the stack leaves its slot's high bits
                // uninitialized — libc printf's `%02x` of a `uint8_t` MAC byte
                // then read garbage (QEMU's default NIC MAC came out malformed).
                let p = self.promote_vararg(pval.clone())?;
                *pval = p;
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

    /// Lower an indirect call to an aggregate-returning function (sret ABI):
    /// allocate the result slot, pass its pointer as the hidden first argument,
    /// and yield that pointer. `func_ty.params[0]` is the sret pointer parameter.
    fn lower_indirect_sret(&mut self, fptr: Val, func_ty: sic_ir::FunctionType, arg_vals: Vec<Val>) -> Result<Val> {
        let ret_ty = func_ty.ret.clone();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: ret_ty.clone(), align: None });
        let slot = Val::Local(slot);
        // Coerce user args against params[1..] (params[0] is the sret pointer).
        let mut coerced = Vec::with_capacity(arg_vals.len() + 1);
        coerced.push(slot.clone());
        for (i, a) in arg_vals.into_iter().enumerate() {
            match func_ty.params.get(i + 1) {
                Some(pty) if !matches!(pty, Type::Struct(_) | Type::Union(_)) => {
                    coerced.push(self.coerce(a, pty)?);
                }
                _ => coerced.push(a),
            }
        }
        self.push_instr(Instr::CallIndirect {
            dest: None,
            fptr,
            args: coerced,
            ret_ty,
            func_ty: Box::new(func_ty),
        });
        Ok(slot)
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
                let div = if signed { BinOp::SDiv } else { BinOp::UDiv };
                // 128-bit divide needs a libcall (see emit_div_rem_libcall).
                let quot_val = if let Some(v) = self.emit_div_rem_libcall(div, result.clone(), a.clone(), &ty) {
                    v
                } else {
                    let quot = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: quot, op: div, lhs: result.clone(), rhs: a.clone(), ty: ty.clone() });
                    Val::Local(quot)
                };
                let mism = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: mism, op: CmpOp::INe, lhs: quot_val, rhs: b.clone(), ty: ty.clone() });
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

    /// Lower `__builtin_{add,sub}c[l|ll](a, b, carryin, *carryout)`: wide
    /// add/subtract with carry. Returns the wrapped result and stores the
    /// outgoing carry (0/1) through `*carryout`.
    fn lower_carry_builtin(
        &mut self, is_sub: bool,
        a_expr: &Expr, b_expr: &Expr, cin_expr: &Expr, cout_expr: &Expr,
    ) -> Result<Val> {
        let a = self.lower_expr(a_expr)?;
        let b = self.lower_expr(b_expr)?;
        let cin = self.lower_expr(cin_expr)?;
        let cout_ptr = self.lower_expr(cout_expr)?;

        let ty = match self.val_type(&cout_ptr) {
            Type::Pointer(inner) => *inner,
            _ => self.val_type(&a),
        };
        let a = self.coerce(a, &ty)?;
        let b = self.coerce(b, &ty)?;
        let cin = self.coerce(cin, &ty)?;

        let op = if is_sub { BinOp::Sub } else { BinOp::Add };
        // First combine a and b, tracking carry/borrow, then fold in carryin.
        let s1 = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: s1, op, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        let s1 = Val::Local(s1);
        // carry1: add → s1 < a; sub (borrow) → a < b.
        let c1 = self.alloc_val();
        if is_sub {
            self.push_instr(Instr::Cmp { dest: c1, op: CmpOp::IULt, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        } else {
            self.push_instr(Instr::Cmp { dest: c1, op: CmpOp::IULt, lhs: s1.clone(), rhs: a.clone(), ty: ty.clone() });
        }
        let s2 = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: s2, op, lhs: s1.clone(), rhs: cin.clone(), ty: ty.clone() });
        let s2 = Val::Local(s2);
        // carry2: add → s2 < s1; sub (borrow) → s1 < cin.
        let c2 = self.alloc_val();
        if is_sub {
            self.push_instr(Instr::Cmp { dest: c2, op: CmpOp::IULt, lhs: s1.clone(), rhs: cin.clone(), ty: ty.clone() });
        } else {
            self.push_instr(Instr::Cmp { dest: c2, op: CmpOp::IULt, lhs: s2.clone(), rhs: s1.clone(), ty: ty.clone() });
        }
        // carryout = (c1 | c2), extended to the result type.
        let c1i = self.coerce(Val::Local(c1), &ty)?;
        let c2i = self.coerce(Val::Local(c2), &ty)?;
        let cout = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: cout, op: BinOp::Or, lhs: c1i, rhs: c2i, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(cout), ptr: cout_ptr });

        Ok(s2)
    }

    // ─── LValue lowering ─────────────────────────────────────────────────────

    /// Extract a pointer's pointee type, resolving an opaque pointee aggregate
    /// to its full definition. Pointees are stored opaque (see `lower_ast_type`);
    /// dereferencing needs the real layout for loads/stores/copies.
    /// Apply the C default argument promotions to a value passed in the `...`
    /// part of a variadic call: integer types narrower than `int` widen to `int`
    /// (preserving value per the source's signedness), and `float` widens to
    /// `double`. Anything already `int`-width or wider is unchanged.
    fn promote_vararg(&mut self, v: Val) -> Result<Val> {
        match self.val_type(&v) {
            Type::Bool => self.coerce(v, &Type::i32()),
            Type::Int { bits, .. } if bits < 32 => self.coerce(v, &Type::i32()),
            Type::Float32 => self.coerce(v, &Type::Float64),
            _ => Ok(v),
        }
    }

    /// Materialize a `size_t`-typed constant (the result type of `sizeof`,
    /// `_Alignof`, `offsetof`). A bare integer constant defaults to i32 when its
    /// value fits, so `sizeof(long) * n` would compute at 32 bits; forcing the
    /// pointer-width unsigned type keeps such products 64-bit (QEMU's ROUND_UP
    /// masks a 64-bit pointer with `-(sizeof(...)*n)` — a 32-bit result truncated
    /// the TB code buffer address and faulted during code generation).
    fn size_t_val(&mut self, v: u64) -> Val {
        let dest = self.alloc_val();
        let ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        self.push_instr(Instr::Cast { dest, op: CastOp::ZExt, val: Constant::uint(v), to_ty: ty });
        Val::Local(dest)
    }

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
                // `*x`: if `x` is an array it decays to a pointer to its element, so
                // the deref yields the element (`*arr` == `arr[0]`); if `x` is a
                // pointer-to-array it yields the whole array. The C type of `x`
                // disambiguates (both are `Pointer(Array)` in the IR).
                let inner_ty = match self.infer_expr_type(inner) {
                    Ok(Type::Array { elem, .. }) => {
                        super::types::resolve_aggregate(&elem, &self.lowerer.struct_types)
                    }
                    Ok(Type::Pointer(t)) => {
                        super::types::resolve_aggregate(&t, &self.lowerer.struct_types)
                    }
                    _ => self.pointee_of(&ptr_ty),
                };
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
        // `Pointer(Array[T;N])` is ambiguous in the IR: it is both the address of
        // an array *variable* `T v[N]` (where `v[i]` is a `T`) and the value of a
        // pointer-to-array `T (*e)[N]` (where `e[i]` is the whole `T[N]`). The C
        // type of `base` disambiguates: an array-typed base indexes to its element,
        // a pointer-typed base dereferences one level.
        let logical = self.infer_expr_type(base).ok();
        let elem_ty = match &base_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { .. } if matches!(logical, Some(Type::Pointer(_))) => {
                    // pointer-to-array: one index yields the whole array element
                    super::types::resolve_aggregate(t, &self.lowerer.struct_types)
                }
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
        // base is normally a struct lvalue; but it can also be a struct *rvalue*
        // (e.g. `f().field` where `f` returns a struct by value), whose address is
        // the materialized temporary.
        let lv = match self.lower_lvalue(base) {
            Ok(lv) => lv,
            Err(_) => {
                let ptr = self.lower_aggregate_ptr(base)?;
                let ty = self.infer_expr_type(base)?;
                LValue::plain(ptr, ty)
            }
        };
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
                    if generic_type_eq(&decay(self.lower_type(qt)?), &ctrl_ty) {
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
    /// Lower `offsetof(T, ...designators...)` to a `size_t` value. A constant
    /// index folds into the constant offset; a NON-constant array index (a GCC
    /// extension, e.g. `offsetof(CPU, segs[i].base)`) makes offsetof a runtime
    /// value `const_offset + index * elem_size`. QEMU registers its per-segment
    /// TCG globals in a loop with exactly this form; treating the index as 0
    /// pointed every segment base at segs[0], breaking CS-relative addressing.
    fn lower_offsetof(&mut self, ty: &crate::ast::QualType, designators: &[crate::ast::OffsetDesignator]) -> Result<Val> {
        use crate::ast::OffsetDesignator;
        let mut cur = self.lower_type(ty)?;
        let mut const_off: u64 = 0;
        let mut runtime: Option<Val> = None; // accumulated runtime byte offset
        for d in designators {
            match d {
                OffsetDesignator::Field(name) => {
                    let resolved = super::types::resolve_aggregate(&cur, &self.lowerer.struct_types);
                    let (off, fty, _) = resolve_field_access(&resolved, name, self.ptr_size(), &self.lowerer.struct_types)
                        .ok_or_else(|| CompileError::new(format!("no field '{}' in offsetof", name)))?;
                    const_off += off;
                    cur = fty;
                }
                OffsetDesignator::Index(e) => {
                    let elem = match &cur {
                        Type::Array { elem, .. } => *elem.clone(),
                        Type::Pointer(t) => *t.clone(),
                        other => other.clone(),
                    };
                    let esz = elem.size_of(self.ptr_size());
                    if let Ok(i) = super::eval_const_expr(e, &self.lowerer.enum_consts) {
                        const_off += (i as u64).wrapping_mul(esz);
                    } else {
                        // Runtime index: emit `index * elem_size` and add it.
                        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
                        let iv = self.lower_expr(e)?;
                        let iv = self.coerce(iv, &usize_ty)?;
                        let term = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: term, op: BinOp::Mul, lhs: iv, rhs: Constant::uint(esz), ty: usize_ty.clone() });
                        runtime = Some(match runtime {
                            None => Val::Local(term),
                            Some(acc) => {
                                let s = self.alloc_val();
                                self.push_instr(Instr::BinOp { dest: s, op: BinOp::Add, lhs: acc, rhs: Val::Local(term), ty: usize_ty.clone() });
                                Val::Local(s)
                            }
                        });
                    }
                    cur = elem;
                }
            }
        }
        match runtime {
            None => self.coerce(Constant::uint(const_off), &Type::u64()),
            Some(rt) => {
                let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
                let dest = self.alloc_val();
                self.push_instr(Instr::BinOp { dest, op: BinOp::Add, lhs: rt, rhs: Constant::uint(const_off), ty: usize_ty });
                Ok(Val::Local(dest))
            }
        }
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
                    // An array decays to a pointer to its element, so `*arr` is
                    // the element type — `sizeof(*arr)` must be the element size,
                    // not the default i32 (QEMU's `qsort(cmds, .., sizeof(*cmds), ..)`
                    // over a `static HMPCommand cmds[]` gave size 4 → memory
                    // corruption during the sort).
                    Type::Array { elem, .. } => super::types::resolve_aggregate(&elem, &self.lowerer.struct_types),
                    _ => Type::i32(),
                })
            }
            ExprKind::Field { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                // sic native-string computed accessors: `.ptr` is a `char*`,
                // `.length` is a `usize` (sic.md §"Built-in string").
                if self.is_sic() && super::types::is_sic_string(&base_ty) {
                    if name == "ptr" { return Ok(Type::char_ptr()); }
                    if name == "length" { return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false }); }
                }
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
            ExprKind::Assign { lhs, .. } => self.infer_expr_type(lhs),
            // A substring slice is itself a `string` (sic.md §"Built-in string").
            ExprKind::Slice { .. } => Ok(super::types::sic_string_type(self.ptr_size())),
            // `new T` / `new T(n)` yields `T*`.
            ExprKind::New { ty, .. } => Ok(Type::Pointer(Box::new(self.lower_type(ty)?))),
            ExprKind::Comma(_, rhs) => self.infer_expr_type(rhs),
            // GCC statement expression `({ ...; expr; })` has the type of its last
            // statement when that is an expression statement, else void. Needed so
            // `typeof(({...; p;}))` (QEMU's nested qobject_ref) keeps `p`'s type.
            // A trailing bare identifier is usually a temporary declared inside the
            // block (`typeof(x) _o = x; _o;`), invisible to the outer scope, so
            // resolve such declarators here.
            ExprKind::StmtExpr(stmts) => {
                match stmts.last() {
                    Some(ast::Stmt::Expr(e, _)) => {
                        if let ExprKind::Ident(name) = &e.kind {
                            for stmt in stmts {
                                if let ast::Stmt::Decl(ast::Decl::Var { declarators, .. }) = stmt {
                                    if let Some(d) = declarators.iter().find(|d| &d.name == name) {
                                        return self.lower_type(&d.ty);
                                    }
                                }
                            }
                        }
                        self.infer_expr_type(e)
                    }
                    _ => Ok(Type::Void),
                }
            }
            ExprKind::BinOp { op, lhs, rhs } => {
                use BinOpKind::*;
                match op {
                    // Relational/logical operators yield int.
                    Eq | Ne | Lt | Le | Gt | Ge | LogAnd | LogOr => Ok(Type::i32()),
                    // sic string concatenation yields a `string`.
                    Add if self.is_sic()
                        && (self.is_string_operand(lhs) || self.is_string_operand(rhs)) =>
                        Ok(super::types::sic_string_type(self.ptr_size())),
                    // Arithmetic: pointer/array ± integer keeps the pointer type
                    // (pointer arithmetic; arrays decay to pointer-to-element).
                    // `ptr - ptr` is ptrdiff_t. Otherwise pick the "richer" operand
                    // type so float/wider integer results survive.
                    _ => {
                        let lt = self.infer_expr_type(lhs).unwrap_or_else(|_| Type::i32());
                        let rt = self.infer_expr_type(rhs).unwrap_or_else(|_| Type::i32());
                        let decay = |t: Type| match t {
                            Type::Array { elem, .. } => Type::Pointer(elem),
                            other => other,
                        };
                        let lt = decay(lt);
                        let rt = decay(rt);
                        Ok(match (&lt, &rt) {
                            (Type::Pointer(_), Type::Pointer(_)) if *op == Sub => Type::i64(),
                            (Type::Pointer(_), _) => lt,
                            (_, Type::Pointer(_)) => rt,
                            _ if lt.is_float() => lt,
                            _ if rt.is_float() => rt,
                            _ if rt.size_of(self.ptr_size()) > lt.size_of(self.ptr_size()) => rt,
                            _ => lt,
                        })
                    }
                }
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

/// Type equality for `_Generic` association matching. Aggregate pointees are
/// stored opaque in some contexts and fully resolved in others, so two
/// otherwise-identical `struct Foo *` can differ by field population; compare
/// named aggregates by name instead.
fn generic_type_eq(a: &Type, b: &Type) -> bool {
    match (a, b) {
        (Type::Pointer(x), Type::Pointer(y)) => generic_type_eq(x, y),
        (Type::Struct(s1), Type::Struct(s2)) => match (&s1.name, &s2.name) {
            (Some(n1), Some(n2)) => n1 == n2,
            _ => a == b,
        },
        (Type::Union(u1), Type::Union(u2)) => match (&u1.name, &u2.name) {
            (Some(n1), Some(n2)) => n1 == n2,
            _ => a == b,
        },
        _ => a == b,
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
/// Map a `__sync_*`/`__atomic_*` builtin name to its width-generic base by
/// stripping a trailing `_1/_2/_4/_8/_16` size suffix. GCC exposes both the
/// type-generic form and these sized forms (QEMU's 128-bit host atomics use the
/// `_16` variant); both share one handler. Names without such a suffix (or that
/// aren't atomics) are returned unchanged.
fn sync_builtin_base(name: &str) -> &str {
    for w in ["_16", "_8", "_4", "_2", "_1"] {
        if let Some(base) = name.strip_suffix(w) {
            if base.starts_with("__sync_") || base.starts_with("__atomic_") {
                return base;
            }
        }
    }
    name
}

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

