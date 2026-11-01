//! One function's IR as LLVM instructions.

use crate::{Cx, R};
use inkwell::attributes::{Attribute, AttributeLoc};
use inkwell::basic_block::BasicBlock;
use inkwell::intrinsics::Intrinsic;
use inkwell::types::BasicTypeEnum;
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue, BasicValueEnum, CallSiteValue, FunctionValue, IntValue, PointerValue,
};
use inkwell::{AtomicOrdering, AtomicRMWBinOp, FloatPredicate, IntPredicate};
use sic_ir::abi::{classify_param, classify_struct_union, AggClass, Chunk, ParamPass, RegClass};
use sic_ir::analysis::{store_type, value_types, PARAM_VAL_BASE};
use sic_ir::fast_hash::HashMap;
use sic_ir::{AtomicOp, BinOp, CastOp, CmpOp, Constant, Function, FunctionType, Instr, Terminator, Type, UnOp, Val};

const SEQ: AtomicOrdering = AtomicOrdering::SequentiallyConsistent;

pub(crate) struct Fx<'ctx, 'a, 'c> {
    pub cx: &'c Cx<'ctx, 'a>,
    f: &'a Function,
    lf: FunctionValue<'ctx>,
    entry: BasicBlock<'ctx>,
    blocks: HashMap<u32, BasicBlock<'ctx>>,
    vals: HashMap<u32, BasicValueEnum<'ctx>>,
    types: HashMap<u32, Type>,
    /// The type of each scalar stack slot: a store is at that width, whatever the
    /// value's (`store 0` in an `i64` local is 8 bytes).
    slots: HashMap<u32, BasicTypeEnum<'ctx>>,
}

/// Floating point and vectors need SSE here: as with GCC, it is an error without.
fn check_no_float(f: &Function, types: &HashMap<u32, Type>) -> R<()> {
    let bad = |t: &Type| matches!(t, Type::Float32 | Type::Float64 | Type::Float80) || t.simd128().is_some();
    if types.values().any(bad) || bad(&f.sig.ret) {
        return Err(format!("function '{}' uses floating-point or vector values, but SSE is disabled (-mno-sse)", f.name).into());
    }
    Ok(())
}

pub fn emit<'ctx>(cx: &Cx<'ctx, '_>, f: &Function, lf: FunctionValue<'ctx>) -> R<()> {
    if f.blocks.is_empty() { return Ok(()); }
    // A block of its own for the stack objects and parameters: the IR may branch
    // to its first block, which LLVM's entry block cannot be.
    let entry = cx.ctx.append_basic_block(lf, "entry");
    let mut blocks = HashMap::default();
    for b in &f.blocks { blocks.insert(b.id.0, cx.ctx.append_basic_block(lf, "")); }
    let mut fx = Fx { cx, f, lf, entry, blocks, vals: HashMap::default(), types: value_types(f), slots: HashMap::default() };
    if !cx.opts.sse { check_no_float(f, &fx.types)?; }
    cx.builder.position_at_end(entry);
    for (dest, ty, align) in f.allocas() {
        // At least a word: the IR stores a whole pointer in a slot of function
        // type, whose size is 1.
        let size = ty.size_of(cx.opts.ptr_size).max(8) as u32;
        let al = (ty.align_of(cx.opts.ptr_size).max(1) as u32).max(align.unwrap_or(0)).next_power_of_two();
        let p = fx.slot(size, al)?;
        fx.vals.insert(dest.0, p.into());
        if !matches!(ty, Type::Array { .. } | Type::Struct(_) | Type::Union(_) | Type::Float80) {
            fx.slots.insert(dest.0, cx.value_type(ty));
        }
    }
    fx.bind_params()?;
    for b in &f.blocks {
        cx.builder.position_at_end(fx.blocks[&b.id.0]);
        for i in &b.instrs { fx.instr(i)?; }
        fx.terminator(&b.terminator)?;
    }
    cx.builder.position_at_end(entry);
    cx.builder.build_unconditional_branch(fx.blocks[&f.blocks[0].id.0])?;
    Ok(())
}

impl<'ctx> Fx<'ctx, '_, '_> {
    pub fn b(&self) -> &inkwell::builder::Builder<'ctx> { self.cx.builder }

    /// A stack object, in the entry block wherever it is asked for.
    fn slot(&self, size: u32, align: u32) -> R<PointerValue<'ctx>> {
        let here = self.b().get_insert_block();
        self.b().position_at_end(self.entry);
        let p = self.b().build_alloca(self.cx.ctx.i8_type().array_type(size), "")?;
        p.as_instruction_value().ok_or("alloca")?.set_alignment(align).map_err(|e| e.to_string())?;
        if let Some(bb) = here { self.b().position_at_end(bb); }
        Ok(p)
    }

    fn bind_params(&mut self) -> R<()> {
        let ptr_size = self.cx.opts.ptr_size;
        let mut next = 0u32;
        for (i, p) in self.f.params.iter().enumerate() {
            let id = PARAM_VAL_BASE + i as u32;
            match classify_param(&p.ty, ptr_size) {
                ParamPass::Scalar | ParamPass::ByValStack(..) => {
                    if let Some(v) = self.lf.get_nth_param(next) { self.vals.insert(id, v); }
                    next += 1;
                }
                ParamPass::X87 => {
                    if let Some(v) = self.lf.get_nth_param(next) {
                        let d = self.b().build_float_trunc(v.into_float_value(), self.cx.ctx.f64_type(), "")?;
                        self.vals.insert(id, d.into());
                    }
                    next += 1;
                }
                ParamPass::Direct(chunks) => {
                    let size = p.ty.size_of(ptr_size) as u32;
                    let addr = self.slot(size, p.ty.align_of(ptr_size).max(1) as u32)?;
                    for c in &chunks {
                        if let Some(v) = self.lf.get_nth_param(next) { self.store_chunk(v, addr, c)?; }
                        next += 1;
                    }
                    self.vals.insert(id, addr.into());
                }
            }
        }
        Ok(())
    }

    fn gep(&self, base: PointerValue<'ctx>, off: IntValue<'ctx>) -> R<PointerValue<'ctx>> {
        Ok(unsafe { self.b().build_gep(self.cx.ctx.i8_type(), base, &[off], "") }?)
    }

    fn gep_const(&self, base: PointerValue<'ctx>, off: u64) -> R<PointerValue<'ctx>> {
        if off == 0 { return Ok(base); }
        self.gep(base, self.cx.ctx.i64_type().const_int(off, true))
    }

    /// Accesses carry no alignment promise: the IR does not say.
    fn load(&self, ty: BasicTypeEnum<'ctx>, p: PointerValue<'ctx>) -> R<BasicValueEnum<'ctx>> {
        let v = self.b().build_load(ty, p, "")?;
        v.as_instruction_value().ok_or("load")?.set_alignment(1).map_err(|e| e.to_string())?;
        Ok(v)
    }

    fn store(&self, p: PointerValue<'ctx>, v: BasicValueEnum<'ctx>) -> R<()> {
        self.b().build_store(p, v)?.set_alignment(1).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Exactly `chunk.bytes` bytes of a register-sized value.
    fn store_chunk(&self, v: BasicValueEnum<'ctx>, base: PointerValue<'ctx>, c: &Chunk) -> R<()> {
        let p = self.gep_const(base, c.offset as u64)?;
        match c.class {
            RegClass::Sse => self.store(p, v),
            RegClass::Int if c.bytes == 8 => self.store(p, v),
            RegClass::Int => {
                let t = self.cx.int_type(c.bytes * 8);
                let n = self.b().build_int_truncate(v.into_int_value(), t, "")?;
                self.store(p, n.into())
            }
        }
    }

    fn load_chunk(&self, base: PointerValue<'ctx>, c: &Chunk) -> R<BasicValueEnum<'ctx>> {
        let p = self.gep_const(base, c.offset as u64)?;
        match c.class {
            RegClass::Sse => self.load(self.cx.chunk_type(c), p),
            RegClass::Int if c.bytes == 8 => self.load(self.cx.ctx.i64_type().into(), p),
            RegClass::Int => {
                let t = self.cx.int_type(c.bytes * 8);
                let v = self.load(t.into(), p)?.into_int_value();
                Ok(self.b().build_int_z_extend(v, self.cx.ctx.i64_type(), "")?.into())
            }
        }
    }

    fn zero(&self, t: BasicTypeEnum<'ctx>) -> BasicValueEnum<'ctx> { t.const_zero() }

    /// A value, a constant taking the type it is wanted at.
    pub fn val(&self, v: &Val, hint: BasicTypeEnum<'ctx>) -> BasicValueEnum<'ctx> {
        match v {
            Val::Local(id) => self.vals.get(&id.0).copied().unwrap_or_else(|| self.zero(hint)),
            Val::Global(g) => match self.cx.globals.get(&g.0) {
                Some(lg) => lg.as_pointer_value().into(),
                None => self.zero(self.cx.ptr()),
            },
            Val::Func(f) => match self.cx.funcs.get(&f.0) {
                Some(lf) => lf.as_global_value().as_pointer_value().into(),
                None => self.zero(self.cx.ptr()),
            },
            Val::Const(c) => self.constant(c, hint),
        }
    }

    fn constant(&self, c: &Constant, hint: BasicTypeEnum<'ctx>) -> BasicValueEnum<'ctx> {
        let i64t = self.cx.ctx.i64_type();
        match c {
            Constant::Int(v) => match hint {
                BasicTypeEnum::IntType(t) => t.const_int(*v as u64, true).into(),
                BasicTypeEnum::FloatType(t) => t.const_float(*v as f64).into(),
                BasicTypeEnum::PointerType(t) => i64t.const_int(*v as u64, true).const_to_pointer(t).into(),
                _ => self.zero(hint),
            },
            Constant::UInt(v) => match hint {
                BasicTypeEnum::IntType(t) => t.const_int(*v, false).into(),
                BasicTypeEnum::FloatType(t) => t.const_float(*v as f64).into(),
                BasicTypeEnum::PointerType(t) => i64t.const_int(*v, false).const_to_pointer(t).into(),
                _ => self.zero(hint),
            },
            Constant::Float(v) => match hint {
                BasicTypeEnum::FloatType(t) => t.const_float(*v).into(),
                _ => self.cx.ctx.f64_type().const_float(*v).into(),
            },
            Constant::Bool(b) => self.cx.ctx.i8_type().const_int(*b as u64, false).into(),
            Constant::Null | Constant::Undef | Constant::Zeroinit => self.zero(hint),
            _ => self.zero(self.cx.ptr()),
        }
    }

    fn intrinsic(&self, name: &str, tys: &[BasicTypeEnum<'ctx>]) -> R<FunctionValue<'ctx>> {
        Intrinsic::find(name).and_then(|i| i.get_declaration(self.cx.module, tys))
            .ok_or_else(|| format!("no LLVM intrinsic {}", name).into())
    }

    pub fn call_intrinsic(&self, name: &str, tys: &[BasicTypeEnum<'ctx>], args: &[BasicMetadataValueEnum<'ctx>]) -> R<BasicValueEnum<'ctx>> {
        let f = self.intrinsic(name, tys)?;
        self.b().build_call(f, args, "")?.try_as_basic_value().basic().ok_or_else(|| format!("{} gives no value", name).into())
    }

    /// `v` as an integer: a pointer is its address.
    fn as_int(&self, v: BasicValueEnum<'ctx>) -> R<IntValue<'ctx>> {
        Ok(match v {
            BasicValueEnum::PointerValue(p) => self.b().build_ptr_to_int(p, self.cx.ctx.i64_type(), "")?,
            BasicValueEnum::IntValue(i) => i,
            BasicValueEnum::FloatValue(f) => {
                let t = self.cx.int_type(f.get_type().get_bit_width());
                self.b().build_bit_cast(f, t, "")?.into_int_value()
            }
            other => return Err(format!("not an integer: {:?}", other).into()),
        })
    }

    pub fn sat(&self, name: &str, f: BasicValueEnum<'ctx>, to: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        self.call_intrinsic(name, &[to, f.get_type()], &[f.into()])
    }

    /// What Cranelift's `coerce` does: operands of the wrong kind or width are
    /// converted, by value between integers and floats.
    pub fn coerce(&self, v: BasicValueEnum<'ctx>, t: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        if v.get_type() == t { return Ok(v); }
        let b = self.b();
        Ok(match (v, t) {
            (BasicValueEnum::FloatValue(f), BasicTypeEnum::FloatType(ft)) => {
                if size_bits(t) > size_bits(v.get_type()) { b.build_float_ext(f, ft, "")?.into() } else { b.build_float_trunc(f, ft, "")?.into() }
            }
            (BasicValueEnum::IntValue(i), BasicTypeEnum::FloatType(ft)) => b.build_signed_int_to_float(i, ft, "")?.into(),
            (BasicValueEnum::PointerValue(_), BasicTypeEnum::FloatType(ft)) => b.build_signed_int_to_float(self.as_int(v)?, ft, "")?.into(),
            (BasicValueEnum::FloatValue(_), BasicTypeEnum::IntType(_)) => self.sat("llvm.fptosi.sat", v, t)?,
            (BasicValueEnum::IntValue(i), BasicTypeEnum::IntType(it)) => {
                if it.get_bit_width() > i.get_type().get_bit_width() { b.build_int_z_extend(i, it, "")?.into() } else { b.build_int_truncate(i, it, "")?.into() }
            }
            (BasicValueEnum::IntValue(i), BasicTypeEnum::PointerType(pt)) => {
                let w = self.coerce(i.into(), self.cx.ctx.i64_type().into())?.into_int_value();
                b.build_int_to_ptr(w, pt, "")?.into()
            }
            (BasicValueEnum::FloatValue(_), BasicTypeEnum::PointerType(_)) => {
                let w = self.sat("llvm.fptosi.sat", v, self.cx.ctx.i64_type().into())?;
                self.coerce(w, t)?
            }
            (BasicValueEnum::PointerValue(p), BasicTypeEnum::IntType(_)) => {
                let w = b.build_ptr_to_int(p, self.cx.ctx.i64_type(), "")?;
                self.coerce(w.into(), t)?
            }
            _ if size_bits(v.get_type()) == size_bits(t) && size_bits(t) > 0 => b.build_bit_cast(v, t, "")?,
            _ => return Err(format!("cannot convert {:?} to {:?}", v.get_type(), t).into()),
        })
    }

    fn ptr_of(&self, v: &Val) -> R<PointerValue<'ctx>> {
        let p = self.cx.ptr();
        Ok(self.coerce(self.val(v, p), p)?.into_pointer_value())
    }

    fn typed(&self, v: &Val, t: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        self.coerce(self.val(v, t), t)
    }

    fn index(&self, v: &Val) -> R<IntValue<'ctx>> {
        let t = self.cx.ctx.i64_type().into();
        let x = self.val(v, t);
        Ok(self.coerce(x, t)?.into_int_value())
    }

    /// A local declared `volatile`. An access through a pointer is not marked in
    /// the IR at all yet.
    fn is_volatile(&self, ptr: &Val) -> bool {
        matches!(ptr, Val::Local(id) if self.f.volatile_slots.contains(id))
    }

    fn is_f80(&self, v: &Val) -> bool {
        matches!(v, Val::Local(id) if self.types.get(&id.0) == Some(&Type::Float80))
    }

    fn is_f80_store(&self, val: &Val, ptr: &Val) -> bool {
        if self.is_f80(val) { return true; }
        let to_f80 = matches!(ptr, Val::Local(id)
            if matches!(self.types.get(&id.0), Some(Type::Pointer(t)) if **t == Type::Float80));
        to_f80 && matches!(val, Val::Const(Constant::Float(_)))
    }

    fn set(&mut self, dest: sic_ir::ValId, v: BasicValueEnum<'ctx>) { self.vals.insert(dest.0, v); }

    fn bool_i8(&self, c: IntValue<'ctx>) -> R<BasicValueEnum<'ctx>> {
        Ok(self.b().build_int_z_extend(c, self.cx.ctx.i8_type(), "")?.into())
    }

    /// `v != 0` as an `i1`.
    fn truth(&self, v: BasicValueEnum<'ctx>) -> R<IntValue<'ctx>> {
        let i = self.as_int(v)?;
        Ok(self.b().build_int_compare(IntPredicate::NE, i, i.get_type().const_zero(), "")?)
    }

    fn instr(&mut self, i: &Instr) -> R<()> {
        let cx = self.cx;
        let p8 = cx.ptr();
        match i {
            Instr::Alloca { .. } | Instr::VaEnd { .. } | Instr::SrcLine(_) | Instr::DbgVar { .. } => {}
            Instr::Load { dest, ptr, ty } | Instr::LoadReadonly { dest, ptr, ty } => {
                let p = self.ptr_of(ptr)?;
                if *ty == Type::Float80 {
                    let x = self.load(cx.ctx.x86_f80_type().into(), p)?.into_float_value();
                    let d = self.b().build_float_trunc(x, cx.ctx.f64_type(), "")?;
                    self.set(*dest, d.into());
                } else {
                    let v = self.load(cx.operand_type(ty), p)?;
                    if self.is_volatile(ptr) { v.as_instruction_value().ok_or("load")?.set_volatile(true).map_err(|e| e.to_string())?; }
                    self.set(*dest, v);
                }
            }
            Instr::Store { val, ptr } => {
                let p = self.ptr_of(ptr)?;
                if self.is_f80_store(val, ptr) {
                    let d = self.typed(val, cx.ctx.f64_type().into())?.into_float_value();
                    let x = self.b().build_float_ext(d, cx.ctx.x86_f80_type(), "")?;
                    return self.store(p, x.into());
                }
                let slot = if let Val::Local(id) = ptr { self.slots.get(&id.0).copied() } else { None };
                let hint = slot.or_else(|| store_type(&self.types, val).map(|t| cx.operand_type(&t)))
                    .unwrap_or(cx.ctx.i32_type().into());
                let mut v = self.val(val, hint);
                if let (Some(t), BasicValueEnum::IntValue(_)) = (slot, v) {
                    if t.is_int_type() { v = self.coerce(v, t)?; }
                }
                let ins = self.b().build_store(p, v)?;
                ins.set_alignment(1).map_err(|e| e.to_string())?;
                if self.is_volatile(ptr) { ins.set_volatile(true).map_err(|e| e.to_string())?; }
            }
            Instr::AtomicLoad { dest, ptr, ty } => {
                let p = self.ptr_of(ptr)?;
                let t = cx.value_type(ty);
                let v = self.b().build_load(t, p, "")?;
                let ins = v.as_instruction_value().ok_or("load")?;
                ins.set_atomic_ordering(SEQ).map_err(|e| e.to_string())?;
                ins.set_alignment(size_bits(t) / 8).map_err(|e| e.to_string())?;
                self.set(*dest, v);
            }
            Instr::AtomicStore { ptr, val, ty } => {
                let p = self.ptr_of(ptr)?;
                let t = cx.value_type(ty);
                let v = self.typed(val, t)?;
                let ins = self.b().build_store(p, v)?;
                ins.set_atomic_ordering(SEQ).map_err(|e| e.to_string())?;
                ins.set_alignment(size_bits(t) / 8).map_err(|e| e.to_string())?;
            }
            Instr::Fence => { self.b().build_fence(SEQ, false, "")?; }
            Instr::AtomicRmw { dest, op, ptr, val, ty } => {
                let p = self.ptr_of(ptr)?;
                let t = atomic_int(cx, ty);
                let v = self.typed(val, t)?.into_int_value();
                let o = match op {
                    AtomicOp::Add => AtomicRMWBinOp::Add, AtomicOp::Sub => AtomicRMWBinOp::Sub,
                    AtomicOp::And => AtomicRMWBinOp::And, AtomicOp::Or => AtomicRMWBinOp::Or,
                    AtomicOp::Xor => AtomicRMWBinOp::Xor, AtomicOp::Xchg => AtomicRMWBinOp::Xchg,
                };
                let old = self.b().build_atomicrmw(o, p, v, SEQ)?;
                self.set(*dest, old.into());
            }
            Instr::AtomicCas { dest, ptr, expected, desired, ty } => {
                let p = self.ptr_of(ptr)?;
                let t = atomic_int(cx, ty);
                let e = self.typed(expected, t)?;
                let d = self.typed(desired, t)?;
                let r = self.b().build_cmpxchg(p, e, d, SEQ, SEQ)?;
                let old = self.b().build_extract_value(r, 0, "")?;
                self.set(*dest, old);
            }
            Instr::BinOp { dest, op, lhs, rhs, ty } => {
                let t = cx.operand_type(ty);
                let v = self.binop(*op, lhs, rhs, t)?;
                self.set(*dest, v);
            }
            Instr::UnaryOp { dest, op, val, ty } => {
                let t = cx.value_type(ty);
                let v = self.typed(val, t)?;
                let b = self.b();
                let r: BasicValueEnum = match op {
                    UnOp::Neg => b.build_int_neg(self.as_int(v)?, "")?.into(),
                    UnOp::FNeg => b.build_float_neg(v.into_float_value(), "")?.into(),
                    UnOp::Not => b.build_not(self.as_int(v)?, "")?.into(),
                    UnOp::BoolNot => {
                        let i = self.as_int(v)?;
                        self.bool_i8(b.build_int_compare(IntPredicate::EQ, i, i.get_type().const_zero(), "")?)?
                    }
                    UnOp::Clz | UnOp::Ctz => {
                        let name = if *op == UnOp::Clz { "llvm.ctlz" } else { "llvm.cttz" };
                        let i = self.as_int(v)?;
                        let no = cx.ctx.bool_type().const_zero();
                        self.call_intrinsic(name, &[i.get_type().into()], &[i.into(), no.into()])?
                    }
                    UnOp::Popcnt => {
                        let i = self.as_int(v)?;
                        self.call_intrinsic("llvm.ctpop", &[i.get_type().into()], &[i.into()])?
                    }
                };
                self.set(*dest, r);
            }
            Instr::Cast { dest, op, val, to_ty } => {
                let dst = cx.value_type(to_ty);
                let hint = match op {
                    CastOp::SIToFP | CastOp::UIToFP => cx.ctx.i64_type().into(),
                    CastOp::FPToSI | CastOp::FPToUI | CastOp::FPExt | CastOp::FPTrunc => cx.ctx.f64_type().into(),
                    _ => dst,
                };
                let v = self.val(val, hint);
                let r = self.cast(v, *op, dst)?;
                self.set(*dest, r);
            }
            Instr::Cmp { dest, op, lhs, rhs, ty } => {
                let v = self.cmp(*op, lhs, rhs, cx.operand_type(ty))?;
                self.set(*dest, v);
            }
            Instr::Call { dest, func, args, ret_ty } => {
                let Some(lf) = cx.funcs.get(&func.0).copied() else {
                    if let Some(d) = dest { self.set(*d, cx.value_type(ret_ty).const_zero()); }
                    return Ok(());
                };
                let sig = cx.ir.func_sig(*func).clone();
                self.call(lf.as_global_value().as_pointer_value(), &sig, args, dest.map(|d| d.0))?;
            }
            Instr::CallIndirect { dest, fptr, args, func_ty, .. } => {
                let p = self.ptr_of(fptr)?;
                self.call(p, func_ty, args, dest.map(|d| d.0))?;
            }
            Instr::GetElemPtr { dest, base, index, elem_size, .. } => {
                let b = self.ptr_of(base)?;
                let mut i = self.index(index)?;
                if *elem_size > 1 { i = self.b().build_int_mul(i, cx.ctx.i64_type().const_int(*elem_size, false), "")?; }
                let p = self.gep(b, i)?;
                self.set(*dest, p.into());
            }
            Instr::GetFieldPtr { dest, base, byte_offset, .. } => {
                let b = self.ptr_of(base)?;
                let p = self.gep_const(b, *byte_offset as u64)?;
                self.set(*dest, p.into());
            }
            Instr::PtrOffset { dest, base, offset } => {
                let b = self.ptr_of(base)?;
                let o = self.index(offset)?;
                let p = self.gep(b, o)?;
                self.set(*dest, p.into());
            }
            Instr::Select { dest, cond, on_true, on_false, ty } => {
                let t = cx.operand_type(ty);
                let c = self.val(cond, cx.ctx.i8_type().into());
                let c = self.truth(c)?;
                let (x, y) = (self.typed(on_true, t)?, self.typed(on_false, t)?);
                let v = self.b().build_select(c, x, y, "")?;
                self.set(*dest, v);
            }
            Instr::MemCopy { dst, src, size, .. } => {
                let (d, s) = (self.ptr_of(dst)?, self.ptr_of(src)?);
                // May overlap: a struct assigned to itself.
                self.b().build_memmove(d, 1, s, 1, cx.ctx.i64_type().const_int(*size, false)).map_err(|e| e.to_string())?;
            }
            Instr::MemSet { dst, val, size, .. } => {
                let d = self.ptr_of(dst)?;
                let v = self.typed(val, cx.ctx.i8_type().into())?.into_int_value();
                self.b().build_memset(d, 1, v, cx.ctx.i64_type().const_int(*size, false)).map_err(|e| e.to_string())?;
            }
            Instr::BSwap { dest, val, ty } => {
                let t = cx.value_type(ty);
                let v = self.typed(val, t)?;
                let r = if size_bits(t) <= 8 { v } else { self.call_intrinsic("llvm.bswap", &[t], &[v.into()])? };
                self.set(*dest, r);
            }
            Instr::Simd { dest, op, args, arg_ty, ty } => {
                let v = self.simd(op, args, arg_ty, ty)?;
                self.set(*dest, v);
            }
            Instr::VecMoveMask { dest, val, ty } => {
                let vt = cx.vector_type(ty).ok_or("VecMoveMask of a non-vector")?;
                let v = self.typed(val, vt)?.into_vector_value();
                let r = self.move_mask(v)?;
                self.set(*dest, r.into());
            }
            Instr::VaStart { list_ptr } => {
                let p = self.ptr_of(list_ptr)?;
                if self.f.sig.variadic {
                    let f = self.intrinsic("llvm.va_start", &[p8])?;
                    self.b().build_call(f, &[p.into()], "")?;
                }
            }
            Instr::VaArg { dest, list_ptr, ty } => {
                let v = self.va_arg(list_ptr, ty)?;
                self.set(*dest, v);
            }
            Instr::ReturnAddress { dest } => {
                let v = self.call_intrinsic("llvm.returnaddress", &[], &[cx.ctx.i32_type().const_zero().into()])?;
                self.set(*dest, v);
            }
            Instr::FrameAddress { dest } => {
                let v = self.call_intrinsic("llvm.frameaddress", &[p8], &[cx.ctx.i32_type().const_zero().into()])?;
                self.set(*dest, v);
            }
        }
        Ok(())
    }

    fn binop(&self, op: BinOp, lhs: &Val, rhs: &Val, t: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        let b = self.b();
        // Pointer arithmetic is integer arithmetic, an addition a GEP.
        if t.is_pointer_type() {
            let l = self.typed(lhs, t)?;
            let i64t = self.cx.ctx.i64_type().into();
            if op == BinOp::Add {
                let r = self.typed(rhs, i64t)?.into_int_value();
                return Ok(self.gep(l.into_pointer_value(), r)?.into());
            }
            let v = self.binop_values(op, self.as_int(l)?.into(), self.typed(rhs, i64t)?, i64t)?;
            return self.coerce(v, t);
        }
        let _ = b;
        let (l, r) = (self.typed(lhs, t)?, self.typed(rhs, t)?);
        self.binop_values(op, l, r, t)
    }

    fn binop_values(&self, op: BinOp, l: BasicValueEnum<'ctx>, r: BasicValueEnum<'ctx>, t: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        let b = self.b();
        use BasicValueEnum::*;
        Ok(match (l, r) {
            (IntValue(x), IntValue(y)) => {
                // A shift count is taken modulo the width: at or over it, LLVM
                // has no defined result, and C code that does it expects x86's.
                let masked = || -> R<inkwell::values::IntValue<'ctx>> {
                    let w = x.get_type().get_bit_width() as u64;
                    Ok(b.build_and(y, x.get_type().const_int(w - 1, false), "")?)
                };
                match op {
                    BinOp::Add => b.build_int_add(x, y, "")?.into(),
                    BinOp::Sub => b.build_int_sub(x, y, "")?.into(),
                    BinOp::Mul => b.build_int_mul(x, y, "")?.into(),
                    BinOp::SDiv => b.build_int_signed_div(x, y, "")?.into(),
                    BinOp::UDiv => b.build_int_unsigned_div(x, y, "")?.into(),
                    BinOp::SRem => b.build_int_signed_rem(x, y, "")?.into(),
                    BinOp::URem => b.build_int_unsigned_rem(x, y, "")?.into(),
                    BinOp::And => b.build_and(x, y, "")?.into(),
                    BinOp::Or => b.build_or(x, y, "")?.into(),
                    BinOp::Xor => b.build_xor(x, y, "")?.into(),
                    BinOp::Shl => b.build_left_shift(x, masked()?, "")?.into(),
                    BinOp::AShr => b.build_right_shift(x, masked()?, true, "")?.into(),
                    BinOp::LShr => b.build_right_shift(x, masked()?, false, "")?.into(),
                    BinOp::Rotl | BinOp::Rotr => {
                        let name = if op == BinOp::Rotl { "llvm.fshl" } else { "llvm.fshr" };
                        self.call_intrinsic(name, &[t], &[x.into(), x.into(), y.into()])?
                    }
                    _ => return Err(format!("{:?} on integers", op).into()),
                }
            }
            (FloatValue(x), FloatValue(y)) => match op {
                BinOp::FAdd => b.build_float_add(x, y, "")?.into(),
                BinOp::FSub => b.build_float_sub(x, y, "")?.into(),
                BinOp::FMul => b.build_float_mul(x, y, "")?.into(),
                BinOp::FDiv => b.build_float_div(x, y, "")?.into(),
                BinOp::FRem => {
                    // As the Cranelift back end: a - trunc(a / b) * b, no libm.
                    let q = b.build_float_div(x, y, "")?;
                    let tr = self.call_intrinsic("llvm.trunc", &[t], &[q.into()])?.into_float_value();
                    let p = b.build_float_mul(tr, y, "")?;
                    b.build_float_sub(x, p, "")?.into()
                }
                _ => return Err(format!("{:?} on floats", op).into()),
            },
            (VectorValue(x), VectorValue(y)) if x.get_type().get_element_type().is_int_type() => match op {
                BinOp::Add => b.build_int_add(x, y, "")?.into(),
                BinOp::Sub => b.build_int_sub(x, y, "")?.into(),
                BinOp::Mul => b.build_int_mul(x, y, "")?.into(),
                BinOp::And => b.build_and(x, y, "")?.into(),
                BinOp::Or => b.build_or(x, y, "")?.into(),
                BinOp::Xor => b.build_xor(x, y, "")?.into(),
                _ => return Err(format!("{:?} on vectors", op).into()),
            },
            // Bitwise on float lanes: the same bits as integers.
            (VectorValue(x), VectorValue(_)) if matches!(op, BinOp::And | BinOp::Or | BinOp::Xor) => {
                let lanes = x.get_type().get_size();
                let it: BasicTypeEnum = self.cx.int_type(size_bits(t) / lanes).vec_type(lanes).into();
                let (p, q) = (b.build_bit_cast(l, it, "")?, b.build_bit_cast(r, it, "")?);
                let v = self.binop_values(op, p, q, it)?;
                b.build_bit_cast(v, t, "")?
            }
            (VectorValue(x), VectorValue(y)) => match op {
                BinOp::FAdd => b.build_float_add(x, y, "")?.into(),
                BinOp::FSub => b.build_float_sub(x, y, "")?.into(),
                BinOp::FMul => b.build_float_mul(x, y, "")?.into(),
                BinOp::FDiv => b.build_float_div(x, y, "")?.into(),
                _ => return Err(format!("{:?} on float vectors", op).into()),
            },
            _ => return Err(format!("{:?} of mismatched values", op).into()),
        })
    }

    fn cmp(&self, op: CmpOp, lhs: &Val, rhs: &Val, t: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        let b = self.b();
        let (l, r) = (self.typed(lhs, t)?, self.typed(rhs, t)?);
        let ip = match op {
            CmpOp::IEq => IntPredicate::EQ, CmpOp::INe => IntPredicate::NE,
            CmpOp::ISLt => IntPredicate::SLT, CmpOp::ISLe => IntPredicate::SLE,
            CmpOp::ISGt => IntPredicate::SGT, CmpOp::ISGe => IntPredicate::SGE,
            CmpOp::IULt => IntPredicate::ULT, CmpOp::IULe => IntPredicate::ULE,
            CmpOp::IUGt => IntPredicate::UGT, CmpOp::IUGe => IntPredicate::UGE,
            _ => IntPredicate::EQ,
        };
        let fp = match op {
            CmpOp::FOEq => FloatPredicate::OEQ,
            // C's `!=`: true when either side is NaN.
            CmpOp::FONe => FloatPredicate::UNE,
            CmpOp::FOLt => FloatPredicate::OLT, CmpOp::FOLe => FloatPredicate::OLE,
            CmpOp::FOGt => FloatPredicate::OGT, CmpOp::FOGe => FloatPredicate::OGE,
            _ => FloatPredicate::OEQ,
        };
        use BasicValueEnum::*;
        Ok(match (l, r) {
            (IntValue(x), IntValue(y)) => self.bool_i8(b.build_int_compare(ip, x, y, "")?)?,
            (PointerValue(_), PointerValue(_)) => {
                let (x, y) = (self.as_int(l)?, self.as_int(r)?);
                self.bool_i8(b.build_int_compare(ip, x, y, "")?)?
            }
            (FloatValue(x), FloatValue(y)) => self.bool_i8(b.build_float_compare(fp, x, y, "")?)?,
            // A lane mask: all ones where it holds.
            (VectorValue(x), VectorValue(y)) => {
                let et = x.get_type();
                let m = if et.get_element_type().is_float_type() {
                    b.build_float_compare(fp, x, y, "")?
                } else {
                    b.build_int_compare(ip, x, y, "")?
                };
                let lanes = et.get_size();
                let it = self.cx.int_type(size_bits(t) / lanes).vec_type(lanes);
                let wide = b.build_int_s_extend(m, it, "")?;
                b.build_bit_cast(wide, t, "")?
            }
            _ => return Err("comparison of mismatched values".into()),
        })
    }

    fn cast(&self, v: BasicValueEnum<'ctx>, op: CastOp, dst: BasicTypeEnum<'ctx>) -> R<BasicValueEnum<'ctx>> {
        if v.get_type() == dst { return Ok(v); }
        let b = self.b();
        Ok(match op {
            CastOp::SExt | CastOp::ZExt | CastOp::BoolToInt | CastOp::Trunc if dst.is_int_type() && !v.is_float_value() => {
                let i = self.as_int(v)?;
                let t = dst.into_int_type();
                let (from, to) = (i.get_type().get_bit_width(), t.get_bit_width());
                if to < from { b.build_int_truncate(i, t, "")?.into() }
                else if to == from { i.into() }
                else if op == CastOp::SExt { b.build_int_s_extend(i, t, "")?.into() }
                else { b.build_int_z_extend(i, t, "")?.into() }
            }
            CastOp::SExt | CastOp::ZExt | CastOp::BoolToInt | CastOp::Trunc
            | CastOp::BitCast | CastOp::IntToPtr | CastOp::PtrToInt => self.coerce(v, dst)?,
            CastOp::SIToFP => b.build_signed_int_to_float(self.as_int(v)?, dst.into_float_type(), "")?.into(),
            CastOp::UIToFP => b.build_unsigned_int_to_float(self.as_int(v)?, dst.into_float_type(), "")?.into(),
            CastOp::FPToSI => self.float_to_int(v, dst, true)?,
            CastOp::FPToUI => self.float_to_int(v, dst, false)?,
            CastOp::FPExt | CastOp::FPTrunc => self.coerce(v, dst)?,
        })
    }

    /// A float out of range has no value in LLVM's `fptosi`: saturate, as
    /// Cranelift does. Unsigned, a negative value converts as signed does.
    fn float_to_int(&self, v: BasicValueEnum<'ctx>, dst: BasicTypeEnum<'ctx>, signed: bool) -> R<BasicValueEnum<'ctx>> {
        let b = self.b();
        let t = dst.into_int_type();
        let wide = if t.get_bit_width() < 32 { self.cx.ctx.i32_type() } else { t };
        let s = self.sat("llvm.fptosi.sat", v, wide.into())?;
        let r = if signed || wide.get_bit_width() < 64 { s } else {
            let u = self.sat("llvm.fptoui.sat", v, wide.into())?;
            let f = v.into_float_value();
            let neg = b.build_float_compare(FloatPredicate::OLT, f, f.get_type().const_zero(), "")?;
            b.build_select(neg, s, u, "")?
        };
        self.coerce(r, dst)
    }

    fn call(&mut self, callee: PointerValue<'ctx>, sig: &FunctionType, args: &[Val], dest: Option<u32>) -> R<()> {
        let cx = self.cx;
        let ptr_size = cx.opts.ptr_size;
        let named = sig.params.len();
        let mut vals: Vec<BasicMetadataValueEnum> = Vec::with_capacity(args.len());
        let mut tys: Vec<BasicTypeEnum> = Vec::with_capacity(args.len());
        let mut attrs: Vec<(u32, Attribute)> = Vec::new();
        let mut named_tys = 0usize;
        for (i, a) in args.iter().enumerate() {
            let is_named = !sig.variadic || i < named;
            let pass = if is_named && i < named { Some(classify_param(&sig.params[i], ptr_size)) }
                else if self.is_f80(a) { Some(ParamPass::X87) } else { None };
            let at = tys.len() as u32;
            match pass {
                Some(ParamPass::Scalar) => {
                    let t = cx.value_type(&sig.params[i]);
                    vals.push(self.typed(a, t)?.into());
                    tys.push(t);
                    if let Some(x) = cx.ext_attr(&sig.params[i]) { attrs.push((at, x)); }
                }
                Some(ParamPass::ByValStack(size, align)) => {
                    vals.push(self.ptr_of(a)?.into());
                    tys.push(cx.ptr());
                    for x in cx.byval_attrs(size, align) { attrs.push((at, x)); }
                }
                Some(ParamPass::X87) => {
                    let d = self.typed(a, cx.ctx.f64_type().into())?.into_float_value();
                    let x = self.b().build_float_ext(d, cx.ctx.x86_f80_type(), "")?;
                    vals.push(x.into());
                    tys.push(cx.ctx.x86_f80_type().into());
                }
                Some(ParamPass::Direct(chunks)) => {
                    let base = self.ptr_of(a)?;
                    for c in &chunks {
                        vals.push(self.load_chunk(base, c)?.into());
                        tys.push(cx.chunk_type(c));
                    }
                }
                None => {
                    // Variadic, or past a prototype: its natural class, with C's
                    // default promotion of `float`.
                    let mut v = self.val(a, cx.ctx.i64_type().into());
                    if v.is_float_value() { v = self.coerce(v, cx.ctx.f64_type().into())?; }
                    vals.push(v.into());
                    tys.push(v.get_type());
                }
            }
            if i < named { named_tys = tys.len(); }
        }
        let fn_ty = if sig.variadic { cx.fn_type(&sig.ret, &tys[..named_tys], true) } else { cx.fn_type(&sig.ret, &tys, false) };
        let site = self.b().build_indirect_call(fn_ty, callee, &vals, "")?;
        for (i, a) in attrs { site.add_attribute(AttributeLoc::Param(i), a); }
        if let Some(a) = cx.ext_attr(&sig.ret) { site.add_attribute(AttributeLoc::Return, a); }
        self.bind_result(site, &sig.ret, dest)
    }

    fn bind_result(&mut self, site: CallSiteValue<'ctx>, ret: &Type, dest: Option<u32>) -> R<()> {
        let Some(d) = dest else { return Ok(()) };
        let cx = self.cx;
        let Some(v) = site.try_as_basic_value().basic() else { return Ok(()) };
        let ptr_size = cx.opts.ptr_size;
        if matches!(ret, Type::Struct(_) | Type::Union(_)) {
            if let AggClass::Regs(chunks) = classify_struct_union(ret, ptr_size) {
                let addr = self.slot(ret.size_of(ptr_size) as u32, ret.align_of(ptr_size).max(1) as u32)?;
                if chunks.len() == 1 {
                    self.store_chunk(v, addr, &chunks[0])?;
                } else {
                    for (i, c) in chunks.iter().enumerate() {
                        let part = self.b().build_extract_value(v.into_struct_value(), i as u32, "")?;
                        self.store_chunk(part, addr, c)?;
                    }
                }
                self.vals.insert(d, addr.into());
                return Ok(());
            }
        }
        if *ret == Type::Float80 {
            let t = self.b().build_float_trunc(v.into_float_value(), cx.ctx.f64_type(), "")?;
            self.vals.insert(d, t.into());
            return Ok(());
        }
        self.vals.insert(d, v);
        Ok(())
    }

    /// Walk the System V `va_list`, as it is a C object that `vprintf` reads too.
    fn va_arg(&self, list: &Val, ty: &Type) -> R<BasicValueEnum<'ctx>> {
        let cx = self.cx;
        let b = self.b();
        let lp = self.ptr_of(list)?;
        let (i32t, i64t, p) = (cx.ctx.i32_type(), cx.ctx.i64_type(), cx.ptr());
        let ovf_at = self.gep_const(lp, 8)?;
        let overflow = self.load(p, ovf_at)?.into_pointer_value();
        if *ty == Type::Float80 {
            // Always in the overflow area, 16-aligned.
            let a = b.build_ptr_to_int(overflow, i64t, "")?;
            let up = b.build_int_add(a, i64t.const_int(15, false), "")?;
            let al = b.build_and(up, i64t.const_int(-16i64 as u64, true), "")?;
            let addr = b.build_int_to_ptr(al, overflow.get_type(), "")?;
            let next = self.gep_const(addr, 16)?;
            self.store(ovf_at, next.into())?;
            let x = self.load(cx.ctx.x86_f80_type().into(), addr)?.into_float_value();
            return Ok(b.build_float_trunc(x, cx.ctx.f64_type(), "")?.into());
        }
        let t = cx.value_type(ty);
        let (field, threshold, step): (u64, u64, u64) = if t.is_float_type() { (4, 176, 16) } else { (0, 48, 8) };
        let off_at = self.gep_const(lp, field)?;
        let offset = self.load(i32t.into(), off_at)?.into_int_value();
        let save_at = self.gep_const(lp, 16)?;
        let reg_save = self.load(p, save_at)?.into_pointer_value();
        let in_reg = b.build_int_compare(IntPredicate::ULT, offset, i32t.const_int(threshold, false), "")?;
        let wide = b.build_int_z_extend(offset, i64t, "")?;
        let reg_addr = self.gep(reg_save, wide)?;
        let new_off = b.build_int_add(offset, i32t.const_int(step, false), "")?;
        let new_ovf = self.gep_const(overflow, 8)?;
        let addr = b.build_select(in_reg, reg_addr, overflow, "")?.into_pointer_value();
        let stored_off = b.build_select(in_reg, new_off, offset, "")?;
        self.store(off_at, stored_off)?;
        let stored_ovf = b.build_select(in_reg, overflow, new_ovf, "")?;
        self.store(ovf_at, stored_ovf)?;
        self.load(t, addr)
    }

    fn terminator(&mut self, t: &Terminator) -> R<()> {
        let cx = self.cx;
        match t {
            Terminator::Ret(v) => {
                let Some(rt) = cx.return_type(&self.f.sig.ret) else {
                    self.b().build_return(None)?;
                    return Ok(());
                };
                let Some(v) = v else {
                    let z = self.zero(rt);
                    self.b().build_return(Some(&z))?;
                    return Ok(());
                };
                let ret = &self.f.sig.ret;
                if *ret == Type::Float80 {
                    let d = self.typed(v, cx.ctx.f64_type().into())?.into_float_value();
                    let x = self.b().build_float_ext(d, cx.ctx.x86_f80_type(), "")?;
                    self.b().build_return(Some(&x))?;
                } else if matches!(ret, Type::Struct(_) | Type::Union(_)) {
                    let AggClass::Regs(chunks) = classify_struct_union(ret, cx.opts.ptr_size) else { return Err("aggregate return".into()) };
                    let base = self.ptr_of(v)?;
                    let parts: Vec<BasicValueEnum> = chunks.iter().map(|c| self.load_chunk(base, c)).collect::<R<_>>()?;
                    if parts.len() == 1 { self.b().build_return(Some(&parts[0]))?; }
                    else { self.b().build_aggregate_return(&parts)?; }
                } else {
                    let r = self.typed(v, rt)?;
                    self.b().build_return(Some(&r))?;
                }
            }
            Terminator::Jump(b) => { self.b().build_unconditional_branch(self.blocks[&b.0])?; }
            Terminator::CondJump { cond, then_bb, else_bb } => {
                let c = self.val(cond, cx.ctx.i8_type().into());
                let c = self.truth(c)?;
                self.b().build_conditional_branch(c, self.blocks[&then_bb.0], self.blocks[&else_bb.0])?;
            }
            Terminator::Switch { val, default, arms } => {
                let v = self.val(val, cx.ctx.i32_type().into());
                let v = self.as_int(v)?;
                let mut seen = sic_ir::fast_hash::HashSet::default();
                let mut cases = Vec::with_capacity(arms.len());
                for (arm, bb) in arms {
                    let c = v.get_type().const_int(*arm as u64, true);
                    // The first of equal labels wins, as in the chain of tests a
                    // label is, truncated to the value's width.
                    if seen.insert(c.get_sign_extended_constant()) { cases.push((c, self.blocks[&bb.0])); }
                }
                self.b().build_switch(v, self.blocks[&default.0], &cases)?;
            }
            Terminator::Unreachable => {
                let f = self.intrinsic("llvm.trap", &[])?;
                self.b().build_call(f, &[], "")?;
                self.b().build_unreachable()?;
            }
        }
        Ok(())
    }
}

fn atomic_int<'ctx>(cx: &Cx<'ctx, '_>, ty: &Type) -> BasicTypeEnum<'ctx> {
    let t = cx.value_type(ty);
    if t.is_pointer_type() { cx.ctx.i64_type().into() } else { t }
}

fn size_bits(t: BasicTypeEnum) -> u32 {
    match t {
        BasicTypeEnum::IntType(i) => i.get_bit_width(),
        BasicTypeEnum::FloatType(f) => f.get_bit_width(),
        BasicTypeEnum::PointerType(_) => 64,
        BasicTypeEnum::VectorType(v) => v.get_size() * size_bits(v.get_element_type()),
        _ => 0,
    }
}

