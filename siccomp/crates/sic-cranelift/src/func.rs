use std::collections::HashMap;
use cranelift_codegen::ir::{self as cir, InstBuilder, MemFlags};
use cranelift_codegen::ir::types as ct;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_module::{FuncId, DataId, Module};
use cranelift_object::ObjectModule;
use sic_ir::*;
use super::types::{cl_type, ptr_cl};
use super::build_cl_sig;

pub fn compile_function(
    f: &Function,
    module_ir: &sic_ir::Module,
    obj_module: &mut ObjectModule,
    func_ids: &HashMap<u32, FuncId>,
    global_ids: &HashMap<u32, DataId>,
    cl_func: &mut cir::Function,
    ptr_size: u32,
) -> Result<(), super::CraneliftError> {
    if f.blocks.is_empty() { return Ok(()); }

    let mut fbctx = FunctionBuilderContext::new();
    let mut builder = FunctionBuilder::new(cl_func, &mut fbctx);
    let ptr_ty = ptr_cl(ptr_size);
    let target_config = obj_module.target_config();

    // Pre-declare all callees and globals inside this function's IR.
    // Sort by key for deterministic ordering (avoids HashMap non-determinism).
    let mut callee_refs: HashMap<u32, cir::FuncRef> = HashMap::new();
    let mut sorted_funcs: Vec<(u32, FuncId)> = func_ids.iter().map(|(&k, &v)| (k, v)).collect();
    sorted_funcs.sort_by_key(|(k, _)| *k);
    for (fref_idx, func_id) in sorted_funcs {
        let fref = obj_module.declare_func_in_func(func_id, builder.func);
        callee_refs.insert(fref_idx, fref);
    }
    let mut data_refs: HashMap<u32, cir::GlobalValue> = HashMap::new();
    let mut sorted_globals: Vec<(u32, DataId)> = global_ids.iter().map(|(&k, &v)| (k, v)).collect();
    sorted_globals.sort_by_key(|(k, _)| *k);
    for (gidx, data_id) in sorted_globals {
        let gv = obj_module.declare_data_in_func(data_id, builder.func);
        data_refs.insert(gidx, gv);
    }

    // Create all CL blocks.
    let mut bb_map: HashMap<u32, cir::Block> = HashMap::new();
    for bb in &f.blocks {
        let cl_bb = builder.create_block();
        bb_map.insert(bb.id.0, cl_bb);
    }

    // Entry block: function parameters become block params.
    let entry_cl = bb_map[&f.blocks[0].id.0];
    builder.append_block_params_for_function_params(entry_cl);
    builder.switch_to_block(entry_cl);

    let mut val_map: HashMap<u32, cir::Value> = HashMap::new();

    // Map param sentinels ValId(0x10000+i) → actual entry-block param values.
    // For variadic functions the signature was padded with extra trailing i64
    // params (see `build_cl_sig_def`); spill those into a contiguous save area
    // that `va_start`/`va_arg` walk with a single cursor pointer.
    let mut va_save_area: Option<cir::Value> = None;
    {
        let params = builder.block_params(entry_cl).to_vec();
        let fixed = f.params.len();
        for i in 0..fixed {
            if i < params.len() {
                val_map.insert(0x10000 + i as u32, params[i]);
            }
        }
        if f.sig.variadic && params.len() > fixed {
            let n = params.len() - fixed;
            let size = (n * 8) as u32;
            let slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                cir::StackSlotKind::ExplicitSlot,
                size,
                3, // align = 2^3 = 8 bytes
            ));
            let base = builder.ins().stack_addr(ptr_ty, slot, 0);
            for i in 0..n {
                builder.ins().store(MemFlags::new(), params[fixed + i], base, (i * 8) as i32);
            }
            va_save_area = Some(base);
        }
    }

    // Emit all blocks.
    for (bi, bb) in f.blocks.iter().enumerate() {
        if bi > 0 {
            let cl_bb = bb_map[&bb.id.0];
            builder.switch_to_block(cl_bb);
        }
        for instr in &bb.instrs {
            emit_instr(
                instr, &mut builder, &mut val_map, &callee_refs, &data_refs,
                ptr_ty, target_config, ptr_size, va_save_area,
            );
        }
        emit_terminator(&bb.terminator, &mut builder, &val_map, &callee_refs, &data_refs, &bb_map, ptr_ty);
    }

    builder.seal_all_blocks();
    builder.finalize();
    Ok(())
}

// ── Instruction emission ──────────────────────────────────────────────────────

fn emit_instr(
    instr: &Instr,
    builder: &mut FunctionBuilder<'_>,
    val_map: &mut HashMap<u32, cir::Value>,
    callee_refs: &HashMap<u32, cir::FuncRef>,
    data_refs: &HashMap<u32, cir::GlobalValue>,
    ptr_ty: cir::Type,
    target_config: cranelift_codegen::isa::TargetFrontendConfig,
    ptr_size: u32,
    va_save_area: Option<cir::Value>,
) {
    match instr {
        Instr::Alloca { dest, ty } => {
            let size = ty.size_of(ptr_size).max(1) as u32;
            let align_bytes = ty.align_of(ptr_size).max(1);
            // StackSlotData takes align as log2(bytes), not bytes
            let align_shift = (align_bytes as u32).trailing_zeros() as u8;
            let slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                cir::StackSlotKind::ExplicitSlot,
                size,
                align_shift,
            ));
            let addr = builder.ins().stack_addr(ptr_ty, slot, 0);
            val_map.insert(dest.0, addr);
        }

        Instr::Load { dest, ptr, ty } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let v = builder.ins().load(cl_ty, MemFlags::new(), pv, 0);
            val_map.insert(dest.0, v);
        }

        Instr::Store { val, ptr } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            // Infer hint from existing value if available
            let hint = if let Val::Local(id) = val {
                val_map.get(&id.0).map(|&v| builder.func.dfg.value_type(v)).unwrap_or(ct::I32)
            } else { ct::I32 };
            let sv = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, hint);
            builder.ins().store(MemFlags::new(), sv, pv, 0);
        }

        Instr::BinOp { dest, op, lhs, rhs, ty } => {
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let l = rval(lhs, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let r = rval(rhs, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let l = coerce(l, cl_ty, builder, ptr_ty);
            let r = coerce(r, cl_ty, builder, ptr_ty);
            let v = emit_binop(op, l, r, builder);
            val_map.insert(dest.0, v);
        }

        Instr::UnaryOp { dest, op, val, ty } => {
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let v = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let result = match op {
                UnOp::Neg     => builder.ins().ineg(v),
                UnOp::FNeg    => builder.ins().fneg(v),
                UnOp::Not     => builder.ins().bnot(v),
                UnOp::BoolNot => {
                    let vty = builder.func.dfg.value_type(v);
                    let zero = builder.ins().iconst(vty, 0);
                    builder.ins().icmp(cir::condcodes::IntCC::Equal, v, zero)
                }
            };
            val_map.insert(dest.0, result);
        }

        Instr::Cast { dest, op, val, to_ty } => {
            let dst_cl = cl_type(to_ty, ptr_size).unwrap_or(ct::I32);
            // Hint the source with a compatible type for the cast operation
            let src_hint = match op {
                CastOp::SIToFP | CastOp::UIToFP => ct::I64,  // source must be integer
                CastOp::FPToSI | CastOp::FPToUI | CastOp::FPExt | CastOp::FPTrunc => ct::F64,  // source must be float
                _ => dst_cl,
            };
            let src_v = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, src_hint);
            let src_ty = builder.func.dfg.value_type(src_v);
            let result = emit_cast(src_v, src_ty, *op, dst_cl, builder, ptr_ty);
            val_map.insert(dest.0, result);
        }

        Instr::Cmp { dest, op, lhs, rhs } => {
            let l = rval(lhs, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I32);
            let r = rval(rhs, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I32);
            let lty = builder.func.dfg.value_type(l);
            let l = coerce(l, lty, builder, ptr_ty);
            let r = coerce(r, lty, builder, ptr_ty);
            let v = emit_cmp(op, l, r, lty, builder);
            val_map.insert(dest.0, v);
        }

        Instr::Call { dest, func, args, ret_ty } => {
            let Some(&cl_fref) = callee_refs.get(&func.0) else {
                let cl_ty = cl_type(ret_ty, ptr_size).unwrap_or(ct::I32);
                let v = builder.ins().iconst(cl_ty, 0);
                if let Some(d) = dest { val_map.insert(d.0, v); }
                return;
            };

            let sig_ref = builder.func.dfg.ext_funcs[cl_fref].signature;
            let (param_tys, declared_count) = {
                let sig = &builder.func.stencil.dfg.signatures[sig_ref];
                let tys: Vec<cir::Type> = sig.params.iter().map(|p| p.value_type).collect();
                let n = tys.len();
                (tys, n)
            };

            let arg_vals: Vec<cir::Value> = args.iter().enumerate().map(|(i, a)| {
                let hint = param_tys.get(i).copied().unwrap_or(ct::I64);
                let v = rval(a, val_map, callee_refs, data_refs, builder, ptr_ty, hint);
                coerce(v, hint, builder, ptr_ty)
            }).collect();

            let inst = if arg_vals.len() > declared_count {
                // Variadic call with extra args: build extended sig and use call_indirect
                let mut new_sig = builder.func.stencil.dfg.signatures[sig_ref].clone();
                for v in &arg_vals[declared_count..] {
                    let ty = builder.func.dfg.value_type(*v);
                    new_sig.params.push(cir::AbiParam::new(ty));
                }
                let new_sig_ref = builder.func.import_signature(new_sig);
                let faddr = builder.ins().func_addr(ptr_ty, cl_fref);
                builder.ins().call_indirect(new_sig_ref, faddr, &arg_vals)
            } else {
                builder.ins().call(cl_fref, &arg_vals)
            };
            if let Some(d) = dest {
                let results = builder.inst_results(inst).to_vec();
                if !results.is_empty() {
                    val_map.insert(d.0, results[0]);
                }
            }
        }

        Instr::CallIndirect { dest, fptr, args, ret_ty, func_ty } => {
            let sig = build_cl_sig(func_ty, ptr_size, builder.func.signature.call_conv);
            let sig_ref = builder.func.import_signature(sig);
            let fp = rval(fptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let param_tys: Vec<cir::Type> = builder.func.stencil.dfg.signatures[sig_ref]
                .params.iter().map(|p| p.value_type).collect();
            let arg_vals: Vec<cir::Value> = args.iter().enumerate().map(|(i, a)| {
                let hint = param_tys.get(i).copied().unwrap_or(ct::I64);
                let v = rval(a, val_map, callee_refs, data_refs, builder, ptr_ty, hint);
                coerce(v, hint, builder, ptr_ty)
            }).collect();
            let inst = builder.ins().call_indirect(sig_ref, fp, &arg_vals);
            if let Some(d) = dest {
                let results = builder.inst_results(inst).to_vec();
                if !results.is_empty() {
                    val_map.insert(d.0, results[0]);
                }
            }
        }

        Instr::GetElemPtr { dest, base, index, elem_size } => {
            let bv = rval(base, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let iv = rval(index, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let ic = coerce(iv, ptr_ty, builder, ptr_ty);
            let addr = if *elem_size <= 1 {
                builder.ins().iadd(bv, ic)
            } else {
                let size_val = builder.ins().iconst(ptr_ty, *elem_size as i64);
                let scaled = builder.ins().imul(ic, size_val);
                builder.ins().iadd(bv, scaled)
            };
            val_map.insert(dest.0, addr);
        }

        Instr::GetFieldPtr { dest, base, byte_offset, .. } => {
            let bv = rval(base, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let addr = builder.ins().iadd_imm(bv, *byte_offset as i64);
            val_map.insert(dest.0, addr);
        }

        Instr::PtrOffset { dest, base, offset } => {
            let bv = rval(base, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let ov = rval(offset, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let oc = coerce(ov, ptr_ty, builder, ptr_ty);
            let addr = builder.ins().iadd(bv, oc);
            val_map.insert(dest.0, addr);
        }

        Instr::Select { dest, cond, on_true, on_false, ty } => {
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let cv = rval(cond, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I8);
            let tv = rval(on_true, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let fv = rval(on_false, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let cb = builder.ins().icmp_imm(cir::condcodes::IntCC::NotEqual, cv, 0);
            let tv = coerce(tv, cl_ty, builder, ptr_ty);
            let fv = coerce(fv, cl_ty, builder, ptr_ty);
            let v = builder.ins().select(cb, tv, fv);
            val_map.insert(dest.0, v);
        }

        Instr::MemCopy { dst, src, size, .. } => {
            let dv = rval(dst, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let sv = rval(src, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let szv = builder.ins().iconst(ptr_ty, *size as i64);
            builder.call_memcpy(target_config, dv, sv, szv);
        }

        Instr::MemSet { dst, val, size, .. } => {
            let dv = rval(dst, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let vv = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I8);
            let vb = coerce(vv, ct::I8, builder, ptr_ty);
            let szv = builder.ins().iconst(ptr_ty, *size as i64);
            builder.call_memset(target_config, dv, vb, szv);
        }

        Instr::BSwap { dest, val, ty } => {
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let v = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let v = coerce(v, cl_ty, builder, ptr_ty);
            let result = builder.ins().bswap(v);
            val_map.insert(dest.0, result);
        }

        Instr::VaStart { list_ptr } => {
            // Point the va_list cursor at the start of the spilled variadic
            // save area. The va_list object stores a single walking pointer.
            if let Some(base) = va_save_area {
                let lp = rval(list_ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
                builder.ins().store(MemFlags::new(), base, lp, 0);
            }
        }

        Instr::VaEnd { .. } => {}

        Instr::VaArg { dest, list_ptr, ty } => {
            // Load the cursor, read the argument, then advance the cursor by one
            // 8-byte slot (integer/pointer varargs are stored one per slot).
            let lp = rval(list_ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cursor = builder.ins().load(ptr_ty, MemFlags::new(), lp, 0);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let v = builder.ins().load(cl_ty, MemFlags::new(), cursor, 0);
            let next = builder.ins().iadd_imm(cursor, 8);
            builder.ins().store(MemFlags::new(), next, lp, 0);
            val_map.insert(dest.0, v);
        }
    }
}

fn emit_terminator(
    term: &Terminator,
    builder: &mut FunctionBuilder<'_>,
    val_map: &HashMap<u32, cir::Value>,
    callee_refs: &HashMap<u32, cir::FuncRef>,
    data_refs: &HashMap<u32, cir::GlobalValue>,
    bb_map: &HashMap<u32, cir::Block>,
    ptr_ty: cir::Type,
) {
    match term {
        Terminator::Ret(None) => { builder.ins().return_(&[]); }
        Terminator::Ret(Some(v)) => {
            let hint = builder.func.signature.returns
                .first().map(|p| p.value_type).unwrap_or(ct::I32);
            let rv = rval(v, val_map, callee_refs, data_refs, builder, ptr_ty, hint);
            let rv = coerce(rv, hint, builder, ptr_ty);
            builder.ins().return_(&[rv]);
        }
        Terminator::Jump(bb) => {
            let cl_bb = bb_map[&bb.0];
            builder.ins().jump(cl_bb, &[]);
        }
        Terminator::CondJump { cond, then_bb, else_bb } => {
            let cv = rval(cond, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I8);
            let then_cl = bb_map[&then_bb.0];
            let else_cl = bb_map[&else_bb.0];
            builder.ins().brif(cv, then_cl, &[], else_cl, &[]);
        }
        Terminator::Switch { val, default, arms } => {
            let v = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I32);
            let default_cl = bb_map[&default.0];
            for (arm_val, arm_bb) in arms {
                let arm_cl = bb_map[&arm_bb.0];
                let next_bb = builder.create_block();
                let eq = builder.ins().icmp_imm(cir::condcodes::IntCC::Equal, v, *arm_val);
                builder.ins().brif(eq, arm_cl, &[], next_bb, &[]);
                builder.seal_block(next_bb);
                builder.switch_to_block(next_bb);
            }
            builder.ins().jump(default_cl, &[]);
        }
        Terminator::Unreachable => {
            builder.ins().trap(cir::TrapCode::STACK_OVERFLOW);
        }
    }
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

fn rval(
    val: &Val,
    val_map: &HashMap<u32, cir::Value>,
    callee_refs: &HashMap<u32, cir::FuncRef>,
    data_refs: &HashMap<u32, cir::GlobalValue>,
    builder: &mut FunctionBuilder<'_>,
    ptr_ty: cir::Type,
    hint: cir::Type,
) -> cir::Value {
    let safe_hint = if hint == ct::INVALID { ct::I64 } else { hint };
    match val {
        Val::Local(id) => val_map.get(&id.0).copied()
            .unwrap_or_else(|| builder.ins().iconst(safe_hint, 0)),
        Val::Const(c)  => emit_const(c, safe_hint, builder, ptr_ty),
        Val::Global(gref) => {
            if let Some(&gv) = data_refs.get(&gref.0) {
                builder.ins().global_value(ptr_ty, gv)
            } else {
                builder.ins().iconst(ptr_ty, 0)
            }
        }
        Val::Func(fref) => {
            if let Some(&cl_fref) = callee_refs.get(&fref.0) {
                builder.ins().func_addr(ptr_ty, cl_fref)
            } else {
                builder.ins().iconst(ptr_ty, 0)
            }
        }
    }
}

fn emit_const(c: &Constant, hint: cir::Type, builder: &mut FunctionBuilder<'_>, ptr_ty: cir::Type) -> cir::Value {
    match c {
        Constant::Int(v) => {
            if hint.is_float() { builder.ins().f64const(*v as f64) }
            else { builder.ins().iconst(hint, *v) }
        }
        Constant::UInt(v) => {
            if hint.is_float() { builder.ins().f64const(*v as f64) }
            else { builder.ins().iconst(hint, *v as i64) }
        }
        Constant::Float(v) => {
            if hint == ct::F32 { builder.ins().f32const(*v as f32) }
            else { builder.ins().f64const(*v) }
        }
        Constant::Bool(b) => builder.ins().iconst(ct::I8, if *b { 1 } else { 0 }),
        Constant::Null | Constant::Undef | Constant::Zeroinit => builder.ins().iconst(hint, 0),
        Constant::Bytes(_) => builder.ins().iconst(ptr_ty, 0),
    }
}

pub fn coerce(v: cir::Value, target: cir::Type, builder: &mut FunctionBuilder<'_>, ptr_ty: cir::Type) -> cir::Value {
    let src = builder.func.dfg.value_type(v);
    if src == target || target == ct::INVALID || src == ct::INVALID { return v; }
    if target.is_float() {
        if src.is_float() {
            return if target.bits() > src.bits() {
                builder.ins().fpromote(target, v)
            } else {
                builder.ins().fdemote(target, v)
            };
        }
        return builder.ins().fcvt_from_sint(target, v);
    }
    if src.is_float() && target.is_int() {
        return builder.ins().fcvt_to_sint_sat(target, v);
    }
    if src.is_int() && target.is_int() {
        return if src.bits() < target.bits() {
            builder.ins().uextend(target, v)
        } else if src.bits() > target.bits() {
            builder.ins().ireduce(target, v)
        } else {
            v
        };
    }
    v
}

fn emit_binop(op: &BinOp, l: cir::Value, r: cir::Value, builder: &mut FunctionBuilder<'_>) -> cir::Value {
    match op {
        BinOp::Add  => builder.ins().iadd(l, r),
        BinOp::Sub  => builder.ins().isub(l, r),
        BinOp::Mul  => builder.ins().imul(l, r),
        BinOp::SDiv => builder.ins().sdiv(l, r),
        BinOp::UDiv => builder.ins().udiv(l, r),
        BinOp::SRem => builder.ins().srem(l, r),
        BinOp::URem => builder.ins().urem(l, r),
        BinOp::FAdd => builder.ins().fadd(l, r),
        BinOp::FSub => builder.ins().fsub(l, r),
        BinOp::FMul => builder.ins().fmul(l, r),
        BinOp::FDiv => builder.ins().fdiv(l, r),
        BinOp::FRem => {
            // fmod(a,b) = a - trunc(a/b) * b
            let q = builder.ins().fdiv(l, r);
            let t = builder.ins().trunc(q);
            let p = builder.ins().fmul(t, r);
            builder.ins().fsub(l, p)
        }
        BinOp::And  => builder.ins().band(l, r),
        BinOp::Or   => builder.ins().bor(l, r),
        BinOp::Xor  => builder.ins().bxor(l, r),
        BinOp::Shl  => builder.ins().ishl(l, r),
        BinOp::AShr => builder.ins().sshr(l, r),
        BinOp::LShr => builder.ins().ushr(l, r),
    }
}

fn emit_cmp(op: &CmpOp, l: cir::Value, r: cir::Value, ty: cir::Type, builder: &mut FunctionBuilder<'_>) -> cir::Value {
    if ty.is_float() {
        let fcc = match op {
            CmpOp::FOEq => cir::condcodes::FloatCC::Equal,
            CmpOp::FONe => cir::condcodes::FloatCC::NotEqual,
            CmpOp::FOLt => cir::condcodes::FloatCC::LessThan,
            CmpOp::FOLe => cir::condcodes::FloatCC::LessThanOrEqual,
            CmpOp::FOGt => cir::condcodes::FloatCC::GreaterThan,
            CmpOp::FOGe => cir::condcodes::FloatCC::GreaterThanOrEqual,
            _ => cir::condcodes::FloatCC::Equal,
        };
        return builder.ins().fcmp(fcc, l, r);
    }
    let icc = match op {
        CmpOp::IEq  => cir::condcodes::IntCC::Equal,
        CmpOp::INe  => cir::condcodes::IntCC::NotEqual,
        CmpOp::ISLt => cir::condcodes::IntCC::SignedLessThan,
        CmpOp::ISLe => cir::condcodes::IntCC::SignedLessThanOrEqual,
        CmpOp::ISGt => cir::condcodes::IntCC::SignedGreaterThan,
        CmpOp::ISGe => cir::condcodes::IntCC::SignedGreaterThanOrEqual,
        CmpOp::IULt => cir::condcodes::IntCC::UnsignedLessThan,
        CmpOp::IULe => cir::condcodes::IntCC::UnsignedLessThanOrEqual,
        CmpOp::IUGt => cir::condcodes::IntCC::UnsignedGreaterThan,
        CmpOp::IUGe => cir::condcodes::IntCC::UnsignedGreaterThanOrEqual,
        _           => cir::condcodes::IntCC::Equal,
    };
    builder.ins().icmp(icc, l, r)
}

fn emit_cast(
    val: cir::Value, src: cir::Type, op: CastOp, dst: cir::Type,
    builder: &mut FunctionBuilder<'_>, ptr_ty: cir::Type,
) -> cir::Value {
    if src == dst { return val; }
    match op {
        CastOp::SExt => {
            if dst.bits() > src.bits() { builder.ins().sextend(dst, val) }
            else if dst.bits() < src.bits() { builder.ins().ireduce(dst, val) }
            else { val }
        }
        CastOp::ZExt | CastOp::BoolToInt => {
            if dst.bits() > src.bits() { builder.ins().uextend(dst, val) }
            else if dst.bits() < src.bits() { builder.ins().ireduce(dst, val) }
            else { val }
        }
        CastOp::Trunc => {
            if dst.bits() < src.bits() { builder.ins().ireduce(dst, val) }
            else { coerce(val, dst, builder, ptr_ty) }
        }
        CastOp::BitCast | CastOp::IntToPtr | CastOp::PtrToInt => coerce(val, dst, builder, ptr_ty),
        CastOp::SIToFP  => builder.ins().fcvt_from_sint(dst, val),
        CastOp::UIToFP  => builder.ins().fcvt_from_uint(dst, val),
        CastOp::FPToSI  => builder.ins().fcvt_to_sint_sat(dst, val),
        CastOp::FPToUI  => {
            // C (unsigned T)x where x is negative is UB; most platforms treat it
            // as sign-conversion: cast to signed then reinterpret as unsigned.
            builder.ins().fcvt_to_sint_sat(dst, val)
        }
        CastOp::FPExt   => builder.ins().fpromote(dst, val),
        CastOp::FPTrunc => builder.ins().fdemote(dst, val),
    }
}
