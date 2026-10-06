use std::collections::HashMap;
use cranelift_codegen::ir::{self as cir, InstBuilder, MemFlagsData};
use cranelift_codegen::ir::types as ct;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_module::{FuncId, DataId, Module};
use cranelift_object::ObjectModule;
use sic_ir::*;
use super::types::{cl_type, ptr_cl, vector_clty};
use super::{build_cl_sig, va_named_reg_counts, VA_GP_REGS, VA_FP_REGS, VA_OVERFLOW_SLOTS};

/// Runtime handles for a variadic function's System V register save area, used
/// by `va_start`/`va_arg`. See `compile_function`'s prologue.
#[derive(Clone, Copy)]
struct VaInfo {
    /// Pointer to the 176-byte register save area (48B GP + 128B XMM).
    reg_save: cir::Value,
    /// Pointer to the captured stack overflow area.
    overflow: cir::Value,
    /// Initial `gp_offset`: named GP args * 8.
    gp_start: u32,
    /// Initial `fp_offset`: 48 + named FP args * 16.
    fp_start: u32,
}

/// A source variable's debug info collected during codegen: its name, IR type,
/// the Cranelift stack slot it lives in, and whether it is a formal parameter.
// Fields are currently unread: Cranelift 0.132 dropped the `CompiledCode` frame-size
// / stack-slot-offset accessors used to emit per-variable DWARF locations. Kept for
// the planned rewiring through `value_labels_ranges`.
#[allow(dead_code)]
pub struct VarDbg {
    pub name: String,
    pub ty: sic_ir::Type,
    pub slot: cir::StackSlot,
    pub is_param: bool,
}

pub fn compile_function(
    f: &Function,
    module_ir: &sic_ir::Module,
    obj_module: &mut ObjectModule,
    func_ids: &HashMap<u32, FuncId>,
    global_ids: &HashMap<u32, DataId>,
    cl_func: &mut cir::Function,
    ptr_size: u32,
    var_dbg: &mut Vec<VarDbg>,
) -> Result<(), super::CraneliftError> {
    if f.blocks.is_empty() { return Ok(()); }

    let mut fbctx = FunctionBuilderContext::new();
    let mut builder = FunctionBuilder::new(cl_func, &mut fbctx);
    let ptr_ty = ptr_cl(ptr_size);
    let target_config = obj_module.target_config();

    // If this function returns a small aggregate in registers, the return
    // terminator gets a pointer to the value and must load these eightbytes into
    // the return registers.
    let ret_chunks: Option<Vec<sic_ir::abi::Chunk>> = match &f.sig.ret {
        sic_ir::Type::Struct(_) | sic_ir::Type::Union(_) => {
            match sic_ir::abi::classify_struct_union(&f.sig.ret, ptr_size) {
                sic_ir::abi::AggClass::Regs(chunks) => Some(chunks),
                sic_ir::abi::AggClass::Memory(_) => None,
            }
        }
        _ => None,
    };

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
    let mut va_info: Option<VaInfo> = None;
    {
        let params = builder.block_params(entry_cl).to_vec();
        let named = f.params.len();
        // Bind each named IR param to its entry-block value(s). A small struct/union
        // (Direct) arrives spread across several block params (one per eightbyte);
        // reconstruct it into a fresh slot and bind the sentinel to that pointer, so
        // the body — which treats every aggregate as a pointer — sees what it expects.
        // A ByValStack aggregate already arrives as a pointer (Cranelift's copy).
        let mut bp = 0usize; // entry-block param cursor
        for i in 0..named {
            let pty = &f.params[i].ty;
            match crate::abi::classify_param(pty, ptr_size) {
                crate::abi::ParamPass::Scalar(_) | crate::abi::ParamPass::ByValStack(_) => {
                    if bp < params.len() {
                        val_map.insert(0x10000 + i as u32, params[bp]);
                    }
                    bp += 1;
                }
                crate::abi::ParamPass::Direct(chunks) => {
                    let size = pty.size_of(ptr_size) as u32;
                    let align = pty.align_of(ptr_size).max(1);
                    let slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                        cir::StackSlotKind::ExplicitSlot, size, align.trailing_zeros() as u8,
                    ));
                    let addr = builder.ins().stack_addr(ptr_ty, slot, 0);
                    for c in &chunks {
                        if bp < params.len() {
                            crate::abi::store_chunk(&mut builder, params[bp], addr, c);
                        }
                        bp += 1;
                    }
                    val_map.insert(0x10000 + i as u32, addr);
                }
            }
        }
        if f.sig.variadic {
            // Reconstruct the System V register save area from the over-declared
            // trailing params (see `build_cl_sig_def`): GP fillers, then FP
            // fillers, then stack-overflow slots. Only the *vararg* slots need
            // correct values — `va_arg`/glibc never read below `gp_offset`/
            // `fp_offset`, which start past the named params.
            let (n_gp, n_fp) = va_named_reg_counts(&f.sig, ptr_size);
            let rsa_slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                cir::StackSlotKind::ExplicitSlot, 176, 4, // 16-byte aligned
            ));
            let reg_save = builder.ins().stack_addr(ptr_ty, rsa_slot, 0);
            let ovf_slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                cir::StackSlotKind::ExplicitSlot, (VA_OVERFLOW_SLOTS * 8) as u32, 3,
            ));
            let overflow = builder.ins().stack_addr(ptr_ty, ovf_slot, 0);

            let n_gp_fill = VA_GP_REGS - n_gp;
            let n_fp_fill = VA_FP_REGS - n_fp;
            // The over-declared va filler params follow the (possibly expanded)
            // named params, so start at the block-param cursor, not the IR count.
            let mut idx = bp;
            for k in 0..n_gp_fill {
                if idx < params.len() {
                    builder.ins().store(MemFlagsData::new(), params[idx], reg_save, ((n_gp + k) * 8) as i32);
                }
                idx += 1;
            }
            for k in 0..n_fp_fill {
                if idx < params.len() {
                    builder.ins().store(MemFlagsData::new(), params[idx], reg_save, (48 + (n_fp + k) * 16) as i32);
                }
                idx += 1;
            }
            for k in 0..VA_OVERFLOW_SLOTS {
                if idx < params.len() {
                    builder.ins().store(MemFlagsData::new(), params[idx], overflow, (k * 8) as i32);
                }
                idx += 1;
            }
            va_info = Some(VaInfo {
                reg_save, overflow,
                gp_start: (n_gp * 8) as u32,
                fp_start: (48 + n_fp * 16) as u32,
            });
        }
    }

    // Emit all blocks.
    // ValId → stack slot (for `Alloca`s), so `DbgVar` can resolve a variable's
    // storage to a Cranelift stack slot for the DWARF location.
    let mut slot_map: HashMap<u32, cir::StackSlot> = HashMap::new();

    // mem2reg for pointer locals (register promotion). An `Alloca` of pointer type
    // whose address never escapes — its ValId is used ONLY as the `ptr` of a
    // Load/Store (never stored elsewhere, GEP'd, passed to a call, memset, …) —
    // becomes a Cranelift `Variable` instead of a stack slot. Cranelift's SSA
    // builder then keeps it in a register with automatic phi insertion, so the
    // pointer isn't reloaded from the stack on every use — which in turn lets the
    // mid-end hoist loop-invariant pointer loads and the `readonly` bounds-size
    // loads that depend on them out of hot loops. Pointer type is required so
    // `def_var` always sees a `ptr_ty`-typed value (sound without tracking every
    // stored value's type). A local with no initializer is zero-set with `MemSet`,
    // which uses the slot address → it escapes and stays a stack slot.
    let mut escaped: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for bb in &f.blocks {
        for instr in &bb.instrs {
            match instr {
                // The `ptr` of a load/store is a legitimate slot use, not an escape.
                Instr::Load { .. } | Instr::LoadReadonly { .. } => {}
                Instr::Store { val, ptr: _ } => {
                    if let Val::Local(id) = val { escaped.insert(id.0); }
                }
                other => other.for_each_val(|v| if let Val::Local(id) = v { escaped.insert(id.0); }),
            }
        }
        bb.terminator.for_each_val(|v| if let Val::Local(id) = v { escaped.insert(id.0); });
    }
    // Cranelift type of a slot: a pointer is `ptr_ty`, any other scalar is its
    // `cl_type` (aggregates return None → not promotable).
    let slot_clty = |t: &Type| if matches!(t, Type::Pointer(_)) { Some(ptr_ty) }
        else if let Some(vt) = vector_clty(t) { Some(vt) }
        else { cl_type(t, ptr_size) };
    let mut promoted: HashMap<u32, (Variable, cir::Type)> = HashMap::new();
    for bb in &f.blocks {
        for instr in &bb.instrs {
            if let Instr::Alloca { dest, ty, .. } = instr {
                if escaped.contains(&dest.0) { continue; }
                // Aggregates (arrays/structs/unions) are memory objects, never a
                // scalar register — EXCEPT a 128-bit SIMD-vector array, which we
                // promote to a vector register (Variable) so chained vector ops
                // (`vc + va*vb`) stay in XMM instead of round-tripping through the
                // stack slot on every step. A vector slot that escapes (its address
                // taken, MemCopy'd, or accessed lane-by-lane via PtrOffset) already
                // failed the escape/consistency checks, so it stays in memory.
                let is_simd_vec = vector_clty(ty).is_some();
                if !is_simd_vec && matches!(ty, Type::Array { .. } | Type::Struct(_) | Type::Union(_)) { continue; }
                let ct = match slot_clty(ty) { Some(t) => t, None => continue };
                // Require every load of this slot to read exactly the slot type — a
                // load of a different width/category is a type-pun that relies on the
                // memory layout, so leave such a slot in memory (sound).
                let mut consistent = true;
                'scan: for b2 in &f.blocks {
                    for i2 in &b2.instrs {
                        if let Instr::Load { ptr: Val::Local(p), ty: lty, .. } = i2 {
                            if p.0 == dest.0 && slot_clty(lty) != Some(ct) { consistent = false; break 'scan; }
                        }
                    }
                }
                if !consistent { continue; }
                let var = builder.declare_var(ct);
                promoted.insert(dest.0, (var, ct));
            }
        }
    }

    // Materialize every non-promoted `Alloca`'s address in the entry block up front.
    // A stack slot is function-global, but its `stack_addr` value must dominate all
    // uses — and an `Alloca` can appear inside a non-entry block (e.g. a local
    // declared in a `switch` case), whose address would otherwise be referenced
    // from sibling blocks it does not dominate. The current fill block here is
    // still the entry block.
    for bb in &f.blocks {
        for instr in &bb.instrs {
            if let Instr::Alloca { dest, ty, align } = instr {
                if promoted.contains_key(&dest.0) { continue; }
                let size = ty.size_of(ptr_size).max(1) as u32;
                let mut align_bytes = ty.align_of(ptr_size).max(1) as u32;
                if let Some(req) = align { align_bytes = align_bytes.max(*req); }
                let align_bytes = align_bytes.next_power_of_two();
                let align_shift = align_bytes.trailing_zeros() as u8;
                let slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                    cir::StackSlotKind::ExplicitSlot, size, align_shift,
                ));
                let addr = builder.ins().stack_addr(ptr_ty, slot, 0);
                slot_map.insert(dest.0, slot);
                val_map.insert(dest.0, addr);
            }
        }
    }

    for (bi, bb) in f.blocks.iter().enumerate() {
        if bi > 0 {
            let cl_bb = bb_map[&bb.id.0];
            builder.switch_to_block(cl_bb);
        }
        for instr in &bb.instrs {
            emit_instr(
                instr, &mut builder, &mut val_map, &callee_refs, &data_refs,
                ptr_ty, target_config, ptr_size, va_info,
                &mut slot_map, var_dbg, module_ir, &promoted,
            );
        }
        emit_terminator(&bb.terminator, &mut builder, &val_map, &callee_refs, &data_refs, &bb_map, ptr_ty, ret_chunks.as_deref());
    }

    builder.seal_all_blocks();
    builder.finalize(target_config);
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
    va_info: Option<VaInfo>,
    slot_map: &mut HashMap<u32, cir::StackSlot>,
    var_dbg: &mut Vec<VarDbg>,
    module_ir: &sic_ir::Module,
    promoted: &HashMap<u32, (Variable, cir::Type)>,
) {
    match instr {
        Instr::Alloca { dest, ty, align } => {
            // A register-promoted scalar local has no stack slot (it is a Variable).
            if promoted.contains_key(&dest.0) { return; }
            // Already materialized in the entry block by the up-front pre-pass.
            if slot_map.contains_key(&dest.0) { return; }
            let size = ty.size_of(ptr_size).max(1) as u32;
            // `_Alignas` overrides the natural alignment (take the larger).
            let mut align_bytes = ty.align_of(ptr_size).max(1) as u32;
            if let Some(req) = align {
                align_bytes = align_bytes.max(*req);
            }
            let align_bytes = align_bytes.next_power_of_two();
            // StackSlotData takes align as log2(bytes), not bytes
            let align_shift = align_bytes.trailing_zeros() as u8;
            let slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                cir::StackSlotKind::ExplicitSlot,
                size,
                align_shift,
            ));
            let addr = builder.ins().stack_addr(ptr_ty, slot, 0);
            slot_map.insert(dest.0, slot);
            val_map.insert(dest.0, addr);
        }

        Instr::Load { dest, ptr, ty } => {
            // Reading a register-promoted scalar local: use the SSA value directly
            // (no memory load), so it stays in a register. Every load of a promoted
            // slot matches the slot type by construction, so no coercion is needed.
            if let Val::Local(id) = ptr {
                if let Some(&(var, _)) = promoted.get(&id.0) {
                    let v = builder.use_var(var);
                    val_map.insert(dest.0, v);
                    return;
                }
            }
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            // A vector-typed load reads a whole XMM register in one unaligned move
            // (the `new[]`/stack arrays these come from are only element-aligned).
            let cl_ty = vector_clty(ty).unwrap_or_else(|| cl_type(ty, ptr_size).unwrap_or(ct::I32));
            let v = builder.ins().load(cl_ty, MemFlagsData::new(), pv, 0);
            val_map.insert(dest.0, v);
        }

        // Load from immutable, always-mapped memory (a `new[]` size/rc header):
        // `readonly` lets the mid-end hoist/CSE it (e.g. a loop-invariant bounds
        // size out of a hot loop); `notrap` says it can never fault.
        Instr::LoadReadonly { dest, ptr, ty } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let flags = MemFlagsData::new().with_readonly().with_notrap();
            let v = builder.ins().load(cl_ty, flags, pv, 0);
            val_map.insert(dest.0, v);
        }

        Instr::Store { val, ptr } => {
            // Writing a register-promoted scalar local: define the SSA variable (no
            // memory store), coercing the value to the variable's type — an
            // int/float resize matches what a narrower/wider memory store would have
            // done, so `def_var` never sees a type mismatch.
            if let Val::Local(id) = ptr {
                if let Some(&(var, vt)) = promoted.get(&id.0) {
                    let sv0 = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, vt);
                    let sv = coerce_scalar(builder, sv0, vt);
                    builder.def_var(var, sv);
                    return;
                }
            }
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            // Infer hint from existing value if available
            let hint = if let Val::Local(id) = val {
                val_map.get(&id.0).map(|&v| builder.func.dfg.value_type(v)).unwrap_or(ct::I32)
            } else { ct::I32 };
            let sv = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, hint);
            builder.ins().store(MemFlagsData::new(), sv, pv, 0);
        }

        // Atomic operations (sic `atomic` types). All sequentially consistent —
        // Cranelift lowers these to the locked/fenced x86 sequences.
        Instr::AtomicLoad { dest, ptr, ty } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let v = builder.ins().atomic_load(cl_ty, MemFlagsData::new(), pv);
            val_map.insert(dest.0, v);
        }
        Instr::AtomicStore { ptr, val, ty } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let sv = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let sv = coerce(sv, cl_ty, builder, ptr_ty);
            builder.ins().atomic_store(MemFlagsData::new(), sv, pv);
        }
        Instr::AtomicRmw { dest, op, ptr, val, ty } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let xv = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let xv = coerce(xv, cl_ty, builder, ptr_ty);
            let clop = match op {
                AtomicOp::Add  => cir::AtomicRmwOp::Add,
                AtomicOp::Sub  => cir::AtomicRmwOp::Sub,
                AtomicOp::And  => cir::AtomicRmwOp::And,
                AtomicOp::Or   => cir::AtomicRmwOp::Or,
                AtomicOp::Xor  => cir::AtomicRmwOp::Xor,
                AtomicOp::Xchg => cir::AtomicRmwOp::Xchg,
            };
            let old = builder.ins().atomic_rmw(cl_ty, MemFlagsData::new(), clop, pv, xv);
            val_map.insert(dest.0, old);
        }
        Instr::AtomicCas { dest, ptr, expected, desired, ty } => {
            let pv = rval(ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let ev = rval(expected, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let ev = coerce(ev, cl_ty, builder, ptr_ty);
            let dv = rval(desired, val_map, callee_refs, data_refs, builder, ptr_ty, cl_ty);
            let dv = coerce(dv, cl_ty, builder, ptr_ty);
            // Returns the observed old value; success is old == expected (the
            // frontend does that comparison for `.cas() -> bool`).
            let old = builder.ins().atomic_cas(MemFlagsData::new(), pv, ev, dv);
            val_map.insert(dest.0, old);
        }

        Instr::BinOp { dest, op, lhs, rhs, ty } => {
            // A vector-typed binop takes two whole XMM values (from vector loads)
            // and lowers to one real SIMD instruction; feed them straight to
            // `emit_binop` (the scalar `coerce`/`cl_type` path would treat the
            // array type as a pointer and corrupt the operands).
            if let Some(vt) = vector_clty(ty) {
                let l = rval(lhs, val_map, callee_refs, data_refs, builder, ptr_ty, vt);
                let r = rval(rhs, val_map, callee_refs, data_refs, builder, ptr_ty, vt);
                let v = emit_binop(op, l, r, builder);
                val_map.insert(dest.0, v);
                return;
            }
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
                UnOp::Clz    => builder.ins().clz(v),
                UnOp::Ctz    => builder.ins().ctz(v),
                UnOp::Popcnt => builder.ins().popcnt(v),
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

        Instr::Cmp { dest, op, lhs, rhs, ty } => {
            // A vector-typed comparison is a per-lane SIMD compare: both operands
            // are whole XMM values and the result is a lane mask (all-ones per
            // matching lane). Feed them straight through — the scalar path would
            // treat the array type as a pointer and corrupt them.
            if let Some(vt) = vector_clty(ty) {
                let l = rval(lhs, val_map, callee_refs, data_refs, builder, ptr_ty, vt);
                let r = rval(rhs, val_map, callee_refs, data_refs, builder, ptr_ty, vt);
                let v = emit_cmp(op, l, r, vt, builder);
                val_map.insert(dest.0, v);
                return;
            }
            // Materialize both operands at the comparison's declared type so a
            // constant operand isn't truncated to a narrower guessed width.
            let cmp_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let l = rval(lhs, val_map, callee_refs, data_refs, builder, ptr_ty, cmp_ty);
            let r = rval(rhs, val_map, callee_refs, data_refs, builder, ptr_ty, cmp_ty);
            let l = coerce(l, cmp_ty, builder, ptr_ty);
            let r = coerce(r, cmp_ty, builder, ptr_ty);
            let v = emit_cmp(op, l, r, cmp_ty, builder);
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

            // A variadic callee's declared signature is padded with trailing
            // GP/FP filler params (see `build_cl_sig_def`) that only exist so the
            // *callee* can spill argument registers. At a call site those fillers
            // must be ignored: arguments past the real named parameters are
            // variadic and must be passed in their natural register class (so a
            // `double` lands in XMM, not a GP filler slot). Use the real named
            // parameter count from the IR as the boundary.
            let ir_sig = module_ir.func_sig(*func);
            let named_count = ir_sig.params.len();
            let is_variadic = ir_sig.variadic;
            let _ = &param_tys;
            let (arg_vals, _named_cl) = marshal_args(
                args, &ir_sig.params, named_count, is_variadic, ptr_size,
                val_map, callee_refs, data_refs, builder, ptr_ty,
            );

            let inst = if is_variadic {
                // Named (already ABI-expanded) params + the actual variadic arg
                // types. Cranelift's SysV lowering places each in its natural class.
                let base = &builder.func.stencil.dfg.signatures[sig_ref];
                let mut new_sig = cir::Signature::new(base.call_conv);
                new_sig.returns = base.returns.clone();
                for v in &arg_vals {
                    let ty = builder.func.dfg.value_type(*v);
                    new_sig.params.push(cir::AbiParam::new(ty));
                }
                let new_sig_ref = builder.func.import_signature(new_sig);
                let faddr = builder.ins().func_addr(ptr_ty, cl_fref);
                builder.ins().call_indirect(new_sig_ref, faddr, &arg_vals)
            } else if arg_vals.len() != declared_count {
                // Argument count doesn't match the declared (expanded) signature —
                // e.g. a no-prototype/K&R call. Build a signature from the actual
                // marshalled values.
                let base = &builder.func.stencil.dfg.signatures[sig_ref];
                let mut new_sig = cir::Signature::new(base.call_conv);
                new_sig.returns = base.returns.clone();
                for v in &arg_vals {
                    let ty = builder.func.dfg.value_type(*v);
                    new_sig.params.push(cir::AbiParam::new(ty));
                }
                let new_sig_ref = builder.func.import_signature(new_sig);
                let faddr = builder.ins().func_addr(ptr_ty, cl_fref);
                builder.ins().call_indirect(new_sig_ref, faddr, &arg_vals)
            } else {
                builder.ins().call(cl_fref, &arg_vals)
            };
            let results = builder.inst_results(inst).to_vec();
            bind_call_result(dest, &results, ret_ty, ptr_size, builder, ptr_ty, val_map);
        }

        Instr::CallIndirect { dest, fptr, args, ret_ty, func_ty } => {
            let base_sig = build_cl_sig(func_ty, ptr_size, builder.func.signature.call_conv);
            let fp = rval(fptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let (arg_vals, _named_cl) = marshal_args(
                args, &func_ty.params, func_ty.params.len(), func_ty.variadic, ptr_size,
                val_map, callee_refs, data_refs, builder, ptr_ty,
            );
            // Build the call signature from the marshalled values: base returns
            // plus the actual (ABI-expanded / variadic) argument types.
            let mut sig = cir::Signature::new(base_sig.call_conv);
            sig.returns = base_sig.returns.clone();
            for v in &arg_vals {
                let ty = builder.func.dfg.value_type(*v);
                sig.params.push(cir::AbiParam::new(ty));
            }
            let sig_ref = builder.func.import_signature(sig);
            let inst = builder.ins().call_indirect(sig_ref, fp, &arg_vals);
            let results = builder.inst_results(inst).to_vec();
            bind_call_result(dest, &results, ret_ty, ptr_size, builder, ptr_ty, val_map);
        }

        Instr::GetElemPtr { dest, base, index, elem_size, .. } => {
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
            let addr = builder.ins().iadd_imm_s(bv, *byte_offset as i64);
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
            let cb = builder.ins().icmp_imm_s(cir::condcodes::IntCC::NotEqual, cv, 0);
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

        Instr::VecMoveMask { dest, val, ty } => {
            // Extract each lane's high bit into a scalar bitmask (x86 `pmovmskb`).
            // `val` is a SIMD vector; feed it straight through (the scalar path
            // would misread the vector type as a pointer). The result is an i32.
            let vt = vector_clty(ty).unwrap_or(ct::I8X16);
            let v = rval(val, val_map, callee_refs, data_refs, builder, ptr_ty, vt);
            let result = builder.ins().vhigh_bits(ct::I32, v);
            val_map.insert(dest.0, result);
        }

        Instr::VaStart { list_ptr } => {
            // Initialize the System V va_list tag:
            //   {u32 gp_offset; u32 fp_offset; void* overflow; void* reg_save;}
            if let Some(va) = va_info {
                let lp = rval(list_ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
                let gp = builder.ins().iconst(ct::I32, va.gp_start as i64);
                builder.ins().store(MemFlagsData::new(), gp, lp, 0);
                let fp = builder.ins().iconst(ct::I32, va.fp_start as i64);
                builder.ins().store(MemFlagsData::new(), fp, lp, 4);
                builder.ins().store(MemFlagsData::new(), va.overflow, lp, 8);
                builder.ins().store(MemFlagsData::new(), va.reg_save, lp, 16);
            }
        }

        Instr::VaEnd { .. } => {}

        Instr::ReturnAddress { dest } => {
            // `__builtin_return_address(0)` — QEMU's GETPC() restart pointer.
            let v = builder.ins().get_return_address(ptr_ty);
            val_map.insert(dest.0, v);
        }

        Instr::VaArg { dest, list_ptr, ty } => {
            // Walk the System V va_list: integer/pointer args come from the GP
            // region (gp_offset < 48) or the overflow area; floating-point args
            // from the FP region (fp_offset < 176) or overflow. Update whichever
            // cursor advanced. No branches: addresses/offsets are chosen with
            // `select`.
            let lp = rval(list_ptr, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
            let cl_ty = cl_type(ty, ptr_size).unwrap_or(ct::I32);
            let is_fp = cl_ty.is_float();
            let (off_field, threshold, step): (i32, i64, i64) =
                if is_fp { (4, 176, 16) } else { (0, 48, 8) };

            let offset = builder.ins().load(ct::I32, MemFlagsData::new(), lp, off_field);
            let offset64 = builder.ins().uextend(ct::I64, offset);
            let reg_save = builder.ins().load(ptr_ty, MemFlagsData::new(), lp, 16);
            let overflow = builder.ins().load(ptr_ty, MemFlagsData::new(), lp, 8);

            let thr = builder.ins().iconst(ct::I32, threshold);
            let in_reg = builder.ins().icmp(IntCC::UnsignedLessThan, offset, thr);

            let reg_addr = builder.ins().iadd(reg_save, offset64);
            let new_off = builder.ins().iadd_imm_s(offset, step);
            let new_ovf = builder.ins().iadd_imm_s(overflow, 8);

            let addr = builder.ins().select(in_reg, reg_addr, overflow);
            // Advance gp/fp_offset only when the value came from a register.
            let stored_off = builder.ins().select(in_reg, new_off, offset);
            builder.ins().store(MemFlagsData::new(), stored_off, lp, off_field);
            // Advance overflow only when the value came from the stack.
            let stored_ovf = builder.ins().select(in_reg, overflow, new_ovf);
            builder.ins().store(MemFlagsData::new(), stored_ovf, lp, 8);

            let v = builder.ins().load(cl_ty, MemFlagsData::new(), addr, 0);
            val_map.insert(dest.0, v);
        }

        // Debug marker: tag subsequently-emitted instructions with this source
        // line. Cranelift records it per machine instruction, which we later
        // read back (`get_srclocs_sorted`) to build the DWARF line table.
        Instr::SrcLine(line) => {
            builder.set_srcloc(cir::SourceLoc::new(*line));
        }

        // Record the variable→stack-slot association for DWARF (no code).
        Instr::DbgVar { name, ty, slot, is_param } => {
            if let Some(&stack_slot) = slot_map.get(&slot.0) {
                var_dbg.push(VarDbg {
                    name: name.clone(),
                    ty: ty.clone(),
                    slot: stack_slot,
                    is_param: *is_param,
                });
            }
        }
    }
}

/// Apply C default argument promotions to a variadic argument: `float` widens
/// to `double` (so it occupies an XMM register per the ABI). Integer/pointer
/// values keep their class.
fn va_promote(v: cir::Value, builder: &mut FunctionBuilder<'_>) -> cir::Value {
    if builder.func.dfg.value_type(v) == ct::F32 {
        builder.ins().fpromote(ct::F64, v)
    } else {
        v
    }
}

/// Bind a call's result(s) to its `dest`. A small aggregate returns in registers
/// (one value per eightbyte); reconstruct it into a fresh slot and bind `dest` to
/// that pointer (aggregates flow as pointers). Scalars bind directly.
fn bind_call_result(
    dest: &Option<ValId>,
    results: &[cir::Value],
    ret_ty: &sic_ir::Type,
    ptr_size: u32,
    builder: &mut FunctionBuilder<'_>,
    ptr_ty: cir::Type,
    val_map: &mut HashMap<u32, cir::Value>,
) {
    let Some(d) = dest else { return };
    if results.is_empty() {
        return;
    }
    if matches!(ret_ty, sic_ir::Type::Struct(_) | sic_ir::Type::Union(_)) {
        if let sic_ir::abi::AggClass::Regs(chunks) =
            sic_ir::abi::classify_struct_union(ret_ty, ptr_size)
        {
            let size = ret_ty.size_of(ptr_size) as u32;
            let align = ret_ty.align_of(ptr_size).max(1);
            let slot = builder.create_sized_stack_slot(cir::StackSlotData::new(
                cir::StackSlotKind::ExplicitSlot, size, align.trailing_zeros() as u8,
            ));
            let addr = builder.ins().stack_addr(ptr_ty, slot, 0);
            for (c, r) in chunks.iter().zip(results) {
                crate::abi::store_chunk(builder, *r, addr, c);
            }
            val_map.insert(d.0, addr);
            return;
        }
    }
    val_map.insert(d.0, results[0]);
}

/// Marshal IR call arguments into Cranelift values per the System V ABI:
/// a small aggregate (Direct) is loaded from its pointer into one value per
/// eightbyte; a MEMORY aggregate (ByValStack) is passed as a pointer (Cranelift
/// copies it to the stack); scalars pass through with coercion. Arguments past
/// `named` are variadic and get the C default promotions in their natural class.
/// Returns the flat value list and how many values the *named* portion produced.
#[allow(clippy::too_many_arguments)]
fn marshal_args(
    args: &[Val],
    ir_params: &[sic_ir::Type],
    named: usize,
    is_variadic: bool,
    ptr_size: u32,
    val_map: &HashMap<u32, cir::Value>,
    callee_refs: &HashMap<u32, cir::FuncRef>,
    data_refs: &HashMap<u32, cir::GlobalValue>,
    builder: &mut FunctionBuilder<'_>,
    ptr_ty: cir::Type,
) -> (Vec<cir::Value>, usize) {
    let mut out: Vec<cir::Value> = Vec::with_capacity(args.len());
    let mut named_cl = 0usize;
    for (i, a) in args.iter().enumerate() {
        let is_named = !is_variadic || i < named;
        if is_named && i < ir_params.len() {
            match crate::abi::classify_param(&ir_params[i], ptr_size) {
                crate::abi::ParamPass::Scalar(t) => {
                    let v = rval(a, val_map, callee_refs, data_refs, builder, ptr_ty, t);
                    out.push(coerce(v, t, builder, ptr_ty));
                }
                crate::abi::ParamPass::ByValStack(_) => {
                    let v = rval(a, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
                    out.push(coerce(v, ptr_ty, builder, ptr_ty));
                }
                crate::abi::ParamPass::Direct(chunks) => {
                    let base = rval(a, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
                    for c in &chunks {
                        let v = crate::abi::load_chunk(builder, base, c);
                        out.push(v);
                    }
                }
            }
            named_cl = out.len();
        } else {
            // Variadic (or over-provided) argument.
            let v = rval(a, val_map, callee_refs, data_refs, builder, ptr_ty, ct::I64);
            out.push(va_promote(v, builder));
        }
    }
    (out, named_cl)
}

fn emit_terminator(
    term: &Terminator,
    builder: &mut FunctionBuilder<'_>,
    val_map: &HashMap<u32, cir::Value>,
    callee_refs: &HashMap<u32, cir::FuncRef>,
    data_refs: &HashMap<u32, cir::GlobalValue>,
    bb_map: &HashMap<u32, cir::Block>,
    ptr_ty: cir::Type,
    ret_chunks: Option<&[sic_ir::abi::Chunk]>,
) {
    match term {
        Terminator::Ret(None) => { builder.ins().return_(&[]); }
        Terminator::Ret(Some(v)) => {
            if let Some(chunks) = ret_chunks {
                // Small aggregate return: `v` is a pointer to the value; load each
                // eightbyte into its return register.
                let base = rval(v, val_map, callee_refs, data_refs, builder, ptr_ty, ptr_ty);
                let rets: Vec<cir::Value> =
                    chunks.iter().map(|c| crate::abi::load_chunk(builder, base, c)).collect();
                builder.ins().return_(&rets);
            } else {
                let hint = builder.func.signature.returns
                    .first().map(|p| p.value_type).unwrap_or(ct::I32);
                let rv = rval(v, val_map, callee_refs, data_refs, builder, ptr_ty, hint);
                let rv = coerce(rv, hint, builder, ptr_ty);
                builder.ins().return_(&[rv]);
            }
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
                let eq = builder.ins().icmp_imm_s(cir::condcodes::IntCC::Equal, v, *arm_val);
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

/// Coerce a scalar Cranelift value to `to` for a promoted-variable `def_var`:
/// int↔int resize (matching a narrower/wider memory store), float↔float resize, or
/// a same-width bitcast across categories. A no-op when already `to`.
fn coerce_scalar(builder: &mut FunctionBuilder<'_>, v: cir::Value, to: cir::Type) -> cir::Value {
    let from = builder.func.dfg.value_type(v);
    if from == to { return v; }
    if from.is_int() && to.is_int() {
        if from.bits() < to.bits() { builder.ins().uextend(to, v) } else { builder.ins().ireduce(to, v) }
    } else if from.is_float() && to.is_float() {
        if from.bits() < to.bits() { builder.ins().fpromote(to, v) } else { builder.ins().fdemote(to, v) }
    } else if from.bits() == to.bits() {
        builder.ins().bitcast(to, MemFlagsData::new(), v)
    } else {
        v // width+category mismatch — not produced for a promoted scalar local
    }
}

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
                // A TLS symbol is accessed through the TLS ABI (%fs-relative /
                // __tls_get_addr), not a plain GOT/PC-relative address.
                let is_tls = matches!(
                    builder.func.global_values[gv],
                    cir::GlobalValueData::Symbol { tls: true, .. }
                );
                if is_tls {
                    builder.ins().tls_value(ptr_ty, gv)
                } else {
                    builder.ins().symbol_value(ptr_ty, gv)
                }
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

/// Choose an integer type that can hold `v` without truncation. If the value
/// fits the requested `hint` width it is used as-is; otherwise it is widened to
/// i64. This prevents a 64-bit constant from being silently masked to 32 bits
/// when a caller passes a narrow hint.
fn int_const_type(fits: bool, hint: cir::Type) -> cir::Type {
    if fits { hint } else { ct::I64 }
}

fn emit_const(c: &Constant, hint: cir::Type, builder: &mut FunctionBuilder<'_>, ptr_ty: cir::Type) -> cir::Value {
    match c {
        Constant::Int(v) => {
            if hint.is_float() { builder.ins().f64const(*v as f64) }
            // Cranelift's `iconst` maxes out at I64; build an I128 by extending
            // a 64-bit const (sign-extend a signed constant).
            else if hint == ct::I128 {
                let lo = builder.ins().iconst(ct::I64, *v);
                builder.ins().sextend(ct::I128, lo)
            }
            else {
                let fits = match hint.bits() {
                    8  => *v >= i8::MIN as i64 && *v <= u8::MAX as i64,
                    16 => *v >= i16::MIN as i64 && *v <= u16::MAX as i64,
                    32 => *v >= i32::MIN as i64 && *v <= u32::MAX as i64,
                    _  => true,
                };
                builder.ins().iconst(int_const_type(fits, hint), *v)
            }
        }
        Constant::UInt(v) => {
            if hint.is_float() { builder.ins().f64const(*v as f64) }
            else if hint == ct::I128 {
                let lo = builder.ins().iconst(ct::I64, *v as i64);
                builder.ins().uextend(ct::I128, lo)
            }
            else {
                let fits = match hint.bits() {
                    8  => *v <= u8::MAX as u64,
                    16 => *v <= u16::MAX as u64,
                    32 => *v <= u32::MAX as u64,
                    _  => true,
                };
                builder.ins().iconst(int_const_type(fits, hint), *v as i64)
            }
        }
        Constant::Float(v) => {
            if hint == ct::F32 { builder.ins().f32const(*v as f32) }
            else { builder.ins().f64const(*v) }
        }
        Constant::Bool(b) => builder.ins().iconst(ct::I8, if *b { 1 } else { 0 }),
        Constant::Null | Constant::Undef | Constant::Zeroinit if hint == ct::I128 => {
            let lo = builder.ins().iconst(ct::I64, 0);
            builder.ins().uextend(ct::I128, lo)
        }
        Constant::Null | Constant::Undef | Constant::Zeroinit => builder.ins().iconst(hint, 0),
        Constant::Bytes(_) => builder.ins().iconst(ptr_ty, 0),
        // Only appears in global initializers (handled in the data section);
        // never emitted into a function body.
        Constant::GlobalAddr(_) => builder.ins().iconst(ptr_ty, 0),
        Constant::Aggregate { .. } => builder.ins().iconst(ptr_ty, 0),
    }
}

pub fn coerce(v: cir::Value, target: cir::Type, builder: &mut FunctionBuilder<'_>, _ptr_ty: cir::Type) -> cir::Value {
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
        BinOp::Rotl => builder.ins().rotl(l, r),
        BinOp::Rotr => builder.ins().rotr(l, r),
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
        // x64 float<->int conversions require the GPR side to be 32 or 64 bits.
        // For narrower ints (i8/i16) widen to i32 first / reduce afterwards.
        CastOp::SIToFP  => {
            let v = if src.bits() < 32 { builder.ins().sextend(ct::I32, val) } else { val };
            builder.ins().fcvt_from_sint(dst, v)
        }
        CastOp::UIToFP  => {
            let v = if src.bits() < 32 { builder.ins().uextend(ct::I32, val) } else { val };
            builder.ins().fcvt_from_uint(dst, v)
        }
        CastOp::FPToSI  => {
            if dst.bits() < 32 {
                let w = builder.ins().fcvt_to_sint_sat(ct::I32, val);
                builder.ins().ireduce(dst, w)
            } else {
                builder.ins().fcvt_to_sint_sat(dst, val)
            }
        }
        CastOp::FPToUI  => {
            // C (unsigned T)x where x is negative is UB; most platforms treat it
            // as sign-conversion: cast to signed then reinterpret as unsigned.
            if dst.bits() < 32 {
                let w = builder.ins().fcvt_to_sint_sat(ct::I32, val);
                builder.ins().ireduce(dst, w)
            } else {
                builder.ins().fcvt_to_sint_sat(dst, val)
            }
        }
        CastOp::FPExt   => builder.ins().fpromote(dst, val),
        CastOp::FPTrunc => builder.ins().fdemote(dst, val),
    }
}
