//! Devirtualization pass: convert `CallIndirect` through a known set of function
//! pointers into a dense `Switch` dispatching to direct `Call` instructions.
//!
//! # IR Pattern (before)
//!
//! Either a global array:
//! ```ir
//! %fns = Global { init: Aggregate { relocs: [
//!     (0, Func(op_add)), (8, Func(op_xor)),
//!     (16, Func(op_mul)), (24, Func(op_sub)),
//! ]}}
//! %fptr = Load(GetElemPtr(%fns, %idx, elem_size=8))
//! %result = CallIndirect %fptr(%arg0, %arg1)
//! ```
//!
//! Or a local array initialized per-element:
//! ```ir
//! %fns = Alloca i8[32]
//! memset %fns, 0, 32
//! %p0 = GetElemPtr(%fns, 0, elem_size=8);  store @op_add → %p0
//! %p1 = GetElemPtr(%fns, 1, elem_size=8);  store @op_xor → %p1
//! ...
//! %gep = GetElemPtr(%fns, %idx, elem_size=8)
//! %fptr = Load(%gep)
//! %result = CallIndirect %fptr(%arg0, %arg1)
//! ```
//!
//! After the pass runs, the existing `inline` pass inlines each direct call,
//! eliminating all call overhead in the hot loop.

use sic_ir::{
    Module, Function, BasicBlock, Instr, Terminator, Val, ValId, BlockId,
    Type, FuncRef, CastOp, Constant, RelocTarget, GlobalRef, Linkage,
};
use crate::ir::pass::IrPass;

/// Devirtualization pass.
#[derive(Default)]
pub struct Devirtualize;

impl Devirtualize {
    pub fn new() -> Self { Devirtualize }
}

impl IrPass for Devirtualize {
    fn name(&self) -> &'static str { "devirtual" }

    fn run(&mut self, m: &mut Module) -> bool {
        let mut changed = false;
        let n = m.functions.len();
        for fi in 0..n {
            changed |= self.devirtualize_fn(fi, m);
        }
        changed
    }
}

fn is_aggregate(ty: &Type) -> bool {
    matches!(ty, Type::Struct(_) | Type::Union(_) | Type::Array { .. })
}

impl Devirtualize {
    fn devirtualize_fn(&self, fi: usize, m: &mut Module) -> bool {
        if fi >= m.functions.len() { return false; }

        let candidates: Vec<(usize, usize)> = {
            let func = &m.functions[fi];
            func.blocks.iter().enumerate().flat_map(|(bi, b)| {
                b.instrs.iter().enumerate()
                    .filter_map(move |(ii, ins)| match ins {
                        Instr::CallIndirect { .. } => Some((bi, ii)),
                        _ => None,
                    })
            }).collect()
        };

        if candidates.is_empty() { return false; }

        let mut changed = false;
        for (bi, ii) in candidates.into_iter().rev() {
            let call = {
                let func = &m.functions[fi];
                let ins = &func.blocks[bi].instrs[ii];
                ins.clone()
            };

            match &call {
                Instr::CallIndirect { fptr, func_ty, .. } => {
                    if is_aggregate(&func_ty.ret) { continue; }
                    if func_ty.variadic { continue; }

                    if let Some((targets, discriminator)) =
                            Self::trace_to_array(fptr, &m.functions[fi], m)
                    {
                        let known = targets.iter().filter(|t| t.is_some()).count();
                        if targets.len() == 1 && targets[0].is_some() {
                            // A one-slot table: any other index is out of bounds.
                            let func = &mut m.functions[fi];
                            let block = &mut func.blocks[bi];
                            if let Instr::CallIndirect { dest, args, ret_ty, .. } = &block.instrs[ii] {
                                block.instrs[ii] = Instr::Call {
                                    dest: *dest,
                                    func: targets[0].unwrap(),
                                    args: args.clone(),
                                    ret_ty: ret_ty.clone(),
                                };
                            }
                            changed = true;
                        } else if known >= 1 && known <= 16 {
                            Self::rewrite_switch(m, fi, bi, ii, &call, targets, discriminator);
                            changed = true;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        changed
    }

    // ── Traceback ──────────────────────────────────────────────────────────

    /// Trace a function-pointer value back to a known array of function refs.
    /// Returns `(targets_vec, discriminator_val)` on success.
    ///
    /// Two code paths:
    ///   1. **Global array**: Load ∘ GetElemPtr → `Val::Global(gr)` with
    ///      `Constant::Aggregate { relocs: [Func, …] }`.
    ///   2. **Local alloca**: Load ∘ GetElemPtr → `Val::Local(alloca)` with
    ///      per-element `Store { val: Val::Func, … }` instructions in the same
    ///      function.
    fn trace_to_array(
        fptr: &Val,
        func: &Function,
        module: &Module,
    ) -> Option<(Vec<Option<FuncRef>>, Val)> {
        let fptr_id = match fptr { Val::Local(id) => *id, _ => return None };

        // fptr = Load(gep_ptr)
        let gep_ptr = Self::find_def(func, fptr_id, |ins| match ins {
            Instr::Load { ptr, .. } | Instr::LoadReadonly { ptr, .. } => Some(ptr.clone()),
            _ => None,
        })?;

        let gep_ptr_id = match &gep_ptr { Val::Local(id) => *id, _ => return None };

        // gep_ptr = GetElemPtr(base, index)
        let (base, discriminator, elem_size) = Self::find_def(func, gep_ptr_id, |ins| match ins {
            Instr::GetElemPtr { base, index, elem_size, .. } => {
                Some((base.clone(), index.clone(), *elem_size))
            }
            _ => None,
        })?;

        match &base {
            Val::Global(gr) => {
                // Only a table that cannot change at run time: `const`, or an
                // internal one whose address only ever feeds loads.
                if !Self::global_table_immutable(module, *gr) { return None; }
                let global = module.globals.get(gr.0 as usize)?;
                let targets = Self::global_table(&global.init, elem_size)?;
                if targets.iter().all(|t| t.is_none()) { return None; }
                Some((targets, discriminator))
            }
            Val::Local(alloca_id) => {
                // Local array: collect per-element stores of Func values — only if
                // nothing else can write it (no runtime-value store, no escape).
                if !Self::alloca_only_table_uses(func, *alloca_id) { return None; }
                Self::extract_alloca_targets(func, *alloca_id, elem_size)
                    .map(|targets| (targets.into_iter().map(Some).collect(), discriminator))
            }
            _ => None,
        }
    }

    /// The function pointers of a global table by element INDEX (`None` = a NULL
    /// slot). A table's relocations cover only its non-null slots, so their byte
    /// offsets — not their order — give the indices (QEMU's
    /// `qdestroy[] = { [QTYPE_NONE] = NULL, [QTYPE_QNULL] = NULL, [QTYPE_QNUM] = … }`
    /// was dispatched two slots off). Every non-relocated slot must be all zero.
    fn global_table(init: &Option<Constant>, elem_size: u64) -> Option<Vec<Option<FuncRef>>> {
        if elem_size != 8 { return None; }
        let (bytes, relocs) = match init {
            Some(Constant::Aggregate { bytes, relocs }) => (bytes, relocs),
            _ => return None,
        };
        if bytes.is_empty() || bytes.len() % 8 != 0 { return None; }
        let n = bytes.len() / 8;
        let mut table: Vec<Option<FuncRef>> = vec![None; n];
        for (off, tgt) in relocs {
            if off % 8 != 0 || off / 8 >= n { return None; }
            let RelocTarget::Func(fr) = tgt else { return None };
            if table[off / 8].is_some() { return None; }
            if bytes[*off..*off + 8].iter().any(|b| *b != 0) { return None; }   // an addend
            table[off / 8] = Some(*fr);
        }
        for (i, t) in table.iter().enumerate() {
            if t.is_none() && bytes[i * 8..i * 8 + 8].iter().any(|b| *b != 0) { return None; }
        }
        Some(table)
    }

    /// Whether global `gr` cannot be written at run time: `const`, or internal
    /// with no address escaping — every use is the base of a `GetElemPtr` whose
    /// result is only loaded from (no store, memcpy, call argument, …), and no
    /// other global's initializer points at it.
    fn global_table_immutable(module: &Module, gr: GlobalRef) -> bool {
        let Some(g) = module.globals.get(gr.0 as usize) else { return false };
        if g.constant { return true; }
        if !matches!(g.linkage, Linkage::Internal | Linkage::Private) { return false; }
        for og in &module.globals {
            if let Some(Constant::Aggregate { relocs, .. }) = &og.init {
                if relocs.iter().any(|(_, t)| matches!(t, RelocTarget::Global(x, _) if *x == gr)) {
                    return false;
                }
            }
        }
        let me = Val::Global(gr);
        for f in &module.functions {
            let mut derived: Vec<ValId> = Vec::new();
            for b in &f.blocks {
                for ins in &b.instrs {
                    if let Instr::GetElemPtr { dest, base, index, .. } = ins {
                        if *base == me && *index != me { derived.push(*dest); continue; }
                    }
                    let mut hit = false;
                    ins.for_each_val(|v| if *v == me { hit = true; });
                    if hit { return false; }
                }
                let mut hit = false;
                b.terminator.for_each_val(|v| if *v == me { hit = true; });
                if hit { return false; }
            }
            if !Self::only_loaded(f, &derived) { return false; }
        }
        true
    }

    /// Whether every use of the pointers `ids` is as the address of a load.
    fn only_loaded(f: &Function, ids: &[ValId]) -> bool {
        if ids.is_empty() { return true; }
        for b in &f.blocks {
            for ins in &b.instrs {
                let is_load = matches!(ins, Instr::Load { .. } | Instr::LoadReadonly { .. });
                let mut bad = false;
                ins.for_each_val(|v| if let Val::Local(id) = v { if ids.contains(id) && !is_load { bad = true; } });
                if bad { return false; }
            }
            let mut bad = false;
            b.terminator.for_each_val(|v| if let Val::Local(id) = v { if ids.contains(id) { bad = true; } });
            if bad { return false; }
        }
        true
    }

    /// Whether local array `alloca_id` is only used as a function table: its
    /// address only feeds element pointers (GEP / field / offset) and a zeroing
    /// memset, and an element pointer is only loaded from or has a function
    /// stored INTO it. A runtime-value store, a memcpy, or the address escaping
    /// (call argument, stored, returned) could change the table: not devirtualized.
    fn alloca_only_table_uses(func: &Function, alloca_id: ValId) -> bool {
        let me = Val::Local(alloca_id);
        let mut derived: Vec<ValId> = Vec::new();
        for b in &func.blocks {
            for ins in &b.instrs {
                match ins {
                    Instr::GetElemPtr { dest, base, .. } | Instr::GetFieldPtr { dest, base, .. }
                    | Instr::PtrOffset { dest, base, .. } if *base == me => { derived.push(*dest); }
                    Instr::MemSet { dst, val: Val::Const(Constant::Int(0)), .. } if *dst == me => {}
                    Instr::Alloca { dest, .. } if *dest == alloca_id => {}
                    _ => {
                        let mut hit = false;
                        ins.for_each_val(|v| if *v == me { hit = true; });
                        if hit { return false; }
                    }
                }
            }
            let mut hit = false;
            b.terminator.for_each_val(|v| if *v == me { hit = true; });
            if hit { return false; }
        }
        for b in &func.blocks {
            for ins in &b.instrs {
                match ins {
                    Instr::Load { .. } | Instr::LoadReadonly { .. } => {}
                    Instr::Store { val, ptr: Val::Local(p) } if derived.contains(p) => {
                        // Only a known function (possibly through a BitCast).
                        let ok = match val {
                            Val::Func(_) => true,
                            Val::Local(v) => Self::find_def(func, *v, |d| match d {
                                Instr::Cast { op: CastOp::BitCast, val: Val::Func(_), .. } => Some(()),
                                _ => None,
                            }).is_some(),
                            _ => false,
                        };
                        if !ok { return false; }
                    }
                    _ => {
                        let mut bad = false;
                        ins.for_each_val(|v| if let Val::Local(id) = v { if derived.contains(id) { bad = true; } });
                        if bad { return false; }
                    }
                }
            }
            let mut bad = false;
            b.terminator.for_each_val(|v| if let Val::Local(id) = v { if derived.contains(id) { bad = true; } });
            if bad { return false; }
        }
        true
    }

    /// For a local alloca initialized with per-element `Store` instructions of
    /// function-pointer values, collect the targets in index order.
    ///
    /// Scans the entire function for stores of the form:
    ///   `Store { val: Val::Func(fr), ptr: GetElemPtr(base=alloca_id, index=Const, …) }`
    /// or:
    ///   `Store { val: Val::Func(fr), ptr: PtrOffset(base=alloca_id, offset=Const) }`
    ///
    /// Returns `None` if any storage index is missing, has a duplicate, or has
    /// a non-function value — i.e. only complete, contiguous arrays starting at
    /// index 0 are accepted.
    fn extract_alloca_targets(
        func: &Function,
        alloca_id: ValId,
        elem_size: u64,
    ) -> Option<Vec<FuncRef>> {
        // Map from element-index → Funcref.
        let mut slots: Vec<(i64, FuncRef)> = Vec::new();

        for block in &func.blocks {
            for ins in &block.instrs {
                // Match stores of function-pointer values.  The stored value may
                // be directly a `Val::Func(fr)` or a local that was produced by a
                // `Cast(BitCast, Val::Func(fr), …)` — trace through casts to find
                // the underlying function reference.
                let fr = match ins {
                    Instr::Store { val: Val::Func(fr), .. } => Some(*fr),
                    Instr::Store { val: Val::Local(vid), .. } => {
                        Self::find_def(func, *vid, |def| match def {
                            Instr::Cast { op: CastOp::BitCast, val: Val::Func(fr), .. } => Some(*fr),
                            _ => None,
                        })
                    }
                    _ => None,
                };
                let fr = match fr {
                    Some(f) => f,
                    None => continue,
                };

                let ptr = match ins {
                    Instr::Store { ptr, .. } => ptr.clone(),
                    _ => unreachable!(),
                };

                // Check whether `ptr` targets this alloca at a known constant
                // index, and get that index.
                let idx = Self::store_index(&ptr, alloca_id, func, elem_size)?;
                slots.push((idx, fr));
            }
        }

        if slots.is_empty() { return None; }

        // Sort by index and verify contiguity from 0.
        slots.sort_by_key(|(idx, _)| *idx);
        let mut targets = Vec::with_capacity(slots.len());
        for (i, (idx, fr)) in slots.iter().enumerate() {
            if *idx != i as i64 { return None; }  // gap or non-zero start
            targets.push(*fr);
        }

        if targets.is_empty() { None } else { Some(targets) }
    }

    /// If `ptr` is a pointer into the alloca at a known constant element index,
    /// return that index.  Handles:
    ///   - `GetElemPtr { base: alloca, index: Const(Int(idx)), elem_size }`
    ///   - `PtrOffset { base: alloca, offset: Const(Int(byte_off)) }`
    ///     where `byte_off % elem_size == 0`.
    fn store_index(
        ptr: &Val,
        alloca_id: ValId,
        func: &Function,
        elem_size: u64,
    ) -> Option<i64> {
        let ptr_id = match ptr { Val::Local(id) => *id, _ => return None };

        Self::find_def(func, ptr_id, |ins| match ins {
            Instr::GetElemPtr { base, index, .. } => {
                match base {
                    Val::Local(b) if *b == alloca_id => {},
                    _ => return None,
                }
                match index {
                    Val::Const(Constant::Int(idx)) => Some(*idx),
                    _ => None,
                }
            }
            Instr::GetFieldPtr { base, byte_offset, .. } => {
                match base {
                    Val::Local(b) if *b == alloca_id => {},
                    _ => return None,
                }
                if (*byte_offset as u64) % elem_size == 0 {
                    Some(*byte_offset as i64 / elem_size as i64)
                } else {
                    None
                }
            }
            Instr::PtrOffset { base, offset, .. } => {
                match base {
                    Val::Local(b) if *b == alloca_id => {},
                    _ => return None,
                }
                match offset {
                    Val::Const(Constant::Int(byte_off)) if *byte_off >= 0
                        && (*byte_off as u64) % elem_size == 0 =>
                    {
                        Some(*byte_off / elem_size as i64)
                    }
                    _ => None,
                }
            }
            _ => None,
        })
    }


    fn find_def<T>(func: &Function, id: ValId, f: impl Fn(&Instr) -> Option<T>) -> Option<T> {
        for block in &func.blocks {
            for ins in &block.instrs {
                if let Some(d) = ins.dest() {
                    if d == id {
                        if let Some(result) = f(ins) {
                            return Some(result);
                        }
                    }
                }
            }
        }
        None
    }

    // ── Rewrite ────────────────────────────────────────────────────────────

    fn rewrite_switch(
        m: &mut Module,
        fi: usize,
        bi: usize,
        ii: usize,
        call: &Instr,
        targets: Vec<Option<FuncRef>>,
        discriminator: Val,
    ) {
        let Instr::CallIndirect { dest, args, ret_ty, .. } = call else { return; };

        let func = &mut m.functions[fi];
        let has_ret = dest.is_some();

        // ── Phase 1: pre-allocate every ID we'll need. ──────────────────────
        let ret_slot = has_ret.then(|| func.alloc_val());
        let cont_id = func.alloc_block();

        let mut arm_ids: Vec<BlockId> = Vec::with_capacity(targets.len());
        let mut arm_dests: Vec<Option<ValId>> = Vec::with_capacity(targets.len());
        for _ in 0..targets.len() {
            arm_ids.push(func.alloc_block());
            arm_dests.push(has_ret.then(|| func.alloc_val()));
        }
        // Any other index is undefined behavior in C (a NULL slot, or past the
        // table's end): trap there, deterministically — the pass used to skip the
        // call silently, leaving its result undefined.
        let default_id = func.alloc_block();

        // ── Phase 2: split the block at the CallIndirect. ───────────────────
        let mut tail = func.blocks[bi].instrs.split_off(ii);
        tail.remove(0);  // drop the CallIndirect itself
        let orig_term = std::mem::replace(
            &mut func.blocks[bi].terminator,
            Terminator::Unreachable,
        );

        if let Some(slot) = ret_slot {
            func.blocks[bi].instrs.push(Instr::Alloca {
                dest: slot, ty: ret_ty.clone(), align: None,
            });
        }

        // ── Phase 3: build all target arm blocks. ───────────────────────────
        let mut new_blocks: Vec<BasicBlock> = Vec::with_capacity(targets.len() + 1);
        let mut arms: Vec<(i64, BlockId)> = Vec::with_capacity(targets.len());

        for (i, target) in targets.iter().enumerate() {
            let Some(target) = target else { continue };
            arms.push((i as i64, arm_ids[i]));
            let mut arm_block = BasicBlock::new(arm_ids[i]);

            arm_block.instrs.push(Instr::Call {
                dest: arm_dests[i],
                func: *target,
                args: args.clone(),
                ret_ty: ret_ty.clone(),
            });

            if let (Some(d), Some(slot)) = (arm_dests[i], ret_slot) {
                arm_block.instrs.push(Instr::Store {
                    val: Val::Local(d),
                    ptr: Val::Local(slot),
                });
            }

            arm_block.terminator = Terminator::Jump(cont_id);
            new_blocks.push(arm_block);
        }
        // (The trap block goes at the END of the function, out of the hot path.)
        let mut trap_block = BasicBlock::new(default_id);
        trap_block.terminator = Terminator::Unreachable;

        // ── Phase 4: build the merge continuation block. ────────────────────
        let mut cont_block = BasicBlock::new(cont_id);

        if has_ret {
            cont_block.instrs.push(Instr::Load {
                dest: dest.unwrap(),
                ptr: Val::Local(ret_slot.unwrap()),
                ty: ret_ty.clone(),
            });
        }

        cont_block.instrs.extend(tail);
        cont_block.terminator = orig_term;
        new_blocks.push(cont_block);

        // ── Phase 5: set the split block's terminator to Switch. ────────────
        func.blocks[bi].terminator = Terminator::Switch {
            val: discriminator,
            default: default_id,
            arms,
        };

        // ── Phase 6: splice the new blocks in right after the split block. ──
        let at = bi + 1;
        func.blocks.splice(at..at, new_blocks);
        func.blocks.push(trap_block);
    }
}
