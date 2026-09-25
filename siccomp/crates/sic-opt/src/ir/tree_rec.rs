//! Tree Recursion Elimination pass.
//!
//! Detects self-recursive functions where two recursive calls' results are added
//! together (Fibonacci: `fib(n) = fib(n-1) + fib(n-2)`) and rewrites them into an
//! accumulator-style loop with a single self-call per iteration.
//!
//! # IR Pattern (before)
//!
//! ```text
//! fn f(param: i32) -> i64 {
//!   bb0:                        ; entry: store param, branch
//!   bb1:                        ; base case: return param (possibly SExt)
//!   bb2:                        ; recursive case
//!     r1 = call f(param - 1)
//!     r2 = call f(param - 2)
//!     result = add r1, r2
//!     store result, ret_slot
//!     jump bb_ret
//!   bb_ret:                     ; return from ret_slot
//! }
//! ```
//!
//! # IR Pattern (after)
//!
//! ```text
//! fn f(param: i32) -> i64 {
//!   bb0:                        ; entry
//!     store param, %slot
//!     acc = 0
//!     jump bb_loop
//!   bb_loop:                    ; loop header
//!     brif n < 2, bb_base, bb_recur
//!   bb_recur:                   ; recursive loop body
//!     r = call f(n - 1)
//!     acc += r
//!     n -= 2
//!     jump bb_loop
//!   bb_base:                    ; base case
//!     return acc + n
//! }
//! ```

use crate::ir::pass::IrPass;
use sic_ir::{
    Module, Instr, Val, ValId, BlockId, BasicBlock,
    Type, BinOp, CmpOp, CastOp, Terminator, FuncRef, Constant,
};

/// The tree recursion elimination pass.
pub struct TreeRec;

impl TreeRec {
    pub fn new() -> Self {
        TreeRec
    }
}

impl IrPass for TreeRec {
    fn name(&self) -> &'static str {
        "tree-rec"
    }

    fn run(&mut self, m: &mut Module) -> bool {
        let func_count = m.functions.len();
        let mut changed = false;

        for fi in 0..func_count {
            if transform_function(fi, m) {
                changed = true;
            }
        }

        changed
    }
}

/// Try to transform function at index `fi` in the module.
///
/// Returns `true` if the function was rewritten.
fn transform_function(fi: usize, m: &mut Module) -> bool {
    // Safety check: function must exist and have blocks
    if fi >= m.functions.len() {
        return false;
    }

    let self_ref = FuncRef::defined(fi);
    let func = &m.functions[fi];

    // Must have at least one parameter, return type must be integer, param type must be integer
    if func.params.is_empty() {
        return false;
    }
    let ret_is_int = func.sig.ret.is_int() || func.sig.ret == Type::Bool;
    let param_is_int = func.params[0].ty.is_int();
    if !ret_is_int || !param_is_int {
        return false;
    }

    let blocks = &func.blocks;
    if blocks.len() < 3 {
        return false;
    }

    // Find the entry block (bb0) — first block
    let entry_idx = 0;

    // Find the return block: it should have `ret %val` as terminator
    let mut ret_idx = None;
    for (idx, b) in blocks.iter().enumerate() {
        if matches!(b.terminator, Terminator::Ret(_)) {
            ret_idx = Some(idx);
            break;
        }
    }
    let ret_idx = match ret_idx {
        Some(i) => i,
        None => return false,
    };

    // Find blocks with self-calls
    let mut recur_block_idx = None;
    let mut base_block_idx = None;

    // Look for a block (not entry or ret) that has self-calls
    for (idx, b) in blocks.iter().enumerate() {
        if idx == entry_idx || idx == ret_idx {
            continue;
        }

        let self_calls: Vec<(usize, &Instr)> = b.instrs.iter().enumerate()
            .filter(|(_, ins)| matches!(ins, Instr::Call { func, .. } if *func == self_ref))
            .collect();

        if self_calls.len() == 2 {
            // Check if both results are used in an Add
            let call_dests: Vec<ValId> = self_calls.iter()
                .filter_map(|(_, ins)| ins.dest())
                .collect();

            if call_dests.len() != 2 {
                continue;
            }

            // Find if there's an Add instruction using both dests
            let has_add = b.instrs.iter().any(|ins| {
                if let Instr::BinOp { op: BinOp::Add, lhs, rhs, .. } = ins {
                    let lhs_id = match lhs { Val::Local(id) => Some(*id), _ => None };
                    let rhs_id = match rhs { Val::Local(id) => Some(*id), _ => None };
                    (lhs_id == Some(call_dests[0]) && rhs_id == Some(call_dests[1]))
                        || (lhs_id == Some(call_dests[1]) && rhs_id == Some(call_dests[0]))
                } else {
                    false
                }
            });

            if !has_add {
                continue;
            }

            // Verify the call args are param - a and param - b where b = a + 1
            // First find the param alloca
            let param_slot = find_param_alloca_id(&blocks[entry_idx]);
            let param_slot = match param_slot {
                Some(id) => id,
                None => continue,
            };

            // Check call args
            let args: Vec<&Val> = self_calls.iter()
                .map(|(_, ins)| {
                    match ins {
                        Instr::Call { args, .. } => args.first().unwrap(),
                        _ => unreachable!(),
                    }
                })
                .collect();

            // Both args should be sub results
            let sub_amounts = args.iter().map(|arg| {
                find_sub_amount(b, *arg, param_slot)
            }).collect::<Option<Vec<i64>>>();

            let sub_amounts = match sub_amounts {
                Some(v) => v,
                None => continue,
            };

            if sub_amounts.len() != 2 {
                continue;
            }

            // The rewrite below hardcodes the Fibonacci recurrence (accumulate
            // `f(n-1)`, step `n -= 2`), so the two calls must be EXACTLY `f(n-1)`
            // and `f(n-2)`. A different consecutive pair (e.g. `f(n-2)+f(n-3)`)
            // has a different telescoping and must NOT be transformed this way.
            let mut amts = sub_amounts.clone();
            amts.sort();
            if amts != [1, 2] {
                continue;
            }

            // Found a candidate — determine which is bb_recur (this block) and which is bb_base
            recur_block_idx = Some(idx);
            // The base case block is where the entry block branches when condition is true
            // (n < 2). It should return the param value (possibly extended).
            // Find it: look at entry's branch targets
            let base_target = find_base_block_target(&blocks[entry_idx]);
            if let Some(base_id) = base_target {
                for (j, b2) in blocks.iter().enumerate() {
                    if b2.id == base_id {
                        base_block_idx = Some(j);
                        break;
                    }
                }
            }

            break;
        }
    }

    let (_recur_idx, base_idx) = match (recur_block_idx, base_block_idx) {
        (Some(r), Some(b)) => (r, b),
        _ => return false,
    };

    // The rewrite hardcodes the base as `n < 2 ? n`, so verify EXACTLY that: the
    // entry branches on `n < 2`, and the base block returns the parameter itself
    // (`(ret_ty)n`). Without these checks a function with a different threshold
    // (`n < 5 ? …`) or a different base value (`n < 2 ? 1 : …`) would be
    // silently miscompiled.
    let param_slot0 = match find_param_alloca_id(&blocks[entry_idx]) {
        Some(id) => id, None => return false,
    };
    if !entry_cond_is_lt2(&blocks[entry_idx], param_slot0) {
        return false;
    }
    let ret_slot = match ret_block_slot(&blocks[ret_idx]) {
        Some(s) => s, None => return false,
    };
    if !base_returns_param(&blocks[base_idx], &blocks[ret_idx], param_slot0, ret_slot) {
        return false;
    }

    // --- Perform the transformation ---

    let func = &mut m.functions[fi];

    // Find the param slot alloca from entry block
    let param_slot = find_param_alloca_id(&func.blocks[entry_idx]).unwrap();

    // 1. Modify entry block: keep its existing instructions up to (but not including)
    //    the terminator, add accumulator alloca, change terminator to jump bb_loop.
    let acc_alloca = func.alloc_val();
    func.blocks[entry_idx].terminator = Terminator::Unreachable;
    // We'll set the new terminator after adding instructions.

    // Add accumulator alloca and initialization after existing instructions
    let acc_ptr = acc_alloca;
    func.blocks[entry_idx].instrs.push(Instr::Alloca {
        dest: acc_ptr,
        ty: func.sig.ret.clone(),
        align: None,
    });

    // store 0, %acc
    func.blocks[entry_idx].instrs.push(Instr::Store {
        val: Constant::int(0),
        ptr: Val::Local(acc_ptr),
    });

    let loop_bb_id = func.alloc_block();
    let recur_bb_id = func.alloc_block();
    let base_bb_id = func.alloc_block();

    // Entry jumps to loop
    func.blocks[entry_idx].terminator = Terminator::Jump(loop_bb_id);

    // 2. Create loop header block: check n < 2, branch to base or recur
    let mut loop_block = BasicBlock::new(loop_bb_id);

    let n_load = func.alloc_val();
    loop_block.instrs.push(Instr::Load {
        dest: n_load,
        ptr: Val::Local(param_slot),
        ty: func.params[0].ty.clone(),
    });

    let cond = func.alloc_val();
    loop_block.instrs.push(Instr::Cmp {
        dest: cond,
        op: CmpOp::ISLt,
        lhs: Val::Local(n_load),
        rhs: Constant::int(2),
        ty: func.params[0].ty.clone(),
    });

    // Follow the same ZExt+ine pattern as the original IR for brif
    let zext_cond = func.alloc_val();
    loop_block.instrs.push(Instr::Cast {
        dest: zext_cond,
        op: CastOp::ZExt,
        val: Val::Local(cond),
        to_ty: Type::i32(),
    });

    let ine_cond = func.alloc_val();
    loop_block.instrs.push(Instr::Cmp {
        dest: ine_cond,
        op: CmpOp::INe,
        lhs: Val::Local(zext_cond),
        rhs: Constant::int(0),
        ty: Type::i32(),
    });

    loop_block.terminator = Terminator::CondJump {
        cond: Val::Local(ine_cond),
        then_bb: base_bb_id,
        else_bb: recur_bb_id,
    };

    // 3. Create recursive block: single call, update acc, n -= 2, jump back to loop
    let mut recur_block = BasicBlock::new(recur_bb_id);

    let n1_load = func.alloc_val();
    recur_block.instrs.push(Instr::Load {
        dest: n1_load,
        ptr: Val::Local(param_slot),
        ty: func.params[0].ty.clone(),
    });

    let n_minus_1 = func.alloc_val();
    recur_block.instrs.push(Instr::BinOp {
        dest: n_minus_1,
        op: BinOp::Sub,
        lhs: Val::Local(n1_load),
        rhs: Constant::int(1),
        ty: func.params[0].ty.clone(),
    });

    let call_result = func.alloc_val();
    recur_block.instrs.push(Instr::Call {
        dest: Some(call_result),
        func: self_ref,
        args: vec![Val::Local(n_minus_1)],
        ret_ty: func.sig.ret.clone(),
    });

    let old_acc = func.alloc_val();
    recur_block.instrs.push(Instr::Load {
        dest: old_acc,
        ptr: Val::Local(acc_ptr),
        ty: func.sig.ret.clone(),
    });

    let new_acc = func.alloc_val();
    recur_block.instrs.push(Instr::BinOp {
        dest: new_acc,
        op: BinOp::Add,
        lhs: Val::Local(old_acc),
        rhs: Val::Local(call_result),
        ty: func.sig.ret.clone(),
    });

    recur_block.instrs.push(Instr::Store {
        val: Val::Local(new_acc),
        ptr: Val::Local(acc_ptr),
    });

    let n2_load = func.alloc_val();
    recur_block.instrs.push(Instr::Load {
        dest: n2_load,
        ptr: Val::Local(param_slot),
        ty: func.params[0].ty.clone(),
    });

    let new_n = func.alloc_val();
    recur_block.instrs.push(Instr::BinOp {
        dest: new_n,
        op: BinOp::Sub,
        lhs: Val::Local(n2_load),
        rhs: Constant::int(2),
        ty: func.params[0].ty.clone(),
    });

    recur_block.instrs.push(Instr::Store {
        val: Val::Local(new_n),
        ptr: Val::Local(param_slot),
    });

    recur_block.terminator = Terminator::Jump(loop_bb_id);

    // 4. Create base block: return acc + n
    let mut base_block = BasicBlock::new(base_bb_id);

    let acc_val = func.alloc_val();
    base_block.instrs.push(Instr::Load {
        dest: acc_val,
        ptr: Val::Local(acc_ptr),
        ty: func.sig.ret.clone(),
    });

    let n_val = func.alloc_val();
    base_block.instrs.push(Instr::Load {
        dest: n_val,
        ptr: Val::Local(param_slot),
        ty: func.params[0].ty.clone(),
    });

    // SExt the parameter to match the return type
    let n_ext = func.alloc_val();
    base_block.instrs.push(Instr::Cast {
        dest: n_ext,
        op: CastOp::SExt,
        val: Val::Local(n_val),
        to_ty: func.sig.ret.clone(),
    });

    let result = func.alloc_val();
    base_block.instrs.push(Instr::BinOp {
        dest: result,
        op: BinOp::Add,
        lhs: Val::Local(acc_val),
        rhs: Val::Local(n_ext),
        ty: func.sig.ret.clone(),
    });

    base_block.terminator = Terminator::Ret(Some(Val::Local(result)));

    // Replace the old blocks with the new structure:
    // [entry, loop, recur, base]
    func.blocks.truncate(1);  // keep only entry block
    func.blocks.push(loop_block);
    func.blocks.push(recur_block);
    func.blocks.push(base_block);

    true
}

/// Find the ValId of the alloca that stores the function parameter in the entry block.
fn find_param_alloca_id(entry: &BasicBlock) -> Option<ValId> {
    for ins in &entry.instrs {
        if let Instr::Alloca { dest, .. } = ins {
            let dest = *dest;
            for ins2 in &entry.instrs {
                if let Instr::Store { val, ptr } = ins2 {
                    if let Val::Local(ptr_id) = ptr {
                        if *ptr_id == dest {
                            if matches!(val, Val::Local(_)) {
                                return Some(dest);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Check if a Val is the result of `param_slot - constant`.
fn find_sub_amount(block: &BasicBlock, arg: &Val, param_slot: ValId) -> Option<i64> {
    let sub_id = match arg {
        Val::Local(id) => *id,
        _ => return None,
    };

    for ins in &block.instrs {
        if let Some(dest) = ins.dest() {
            if dest == sub_id {
                if let Instr::BinOp { op: BinOp::Sub, lhs, rhs, .. } = ins {
                    match lhs {
                        Val::Local(load_id) => {
                            for ins2 in &block.instrs {
                                if let Some(d2) = ins2.dest() {
                                    if d2 == *load_id {
                                        if let Instr::Load { ptr, .. } = ins2 {
                                            match ptr {
                                                Val::Local(ptr_id) if *ptr_id == param_slot => {
                                                    return match rhs {
                                                        Val::Const(Constant::Int(v)) => Some(*v),
                                                        Val::Const(Constant::UInt(v)) => Some(*v as i64),
                                                        _ => None,
                                                    };
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                return None;
            }
        }
    }
    None
}

/// Find the target block id that the entry block jumps to when the condition is true
/// (the "base case" block in the original IR).
fn find_base_block_target(entry: &BasicBlock) -> Option<BlockId> {
    match &entry.terminator {
        Terminator::CondJump { then_bb, .. } => Some(*then_bb),
        _ => None,
    }
}

/// Find the def of `id` within `block`.
fn def_of(block: &BasicBlock, id: ValId) -> Option<&Instr> {
    block.instrs.iter().find(|ins| ins.dest() == Some(id))
}

/// Verify the entry block branches on exactly `param < 2` (the fib base test),
/// i.e. its `CondJump` condition traces back — through the usual `ine(zext(_),0)`
/// wrapping — to `islt(load(param_slot), 2)`.
fn entry_cond_is_lt2(entry: &BasicBlock, param_slot: ValId) -> bool {
    let mut id = match &entry.terminator {
        Terminator::CondJump { cond: Val::Local(id), .. } => *id,
        _ => return false,
    };
    // Optional `ine(x, 0)` then optional `zext(x)` wrapping the comparison.
    if let Some(Instr::Cmp { op: CmpOp::INe, lhs: Val::Local(l), rhs: Val::Const(Constant::Int(0)), .. }) = def_of(entry, id) {
        id = *l;
    }
    if let Some(Instr::Cast { op: CastOp::ZExt, val: Val::Local(l), .. }) = def_of(entry, id) {
        id = *l;
    }
    // Must be `islt(load(param), 2)`.
    if let Some(Instr::Cmp { op: CmpOp::ISLt, lhs: Val::Local(l), rhs: Val::Const(Constant::Int(2)), .. }) = def_of(entry, id) {
        if let Some(Instr::Load { ptr: Val::Local(p), .. }) = def_of(entry, *l) {
            return *p == param_slot;
        }
    }
    false
}

/// The slot the return block loads its value from (`bbN: %v = load %slot; ret %v`).
fn ret_block_slot(ret_block: &BasicBlock) -> Option<ValId> {
    let ret_id = match &ret_block.terminator {
        Terminator::Ret(Some(Val::Local(id))) => *id,
        _ => return None,
    };
    match def_of(ret_block, ret_id) {
        Some(Instr::Load { ptr: Val::Local(slot), .. }) => Some(*slot),
        _ => None,
    }
}

/// Verify the base block returns exactly the parameter: its (only) store into the
/// return slot is `(ret_ty)load(param_slot)` (an `SExt`, or a direct load if the
/// widths match), it makes no calls, and it jumps to the return block. This is what
/// makes the hardcoded `return acc + n` base sound.
fn base_returns_param(base: &BasicBlock, ret_block: &BasicBlock, param_slot: ValId, ret_slot: ValId) -> bool {
    // No calls in the base case (it must be side-effect free).
    if base.instrs.iter().any(|ins| matches!(ins, Instr::Call { .. } | Instr::CallIndirect { .. })) {
        return false;
    }
    // Its only store must target the return slot.
    let mut stored: Option<ValId> = None;
    for ins in &base.instrs {
        if let Instr::Store { val, ptr } = ins {
            let p = match ptr { Val::Local(p) => *p, _ => return false };
            if p != ret_slot { return false; }        // stores elsewhere → not a plain base
            stored = match val { Val::Local(v) => Some(*v), _ => return false };
        }
    }
    let stored = match stored { Some(v) => v, None => return false };
    // stored == SExt(load param)  OR  load param directly (widths equal).
    let src = match def_of(base, stored) {
        Some(Instr::Cast { op: CastOp::SExt, val: Val::Local(l), .. }) => *l,
        Some(Instr::Load { ptr: Val::Local(p), .. }) => {
            return *p == param_slot && jumps_to_ret(base, ret_block);
        }
        _ => return false,
    };
    matches!(def_of(base, src), Some(Instr::Load { ptr: Val::Local(p), .. }) if *p == param_slot)
        && jumps_to_ret(base, ret_block)
}

fn jumps_to_ret(base: &BasicBlock, ret_block: &BasicBlock) -> bool {
    matches!(&base.terminator, Terminator::Jump(id) if *id == ret_block.id)
}