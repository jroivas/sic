//! If-conversion: turn `if (cond) { x += C; }` into `x += select(cond, C, 0)`.
//! This eliminates data-dependent branches inside hot loops — in particular the
//! `if (arr[i] >= K) cnt++` pattern that the vectorizer cannot handle.

use sic_ir::{Function, Instr, Val, ValId, BinOp, Terminator, Constant};
use crate::ir::pass::IrPass;

#[derive(Default)]
pub struct IfConv;

impl IfConv {
    pub fn new() -> Self { IfConv }
}

impl IrPass for IfConv {
    fn name(&self) -> &'static str { "if-conv" }
    fn run(&mut self, m: &mut sic_ir::Module) -> bool {
        let mut changed = false;
        for func in &mut m.functions {
            changed |= run_if_conv(func);
        }
        changed
    }
}

/// True if the instruction has no side effects and its result depends only on
/// its operands (so hoisting it out of a branch is safe).
fn is_pure_no_load_store(ins: &Instr) -> bool {
    matches!(ins,
        Instr::BinOp { .. } |
        Instr::UnaryOp { .. } |
        Instr::Cast { .. } |
        Instr::Cmp { .. } |
        Instr::Select { .. }
    )
}

/// Try to match the tail of a block as:
///   [pure_prefix*] load slot -> [pure_mid*] binop(add|sub slot, X) -> [pure_suffix*] store slot
/// Returns (slot, X, op, ty, prefix+mid+suffix instructions, ld_dest) on success.
fn match_inc_tail(instrs: &[Instr]) -> Option<(ValId, Val, BinOp, sic_ir::Type, Vec<Instr>, ValId)> {
    if instrs.len() < 3 { return None; }

    // Last instruction must be store to a local slot
    let store_ins = instrs.last()?;
    let (stv, stp) = match store_ins {
        Instr::Store { val, ptr } => (val, ptr),
        _ => return None,
    };
    let slot = match stp {
        Val::Local(v) => *v,
        _ => return None,
    };
    let stv_local = match stv {
        Val::Local(v) => *v,
        _ => return None,
    };

    // Find the binop that produces stv_local (or flows to it through pure ops)
    let mut cur_val = stv_local;
    let mut binop_idx = None;

    // Walk backwards from the store to find the binop
    for i in (0..instrs.len()-1).rev() {
        match &instrs[i] {
            Instr::BinOp { dest, .. } if *dest == cur_val => {
                binop_idx = Some(i);
                break;
            }
            ins if is_pure_no_load_store(ins) && ins.dest() == Some(cur_val) => {
                match ins {
                    Instr::Cast { val, .. } | Instr::UnaryOp { val, .. } => {
                        match val {
                            Val::Local(v) => cur_val = *v,
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            _ => break,
        }
    }

    let binop_idx = binop_idx?;

    // Verify everything between binop and store is pure
    for i in binop_idx+1..instrs.len()-1 {
        if !is_pure_no_load_store(&instrs[i]) { return None; }
    }

    // Parse the binop
    let (op, lhs, rhs, ty) = match &instrs[binop_idx] {
        Instr::BinOp { op, lhs, rhs, ty, .. } => {
            if !matches!(op, BinOp::Add | BinOp::Sub) { return None; }
            (*op, lhs.clone(), rhs.clone(), ty.clone())
        }
        _ => return None,
    };

    // Find the load of slot
    let ld_idx = instrs.iter().position(|ins| {
        matches!(ins, Instr::Load { dest, ptr, .. } if {
            let ld_local = Val::Local(*dest);
            (ld_local == lhs || ld_local == rhs) && matches!(ptr, Val::Local(s) if *s == slot)
        })
    })?;

    if ld_idx >= binop_idx { return None; }

    // Everything between load and binop must be pure
    for i in ld_idx+1..binop_idx {
        if !is_pure_no_load_store(&instrs[i]) { return None; }
    }

    // Everything before load must be pure
    for i in 0..ld_idx {
        if !is_pure_no_load_store(&instrs[i]) { return None; }
    }

    // The loaded value is one operand; the other is the increment
    let ld_local = match &instrs[ld_idx] {
        Instr::Load { dest, .. } => Val::Local(*dest),
        _ => unreachable!(),
    };
    let inc_val = if lhs == ld_local { rhs } else { lhs };

    // Verify the increment value or any pure chain producing it is defined
    // entirely within this block (so moving the prefix/mid is safe)
    let mut defs_in_block: std::collections::HashSet<ValId> = std::collections::HashSet::new();
    for ins in instrs {
        if let Some(d) = ins.dest() { defs_in_block.insert(d); }
    }

    let mut check_val = inc_val.clone();
    loop {
        match &check_val {
            Val::Const(_) => break,
            Val::Local(id) if defs_in_block.contains(id) => {
                let def_idx = instrs.iter().position(|ins| ins.dest() == Some(*id))?;
                match &instrs[def_idx] {
                    Instr::Cast { val, .. } | Instr::UnaryOp { val, .. } => {
                        check_val = val.clone();
                    }
                    _ => break,
                }
            }
            Val::Local(id) if *id == match &instrs[ld_idx] { Instr::Load { dest, .. } => *dest, _ => ValId(0) } => {
                return None;
            }
            _ => { return None; }
        }
    }

    let ld_dest = match &instrs[ld_idx] {
        Instr::Load { dest, .. } => *dest,
        _ => unreachable!(),
    };

    // Collect all pure instructions EXCEPT the load, binop, and store
    let mut pure_insts = Vec::new();
    for i in 0..instrs.len() {
        if i == ld_idx || i == binop_idx || i == instrs.len() - 1 { continue; }
        pure_insts.push(instrs[i].clone());
    }

    Some((slot, inc_val, op, ty, pure_insts, ld_dest))
}

fn run_if_conv(func: &mut Function) -> bool {
    let mut changed = false;
    let mut idx = 0;
    while idx < func.blocks.len() {
        let b = &func.blocks[idx];
        let (cond_val, then_bb, else_bb) = match &b.terminator {
            Terminator::CondJump { cond, then_bb, else_bb } => (cond.clone(), *then_bb, *else_bb),
            _ => { idx += 1; continue; }
        };

        // --- inspect the "then" block ---
        let then_idx = match func.blocks.iter().position(|bb| bb.id == then_bb) {
            Some(i) => i,
            None => { idx += 1; continue; }
        };

        // Copy data we need from the then block before any mutable borrow
        let then_block_ref = &func.blocks[then_idx];
        let (slot, inc_val, op, ty, pure_insts, _ld_dest) = match match_inc_tail(&then_block_ref.instrs) {
            Some(r) => r,
            None => { idx += 1; continue; }
        };

        let then_merge = match then_block_ref.terminator {
            Terminator::Jump(target) => target,
            _ => { idx += 1; continue; }
        };

        // --- inspect the "else" block ---
        let else_idx = match func.blocks.iter().position(|bb| bb.id == else_bb) {
            Some(i) => i,
            None => { idx += 1; continue; }
        };
        let else_block_ref = &func.blocks[else_idx];

        let merge_bb = if else_block_ref.instrs.is_empty() {
            match else_block_ref.terminator {
                Terminator::Jump(target) => target,
                _ => { idx += 1; continue; }
            }
        } else {
            else_bb
        };

        // Handle "then jumps to else" forwarding pattern
        let merge_bb = if then_merge == else_bb && else_block_ref.instrs.is_empty() {
            match else_block_ref.terminator {
                Terminator::Jump(target) => target,
                _ => merge_bb,
            }
        } else if then_merge == merge_bb {
            merge_bb
        } else {
            idx += 1; continue;
        };

        // Make sure the merge block actually exists
        let _merge_idx = match func.blocks.iter().position(|bb| bb.id == merge_bb) {
            Some(i) => i,
            None => { idx += 1; continue; }
        };

        // --- allocate new value ids BEFORE borrowing the block mutably ---
        let ld_dest_new = func.alloc_val();
        let sel_dest = func.alloc_val();
        let result_dest = func.alloc_val();

        // --- rewrite the current block ---
        let cur = &mut func.blocks[idx];

        // Copy pure instructions from the then block (casts, etc.)
        for ins in &pure_insts {
            cur.instrs.push(ins.clone());
        }

        // load slot
        cur.instrs.push(Instr::Load { dest: ld_dest_new, ptr: Val::Local(slot), ty: ty.clone() });

        // select(cond, inc, 0)
        let zero = Constant::int(0);
        cur.instrs.push(Instr::Select {
            dest: sel_dest,
            cond: cond_val.clone(),
            on_true: inc_val.clone(),
            on_false: zero,
            ty: ty.clone(),
        });

        // add/sub
        cur.instrs.push(Instr::BinOp {
            dest: result_dest,
            op,
            lhs: Val::Local(ld_dest_new),
            rhs: Val::Local(sel_dest),
            ty: ty.clone(),
        });

        // store back
        cur.instrs.push(Instr::Store { val: Val::Local(result_dest), ptr: Val::Local(slot) });

        // change terminator to unconditional jump to merge
        cur.terminator = Terminator::Jump(merge_bb);

        changed = true;
        idx += 1;
    }
    changed
}
