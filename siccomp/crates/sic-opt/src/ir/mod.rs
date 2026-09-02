//! Typed IR optimization stage. Runs *after* lowering, so every instruction
//! carries its result `Type` — width-sensitive rewrites (constant folding at the
//! right width, algebraic identities, strength reduction) are sound here in a way
//! they are not on the untyped AST.
//!
//! A subtle but important property: IR operands are already-evaluated SSA values,
//! so replacing an instruction's *result* (e.g. `x * 0` → `0`) can never skip a
//! side effect — `x`'s computation lives in its own instruction and stays put
//! (only `dce` may remove it, and only when it is pure). So these passes need no
//! AST-style purity check on operands.

use std::collections::HashMap;
use sic_ir::{Module, Function, Val, ValId};
use crate::pass::PassConfig;

pub mod pass;
pub mod fold;
pub mod algebraic;
pub mod dce;

pub use pass::{IrPass, IrPassManager};

/// Run the enabled IR-stage passes over `module` in place.
pub fn run_ir_passes(module: &mut Module, cfg: &PassConfig) {
    let mut pm = IrPassManager::new(cfg.max_iters, cfg.debug);
    if cfg.is_enabled("ir-fold") { pm.add(Box::new(fold::IrFold::new())); }
    if cfg.is_enabled("algebraic") { pm.add(Box::new(algebraic::Algebraic::new())); }
    if cfg.is_enabled("dce") { pm.add(Box::new(dce::Dce::new())); }
    pm.run(module);
}

/// Substitute every use of each mapped `ValId` with its replacement `Val`
/// throughout the function (instruction operands and terminators), following
/// chains (a replacement that is itself a replaced local). Only replaces *uses*;
/// the defining instructions are pruned separately.
pub(crate) fn apply_replacements(func: &mut Function, repl: &HashMap<ValId, Val>) {
    if repl.is_empty() { return; }
    let resolve = |v: &Val| -> Val {
        let mut cur = v.clone();
        let mut guard = 0;
        while let Val::Local(id) = cur {
            match repl.get(&id) {
                Some(r) if *r != cur => { cur = r.clone(); }
                _ => break,
            }
            guard += 1;
            if guard > 10_000 { break; } // defensive: never loop on a cycle
        }
        cur
    };
    for b in &mut func.blocks {
        for ins in &mut b.instrs {
            ins.for_each_val_mut(|v| *v = resolve(v));
        }
        b.terminator.for_each_val_mut(|v| *v = resolve(v));
    }
}

/// Remove instructions whose `dest` is one of the given (now fully-substituted,
/// hence dead) value ids. Callers only ever pass ids of *pure* defs.
pub(crate) fn prune_defs(func: &mut Function, dead: &HashMap<ValId, Val>) {
    if dead.is_empty() { return; }
    for b in &mut func.blocks {
        b.instrs.retain(|ins| match ins.dest() {
            Some(d) => !dead.contains_key(&d),
            None => true,
        });
    }
}
