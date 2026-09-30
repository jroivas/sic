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

use std::collections::{HashMap, HashSet};
use sic_ir::{Module, Function, Instr, Val, ValId};
use crate::pass::PassConfig;
pub mod devirtual;

pub mod pass;
pub mod fold;
pub mod algebraic;
pub mod dce;
pub mod tree_rec;
pub mod inline;

pub use pass::{IrPass, IrPassManager};

/// Run the enabled IR-stage passes over `module` in place.
pub fn run_ir_passes(module: &mut Module, cfg: &PassConfig) {
    let mut pm = IrPassManager::new(cfg.max_iters, cfg.debug);
    // Inline first: it exposes more constants/dead code and larger loop bodies for
    // the folding/algebraic/dce passes that follow.
    if cfg.is_enabled("inline") {
        pm.add(Box::new(inline::Inline::new(cfg.inline_threshold, cfg.inline_aggressive)));
    }
    if cfg.is_enabled("devirtual") { pm.add(Box::new(devirtual::Devirtualize::new())); }
    if cfg.is_enabled("ir-fold") { pm.add(Box::new(fold::IrFold::new())); }
    if cfg.is_enabled("algebraic") { pm.add(Box::new(algebraic::Algebraic::new())); }
    if cfg.is_enabled("dce") { pm.add(Box::new(dce::Dce::new())); }
    if cfg.is_enabled("tree-rec") { pm.add(Box::new(tree_rec::TreeRec::new())); }
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
            // A `Store` carries no result type; codegen infers the width of a
            // *constant* store as i32 (see sic-cranelift). Substituting a folded
            // constant into the stored value would therefore silently change the
            // store width — corrupting narrow (i8/i16) or wide (i64) stores. Keep
            // the original, typed SSA value there and only rewrite the pointer.
            if let Instr::Store { ptr, .. } = ins {
                *ptr = resolve(ptr);
                continue;
            }
            ins.for_each_val_mut(|v| *v = resolve(v));
        }
        b.terminator.for_each_val_mut(|v| *v = resolve(v));
    }
}

/// Remove instructions whose `dest` was folded away and is no longer used.
/// A folded def may still be referenced — e.g. by a `Store` value, which
/// `apply_replacements` intentionally leaves untouched — so removal is gated on
/// there being no remaining use, not merely on membership in `dead`. Callers
/// only ever pass ids of *pure* defs.
pub(crate) fn prune_defs(func: &mut Function, dead: &HashMap<ValId, Val>) {
    if dead.is_empty() { return; }
    let mut used: HashSet<ValId> = HashSet::new();
    for b in &func.blocks {
        for ins in &b.instrs {
            ins.for_each_val(|v| if let Val::Local(id) = v { used.insert(*id); });
        }
        b.terminator.for_each_val(|v| if let Val::Local(id) = v { used.insert(*id); });
    }
    for b in &mut func.blocks {
        b.instrs.retain(|ins| match ins.dest() {
            Some(d) => !(dead.contains_key(&d) && !used.contains(&d)),
            None => true,
        });
    }
}
