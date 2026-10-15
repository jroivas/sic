//! Function inlining (typed IR stage).
//!
//! Cranelift compiles one function at a time and does not inline across function
//! boundaries, so a small helper called in a hot loop (e.g. a `min3` in an
//! edit-distance kernel) pays a full call per invocation. This pass splices a
//! called function's body into its caller at the call site, replacing the `Call`.
//!
//! Eligibility (a callee must be ALL of): defined here (not `extern`), not
//! variadic, a SCALAR/void return (no aggregate/sret return — keeps parameter
//! numbering simple and avoids the caller-slot ABI), free of frame-sensitive
//! intrinsics (`__builtin_return_address`, `va_*`), and not directly self-recursive.
//! A non-leaf callee (one that itself calls) is fine — its inner calls come along
//! and may be inlined on a later pass iteration. A call is inlined when the callee
//! is at most `threshold` IR instructions, or always when `aggressive` (`-O3`+).
//! Per-caller growth and inline-count caps keep the worst case bounded.
//!
//! Correctness notes:
//!  - Call arguments are already coerced to their parameter types at the call site
//!    (`lower_call`), so feeding an argument into the callee's parameter store is
//!    width-correct — a `Const` only reaches a `Call` when its width already
//!    matches the parameter (otherwise coercion made it a `Cast`ed local).
//!  - The result flows back either as an SSA value (single non-const return →
//!    substitute the call's dest) or, for multiple / constant returns, through a
//!    fresh return-slot alloca that the continuation block loads.
//!  - BLOCK ORDER MATTERS: the inlined blocks + continuation are spliced in right
//!    AFTER the split block, keeping the block vector in a mostly-topological order
//!    (predecessors before successors). Appending them at the end instead broke
//!    the backend's SSA reconstruction for a register-promoted pointer used in the
//!    spliced continuation (`use_var` reconstructed a null value), which surfaced
//!    as a null-pointer crash whenever inlining into a function with fat-pointer
//!    bounds checks. See `do_inline` step 5/6.

use std::collections::{HashMap, HashSet};
use sic_ir::{Module, Function, BasicBlock, Instr, Terminator, Val, ValId, BlockId, Type};
use super::pass::IrPass;

pub struct Inline {
    threshold: usize,
    aggressive: bool,
    /// Self-recursive functions already expanded into themselves (by name): the
    /// pass manager reruns passes to a fixpoint, and each rerun would otherwise
    /// unroll the recursion one level deeper.
    self_done: HashSet<String>,
}

impl Inline {
    pub fn new(threshold: usize, aggressive: bool) -> Self {
        Inline { threshold, aggressive, self_done: HashSet::new() }
    }
}

/// Self-inlining of a small, directly self-recursive function (gcc does the
/// same to fib): splice copies of its ORIGINAL body into its own recursive call
/// sites, up to this many copies, each call level saved being a frame.
const SELF_INLINE_COPIES: usize = 14;
/// Breadth-first expansion rounds (each expands every site present before it).
const SELF_INLINE_ROUNDS: usize = 3;
/// Only for a function this small (post-mem2reg cost), and while the expanded
/// body stays under this size.
const SELF_INLINE_MAX_COST: usize = 40;
const SELF_INLINE_MAX_GROWN: usize = 800;

/// Per-function inlinability summary, computed once per pass run.
struct FnInfo {
    /// May this function be inlined into a caller?
    eligible: bool,
    /// Estimated post-mem2reg size (see `inline_cost`) — the number the threshold
    /// gate judges, not the raw IR count.
    size: usize,
    /// Number of `Ret(Some(_))` — a value-returning call needs at least one.
    ret_val_count: usize,
    /// Directly self-recursive, and otherwise eligible (self-inlining candidate).
    self_recursive: bool,
}

/// The parameter-value sentinel base used by the frontend: parameter `i` of a
/// non-sret function is referenced in the body as `Val::Local(ValId(SENTINEL+i))`
/// (see `lower_function`). We only inline non-sret callees, so the base is fixed.
const SENTINEL: u32 = 0x10000;

/// Per-caller caps so inlining can't blow up compile time or code size on
/// pathological (e.g. deep or mutually-recursive) call graphs.
const MAX_INLINES_PER_FN: usize = 1000;
const MAX_CALLER_INSTRS: usize = 20000;

fn func_size(f: &Function) -> usize {
    f.blocks.iter().map(|b| b.instrs.len()).sum()
}

/// Estimate a function's size *as the back end will actually compile it* — the
/// number the inline threshold should judge, as opposed to `func_size` (raw IR,
/// used only for the hard growth caps).
///
/// The frontend emits an alloca per local and a load/store per access, plus debug
/// markers; the Cranelift backend's mem2reg promotes every non-escaping scalar
/// alloca to a register, erasing the alloca and all its load/store traffic, and
/// the debug pseudo-ops emit no machine code. Counting the raw IR therefore
/// grossly overstates small helpers — a 6-op `min3` scans as ~30 instructions and
/// never meets the -O2 threshold, so it is never inlined (and pays a call in the
/// hot loop) even though gcc/clang inline it freely. This mirrors the promotion:
/// debug markers and allocas cost 0, load/store to a local alloca slot cost 0
/// (promoted to a register), and every real compute / call / memory op costs 1.
fn inline_cost(f: &Function) -> usize {
    // Scalar-ish slots the backend promotes: an alloca whose traffic disappears.
    // (Approximate — we do not re-run escape analysis here; over-counting a
    // promoted slot only forgoes an inline, and under-counting an escaping one is
    // bounded by the per-caller growth cap. Inlining stays correct either way.)
    let mut slots: std::collections::HashSet<ValId> = std::collections::HashSet::new();
    for b in &f.blocks {
        for ins in &b.instrs {
            if let Instr::Alloca { dest, .. } = ins { slots.insert(*dest); }
        }
    }
    let promoted = |ptr: &Val| matches!(ptr, Val::Local(v) if slots.contains(v));
    let mut cost = 0usize;
    for b in &f.blocks {
        for ins in &b.instrs {
            cost += match ins {
                // Scaffolding the backend erases.
                Instr::Alloca { .. } | Instr::SrcLine(_) | Instr::DbgVar { .. } => 0,
                Instr::Load { ptr, .. } | Instr::LoadReadonly { ptr, .. } if promoted(ptr) => 0,
                Instr::Store { ptr, .. } if promoted(ptr) => 0,
                _ => 1,
            };
        }
    }
    cost
}

fn is_aggregate(t: &Type) -> bool {
    matches!(t, Type::Struct(_) | Type::Union(_) | Type::Array { .. })
}

fn analyze(f: &Function, self_idx: usize) -> FnInfo {
    // A declaration (no body), a variadic, or an aggregate-return function is never
    // a candidate. Scan for the disqualifiers below.
    let mut eligible = !f.blocks.is_empty() && !f.sig.variadic && !is_aggregate(&f.sig.ret) && !f.noinline;
    let mut ret_val_count = 0;
    let mut self_rec = false;
    if eligible {
        'scan: for b in &f.blocks {
            for ins in &b.instrs {
                match ins {
                    // Frame-sensitive intrinsics change meaning when moved into the
                    // caller's frame.
                    Instr::ReturnAddress { .. } | Instr::VaStart { .. }
                    | Instr::VaArg { .. } | Instr::VaEnd { .. } => { eligible = false; break 'scan; }
                    // Directly self-recursive: inlining it into itself never
                    // terminates (and into others it just re-expands to the caps).
                    Instr::Call { func, .. } if !func.is_extern() && func.index() == self_idx => {
                        self_rec = true;
                    }
                    _ => {}
                }
            }
            if let Terminator::Ret(Some(_)) = &b.terminator { ret_val_count += 1; }
        }
    }
    // Directly self-recursive: inlining it into itself never terminates (and into
    // others it just re-expands to the caps) — only the bounded self-inlining
    // step expands it.
    let self_recursive = eligible && self_rec;
    if self_rec { eligible = false; }
    FnInfo { eligible, size: inline_cost(f), ret_val_count, self_recursive }
}

impl IrPass for Inline {
    fn name(&self) -> &'static str { "inline" }

    fn run(&mut self, m: &mut Module) -> bool {
        let n = m.functions.len();
        let info: Vec<FnInfo> = (0..n).map(|i| analyze(&m.functions[i], i)).collect();
        let mut changed = false;
        for caller in 0..n {
            changed |= self.inline_into(m, caller, &info);
        }
        for f in 0..n {
            changed |= self.self_inline(m, f, &info);
        }
        changed
    }
}

impl Inline {
    /// Inline eligible call sites in function `caller` (repeatedly, so transitive
    /// and multiple-site cases are handled in one pass run, up to the caps).
    fn inline_into(&self, m: &mut Module, caller: usize, info: &[FnInfo]) -> bool {
        let mut changed = false;
        let mut done = 0usize;
        loop {
            if done >= MAX_INLINES_PER_FN { break; }
            if func_size(&m.functions[caller]) > MAX_CALLER_INSTRS { break; }
            // Find the first inlinable call site (block index, instr index).
            let mut site = None;
            'find: for (bi, b) in m.functions[caller].blocks.iter().enumerate() {
                for (ii, ins) in b.instrs.iter().enumerate() {
                    if let Instr::Call { dest, func, args, .. } = ins {
                        if func.is_extern() { continue; }
                        let callee = func.index();
                        if callee == caller { continue; }              // no direct self-inline
                        let ci = &info[callee];
                        if !ci.eligible { continue; }
                        if !(self.aggressive || ci.size <= self.threshold) { continue; }
                        // parameter/argument arity must match (variadic excluded).
                        if args.len() != m.functions[callee].params.len() { continue; }
                        // a value-returning call needs the callee to actually return one.
                        if dest.is_some() && ci.ret_val_count == 0 { continue; }
                        site = Some((bi, ii));
                        break 'find;
                    }
                }
            }
            let Some((bi, ii)) = site else { break };
            self.do_inline(m, caller, bi, ii);
            changed = true;
            done += 1;
        }
        changed
    }

    /// Expand a small self-recursive function into itself: splice its original
    /// body at its own call sites, a bounded number of times, once per function.
    fn self_inline(&mut self, m: &mut Module, f: usize, info: &[FnInfo]) -> bool {
        let fi = &info[f];
        if !fi.self_recursive || fi.size > SELF_INLINE_MAX_COST || fi.ret_val_count == 0 { return false; }
        if !self.self_done.insert(m.functions[f].name.clone()) { return false; }
        let snapshot = m.functions[f].clone();
        // The recursive call sites of the current body, by result value.
        let sites = |func: &Function| -> Vec<ValId> {
            let mut v = Vec::new();
            for b in &func.blocks {
                for ins in &b.instrs {
                    if let Instr::Call { dest: Some(d), func: callee, args, .. } = ins {
                        if !callee.is_extern() && callee.index() == f && args.len() == snapshot.params.len() {
                            v.push(*d);
                        }
                    }
                }
            }
            v
        };
        // Breadth-first: each round expands the sites that existed before it, so
        // the recursion tree is unrolled evenly (fib's two calls both get a copy)
        // rather than down one spine.
        let mut copies = 0;
        'rounds: for _ in 0..SELF_INLINE_ROUNDS {
            let round = sites(&m.functions[f]);
            if round.is_empty() { break; }
            for d in round {
                if copies >= SELF_INLINE_COPIES || func_size(&m.functions[f]) > SELF_INLINE_MAX_GROWN {
                    break 'rounds;
                }
                let pos = m.functions[f].blocks.iter().enumerate().find_map(|(bi, b)| {
                    b.instrs.iter().position(|ins| matches!(ins, Instr::Call { dest: Some(x), .. } if *x == d))
                        .map(|ii| (bi, ii))
                });
                let Some((bi, ii)) = pos else { continue };
                self.splice_body(m, f, bi, ii, &snapshot);
                copies += 1;
            }
        }
        copies > 0
    }

    /// Splice the callee body in at `caller.blocks[bi].instrs[ii]` (a `Call`).
    fn do_inline(&self, m: &mut Module, caller_idx: usize, bi: usize, ii: usize) {
        let callee_idx = match &m.functions[caller_idx].blocks[bi].instrs[ii] {
            Instr::Call { func, .. } => func.index(),
            _ => return,
        };
        // Clone the callee body (avoids aliasing the two `&mut` borrows).
        let callee = m.functions[callee_idx].clone();
        self.splice_body(m, caller_idx, bi, ii, &callee);
    }

    /// Splice `callee` (a body snapshot) in at the call `caller.blocks[bi].instrs[ii]`.
    fn splice_body(&self, m: &mut Module, caller_idx: usize, bi: usize, ii: usize, callee: &Function) {
        let (dest, args, ret_ty) = match &m.functions[caller_idx].blocks[bi].instrs[ii] {
            Instr::Call { dest, args, ret_ty, .. } => (*dest, args.clone(), ret_ty.clone()),
            _ => return,
        };
        let caller = &mut m.functions[caller_idx];

        // --- 1. Build the ValId remap for the callee. -----------------------------
        // Every value the callee DEFINES (instruction dest, alloca, dbg slot) gets a
        // fresh caller ValId; every parameter sentinel maps to the matching argument.
        let mut vmap: HashMap<ValId, Val> = HashMap::new();
        for (i, a) in args.iter().enumerate() {
            vmap.insert(ValId(SENTINEL + i as u32), a.clone());
        }
        for b in &callee.blocks {
            for ins in &b.instrs {
                if let Some(d) = ins.dest() {
                    vmap.entry(d).or_insert_with(|| Val::Local(caller.alloc_val()));
                }
                if let Instr::DbgVar { slot, .. } = ins {
                    vmap.entry(*slot).or_insert_with(|| Val::Local(caller.alloc_val()));
                }
            }
        }
        // --- 2. Fresh block ids for every callee block + a continuation block. ----
        let mut bmap: HashMap<BlockId, BlockId> = HashMap::new();
        for b in &callee.blocks {
            bmap.insert(b.id, caller.alloc_block());
        }
        let cont_id = caller.alloc_block();
        let callee_entry = bmap[&callee.blocks[0].id];

        // --- 3. Decide how the result flows back. ---------------------------------
        // Collect the (remapped) values of every `Ret(Some)`. When the call wants a
        // result and there is exactly ONE return value that is NOT a bare constant,
        // route it as an SSA value (substitute the call's dest with it) — Cranelift
        // does not promote stack slots, so a slot round-trip would be slower than
        // the call it replaces. Otherwise (no result, several returns, or a constant
        // return) fall back to a return slot, which is always correct.
        let ret_vals: Vec<Val> = callee.blocks.iter()
            .filter_map(|b| match &b.terminator {
                Terminator::Ret(Some(v)) => Some(remap_val(v, &vmap)),
                _ => None,
            })
            .collect();
        let ssa_ret: Option<Val> = match (dest, ret_vals.as_slice()) {
            (Some(_), [v]) if !matches!(v, Val::Const(_)) => Some(v.clone()),
            _ => None,
        };
        let ret_slot = match (dest, &ssa_ret) {
            (Some(_), None) => Some(caller.alloc_val()),   // slow path: a real slot
            _ => None,
        };

        // --- 4. Split the caller block at the call. -------------------------------
        let b = &mut caller.blocks[bi];
        let mut tail = b.instrs.split_off(ii);   // tail[0] == the Call
        tail.remove(0);                          // drop the Call itself
        let orig_term = std::mem::replace(&mut b.terminator, Terminator::Jump(callee_entry));
        if let Some(s) = ret_slot {
            // The slot alloca lives at the end of the (now call-free) caller block,
            // so it dominates the inlined return stores and the continuation load.
            b.instrs.push(Instr::Alloca { dest: s, ty: ret_ty.clone(), align: None });
        }

        // --- 5. Clone every callee block with the remap; rewrite returns. ---------
        // Collected and inserted right AFTER the split block (rather than appended at
        // the end of the function) so the block vector keeps a natural, mostly-
        // topological order: predecessors precede successors. Cranelift's SSA builder
        // is meant to be order-independent given `seal_all_blocks`, but a promoted
        // pointer Variable used in a spliced continuation reconstructed to a wrong
        // (null) value when the inlined blocks trailed all their predecessors.
        let mut new_blocks: Vec<BasicBlock> = Vec::with_capacity(callee.blocks.len() + 1);
        for cb in &callee.blocks {
            let new_id = bmap[&cb.id];
            let mut nb = BasicBlock::new(new_id);
            for ins in &cb.instrs {
                nb.instrs.push(remap_instr(ins, &vmap));
            }
            nb.terminator = match &cb.terminator {
                Terminator::Ret(v) => {
                    if let (Some(s), Some(rv)) = (ret_slot, v) {
                        nb.instrs.push(Instr::Store { val: remap_val(rv, &vmap), ptr: Val::Local(s) });
                    }
                    Terminator::Jump(cont_id)
                }
                other => remap_term(other, &vmap, &bmap),
            };
            new_blocks.push(nb);
        }

        // --- 6. Continuation block: materialize the result, then the caller tail. -
        let mut cont = BasicBlock::new(cont_id);
        if let (Some(s), Some(d)) = (ret_slot, dest) {
            cont.instrs.push(Instr::Load { dest: d, ptr: Val::Local(s), ty: ret_ty });
        }
        cont.instrs.extend(tail);
        cont.terminator = orig_term;
        new_blocks.push(cont);

        // Splice the inlined blocks + continuation in right after the split block.
        let at = bi + 1;
        caller.blocks.splice(at..at, new_blocks);

        // --- 7. SSA fast path: replace the call's dest with the single return value.
        // Safe to rewrite EVERY use (including `Store` values and terminators)
        // because the value is a non-constant local/global/func whose width is its
        // own type — the store-width hazard only exists for bare constants, which
        // the `ssa_ret` guard excluded (those took the slot path).
        if let (Some(d), Some(rv)) = (dest, ssa_ret) {
            substitute(caller, d, &rv);
        }
    }
}

/// Replace every use of `from` with `to` throughout the caller — instruction
/// operands (including `Store` values) and terminators. `to` is always a
/// non-constant value here, so there is no store-width hazard (that is why the
/// caller gates this on `!matches!(v, Val::Const(_))`).
fn substitute(func: &mut Function, from: ValId, to: &Val) {
    let repl = |v: &mut Val| { if let Val::Local(id) = v { if *id == from { *v = to.clone(); } } };
    for b in &mut func.blocks {
        for ins in &mut b.instrs {
            ins.for_each_val_mut(repl);
        }
        b.terminator.for_each_val_mut(repl);
    }
}

/// Map a callee operand `Val` to the caller: a local is looked up in `vmap`
/// (parameter → argument, or defined value → fresh local); everything else
/// (globals, funcs, constants) is unchanged.
fn remap_val(v: &Val, vmap: &HashMap<ValId, Val>) -> Val {
    match v {
        Val::Local(id) => vmap.get(id).cloned().unwrap_or_else(|| v.clone()),
        _ => v.clone(),
    }
}

/// The fresh caller ValId a callee-defined ValId maps to (a def always maps to a
/// `Local`).
fn map_dest(id: ValId, vmap: &HashMap<ValId, Val>) -> ValId {
    match vmap.get(&id) {
        Some(Val::Local(n)) => *n,
        _ => id,
    }
}

fn remap_term(t: &Terminator, vmap: &HashMap<ValId, Val>, bmap: &HashMap<BlockId, BlockId>) -> Terminator {
    match t {
        Terminator::Ret(v) => Terminator::Ret(v.as_ref().map(|x| remap_val(x, vmap))),
        Terminator::Jump(b) => Terminator::Jump(bmap[b]),
        Terminator::CondJump { cond, then_bb, else_bb } =>
            Terminator::CondJump { cond: remap_val(cond, vmap), then_bb: bmap[then_bb], else_bb: bmap[else_bb] },
        Terminator::Switch { val, default, arms } =>
            Terminator::Switch {
                val: remap_val(val, vmap),
                default: bmap[default],
                arms: arms.iter().map(|(c, b)| (*c, bmap[b])).collect(),
            },
        Terminator::Unreachable => Terminator::Unreachable,
    }
}

/// Clone an instruction with all operands and its dest / dbg-slot remapped into
/// the caller's value space.
fn remap_instr(ins: &Instr, vmap: &HashMap<ValId, Val>) -> Instr {
    let mut n = ins.clone();
    n.for_each_val_mut(|v| *v = remap_val(v, vmap));
    let md = |id: ValId| map_dest(id, vmap);
    match &mut n {
        Instr::Alloca { dest, .. } | Instr::Load { dest, .. } | Instr::LoadReadonly { dest, .. }
        | Instr::BinOp { dest, .. } | Instr::UnaryOp { dest, .. } | Instr::Cast { dest, .. }
        | Instr::Cmp { dest, .. } | Instr::GetFieldPtr { dest, .. } | Instr::GetElemPtr { dest, .. }
        | Instr::PtrOffset { dest, .. } | Instr::Select { dest, .. } | Instr::BSwap { dest, .. }
        | Instr::VecMoveMask { dest, .. }
        | Instr::AtomicLoad { dest, .. } | Instr::AtomicRmw { dest, .. } | Instr::AtomicCas { dest, .. }
        | Instr::VaArg { dest, .. } | Instr::ReturnAddress { dest } => { *dest = md(*dest); }
        Instr::Call { dest, .. } | Instr::CallIndirect { dest, .. } => { if let Some(d) = dest { *d = md(*d); } }
        Instr::DbgVar { slot, .. } => { *slot = md(*slot); }
        // No dest / no ValId field to remap (operands already handled above).
        Instr::Store { .. } | Instr::MemCopy { .. } | Instr::MemSet { .. }
        | Instr::AtomicStore { .. } | Instr::Fence | Instr::VaStart { .. } | Instr::VaEnd { .. }
        | Instr::SrcLine(_) => {}
    }
    n
}
