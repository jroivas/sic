//! Local variables after inlining. The front end gives every variable and
//! parameter a stack slot, so what one holds stays hidden from the passes that
//! fold on SSA values; Linux relies on it being seen through (a canary a compiler
//! must prove impossible, a parameter that is the same constant at every call).
//!
//! * A slot stored once before all its loads is that value; a slot never loaded
//!   needs no stores (an inlined stub's unused argument, which may be the only
//!   reference to a table of functions).
//! * For every integer in a slot whose address does not escape, the set of values
//!   it can hold, flowing through stores and narrowed on the branches testing it
//!   (`s.state != ss_done` leaves `ss_done` out of the loop body).
//! * A parameter of a `static` function that every call passes the same constant.
//!
//! `volatile` slots stay as they are, and so does all of a function that can
//! return twice (`setjmp`): a value may change behind the code's back.

use std::collections::{BTreeSet};
use sic_ir::fast_hash::{HashMap, HashSet};
use sic_ir::*;
use super::inline::SENTINEL;
use super::asm_imm::prune_dead_blocks;
use super::dce::Dce;
use super::IrPass;

/// A function with more than this many (locations × blocks) to track is left
/// alone: the analysis copies each location's values per block.
const MAX_WORK: usize = 4_000_000;
const MAX_VALUES: usize = 16;

pub fn run(m: &mut Module) {
    for _ in 0..4 {
        let twice: HashSet<usize> = (0..m.functions.len()).filter(|&i| returns_twice(m, i)).collect();
        let mut changed = false;
        for (i, f) in m.functions.iter_mut().enumerate() {
            if f.blocks.is_empty() || twice.contains(&i) { continue; }
            changed |= forward_stored(f);
            changed |= narrow_values(f);
        }
        changed |= constant_params(m);
        prune_dead_blocks(m);
        // Unused now: what kept a table or a call's argument referenced.
        Dce::new().run(m);
        if !changed { break; }
    }
}

fn returns_twice(m: &Module, i: usize) -> bool {
    m.functions[i].blocks.iter().flat_map(|b| &b.instrs).any(|ins| match ins {
        Instr::Call { func, .. } if func.is_extern() =>
            matches!(m.externs[func.index()].name.as_str(), "setjmp" | "_setjmp" | "__sigsetjmp" | "sigsetjmp" | "vfork"),
        _ => false,
    })
}

/// Replace uses of `repl`'s keys. A `Store` keeps its value when that would be a
/// bare constant, which has no width of its own (see `apply_replacements`).
fn replace_uses(f: &mut Function, repl: &HashMap<ValId, Val>) {
    let resolve = |v: &Val| -> Val {
        let mut cur = v.clone();
        for _ in 0..64 {
            match &cur {
                Val::Local(id) => match repl.get(id) { Some(r) => cur = r.clone(), None => break },
                _ => break,
            }
        }
        cur
    };
    for b in &mut f.blocks {
        for ins in &mut b.instrs {
            if let Instr::Store { val, ptr } = ins {
                *ptr = resolve(ptr);
                let r = resolve(val);
                if !matches!(r, Val::Const(_)) { *val = r; }
                continue;
            }
            ins.for_each_val_mut(|v| *v = resolve(v));
        }
        b.terminator.for_each_val_mut(|v| *v = resolve(v));
    }
}

fn successors(t: &Terminator) -> Vec<BlockId> {
    match t {
        Terminator::Jump(b) => vec![*b],
        Terminator::CondJump { then_bb, else_bb, .. } => vec![*then_bb, *else_bb],
        Terminator::Switch { default, arms, .. } =>
            std::iter::once(*default).chain(arms.iter().map(|(_, b)| *b)).collect(),
        _ => vec![],
    }
}

/// Block indices in reverse post-order from the entry.
fn rpo(f: &Function, index: &HashMap<BlockId, usize>) -> Vec<usize> {
    let mut seen = vec![false; f.blocks.len()];
    let mut post = Vec::with_capacity(f.blocks.len());
    let mut stack: Vec<(usize, Vec<usize>)> = Vec::new();
    let succ = |i: usize| -> Vec<usize> {
        successors(&f.blocks[i].terminator).iter().filter_map(|b| index.get(b).copied()).collect()
    };
    seen[0] = true;
    stack.push((0, succ(0)));
    while let Some((i, rest)) = stack.last_mut() {
        match rest.pop() {
            Some(n) => if !seen[n] { seen[n] = true; let s = succ(n); stack.push((n, s)); },
            None => { post.push(*i); stack.pop(); }
        }
    }
    post.reverse();
    post
}

/// Immediate dominators by block index (Cooper, Harvey and Kennedy).
fn dominators(f: &Function, order: &[usize], index: &HashMap<BlockId, usize>) -> Vec<Option<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); f.blocks.len()];
    for &i in order {
        for s in successors(&f.blocks[i].terminator) {
            if let Some(&j) = index.get(&s) { preds[j].push(i); }
        }
    }
    let mut pos = vec![usize::MAX; f.blocks.len()];
    for (k, &i) in order.iter().enumerate() { pos[i] = k; }
    let mut idom: Vec<Option<usize>> = vec![None; f.blocks.len()];
    idom[order[0]] = Some(order[0]);
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &order[1..] {
            let mut new: Option<usize> = None;
            for &p in &preds[b] {
                if idom[p].is_none() { continue; }
                new = Some(match new {
                    None => p,
                    Some(mut a) => {
                        let mut c = p;
                        while a != c {
                            while pos[a] > pos[c] { a = idom[a].unwrap(); }
                            while pos[c] > pos[a] { c = idom[c].unwrap(); }
                        }
                        a
                    }
                });
            }
            if new.is_some() && idom[b] != new { idom[b] = new; changed = true; }
        }
    }
    idom
}

fn dominates(idom: &[Option<usize>], a: usize, mut b: usize) -> bool {
    loop {
        if a == b { return true; }
        match idom[b] {
            Some(p) if p != b => b = p,
            _ => return false,
        }
    }
}

fn scalar(t: &Type) -> bool {
    matches!(t, Type::Int { bits, .. } if *bits <= 64) || matches!(t, Type::Pointer(_) | Type::Bool)
}

/// The types of the values defined in `f`, where an instruction states one.
fn value_types(f: &Function) -> HashMap<ValId, Type> {
    let mut types = HashMap::default();
    for (i, p) in f.params.iter().enumerate() { types.insert(ValId(SENTINEL + i as u32), p.ty.clone()); }
    for b in &f.blocks {
        for ins in &b.instrs {
            let t = match ins {
                Instr::Alloca { dest, ty, .. } => (*dest, Type::Pointer(Box::new(ty.clone()))),
                Instr::Load { dest, ty, .. } | Instr::BinOp { dest, ty, .. } | Instr::UnaryOp { dest, ty, .. }
                | Instr::Select { dest, ty, .. } => (*dest, ty.clone()),
                Instr::Cast { dest, to_ty, .. } => (*dest, to_ty.clone()),
                Instr::GetFieldPtr { dest, result_ty, .. } => (*dest, result_ty.clone()),
                Instr::Call { dest: Some(d), ret_ty, .. } => (*d, ret_ty.clone()),
                _ => continue,
            };
            types.insert(t.0, t.1);
        }
    }
    types
}

/// `v` can stand in for a load of type `ty`: the store did not reinterpret it
/// (`__builtin_signbit` reads a `double` through a `u64` slot).
fn same_kind(v: &Val, ty: &Type, types: &HashMap<ValId, Type>) -> bool {
    match v {
        Val::Const(Constant::Int(_) | Constant::UInt(_)) => matches!(ty, Type::Int { .. } | Type::Bool),
        Val::Const(Constant::Null) | Val::Global(_) | Val::Func(_) => matches!(ty, Type::Pointer(_)),
        Val::Local(id) => match (types.get(id), ty) {
            (Some(Type::Int { bits: a, .. }), Type::Int { bits: b, .. }) => a == b,
            (Some(Type::Pointer(_)), Type::Pointer(_)) | (Some(Type::Bool), Type::Bool) => true,
            _ => false,
        },
        _ => false,
    }
}

#[derive(Default)]
struct SlotUse {
    stores: Vec<(usize, usize, Val)>,
    loads: Vec<(usize, usize, ValId)>,
    escaped: bool,
}

/// Slots stored once before every load become that value; slots no load reads
/// lose their stores.
fn forward_stored(f: &mut Function) -> bool {
    let volatile: HashSet<ValId> = f.volatile_slots.iter().copied().collect();
    let mut slots: HashMap<ValId, (SlotUse, Type)> = HashMap::default();
    for b in &f.blocks {
        for ins in &b.instrs {
            if let Instr::Alloca { dest, ty, .. } = ins {
                if scalar(ty) && !volatile.contains(dest) { slots.insert(*dest, (SlotUse::default(), ty.clone())); }
            }
        }
    }
    if slots.is_empty() { return false; }
    for (bi, b) in f.blocks.iter().enumerate() {
        for (ii, ins) in b.instrs.iter().enumerate() {
            match ins {
                Instr::Load { dest, ptr: Val::Local(p), ty } if slots.contains_key(p) => {
                    let (u, t) = slots.get_mut(p).unwrap();
                    if t != ty { u.escaped = true; }
                    u.loads.push((bi, ii, *dest));
                }
                Instr::Store { val, ptr: Val::Local(p) } if slots.contains_key(p) => {
                    if let Val::Local(v) = val { if let Some(s) = slots.get_mut(v) { s.0.escaped = true; } }
                    slots.get_mut(p).unwrap().0.stores.push((bi, ii, val.clone()));
                }
                other => other.for_each_val(|v| if let Val::Local(id) = v {
                    if let Some(s) = slots.get_mut(id) { s.0.escaped = true; }
                }),
            }
        }
        b.terminator.for_each_val(|v| if let Val::Local(id) = v {
            if let Some(s) = slots.get_mut(id) { s.0.escaped = true; }
        });
    }
    let index: HashMap<BlockId, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
    let order = rpo(f, &index);
    let idom = dominators(f, &order, &index);
    let types = value_types(f);
    // The back end emits blocks in list order and knows a value from its
    // definition on, so a use may not move to a block listed before it.
    let mut def_block: HashMap<ValId, usize> = HashMap::default();
    for (bi, b) in f.blocks.iter().enumerate() {
        for ins in &b.instrs { if let Some(d) = ins.dest() { def_block.insert(d, bi); } }
    }
    let mut repl: HashMap<ValId, Val> = HashMap::default();
    let mut gone: HashSet<ValId> = HashSet::default();
    let mut dead_loads: HashSet<ValId> = HashSet::default();
    for (slot, (u, ty)) in &slots {
        if u.escaped { continue; }
        if u.loads.is_empty() {
            gone.insert(*slot);
        } else if let [(sb, si, val)] = u.stores.as_slice() {
            let def = match val { Val::Local(id) => def_block.get(id).copied(), _ => None };
            let before_all = same_kind(val, ty, &types) && u.loads.iter().all(|&(lb, li, _)|
                def.is_none_or(|d| d <= lb) && if lb == *sb { *si < li } else { dominates(&idom, *sb, lb) });
            if before_all {
                for &(_, _, d) in &u.loads { repl.insert(d, val.clone()); dead_loads.insert(d); }
                gone.insert(*slot);
            }
        }
    }
    if repl.is_empty() && gone.is_empty() { return false; }
    replace_uses(f, &repl);
    // A constant stays stored where a `Store` needed its width: such a load lives.
    let mut still: HashSet<ValId> = HashSet::default();
    for b in &f.blocks {
        for ins in &b.instrs { ins.for_each_val(|v| if let Val::Local(id) = v { still.insert(*id); }); }
        b.terminator.for_each_val(|v| if let Val::Local(id) = v { still.insert(*id); });
    }
    let kept: HashSet<ValId> = slots.iter()
        .filter(|(s, (u, _))| gone.contains(s) && u.loads.iter().any(|&(_, _, d)| still.contains(&d)))
        .map(|(s, _)| *s).collect();
    for b in &mut f.blocks {
        b.instrs.retain(|ins| match ins {
            Instr::Load { dest, ptr: Val::Local(p), .. } if gone.contains(p) && !kept.contains(p) && dead_loads.contains(dest) => false,
            Instr::Load { dest, .. } if dead_loads.contains(dest) && !still.contains(dest) => false,
            Instr::Store { ptr: Val::Local(p), .. } if gone.contains(p) && !kept.contains(p) => false,
            Instr::DbgVar { slot, .. } if gone.contains(slot) && !kept.contains(slot) => false,
            Instr::Alloca { dest, .. } if gone.contains(dest) && !kept.contains(dest) => false,
            _ => true,
        });
    }
    true
}

type Values = Option<BTreeSet<i64>>;   // None: anything

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Loc { slot: ValId, off: u64 }

/// The slots whose every use is a load, store or `memset` at a known offset, and
/// the integer locations in them, with their widths in bits.
struct Tracked {
    ptrs: HashMap<ValId, (Loc, Type)>,
    locs: HashMap<Loc, (usize, u32)>,
}

fn ptr_pointee(t: &Type) -> Option<Type> {
    match t { Type::Pointer(p) => Some((**p).clone()), _ => None }
}

fn tracked_locs(f: &Function) -> Option<Tracked> {
    let volatile: HashSet<ValId> = f.volatile_slots.iter().copied().collect();
    let mut ptrs: HashMap<ValId, (Loc, Type)> = HashMap::default();
    for b in &f.blocks {
        for ins in &b.instrs {
            if let Instr::Alloca { dest, ty, .. } = ins {
                if !volatile.contains(dest) { ptrs.insert(*dest, (Loc { slot: *dest, off: 0 }, ty.clone())); }
            }
        }
    }
    if ptrs.is_empty() { return None; }
    for _ in 0..4 {
        let before = ptrs.len();
        for b in &f.blocks {
            for ins in &b.instrs {
                match ins {
                    Instr::GetFieldPtr { dest, base: Val::Local(p), byte_offset, result_ty, .. } => {
                        if let (Some((l, _)), Some(t)) = (ptrs.get(p).cloned(), ptr_pointee(result_ty)) {
                            ptrs.insert(*dest, (Loc { slot: l.slot, off: l.off + byte_offset }, t));
                        }
                    }
                    Instr::Cast { dest, op: CastOp::BitCast, val: Val::Local(p), to_ty } => {
                        if let (Some((l, _)), Some(t)) = (ptrs.get(p).cloned(), ptr_pointee(to_ty)) {
                            ptrs.insert(*dest, (l, t));
                        }
                    }
                    _ => {}
                }
            }
        }
        if ptrs.len() == before { break; }
    }
    let mut bad: HashSet<ValId> = HashSet::default();
    let mut access: HashMap<ValId, Vec<(u64, u64)>> = HashMap::default();
    let slot_of = |v: &Val| match v { Val::Local(id) => ptrs.get(id).map(|(l, t)| (*l, t.clone())), _ => None };
    for b in &f.blocks {
        for ins in &b.instrs {
            match ins {
                Instr::Load { ptr, ty, .. } => {
                    if let Some((l, _)) = slot_of(ptr) {
                        if scalar(ty) { access.entry(l.slot).or_default().push((l.off, ty.size_of(sic_ir::target::ptr_size()))); }
                        else { bad.insert(l.slot); }
                    }
                }
                Instr::Store { val, ptr } => {
                    if let Some((l, _)) = slot_of(val) { bad.insert(l.slot); }
                    if let Some((l, t)) = slot_of(ptr) {
                        if scalar(&t) { access.entry(l.slot).or_default().push((l.off, t.size_of(sic_ir::target::ptr_size()))); }
                        else { bad.insert(l.slot); }
                    }
                }
                Instr::MemSet { val, .. } => {
                    if let Some((l, _)) = slot_of(val) { bad.insert(l.slot); }
                }
                Instr::GetFieldPtr { base, dest, .. } if slot_of(base).is_some() && ptrs.contains_key(dest) => {}
                Instr::Cast { op: CastOp::BitCast, val, dest, .. } if slot_of(val).is_some() && ptrs.contains_key(dest) => {}
                other => other.for_each_val(|v| if let Some((l, _)) = slot_of(v) { bad.insert(l.slot); }),
            }
        }
        b.terminator.for_each_val(|v| if let Some((l, _)) = slot_of(v) { bad.insert(l.slot); });
    }
    // Accesses at one offset all have one width, and different offsets do not overlap.
    for (slot, list) in &mut access {
        list.sort();
        list.dedup();
        if list.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) { bad.insert(*slot); }
    }
    // Only a location some constant reaches can be narrowed: one written with a
    // constant, by a `memset`, or copied from another slot.
    let constants = constant_defs(f);
    let mut seeded: HashSet<Loc> = HashSet::default();
    let mut zeroed: HashSet<ValId> = HashSet::default();
    let mut copied: HashSet<ValId> = HashSet::default();
    for b in &f.blocks {
        for ins in &b.instrs {
            match ins {
                Instr::Store { val, ptr } => {
                    let Some((l, _)) = slot_of(ptr) else { continue };
                    let known = const_int(val).is_some()
                        || matches!(val, Val::Local(id) if constants.contains_key(id) || copied.contains(id));
                    if known { seeded.insert(l); }
                }
                Instr::Load { dest, ptr, .. } => { if slot_of(ptr).is_some() { copied.insert(*dest); } }
                Instr::Cast { dest, op: CastOp::BitCast, val: Val::Local(v), .. } => { if copied.contains(v) { copied.insert(*dest); } }
                Instr::MemSet { dst, .. } => { if let Some((l, _)) = slot_of(dst) { zeroed.insert(l.slot); } }
                _ => {}
            }
        }
    }
    let mut locs: HashMap<Loc, (usize, u32)> = HashMap::default();
    for b in &f.blocks {
        for ins in &b.instrs {
            let Instr::Load { ptr, ty: Type::Int { bits, .. }, .. } = ins else { continue };
            let Some((l, _)) = slot_of(ptr) else { continue };
            if bad.contains(&l.slot) || *bits > 64 || locs.contains_key(&l) { continue; }
            if !seeded.contains(&l) && !zeroed.contains(&l.slot) { continue; }
            let n = locs.len();
            locs.insert(l, (n, *bits));
        }
    }
    if locs.is_empty() || locs.len().saturating_mul(f.blocks.len()) > MAX_WORK { return None; }
    Some(Tracked { ptrs, locs })
}

fn norm(v: i64, bits: u32) -> i64 {
    if bits >= 64 { v } else { v & ((1i64 << bits) - 1) }
}

fn sign_extend(v: i64, bits: u32) -> i64 {
    if bits >= 64 { v } else { (v << (64 - bits)) >> (64 - bits) }
}

fn const_int(v: &Val) -> Option<i64> {
    match v {
        Val::Const(Constant::Int(i)) => Some(*i),
        Val::Const(Constant::UInt(u)) => Some(*u as i64),
        _ => None,
    }
}

/// Integer constants in value form: a constant cast to a type.
fn constant_defs(f: &Function) -> HashMap<ValId, i64> {
    let mut defs = HashMap::default();
    for b in &f.blocks {
        for ins in &b.instrs {
            if let Instr::Cast { dest, op: op @ (CastOp::BitCast | CastOp::ZExt | CastOp::SExt), val, to_ty: Type::Int { bits, signed } } = ins {
                if *bits > 64 { continue; }
                let c = const_int(val).or_else(|| match val { Val::Local(id) => defs.get(id).copied(), _ => None });
                // Without the source width, only a non-negative value zero-extends to itself.
                if let Some(c) = c.filter(|c| *op != CastOp::ZExt || *c >= 0) {
                    let v = norm(c, *bits);
                    defs.insert(*dest, if *signed { sign_extend(v, *bits) } else { v });
                }
            }
        }
    }
    defs
}

struct Flow<'a> {
    t: &'a Tracked,
    constants: HashMap<ValId, i64>,
    loc_bits: Vec<u32>,
}

/// What a block's end knows: the value of each location, and for a branch the
/// location a condition tests.
struct BlockEnd {
    state: Vec<Values>,
    copies: HashMap<ValId, usize>,
    conds: HashMap<ValId, (usize, bool, i64)>,
}

impl Flow<'_> {
    fn loc_of(&self, v: &Val) -> Option<(usize, u32)> {
        let Val::Local(id) = v else { return None };
        let (l, _) = self.t.ptrs.get(id)?;
        self.t.locs.get(l).copied()
    }

    fn constant(&self, v: &Val) -> Option<i64> {
        const_int(v).or_else(|| match v { Val::Local(id) => self.constants.get(id).copied(), _ => None })
    }

    /// Run a block; `visit` sees each instruction with the state before it.
    fn transfer(&self, f: &Function, bi: usize, mut state: Vec<Values>,
                mut visit: impl FnMut(usize, &Instr, &[Values], &HashMap<ValId, usize>, &HashMap<ValId, (usize, bool, i64)>)) -> BlockEnd {
        let loc_bits = &self.loc_bits;
        let mut copies: HashMap<ValId, usize> = HashMap::default();
        let mut conds: HashMap<ValId, (usize, bool, i64)> = HashMap::default();
        for (ii, ins) in f.blocks[bi].instrs.iter().enumerate() {
            visit(ii, ins, &state, &copies, &conds);
            match ins {
                Instr::Load { dest, ptr, .. } => {
                    if let Some((n, _)) = self.loc_of(ptr) { copies.insert(*dest, n); }
                }
                Instr::Cast { dest, op: CastOp::BitCast, val: Val::Local(v), to_ty: Type::Int { .. } } => {
                    if let Some(&n) = copies.get(v) { copies.insert(*dest, n); }
                }
                Instr::Cast { dest, op: CastOp::ZExt | CastOp::BitCast, val: Val::Local(v), .. } => {
                    if let Some(&c) = conds.get(v) { conds.insert(*dest, c); }
                }
                Instr::Cmp { dest, op, lhs, rhs, ty } => {
                    if let (Val::Local(l), Some(k)) = (lhs, self.constant(rhs)) {
                        let eq = match op { CmpOp::IEq => Some(true), CmpOp::INe => Some(false), _ => None };
                        if let (Some(eq), Some(&n)) = (eq, copies.get(l)) {
                            let bits = match ty { Type::Int { bits, .. } => *bits, _ => 64 };
                            conds.insert(*dest, (n, eq, norm(k, bits)));
                        } else if let (Some(eq), Some(&(n, e, c)), 0) = (eq, conds.get(l), k) {
                            conds.insert(*dest, (n, if eq { !e } else { e }, c));
                        }
                    }
                }
                Instr::Store { val, ptr } => {
                    if let Some((n, bits)) = self.loc_of(ptr) {
                        // A value just read from another location holds what it holds.
                        let copied = match val { Val::Local(id) => copies.get(id).copied(), _ => None };
                        state[n] = match (self.constant(val), copied) {
                            (Some(c), _) => Some(BTreeSet::from([norm(c, bits)])),
                            (None, Some(m)) if loc_bits[m] == bits => state[m].clone(),
                            _ => None,
                        };
                        copies.retain(|_, m| *m != n);
                        conds.retain(|_, c| c.0 != n);
                    }
                }
                Instr::MemSet { dst, val, size, .. } => {
                    let Val::Local(id) = dst else { continue };
                    let Some((l, _)) = self.t.ptrs.get(id) else { continue };
                    let zero = self.constant(val) == Some(0);
                    for (loc, &(n, _)) in &self.t.locs {
                        if loc.slot == l.slot && loc.off >= l.off && loc.off < l.off + size {
                            state[n] = if zero { Some(BTreeSet::from([0])) } else { None };
                            copies.retain(|_, m| *m != n);
                            conds.retain(|_, c| c.0 != n);
                        }
                    }
                }
                _ => {}
            }
        }
        BlockEnd { state, copies, conds }
    }
}

fn narrow(v: &Values, k: i64, eq: bool) -> Option<Values> {
    match (v, eq) {
        (None, true) => Some(Some(BTreeSet::from([k]))),
        (None, false) => Some(None),
        (Some(s), true) => if s.contains(&k) { Some(Some(BTreeSet::from([k]))) } else { None },
        (Some(s), false) => {
            let mut r = s.clone();
            r.remove(&k);
            if r.is_empty() { None } else { Some(Some(r)) }
        }
    }
}

/// The states flowing out of a block, by successor. A successor missing here
/// cannot be reached from it.
fn edges(f: &Function, bi: usize, end: &BlockEnd, loc_bits: &[u32]) -> Vec<(BlockId, Vec<Values>)> {
    let with = |n: usize, v: Values| { let mut s = end.state.clone(); s[n] = v; s };
    match &f.blocks[bi].terminator {
        Terminator::Jump(b) => vec![(*b, end.state.clone())],
        Terminator::CondJump { cond, then_bb, else_bb } => {
            if let Some(&(n, eq, k)) = match cond { Val::Local(id) => end.conds.get(id), _ => None } {
                let mut out = Vec::new();
                if let Some(v) = narrow(&end.state[n], k, eq) { out.push((*then_bb, with(n, v))); }
                if let Some(v) = narrow(&end.state[n], k, !eq) { out.push((*else_bb, with(n, v))); }
                out
            } else {
                vec![(*then_bb, end.state.clone()), (*else_bb, end.state.clone())]
            }
        }
        Terminator::Switch { val, default, arms } => {
            if let Some(&n) = match val { Val::Local(id) => end.copies.get(id), _ => None } {
                let bits = loc_bits[n];
                let mut out = Vec::new();
                let mut rest = Some(end.state[n].clone());
                for (k, b) in arms {
                    let k = norm(*k, bits);
                    if let Some(v) = narrow(&end.state[n], k, true) { out.push((*b, with(n, v))); }
                    if let Some(r) = &rest { rest = narrow(r, k, false); }
                }
                if let Some(r) = rest { out.push((*default, with(n, r))); }
                out
            } else {
                successors(&f.blocks[bi].terminator).into_iter().map(|b| (b, end.state.clone())).collect()
            }
        }
        _ => vec![],
    }
}

fn join(into: &mut Vec<Values>, from: &[Values]) -> bool {
    let mut changed = false;
    for (a, b) in into.iter_mut().zip(from) {
        match (a.as_mut(), b) {
            (None, _) => {}
            (Some(_), None) => { *a = None; changed = true; }
            (Some(s), Some(t)) => {
                let n = s.len();
                s.extend(t.iter().copied());
                if s.len() != n {
                    changed = true;
                    if s.len() > MAX_VALUES { *a = None; }
                }
            }
        }
    }
    changed
}

/// The value-set analysis, then what it proves: loads of one possible value,
/// comparisons with one outcome, switch arms no value reaches.
fn narrow_values(f: &mut Function) -> bool {
    let Some(t) = tracked_locs(f) else { return false };
    let mut loc_bits = vec![0u32; t.locs.len()];
    for &(n, bits) in t.locs.values() { loc_bits[n] = bits; }
    let flow = Flow { t: &t, constants: constant_defs(f), loc_bits: loc_bits.clone() };
    let index: HashMap<BlockId, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
    let order = rpo(f, &index);
    let mut entry: Vec<Option<Vec<Values>>> = vec![None; f.blocks.len()];
    entry[0] = Some(vec![None; loc_bits.len()]);
    let mut changed = true;
    while changed {
        changed = false;
        for &bi in &order {
            let Some(state) = entry[bi].clone() else { continue };
            let end = flow.transfer(f, bi, state, |_, _, _, _, _| {});
            for (succ, out) in edges(f, bi, &end, &loc_bits) {
                let Some(&si) = index.get(&succ) else { continue };
                match &mut entry[si] {
                    Some(s) => changed |= join(s, &out),
                    e @ None => { *e = Some(out); changed = true; }
                }
            }
        }
    }
    let mut repl: HashMap<ValId, Val> = HashMap::default();
    let mut arms_left: Vec<(usize, Vec<(i64, BlockId)>)> = Vec::new();
    for &bi in &order {
        let Some(state) = entry[bi].clone() else { continue };
        let end = flow.transfer(f, bi, state, |_, ins, st, copies, _| match ins {
            Instr::Load { dest, ptr, ty } => {
                if let Some((n, _)) = flow.loc_of(ptr) {
                    if let Some(s) = &st[n] {
                        if s.len() == 1 {
                            let v = *s.iter().next().unwrap();
                            let v = match ty {
                                Type::Int { bits, signed: true } => sign_extend(v, *bits),
                                _ => v,
                            };
                            repl.insert(*dest, Val::Const(Constant::Int(v)));
                        }
                    }
                }
            }
            Instr::Cmp { dest, op, lhs, rhs, ty } => {
                let (Val::Local(l), Some(k)) = (lhs, flow.constant(rhs)) else { return };
                let eq = match op { CmpOp::IEq => true, CmpOp::INe => false, _ => return };
                let Some(&n) = copies.get(l) else { return };
                let Some(s) = &st[n] else { return };
                let bits = match ty { Type::Int { bits, .. } => *bits, _ => 64 };
                let k = norm(k, bits);
                let same = if !s.contains(&k) { Some(false) } else if s.len() == 1 { Some(true) } else { None };
                if let Some(same) = same {
                    repl.insert(*dest, Val::Const(Constant::Int((same == eq) as i64)));
                }
            }
            _ => {}
        });
        if let Terminator::Switch { val, arms, .. } = &f.blocks[bi].terminator {
            if let Some(&n) = match val { Val::Local(id) => end.copies.get(id), _ => None } {
                if let Some(s) = &end.state[n] {
                    let bits = loc_bits[n];
                    let kept: Vec<(i64, BlockId)> = arms.iter().filter(|(k, _)| s.contains(&norm(*k, bits))).cloned().collect();
                    if kept.len() != arms.len() { arms_left.push((bi, kept)); }
                }
            }
        }
    }
    let any = !repl.is_empty() || !arms_left.is_empty();
    for (bi, kept) in arms_left {
        if let Terminator::Switch { arms, .. } = &mut f.blocks[bi].terminator { *arms = kept; }
    }
    replace_uses(f, &repl);
    any
}

/// `static` functions whose every call passes one constant for a parameter (GCC's
/// `.constprop`): the parameter becomes that constant.
fn constant_params(m: &mut Module) -> bool {
    let n = m.functions.len();
    let mut open: HashSet<usize> = (0..n).filter(|&i| {
        let f = &m.functions[i];
        f.linkage == Linkage::Internal && !f.sig.variadic && !f.params.is_empty() && !f.blocks.is_empty()
            && f.constructor.is_none() && !m.used_functions.contains(&f.name)
    }).collect();
    if open.is_empty() { return false; }
    let asm = m.asm_names();
    open.retain(|&i| !asm.contains(m.functions[i].name.as_str()));
    let close = |v: &Val, open: &mut HashSet<usize>| {
        if let Val::Func(fr) = v { if !fr.is_extern() { open.remove(&fr.index()); } }
    };
    for g in &m.globals {
        if let Some(Constant::Aggregate { relocs, .. }) = &g.init {
            for (_, t) in relocs {
                if let RelocTarget::Func(fr) = t { if !fr.is_extern() { open.remove(&fr.index()); } }
            }
        }
    }
    let mut args: HashMap<usize, Vec<Option<Option<i64>>>> = HashMap::default();
    for f in &m.functions {
        let constants = constant_defs(f);
        for b in &f.blocks {
            for ins in &b.instrs {
                ins.for_each_val(|v| close(v, &mut open));
                let Instr::Call { func, args: a, .. } = ins else { continue };
                if func.is_extern() || !open.contains(&func.index()) { continue; }
                let seen = args.entry(func.index()).or_insert_with(|| vec![None; m.functions[func.index()].params.len()]);
                for (s, v) in seen.iter_mut().zip(a) {
                    let c = const_int(v).or_else(|| match v { Val::Local(id) => constants.get(id).copied(), _ => None });
                    *s = match *s {
                        None => Some(c),
                        Some(old) if old == c => Some(old),
                        Some(_) => Some(None),
                    };
                }
            }
            b.terminator.for_each_val(|v| close(v, &mut open));
        }
    }
    let mut changed = false;
    for (fi, seen) in args {
        if !open.contains(&fi) { continue; }
        for (i, s) in seen.into_iter().enumerate() {
            let Some(Some(c)) = s else { continue };
            let f = &mut m.functions[fi];
            if !matches!(f.params[i].ty, Type::Int { .. }) { continue; }
            let sentinel = ValId(SENTINEL + i as u32);
            let mut used = false;
            for b in &f.blocks {
                for ins in &b.instrs { ins.for_each_val(|v| used |= *v == Val::Local(sentinel)); }
                b.terminator.for_each_val(|v| used |= *v == Val::Local(sentinel));
            }
            if !used { continue; }
            let d = f.alloc_val();
            let to_ty = f.params[i].ty.clone();
            let repl = [(sentinel, Val::Local(d))].into_iter().collect();
            replace_uses(f, &repl);
            f.blocks[0].instrs.insert(0, Instr::Cast { dest: d, op: CastOp::BitCast, val: Val::Const(Constant::Int(c)), to_ty });
            changed = true;
        }
    }
    changed
}
