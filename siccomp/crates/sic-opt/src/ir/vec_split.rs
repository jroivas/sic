//! Vector slot splitting (typed IR stage).
//!
//! GCC vector values (`__m128`, `__m256`, …) are aggregates in the IR: each
//! lives in a stack slot, reached through pointer `BitCast`s, `PtrOffset`s to
//! its 16-byte halves and whole-slot `MemCopy`s (by-value parameters, returns,
//! assignments). The back end keeps a slot in a register only when it is used
//! by plain loads and stores of its own address, so these never qualify and
//! every intrinsic round-trips its operands through memory.
//!
//! A slot of 16 to 256 bytes whose every use, through casts and constant
//! offsets or indices, is a 16-byte vector load or store at a 16-byte
//! boundary, or a copy or constant fill of whole 16-byte parts, is split
//! into 16-byte vector slots accessed directly; a copy becomes a load and
//! store per part. Any other use (a lane read as a
//! scalar, the address passed on) leaves the slot as it is.

use std::collections::{HashMap, HashSet};
use sic_ir::{Module, Function, Instr, Val, ValId, Type, CastOp, Constant, SimdOp};
use super::pass::IrPass;

pub struct VecSplit;

impl VecSplit {
    pub fn new() -> Self { VecSplit }
}

impl IrPass for VecSplit {
    fn name(&self) -> &'static str { "vec-split" }

    fn run(&mut self, m: &mut Module) -> bool {
        let mut changed = false;
        for f in &mut m.functions {
            changed |= split_function(f);
        }
        changed
    }
}

fn is_v128(t: &Type) -> bool { t.simd128().is_some() }

fn part_ty() -> Type { Type::Array { elem: Box::new(Type::Int { bits: 64, signed: true }), len: 2 } }

fn const_off(v: &Val) -> Option<i64> {
    match v {
        Val::Const(Constant::Int(n)) => Some(*n),
        Val::Const(Constant::UInt(n)) => Some(*n as i64),
        _ => None,
    }
}

/// Result types of the instructions whose values may be stored to a slot.
fn value_types(f: &Function) -> HashMap<ValId, Type> {
    let mut t = HashMap::new();
    for b in &f.blocks {
        for ins in &b.instrs {
            let r = match ins {
                Instr::Load { dest, ty, .. } | Instr::LoadReadonly { dest, ty, .. } => Some((*dest, ty.clone())),
                Instr::Simd { dest, ty, .. } => Some((*dest, ty.clone())),
                Instr::BinOp { dest, ty, .. } | Instr::UnaryOp { dest, ty, .. } | Instr::Select { dest, ty, .. } => Some((*dest, ty.clone())),
                _ => None,
            };
            if let Some((d, ty)) = r { t.insert(d, ty); }
        }
    }
    t
}

fn split_function(f: &mut Function) -> bool {
    // Candidate slots and their sizes.
    let mut size: HashMap<ValId, u64> = HashMap::new();
    for b in &f.blocks {
        for ins in &b.instrs {
            if let Instr::Alloca { dest, ty, align } = ins {
                let s = ty.size_of(8);
                if s >= 16 && s <= 256 && s % 16 == 0 && align.map_or(true, |a| a <= 16) {
                    size.insert(*dest, s);
                }
            }
        }
    }
    if size.is_empty() { return false; }
    // Integer constants behind extensions (an index typed by a cast).
    let mut konst: HashMap<ValId, i64> = HashMap::new();
    for b in &f.blocks {
        for ins in &b.instrs {
            if let Instr::Cast { dest, op: CastOp::SExt | CastOp::ZExt, val, .. } = ins {
                if let Some(c) = const_off(val) { konst.insert(*dest, c); }
            }
        }
    }
    let const_off = |v: &Val| match v {
        Val::Local(id) => konst.get(id).copied(),
        _ => const_off(v),
    };
    // Pointers into a candidate: (slot, byte offset), through pointer casts and
    // constant offsets (to a fixed point: definitions may follow uses in block
    // order).
    let mut alias: HashMap<ValId, (ValId, i64)> = size.keys().map(|&k| (k, (k, 0))).collect();
    loop {
        let mut grew = false;
        for b in &f.blocks {
            for ins in &b.instrs {
                let (d, base, off) = match ins {
                    // The frontend's pointer reinterpretation: a `BitCast` to the
                    // pointee (aggregate) or a pointer type.
                    Instr::Cast { dest, op: CastOp::BitCast, val: Val::Local(v), .. } => (*dest, *v, 0),
                    Instr::PtrOffset { dest, base: Val::Local(v), offset } => match const_off(offset) {
                        Some(o) => (*dest, *v, o),
                        None => continue,
                    },
                    Instr::GetElemPtr { dest, base: Val::Local(v), index, elem_size, .. } => match const_off(index) {
                        Some(i) => (*dest, *v, i * *elem_size as i64),
                        None => continue,
                    },
                    Instr::GetFieldPtr { dest, base: Val::Local(v), byte_offset, .. } => (*dest, *v, *byte_offset as i64),
                    _ => continue,
                };
                if alias.contains_key(&d) { continue; }
                if let Some(&(root, o)) = alias.get(&base) {
                    alias.insert(d, (root, o + off));
                    grew = true;
                }
            }
        }
        if !grew { break; }
    }
    let vt = value_types(f);
    // Reject a slot on any use other than whole-part loads/stores or whole-slot copies.
    let mut bad: HashSet<ValId> = HashSet::new();
    let mut rewrite: HashSet<ValId> = HashSet::new();
    let part_ok = |root: ValId, off: i64, size: &HashMap<ValId, u64>| off >= 0 && off % 16 == 0 && (off as u64) + 16 <= size[&root];
    for b in &f.blocks {
        for ins in &b.instrs {
            let reject = |v: &Val, bad: &mut HashSet<ValId>| {
                if let Val::Local(id) = v { if let Some(&(r, _)) = alias.get(id) { bad.insert(r); } }
            };
            match ins {
                Instr::Load { dest: _, ptr: Val::Local(p), ty } => {
                    if let Some(&(r, o)) = alias.get(p) {
                        if !is_v128(ty) || !part_ok(r, o, &size) { bad.insert(r); }
                        else if *p != r || size[&r] != 16 { rewrite.insert(r); }
                    }
                }
                Instr::Store { val, ptr: Val::Local(p) } => {
                    reject(val, &mut bad);
                    if let Some(&(r, o)) = alias.get(p) {
                        let ty_ok = matches!(val, Val::Local(v) if vt.get(v).map_or(false, is_v128));
                        if !ty_ok || !part_ok(r, o, &size) { bad.insert(r); }
                        else if *p != r || size[&r] != 16 { rewrite.insert(r); }
                    }
                }
                // Copies and constant fills of whole 16-byte parts.
                Instr::MemCopy { dst, src, size: n, .. } => {
                    for v in [dst, src] {
                        if let Val::Local(id) = v {
                            if let Some(&(r, o)) = alias.get(id) {
                                let fits = o >= 0 && o % 16 == 0 && n % 16 == 0 && *n > 0 && o as u64 + n <= size[&r];
                                if !fits { bad.insert(r); } else { rewrite.insert(r); }
                            }
                        }
                    }
                }
                Instr::MemSet { dst: Val::Local(id), val, size: n, .. } if alias.contains_key(id) => {
                    let (r, o) = alias[id];
                    let fits = o >= 0 && o % 16 == 0 && n % 16 == 0 && *n > 0 && o as u64 + n <= size[&r];
                    if !fits || const_off(val).is_none() { bad.insert(r); } else { rewrite.insert(r); }
                }
                Instr::Cast { op: CastOp::BitCast, val: Val::Local(v), .. } if alias.contains_key(v) => {}
                Instr::PtrOffset { base: Val::Local(v), offset, .. } if alias.contains_key(v) && const_off(offset).is_some() => {}
                Instr::GetElemPtr { base: Val::Local(v), index, .. } if alias.contains_key(v) && const_off(index).is_some() => {}
                Instr::GetFieldPtr { base: Val::Local(v), .. } if alias.contains_key(v) => {}
                Instr::Alloca { .. } | Instr::DbgVar { .. } | Instr::SrcLine(_) => {}
                other => other.for_each_val(|v| reject(v, &mut bad)),
            }
        }
        b.terminator.for_each_val(|v| if let Val::Local(id) = v { if let Some(&(r, _)) = alias.get(id) { bad.insert(r); } });
    }
    let split: HashSet<ValId> = rewrite.difference(&bad).copied().collect();
    if split.is_empty() { return false; }

    // The parts of each split slot.
    let mut parts: HashMap<ValId, Vec<ValId>> = HashMap::new();
    for &r in &split {
        let n = size[&r] / 16;
        parts.insert(r, (0..n).map(|_| f.alloc_val()).collect());
    }
    let part_of = |p: &ValId| alias.get(p).filter(|(r, _)| split.contains(r)).map(|&(r, o)| (r, o));

    let mut blocks = std::mem::take(&mut f.blocks);
    for b in &mut blocks {
        let old = std::mem::take(&mut b.instrs);
        let mut out = Vec::with_capacity(old.len());
        for ins in old {
            match &ins {
                Instr::Alloca { dest, .. } if split.contains(dest) => {
                    for &p in &parts[dest] {
                        out.push(Instr::Alloca { dest: p, ty: part_ty(), align: None });
                    }
                }
                Instr::DbgVar { slot, .. } if split.contains(slot) => {}
                Instr::Cast { dest, .. } | Instr::PtrOffset { dest, .. } | Instr::GetElemPtr { dest, .. }
                | Instr::GetFieldPtr { dest, .. }
                    if part_of(dest).is_some() && !split.contains(dest) => {}
                Instr::Load { dest, ptr: Val::Local(p), ty } if part_of(p).is_some() => {
                    let (r, o) = part_of(p).unwrap();
                    out.push(Instr::Load { dest: *dest, ptr: Val::Local(parts[&r][(o / 16) as usize]), ty: ty.clone() });
                }
                Instr::Store { val, ptr: Val::Local(p) } if part_of(p).is_some() => {
                    let (r, o) = part_of(p).unwrap();
                    out.push(Instr::Store { val: val.clone(), ptr: Val::Local(parts[&r][(o / 16) as usize]) });
                }
                Instr::MemSet { dst: Val::Local(d), val, size: n, .. } if part_of(d).is_some() => {
                    let (r, o) = part_of(d).unwrap();
                    let byte = const_off(val).unwrap_or(0) as u8;
                    let c = f.alloc_val();
                    out.push(Instr::Simd { dest: c, op: SimdOp::Const(Box::new([byte; 16])), args: vec![], arg_ty: part_ty(), ty: part_ty() });
                    for k in 0..(n / 16) as usize {
                        out.push(Instr::Store { val: Val::Local(c), ptr: Val::Local(parts[&r][(o / 16) as usize + k]) });
                    }
                }
                Instr::MemCopy { dst, src, size: n, .. }
                    if matches!(dst, Val::Local(d) if part_of(d).is_some()) || matches!(src, Val::Local(s) if part_of(s).is_some()) =>
                {
                    let side = |v: &Val| match v { Val::Local(id) => part_of(id).map(|(r, o)| (r, (o / 16) as usize)), _ => None };
                    let (ds, ss) = (side(dst), side(src));
                    for k in 0..(n / 16) as usize {
                        let from = match ss {
                            Some((r, p0)) => Val::Local(parts[&r][p0 + k]),
                            None => {
                                let a = f.alloc_val();
                                out.push(Instr::PtrOffset { dest: a, base: src.clone(), offset: Constant::int(16 * k as i64) });
                                Val::Local(a)
                            }
                        };
                        let v = f.alloc_val();
                        out.push(Instr::Load { dest: v, ptr: from, ty: part_ty() });
                        let to = match ds {
                            Some((r, p0)) => Val::Local(parts[&r][p0 + k]),
                            None => {
                                let a = f.alloc_val();
                                out.push(Instr::PtrOffset { dest: a, base: dst.clone(), offset: Constant::int(16 * k as i64) });
                                Val::Local(a)
                            }
                        };
                        out.push(Instr::Store { val: Val::Local(v), ptr: to });
                    }
                }
                _ => out.push(ins),
            }
        }
        b.instrs = out;
    }
    f.blocks = blocks;
    true
}
