//! Inline-assembly `"i"` operands known only after optimization (see
//! [`sic_ir::AsmDeferred`]).
//!
//! GCC and Clang accept an `"i"` operand that becomes a constant once the
//! statement is optimized: Linux's `arch_static_branch(key, branch)` is an
//! `always_inline` function whose `asm goto` takes `"i"(key)`, constant only
//! after inlining; `auto __flags = …; asm(… "i"(__flags))` is a local. The
//! frontend passes such operands as trailing arguments of the helper call;
//! here, after the IR passes, each call's arguments are traced back to a
//! constant or `symbol + offset`, printed into a copy of the helper text, and
//! the call is pointed at that copy without them. An operand that does not
//! resolve in a function that is emitted is an error, as GCC's "impossible
//! constraint in asm". (No mem2reg runs on the IR, so a value reaches the call
//! through stack slots: a slot whose one store is the value and which is
//! otherwise only loaded is followed.)

use sic_ir::fast_hash::{HashMap, HashSet};
use sic_ir::*;

/// Brackets an operand placeholder in a helper body (see `AsmDeferred`).
const MARK: char = '\u{1}';

#[derive(Clone, Debug, PartialEq)]
enum Imm {
    Int(i64),
    /// A symbol's address plus a byte offset.
    Sym(String, i64),
}

fn sym_off(s: &str, off: i64) -> String {
    let s = if s.chars().all(|c| c.is_ascii_alphanumeric() || "_.$".contains(c)) { s.to_string() }
        else { format!("\"{}\"", s.replace('"', "\\\"")) };
    match off { 0 => s, o if o > 0 => format!("{}+{}", s, o), o => format!("{}{}", s, o) }
}

impl Imm {
    /// As GCC prints an immediate: `$v` bare, `v` with `%c`/`%P`, `-v` with
    /// `%n`; a symbol `$sym+off`, `sym+off`, and with `%a` `sym+off(%rip)`.
    fn print(&self, m: char) -> Option<String> {
        Some(match (self, m) {
            (Imm::Int(v), '$') => format!("${}", v),
            (Imm::Int(v), 'c' | 'a') => format!("{}", v),
            (Imm::Int(v), 'n') => format!("{}", v.wrapping_neg()),
            (Imm::Sym(s, o), '$') => format!("${}", sym_off(s, *o)),
            (Imm::Sym(s, o), 'c') => sym_off(s, *o),
            (Imm::Sym(s, o), 'a') => format!("{}(%rip)", sym_off(s, *o)),
            _ => return None,
        })
    }
}

/// Values in one function: what defines each local, and slot contents.
struct Resolver<'a> {
    m: &'a Module,
    f: &'a Function,
    defs: HashMap<u32, &'a Instr>,
    /// Where each value is defined: (block, instruction index).
    at: HashMap<u32, (usize, usize)>,
    /// Defined functions whose address an operand took (kept as `used`).
    used_fns: Vec<String>,
}

impl<'a> Resolver<'a> {
    fn new(m: &'a Module, f: &'a Function) -> Self {
        let mut defs = HashMap::default();
        let mut at = HashMap::default();
        for (bi, b) in f.blocks.iter().enumerate() {
            for (ii, i) in b.instrs.iter().enumerate() {
                if let Some(d) = instr_dest(i) { defs.insert(d.0, i); at.insert(d.0, (bi, ii)); }
            }
        }
        Resolver { m, f, defs, at, used_fns: Vec::new() }
    }

    /// The value the load `load` (a value id) reads from `slot`: the closest
    /// earlier store to the slot in the same block — Linux's `rip_rel_ptr(p)`
    /// stores its asm output back into `p`, after the asm read it — or, with
    /// none there, the slot's only store. Only for a slot whose address never
    /// escapes, so nothing but those stores writes it.
    fn loaded_value(&self, load: ValId, slot: ValId) -> Option<Val> {
        let sv = Val::Local(slot);
        if !self.slot_private(slot) { return None; }
        let &(bi, ii) = self.at.get(&load.0)?;
        for i in self.f.blocks[bi].instrs[..ii].iter().rev() {
            if let Instr::Store { val, ptr } = i {
                if *ptr == sv { return Some(val.clone()); }
            }
        }
        self.slot_value(slot)
    }

    /// Whether a slot is used only by loads from it and stores into it.
    fn slot_private(&self, slot: ValId) -> bool {
        let sv = Val::Local(slot);
        for b in &self.f.blocks {
            for i in &b.instrs {
                match i {
                    Instr::Load { ptr, .. } if *ptr == sv => continue,
                    Instr::Store { val, ptr } if *ptr == sv && *val != sv => continue,
                    _ => {}
                }
                let mut esc = false;
                i.for_each_val(|v| if *v == sv { esc = true; });
                if esc { return false; }
            }
            let mut esc = false;
            b.terminator.for_each_val(|v| if *v == sv { esc = true; });
            if esc { return false; }
        }
        true
    }

    /// The value a stack slot always holds: its only store, when every other
    /// use of the slot is a load (its address never escapes).
    fn slot_value(&self, slot: ValId) -> Option<Val> {
        let sv = Val::Local(slot);
        let (mut stored, mut n) = (None, 0);
        for b in &self.f.blocks {
            for i in &b.instrs {
                match i {
                    Instr::Load { ptr, .. } if *ptr == sv => continue,
                    Instr::Store { val, ptr } if *ptr == sv && *val != sv => { n += 1; stored = Some(val.clone()); continue; }
                    _ => {}
                }
                let mut esc = false;
                i.for_each_val(|v| if *v == sv { esc = true; });
                if esc { return None; }
            }
            let mut esc = false;
            b.terminator.for_each_val(|v| if *v == sv { esc = true; });
            if esc { return None; }
        }
        if n == 1 { stored } else { None }
    }

    fn resolve(&mut self, v: &Val, depth: u32) -> Option<Imm> {
        if depth > 64 { return None; }
        match v {
            Val::Const(c) => match c {
                Constant::Int(i) => Some(Imm::Int(*i)),
                Constant::UInt(u) => Some(Imm::Int(*u as i64)),
                Constant::Bool(b) => Some(Imm::Int(*b as i64)),
                Constant::Null => Some(Imm::Int(0)),
                Constant::GlobalAddr(g) => Some(Imm::Sym(self.m.globals[g.0 as usize].name.clone(), 0)),
                _ => None,
            },
            Val::Global(g) => Some(Imm::Sym(self.m.globals[g.0 as usize].name.clone(), 0)),
            Val::Func(fr) => {
                let name = if fr.is_extern() { self.m.externs[fr.index()].name.clone() } else {
                    let n = self.m.functions[fr.index()].name.clone();
                    self.used_fns.push(n.clone());
                    n
                };
                Some(Imm::Sym(name, 0))
            }
            Val::Local(id) => {
                let ins = *self.defs.get(&id.0)?;
                match ins {
                    Instr::Load { ptr: Val::Local(slot), .. }
                        if matches!(self.defs.get(&slot.0), Some(Instr::Alloca { .. })) => {
                        let stored = self.loaded_value(*id, *slot)?;
                        self.resolve(&stored, depth + 1)
                    }
                    Instr::Cast { op, val, to_ty, .. } => {
                        let x = self.resolve(val, depth + 1)?;
                        match (op, x) {
                            (CastOp::BitCast, Imm::Int(v)) if matches!(to_ty, Type::Int { .. }) => Some(Imm::Int(truncate(v, to_ty))),
                            (CastOp::PtrToInt | CastOp::IntToPtr | CastOp::BitCast, x) => Some(x),
                            (CastOp::SExt, x @ Imm::Int(_)) => Some(x),
                            // The source width is not known here: only a
                            // non-negative value zero-extends to itself.
                            (CastOp::ZExt, Imm::Int(v)) if v >= 0 => Some(Imm::Int(v)),
                            (CastOp::Trunc, Imm::Int(v)) => Some(Imm::Int(truncate(v, to_ty))),
                            _ => None,
                        }
                    }
                    Instr::PtrOffset { base, offset, .. } => {
                        let b = self.resolve(base, depth + 1)?;
                        let Imm::Int(o) = self.resolve(offset, depth + 1)? else { return None };
                        Some(add(b, o))
                    }
                    Instr::GetElemPtr { base, index, elem_size, .. } => {
                        let b = self.resolve(base, depth + 1)?;
                        let Imm::Int(i) = self.resolve(index, depth + 1)? else { return None };
                        Some(add(b, i.wrapping_mul(*elem_size as i64)))
                    }
                    Instr::GetFieldPtr { base, byte_offset, .. } => {
                        let b = self.resolve(base, depth + 1)?;
                        Some(add(b, *byte_offset as i64))
                    }
                    Instr::BinOp { op, lhs, rhs, ty, .. } => {
                        let l = self.resolve(lhs, depth + 1)?;
                        let r = self.resolve(rhs, depth + 1)?;
                        match (l, r) {
                            (Imm::Int(a), Imm::Int(b)) => {
                                // Values are i64 here: nothing wider folds, and a
                                // shift count must be below the type's width.
                                let bits = int_bits(ty);
                                if bits > 64 { return None; }
                                if matches!(op, BinOp::Shl | BinOp::AShr | BinOp::LShr)
                                    && !(0..bits as i64).contains(&b) { return None; }
                                let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                                let v = match op {
                                    BinOp::Add => a.wrapping_add(b), BinOp::Sub => a.wrapping_sub(b),
                                    BinOp::Mul => a.wrapping_mul(b),
                                    BinOp::And => a & b, BinOp::Or => a | b, BinOp::Xor => a ^ b,
                                    BinOp::Shl => a.wrapping_shl(b as u32),
                                    BinOp::AShr => a.wrapping_shr(b as u32),
                                    BinOp::LShr => (((a as u64) & mask).wrapping_shr(b as u32)) as i64,
                                    _ => return None,
                                };
                                Some(Imm::Int(truncate(v, ty)))
                            }
                            (s @ Imm::Sym(..), Imm::Int(b)) if *op == BinOp::Add => Some(add(s, b)),
                            (Imm::Int(a), s @ Imm::Sym(..)) if *op == BinOp::Add => Some(add(s, a)),
                            (s @ Imm::Sym(..), Imm::Int(b)) if *op == BinOp::Sub => Some(add(s, b.wrapping_neg())),
                            (Imm::Sym(x, a), Imm::Sym(y, b)) if *op == BinOp::Sub && x == y => Some(Imm::Int(a - b)),
                            _ => None,
                        }
                    }
                    Instr::Cmp { op, lhs, rhs, ty, .. } => {
                        let (Imm::Int(a), Imm::Int(b)) = (self.resolve(lhs, depth + 1)?, self.resolve(rhs, depth + 1)?)
                            else { return None };
                        let bits = int_bits(ty);
                        if bits > 64 { return None; }
                        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                        let (ua, ub) = ((a as u64) & mask, (b as u64) & mask);
                        let sext = |u: u64| if bits < 64 && (u >> (bits - 1)) & 1 == 1 { (u | !mask) as i64 } else { u as i64 };
                        let (sa, sb) = (sext(ua), sext(ub));
                        let r = match op {
                            CmpOp::IEq => ua == ub, CmpOp::INe => ua != ub,
                            CmpOp::ISLt => sa < sb, CmpOp::ISLe => sa <= sb, CmpOp::ISGt => sa > sb, CmpOp::ISGe => sa >= sb,
                            CmpOp::IULt => ua < ub, CmpOp::IULe => ua <= ub, CmpOp::IUGt => ua > ub, CmpOp::IUGe => ua >= ub,
                            _ => return None,
                        };
                        Some(Imm::Int(r as i64))
                    }
                    Instr::UnaryOp { op, val, ty, .. } => {
                        let Imm::Int(v) = self.resolve(val, depth + 1)? else { return None };
                        Some(Imm::Int(match op {
                            UnOp::Neg => truncate(v.wrapping_neg(), ty),
                            UnOp::Not => truncate(!v, ty),
                            UnOp::BoolNot => (v == 0) as i64,
                            _ => return None,
                        }))
                    }
                    Instr::Select { cond, on_true, on_false, .. } => {
                        let Imm::Int(c) = self.resolve(cond, depth + 1)? else { return None };
                        self.resolve(if c != 0 { on_true } else { on_false }, depth + 1)
                    }
                    _ => None,
                }
            }
        }
    }
}

fn int_bits(ty: &Type) -> u32 {
    match ty { Type::Int { bits, .. } => *bits, Type::Bool => 1, _ => 64 }
}

fn add(x: Imm, o: i64) -> Imm {
    match x { Imm::Int(v) => Imm::Int(v.wrapping_add(o)), Imm::Sym(s, b) => Imm::Sym(s, b.wrapping_add(o)) }
}

/// `v` as an integer of type `ty` (its width and signedness).
fn truncate(v: i64, ty: &Type) -> i64 {
    match ty {
        Type::Int { bits, signed } if *bits < 64 => {
            let m = (1u64 << bits) - 1;
            let u = (v as u64) & m;
            if *signed && (u >> (bits - 1)) & 1 == 1 { (u | !m) as i64 } else { u as i64 }
        }
        Type::Bool => (v != 0) as i64,
        _ => v,
    }
}

fn instr_dest(i: &Instr) -> Option<ValId> {
    Some(match i {
        Instr::Alloca { dest, .. } | Instr::Load { dest, .. } | Instr::Cast { dest, .. }
        | Instr::PtrOffset { dest, .. } | Instr::GetElemPtr { dest, .. } | Instr::GetFieldPtr { dest, .. }
        | Instr::BinOp { dest, .. } | Instr::Select { dest, .. } | Instr::Cmp { dest, .. }
        | Instr::UnaryOp { dest, .. } => *dest,
        _ => return None,
    })
}

/// `body` with each placeholder replaced by its operand, and the helper's
/// unique-number placeholder (`<mark>U<mark>`: its local labels, `%=`) by `uid`.
fn substitute(body: &str, vals: &[Imm], uid: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = body;
    while let Some(st) = rest.find(MARK) {
        out.push_str(&rest[..st]);
        let after = &rest[st + MARK.len_utf8()..];
        let end = after.find(MARK)?;
        let ph = &after[..end];
        if ph == "U" { out.push_str(uid); rest = &after[end + MARK.len_utf8()..]; continue; }
        let m = ph.chars().last()?;
        let k: usize = ph[..ph.len() - m.len_utf8()].parse().ok()?;
        out.push_str(&vals.get(k)?.print(m)?);
        rest = &after[end + MARK.len_utf8()..];
    }
    out.push_str(rest);
    Some(out)
}

/// Fold each branch whose condition is a constant (after the IR passes, as
/// resolved here) into a jump: Linux's `switch (sizeof(*ptr)) { case 1: asm
/// ("cmpxchgb …") … }` must not reach the assembler through its dead arms,
/// whose operands do not fit (GCC and Clang drop them before emitting asm).
fn fold_constant_branches(m: &mut Module) {
    for fi in 0..m.functions.len() {
        let mut folds: Vec<(usize, BlockId)> = Vec::new();
        {
            let f = &m.functions[fi];
            let mut r = Resolver::new(m, f);
            for (bi, b) in f.blocks.iter().enumerate() {
                match &b.terminator {
                    Terminator::CondJump { cond, then_bb, else_bb } => {
                        if let Some(Imm::Int(c)) = r.resolve(cond, 0) {
                            folds.push((bi, if c != 0 { *then_bb } else { *else_bb }));
                        }
                    }
                    Terminator::Switch { val, default, arms } => {
                        if let Some(Imm::Int(v)) = r.resolve(val, 0) {
                            let to = arms.iter().find(|(k, _)| *k == v).map_or(*default, |(_, b)| *b);
                            folds.push((bi, to));
                        }
                    }
                    _ => {}
                }
            }
        }
        for (bi, to) in folds { m.functions[fi].blocks[bi].terminator = Terminator::Jump(to); }
    }
}

/// Fold constant branches and empty the blocks they cut off, so a call only dead
/// code makes keeps nothing alive: a `static` function, an extern symbol (Linux
/// leaves references to what a disabled config does not define in such branches).
/// A dead block keeps what live code may still name: a variable's slot, when a
/// `goto` jumps past its declaration.
pub fn prune_dead_blocks(m: &mut Module) {
    fold_constant_branches(m);
    for f in &mut m.functions {
        let live = reachable_blocks(f);
        if live.len() == f.blocks.len() { continue; }
        let mut used: HashSet<ValId> = HashSet::default();
        for (bi, b) in f.blocks.iter().enumerate() {
            if !live.contains(&bi) { continue; }
            for ins in &b.instrs { ins.for_each_val(|v| if let Val::Local(id) = v { used.insert(*id); }); }
            b.terminator.for_each_val(|v| if let Val::Local(id) = v { used.insert(*id); });
        }
        for (bi, b) in f.blocks.iter_mut().enumerate() {
            if live.contains(&bi) { continue; }
            b.instrs.retain(|i| matches!(i, Instr::Alloca { .. }) || i.dest().is_some_and(|d| used.contains(&d)));
            b.terminator = Terminator::Unreachable;
        }
    }
}

/// Indices of the blocks reachable from the function's entry (its first block).
fn reachable_blocks(f: &Function) -> HashSet<usize> {
    let index: HashMap<BlockId, usize> = f.blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
    let mut seen = HashSet::default();
    let mut work = if f.blocks.is_empty() { vec![] } else { vec![0usize] };
    while let Some(i) = work.pop() {
        if !seen.insert(i) { continue; }
        let succ: Vec<BlockId> = match &f.blocks[i].terminator {
            Terminator::Jump(b) => vec![*b],
            Terminator::CondJump { then_bb, else_bb, .. } => vec![*then_bb, *else_bb],
            Terminator::Switch { default, arms, .. } => std::iter::once(*default).chain(arms.iter().map(|(_, b)| *b)).collect(),
            _ => vec![],
        };
        work.extend(succ.into_iter().filter_map(|b| index.get(&b).copied()));
    }
    seen
}

/// Finish the inline-assembly helpers after the IR passes: fold constant
/// branches, specialize every deferred helper call in reachable code of the
/// functions that are emitted, and keep only the helpers such code still
/// calls (a helper of dead code may not even assemble).
pub fn specialize_asm(m: &mut Module) -> Result<(), String> {
    if m.asm_text_helpers.is_empty() { return Ok(()); }
    fold_constant_branches(m);
    let deferred: HashMap<String, AsmDeferred> = m.asm_deferred.iter().map(|d| (d.helper.clone(), d.clone())).collect();
    let bodies: HashMap<String, String> = m.asm_text_helpers.iter()
        .filter(|(n, _)| deferred.contains_key(n)).cloned().collect();
    let reachable = m.reachable_functions();
    let mut new_helpers: Vec<(String, String)> = Vec::new();
    // (function, block, instruction, specialized helper, its params)
    let mut rewrites: Vec<(usize, usize, usize, String, Vec<Type>, Type)> = Vec::new();
    let mut used_fns: Vec<String> = Vec::new();
    // Helpers that live (emitted, reachable) code calls.
    let mut called: HashSet<String> = HashSet::default();
    for (fi, f) in m.functions.iter().enumerate() {
        if f.linkage == Linkage::Internal && !reachable.contains(&(fi as u32)) { continue; }
        let live = reachable_blocks(f);
        let mut r = Resolver::new(m, f);
        for (bi, b) in f.blocks.iter().enumerate() {
            if !live.contains(&bi) { continue; }
            for (ii, ins) in b.instrs.iter().enumerate() {
                if let Instr::Call { func, .. } = ins {
                    if func.is_extern() { called.insert(m.externs[func.index()].name.clone()); }
                }
                let Instr::Call { func, args, .. } = ins else { continue };
                if !func.is_extern() { continue; }
                let ext = &m.externs[func.index()];
                let Some(d) = deferred.get(&ext.name) else { continue };
                let err = || format!("{}:{}:{}: error: impossible constraint in asm: an \"i\" operand is not a constant (or a symbol's address) after optimization (in '{}')",
                    d.file.as_deref().unwrap_or("<unknown>"), d.line, d.col, f.name);
                let mut vals = Vec::new();
                for (k, a) in args.iter().enumerate().skip(d.first_imm) {
                    let v = r.resolve(a, 0).ok_or_else(err)?;
                    if d.int_only.get(k - d.first_imm).copied().unwrap_or(false) && !matches!(v, Imm::Int(_)) {
                        return Err(err());
                    }
                    vals.push(v);
                }
                // Identical copies of one statement share a helper. Every helper
                // gets its own label number, also those of two statements with
                // the same text: all bodies land in one assembler file, and a
                // number from the text would repeat (Linux's WARN()s, with the
                // same file name string).
                let pre = substitute(&bodies[&ext.name], &vals, "").ok_or_else(err)?;
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                pre.hash(&mut h);
                let name = format!("{}_{:016x}", ext.name, h.finish());
                if !new_helpers.iter().any(|(n, _)| *n == name) {
                    let uid = m.asm_text_helpers.len() + new_helpers.len();
                    let body = substitute(&bodies[&ext.name], &vals, &uid.to_string()).ok_or_else(err)?;
                    new_helpers.push((name.clone(), body));
                }
                called.insert(name.clone());
                rewrites.push((fi, bi, ii, name, ext.sig.params[..d.first_imm].to_vec(), ext.sig.ret.clone()));
            }
        }
        used_fns.append(&mut r.used_fns);
    }
    for (fi, bi, ii, name, params, ret) in rewrites {
        let fref = match m.func_ref_by_name(&name) {
            Some(f) => f,
            None => m.add_extern(ExternFunc { name, sig: FunctionType { ret, params: params.clone(), variadic: false } }),
        };
        if let Instr::Call { func, args, .. } = &mut m.functions[fi].blocks[bi].instrs[ii] {
            *func = fref;
            args.truncate(params.len());
        }
    }
    let gone: HashSet<String> = deferred.keys().cloned().collect();
    m.asm_text_helpers.retain(|(n, _)| !gone.contains(n));
    m.asm_text_helpers.extend(new_helpers);
    m.asm_text_helpers.retain(|(n, _)| called.contains(n));
    for n in used_fns { if !m.used_functions.contains(&n) { m.used_functions.push(n); } }
    m.asm_deferred.clear();
    Ok(())
}
