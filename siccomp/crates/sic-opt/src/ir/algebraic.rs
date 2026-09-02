//! Algebraic simplification and strength reduction on the typed IR.
//!
//! Two kinds of rewrite:
//!   * **identity / annihilator** — the result equals an operand or a constant
//!     (`x+0`→`x`, `x*1`→`x`, `x*0`→`0`, `x&0`→`0`, `x|­-1`→`-1`, `x<<0`→`x`, …).
//!     Implemented as a dest→value substitution + prune of the (pure) def.
//!   * **strength reduction** — replace a costly op with a cheaper one at the same
//!     width (`x * 2^k`→`x << k`, unsigned `x / 2^k`→`x >> k`,
//!     `x % 2^k`→`x & (2^k-1)`). Implemented as an in-place instruction rewrite.
//!
//! All are width-correct because each instruction carries its result `Type`.
//! Signed division/remainder by a power of two is *not* reduced (its rounding
//! differs from a shift).

use std::collections::HashMap;
use sic_ir::{Module, Val, ValId, Instr, Constant, Type, BinOp};
use crate::ir::pass::IrPass;
use crate::ir::fold::{as_int, as_uint, as_float, wrap_int};
use crate::ir::{apply_replacements, prune_defs};

#[derive(Default)]
pub struct Algebraic;

impl Algebraic {
    pub fn new() -> Self { Algebraic }
}

impl IrPass for Algebraic {
    fn name(&self) -> &'static str { "algebraic" }
    fn run(&mut self, m: &mut Module) -> bool {
        let mut changed = false;
        for func in &mut m.functions {
            // Step A: in-place strength reduction.
            for b in &mut func.blocks {
                for ins in &mut b.instrs {
                    if strength_reduce(ins) { changed = true; }
                }
            }
            // Step B: identity/annihilator substitutions.
            let mut repl: HashMap<ValId, Val> = HashMap::new();
            for b in &func.blocks {
                for ins in &b.instrs {
                    if let Instr::BinOp { dest, op, lhs, rhs, ty } = ins {
                        if let Some(v) = identity(*op, lhs, rhs, ty) {
                            repl.insert(*dest, v);
                        }
                    }
                }
            }
            if !repl.is_empty() {
                apply_replacements(func, &repl);
                prune_defs(func, &repl);
                changed = true;
            }
        }
        changed
    }
}

// ─── constant-operand predicates ────────────────────────────────────────────

fn cint(v: &Val) -> Option<i128> {
    match v { Val::Const(c) => as_int(c), _ => None }
}
fn cfloat(v: &Val) -> Option<f64> {
    match v { Val::Const(c) => as_float(c), _ => None }
}
fn is_int_zero(v: &Val) -> bool { cint(v) == Some(0) }
fn is_int_one(v: &Val) -> bool { cint(v) == Some(1) }
fn is_float(v: &Val, target: f64) -> bool { cfloat(v) == Some(target) }

/// Mask of all-ones for `ty`'s width (as i128), or None for non-integers.
fn all_ones(ty: &Type) -> Option<i128> {
    let bits = ty.int_bits()?.clamp(1, 64);
    Some(if bits == 64 { u64::MAX as i128 } else { ((1u64 << bits) - 1) as i128 })
}
/// Whether `v` is the all-ones bit pattern at `ty`'s width.
fn is_all_ones(v: &Val, ty: &Type) -> bool {
    match (cint(v), all_ones(ty)) {
        (Some(x), Some(m)) => (x as u64 & m as u64) == m as u64,
        _ => false,
    }
}
fn const_of(ty: &Type, v: i128) -> Val { Val::Const(wrap_int(v, ty)) }

/// A constant operand that is a power of two ≥ 2, returning the exponent `k`.
fn pow2_exp(v: &Val, ty: &Type) -> Option<u32> {
    let c = match v { Val::Const(c) => as_uint(c)?, _ => return None } as u64;
    let bits = ty.int_bits()?.clamp(1, 64);
    if c >= 2 && c.is_power_of_two() && c.trailing_zeros() < bits {
        Some(c.trailing_zeros())
    } else {
        None
    }
}

// ─── identities ─────────────────────────────────────────────────────────────

fn identity(op: BinOp, lhs: &Val, rhs: &Val, ty: &Type) -> Option<Val> {
    use BinOp::*;
    Some(match op {
        // Integer additive.
        Add if is_int_zero(rhs) => lhs.clone(),
        Add if is_int_zero(lhs) => rhs.clone(),
        Sub if is_int_zero(rhs) => lhs.clone(),
        // Integer multiplicative.
        Mul if is_int_zero(rhs) || is_int_zero(lhs) => const_of(ty, 0),
        Mul if is_int_one(rhs) => lhs.clone(),
        Mul if is_int_one(lhs) => rhs.clone(),
        SDiv | UDiv if is_int_one(rhs) => lhs.clone(),
        // Bitwise.
        And if is_int_zero(rhs) || is_int_zero(lhs) => const_of(ty, 0),
        And if is_all_ones(rhs, ty) => lhs.clone(),
        And if is_all_ones(lhs, ty) => rhs.clone(),
        Or if is_int_zero(rhs) => lhs.clone(),
        Or if is_int_zero(lhs) => rhs.clone(),
        Or if is_all_ones(rhs, ty) || is_all_ones(lhs, ty) => const_of(ty, -1),
        Xor if is_int_zero(rhs) => lhs.clone(),
        Xor if is_int_zero(lhs) => rhs.clone(),
        // Shifts by zero.
        Shl | AShr | LShr if is_int_zero(rhs) => lhs.clone(),
        // Float identities (never `x*0.0` — unsafe for NaN/inf/-0.0).
        FAdd if is_float(rhs, 0.0) => lhs.clone(),
        FAdd if is_float(lhs, 0.0) => rhs.clone(),
        FSub if is_float(rhs, 0.0) => lhs.clone(),
        FMul if is_float(rhs, 1.0) => lhs.clone(),
        FMul if is_float(lhs, 1.0) => rhs.clone(),
        FDiv if is_float(rhs, 1.0) => lhs.clone(),
        _ => return None,
    })
}

// ─── strength reduction ─────────────────────────────────────────────────────

fn strength_reduce(ins: &mut Instr) -> bool {
    let Instr::BinOp { op, lhs, rhs, ty, .. } = ins else { return false };
    if !ty.is_int() { return false; }
    match *op {
        BinOp::Mul => {
            if let Some(k) = pow2_exp(rhs, ty) {
                *op = BinOp::Shl;
                *rhs = Val::Const(Constant::Int(k as i64));
                true
            } else if let Some(k) = pow2_exp(lhs, ty) {
                // c * x → x << k
                *lhs = rhs.clone();
                *op = BinOp::Shl;
                *rhs = Val::Const(Constant::Int(k as i64));
                true
            } else {
                false
            }
        }
        BinOp::UDiv => {
            if let Some(k) = pow2_exp(rhs, ty) {
                *op = BinOp::LShr;
                *rhs = Val::Const(Constant::Int(k as i64));
                true
            } else {
                false
            }
        }
        BinOp::URem => {
            if let Some(k) = pow2_exp(rhs, ty) {
                *op = BinOp::And;
                *rhs = const_of(ty, (1i128 << k) - 1);
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sic_ir::ValId;

    fn local(n: u32) -> Val { Val::Local(ValId(n)) }
    fn ci(n: i64) -> Val { Val::Const(Constant::Int(n)) }

    #[test]
    fn identities() {
        let x = local(1);
        assert_eq!(identity(BinOp::Add, &x, &ci(0), &Type::i32()), Some(x.clone())); // x+0
        assert_eq!(identity(BinOp::Add, &ci(0), &x, &Type::i32()), Some(x.clone())); // 0+x
        assert_eq!(identity(BinOp::Mul, &x, &ci(1), &Type::i32()), Some(x.clone())); // x*1
        assert_eq!(identity(BinOp::Mul, &x, &ci(0), &Type::i32()), Some(ci(0)));     // x*0 -> 0
        assert_eq!(identity(BinOp::Or,  &x, &ci(-1), &Type::i32()), Some(ci(-1)));   // x|-1 -> -1
        assert_eq!(identity(BinOp::And, &x, &ci(0), &Type::i32()), Some(ci(0)));     // x&0 -> 0
        assert_eq!(identity(BinOp::Shl, &x, &ci(0), &Type::i32()), Some(x.clone())); // x<<0
        // No identity when neither operand is the special constant.
        assert_eq!(identity(BinOp::Add, &x, &ci(3), &Type::i32()), None);
    }

    #[test]
    fn strength_reduce_mul_and_udiv() {
        // x * 8  ->  x << 3
        let mut m = Instr::BinOp { dest: ValId(9), op: BinOp::Mul, lhs: local(1), rhs: ci(8), ty: Type::i32() };
        assert!(strength_reduce(&mut m));
        match m { Instr::BinOp { op, rhs, .. } => {
            assert_eq!(op, BinOp::Shl); assert_eq!(rhs, ci(3)); } _ => panic!() }
        // unsigned x / 4  ->  x >> 2
        let mut d = Instr::BinOp { dest: ValId(9), op: BinOp::UDiv, lhs: local(1), rhs: ci(4), ty: Type::u32() };
        assert!(strength_reduce(&mut d));
        match d { Instr::BinOp { op, rhs, .. } => {
            assert_eq!(op, BinOp::LShr); assert_eq!(rhs, ci(2)); } _ => panic!() }
        // x * 3 is not a power of two -> unchanged.
        let mut n = Instr::BinOp { dest: ValId(9), op: BinOp::Mul, lhs: local(1), rhs: ci(3), ty: Type::i32() };
        assert!(!strength_reduce(&mut n));
    }
}
