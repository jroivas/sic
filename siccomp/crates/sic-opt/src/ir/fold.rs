//! IR constant folding: instructions whose operands are all constants fold to a
//! single constant of the instruction's own `Type` (so integer results are
//! wrapped/sign-extended to the correct width — the win over untyped AST
//! folding). The now-constant result is substituted into every use and the
//! defining (pure) instruction removed; the pass manager's fixpoint lets a
//! folded constant feed the next fold.

use std::collections::HashMap;
use sic_ir::{Module, Val, ValId, Instr, Constant, Type, BinOp, UnOp, CmpOp, CastOp};
use crate::ir::pass::IrPass;
use crate::ir::{apply_replacements, prune_defs};

#[derive(Default)]
pub struct IrFold;

impl IrFold {
    pub fn new() -> Self { IrFold }
}

impl IrPass for IrFold {
    fn name(&self) -> &'static str { "ir-fold" }
    fn run(&mut self, m: &mut Module) -> bool {
        let mut changed = false;
        for func in &mut m.functions {
            let mut repl: HashMap<ValId, Val> = HashMap::new();
            for b in &func.blocks {
                for ins in &b.instrs {
                    if let (Some(dest), Some(c)) = (ins.dest(), fold_instr(ins)) {
                        repl.insert(dest, Val::Const(c));
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

pub(crate) fn as_int(c: &Constant) -> Option<i128> {
    match c {
        Constant::Int(v) => Some(*v as i128),
        Constant::UInt(v) => Some(*v as i128),
        Constant::Bool(b) => Some(*b as i128),
        _ => None,
    }
}
pub(crate) fn as_uint(c: &Constant) -> Option<u128> {
    match c {
        Constant::Int(v) => Some(*v as u64 as u128),
        Constant::UInt(v) => Some(*v as u128),
        Constant::Bool(b) => Some(*b as u128),
        _ => None,
    }
}
pub(crate) fn as_float(c: &Constant) -> Option<f64> {
    match c { Constant::Float(v) => Some(*v), _ => None }
}
pub(crate) fn konst(v: &Val) -> Option<&Constant> {
    match v { Val::Const(c) => Some(c), _ => None }
}

/// Wrap an integer value to `ty`'s width, producing the matching constant.
pub(crate) fn wrap_int(v: i128, ty: &Type) -> Constant {
    match ty {
        Type::Bool => Constant::Bool(v != 0),
        Type::Int { bits, signed } => {
            let bits = (*bits).clamp(1, 64) as u32;
            let raw: u64 = if bits == 64 { v as u64 } else { (v as u64) & ((1u64 << bits) - 1) };
            if *signed {
                let shift = 64 - bits;
                Constant::Int(((raw << shift) as i64) >> shift)
            } else {
                Constant::UInt(raw)
            }
        }
        _ => Constant::Int(v as i64),
    }
}

fn fold_instr(ins: &Instr) -> Option<Constant> {
    match ins {
        Instr::BinOp { op, lhs, rhs, ty, .. } =>
            fold_binop(*op, konst(lhs)?, konst(rhs)?, ty),
        Instr::UnaryOp { op, val, ty, .. } =>
            fold_unop(*op, konst(val)?, ty),
        Instr::Cmp { op, lhs, rhs, .. } =>
            fold_cmp(*op, konst(lhs)?, konst(rhs)?),
        Instr::Cast { op, val, to_ty, .. } =>
            fold_cast(*op, konst(val)?, to_ty),
        _ => None,
    }
}

fn fold_binop(op: BinOp, l: &Constant, r: &Constant, ty: &Type) -> Option<Constant> {
    use BinOp::*;
    // Float ops are deliberately NOT folded: `Constant::Float` carries no width,
    // so a folded f32 result would be indistinguishable from an f64 one and lose
    // the rounding/representation the eliminated instruction performed. Leave all
    // float arithmetic to codegen (source-level literal folding already happened
    // in the AST `const-fold` pass).
    if matches!(op, FAdd | FSub | FMul | FDiv | FRem) { return None; }
    // Integer ops, wrapped to the result width.
    Some(match op {
        Add => wrap_int(as_int(l)?.wrapping_add(as_int(r)?), ty),
        Sub => wrap_int(as_int(l)?.wrapping_sub(as_int(r)?), ty),
        Mul => wrap_int(as_int(l)?.wrapping_mul(as_int(r)?), ty),
        And => wrap_int(as_int(l)? & as_int(r)?, ty),
        Or  => wrap_int(as_int(l)? | as_int(r)?, ty),
        Xor => wrap_int(as_int(l)? ^ as_int(r)?, ty),
        Shl => wrap_int(as_int(l)?.wrapping_shl((as_uint(r)? & 63) as u32), ty),
        SDiv => { let b = as_int(r)?; if b == 0 { return None; } wrap_int(as_int(l)?.wrapping_div(b), ty) }
        SRem => { let b = as_int(r)?; if b == 0 { return None; } wrap_int(as_int(l)?.wrapping_rem(b), ty) }
        UDiv => { let b = as_uint(r)?; if b == 0 { return None; } wrap_int((as_uint(l)? / b) as i128, ty) }
        URem => { let b = as_uint(r)?; if b == 0 { return None; } wrap_int((as_uint(l)? % b) as i128, ty) }
        // Logical shift right operates on the unsigned bit pattern at width.
        LShr => {
            let bits = ty.int_bits().unwrap_or(64).clamp(1, 64);
            let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
            let v = (as_uint(l)? as u64) & mask;
            wrap_int((v >> ((as_uint(r)? & 63) as u32)) as i128, ty)
        }
        // Arithmetic shift right respects the signed value.
        AShr => wrap_int((as_int(l)? as i64 >> ((as_uint(r)? & 63) as u32)) as i128, ty),
        _ => return None, // Rotl/Rotr and any float op handled above
    })
}

fn fold_unop(op: UnOp, v: &Constant, ty: &Type) -> Option<Constant> {
    use UnOp::*;
    Some(match op {
        Neg => wrap_int(as_int(v)?.wrapping_neg(), ty),
        Not => wrap_int(!as_int(v)?, ty),
        BoolNot => Constant::Bool(as_int(v)? == 0),
        // FNeg produces a width-ambiguous float constant — leave to codegen.
        FNeg => return None,
        Clz => wrap_int((as_uint(v)? as u64).leading_zeros() as i128, ty),
        Ctz => wrap_int((as_uint(v)? as u64).trailing_zeros() as i128, ty),
        Popcnt => wrap_int((as_uint(v)? as u64).count_ones() as i128, ty),
    })
}

fn fold_cmp(op: CmpOp, l: &Constant, r: &Constant) -> Option<Constant> {
    use CmpOp::*;
    let b = match op {
        IEq => as_int(l)? == as_int(r)?,
        INe => as_int(l)? != as_int(r)?,
        ISLt => as_int(l)? < as_int(r)?,
        ISLe => as_int(l)? <= as_int(r)?,
        ISGt => as_int(l)? > as_int(r)?,
        ISGe => as_int(l)? >= as_int(r)?,
        IULt => as_uint(l)? < as_uint(r)?,
        IULe => as_uint(l)? <= as_uint(r)?,
        IUGt => as_uint(l)? > as_uint(r)?,
        IUGe => as_uint(l)? >= as_uint(r)?,
        // Float comparisons read width-ambiguous constants (an f32 operand stored
        // as an f64 could compare differently) — leave to codegen.
        FOEq | FONe | FOLt | FOLe | FOGt | FOGe => return None,
    };
    Some(Constant::Bool(b))
}

fn fold_cast(op: CastOp, v: &Constant, to_ty: &Type) -> Option<Constant> {
    use CastOp::*;
    // A `Constant` records its value but NOT its source bit width. Any cast whose
    // result depends on the source width therefore cannot be folded correctly
    // here — sign/zero extension of a value whose source high bit is set needs
    // the source width, and getting it wrong silently miscompiles. So integer
    // width *extension* (SExt/ZExt) is deliberately left to codegen.
    let vi = as_int(v);
    Some(match op {
        // Truncation keeps the low bits — correct regardless of source width.
        Trunc => wrap_int(vi?, to_ty),
        // bool is 0/1, unambiguous.
        BoolToInt => wrap_int(vi?, to_ty),
        // Float→int is fine (the int result carries its width via `to_ty`).
        FPToSI => wrap_int(as_float(v)? as i64 as i128, to_ty),
        FPToUI => wrap_int(as_float(v)? as u64 as i128, to_ty),
        // Any cast whose RESULT is a float (int→float, or float width change)
        // yields a width-ambiguous `Constant::Float` — leave those to codegen.
        SIToFP | UIToFP | FPExt | FPTrunc => return None,
        // A same-size integer BitCast is a value-preserving reinterpret; fold it
        // (non-negative only, to stay clear of the width ambiguity) so constants
        // hidden behind the casts lowering inserts — e.g. `4` → `BitCast 4 to
        // u32` — reach the algebraic pass. int↔float / pointer bitcasts: skip.
        BitCast if matches!(to_ty, Type::Int { .. } | Type::Bool) && vi.map_or(false, |x| x >= 0) =>
            wrap_int(vi?, to_ty),
        // SExt / ZExt (need source width) and pointer casts: leave to codegen.
        SExt | ZExt | IntToPtr | PtrToInt | BitCast => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_int_arithmetic_at_width() {
        // (i32) 2 + 3 => 5
        assert_eq!(fold_binop(BinOp::Add, &Constant::Int(2), &Constant::Int(3), &Type::i32()),
                   Some(Constant::Int(5)));
        // (i8) 200 + 100 wraps: 300 & 0xFF = 44 => sign-extended i8 = 44
        assert_eq!(fold_binop(BinOp::Add, &Constant::Int(200), &Constant::Int(100), &Type::i8()),
                   Some(Constant::Int(44)));
        // unsigned div by zero: not folded
        assert_eq!(fold_binop(BinOp::UDiv, &Constant::UInt(10), &Constant::UInt(0), &Type::u32()), None);
    }

    #[test]
    fn cmp_yields_bool() {
        assert_eq!(fold_cmp(CmpOp::ISLt, &Constant::Int(1), &Constant::Int(2)),
                   Some(Constant::Bool(true)));
        // float comparisons are left to codegen (width-ambiguous operands)
        assert_eq!(fold_cmp(CmpOp::FOEq, &Constant::Float(1.0), &Constant::Float(1.0)), None);
    }

    #[test]
    fn does_not_fold_width_extending_casts() {
        // SExt / ZExt need the source width, which a Constant does not carry.
        assert_eq!(fold_cast(CastOp::SExt, &Constant::Int(-1), &Type::i64()), None);
        assert_eq!(fold_cast(CastOp::ZExt, &Constant::Int(-1), &Type::u64()), None);
        // Truncation is always low-bits-correct.
        assert_eq!(fold_cast(CastOp::Trunc, &Constant::Int(0x1FF), &Type::i8()), Some(Constant::Int(-1)));
    }

    #[test]
    fn never_produces_float_constants() {
        // Float-producing casts and ops are width-ambiguous (f32 vs f64) → skip.
        assert_eq!(fold_cast(CastOp::SIToFP, &Constant::Int(3), &Type::Float32), None);
        assert_eq!(fold_cast(CastOp::FPTrunc, &Constant::Float(4.0), &Type::Float32), None);
        assert_eq!(fold_unop(UnOp::FNeg, &Constant::Float(1.0), &Type::Float64), None);
        // Float→int is fine (int carries width via to_ty).
        assert_eq!(fold_cast(CastOp::FPToSI, &Constant::Float(4.9), &Type::i32()), Some(Constant::Int(4)));
    }
}
