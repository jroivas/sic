//! Lowering of [`Instr::Simd`]: portable 128-bit vector operations, mapped to
//! Cranelift's vector instructions (no target-specific ones).

use cranelift_codegen::ir::{self as cir, InstBuilder, MemFlagsData, Endianness};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::types as ct;
use cranelift_frontend::FunctionBuilder;
use sic_ir::{FCmp, SimdOp, Type};

use super::types::vector_clty;

/// The Cranelift type of operand `i` of `op`: the vector type `at` for vector
/// operands, the lane or count type for scalar ones.
pub(crate) fn operand_type(op: &SimdOp, i: usize, at: &Type, rt: &Type) -> cir::Type {
    let lane = |t: &Type| vector_clty(t).map(|v| v.lane_type()).unwrap_or(ct::I32);
    match (op, i) {
        (SimdOp::Splat, 0) => lane(rt),
        (SimdOp::Insert(_), 1) => lane(rt),
        (SimdOp::Shl | SimdOp::LShr | SimdOp::AShr, 1) => ct::I32,
        _ => vector_clty(at).unwrap_or(ct::I8X16),
    }
}

/// `v` reinterpreted as the vector type `to` (the same 128 bits).
pub(crate) fn bitcast(b: &mut FunctionBuilder<'_>, v: cir::Value, to: cir::Type) -> cir::Value {
    if b.func.dfg.value_type(v) == to { return v; }
    b.ins().bitcast(to, MemFlagsData::new().with_endianness(Endianness::Little), v)
}

/// `v` as the integer scalar type `to` (scalar operands may be wider or
/// narrower than the lane).
fn scalar(b: &mut FunctionBuilder<'_>, v: cir::Value, to: cir::Type) -> cir::Value {
    let from = b.func.dfg.value_type(v);
    if from == to { v }
    else if from.is_int() && to.is_int() {
        if from.bits() > to.bits() { b.ins().ireduce(to, v) } else { b.ins().uextend(to, v) }
    } else if from.bits() == to.bits() {
        b.ins().bitcast(to, MemFlagsData::new(), v)
    } else {
        v
    }
}

fn vconst(b: &mut FunctionBuilder<'_>, ty: cir::Type, bytes: &[u8; 16]) -> cir::Value {
    let c = b.func.dfg.constants.insert(bytes.to_vec().into());
    b.ins().vconst(ty, c)
}

fn splat_bits(b: &mut FunctionBuilder<'_>, ty: cir::Type, bits: u64) -> cir::Value {
    let lane_bytes = (ty.lane_bits() / 8) as usize;
    let mut bytes = [0u8; 16];
    for (i, x) in bytes.iter_mut().enumerate() {
        *x = (bits >> (8 * (i % lane_bytes))) as u8;
    }
    vconst(b, ty, &bytes)
}

fn fcmp(b: &mut FunctionBuilder<'_>, k: FCmp, x: cir::Value, y: cir::Value) -> cir::Value {
    let cc = match k {
        FCmp::Eq => FloatCC::Equal,
        FCmp::Ne => FloatCC::OrderedNotEqual,
        FCmp::Lt => FloatCC::LessThan,
        FCmp::Le => FloatCC::LessThanOrEqual,
        FCmp::Gt => FloatCC::GreaterThan,
        FCmp::Ge => FloatCC::GreaterThanOrEqual,
        FCmp::Ord => FloatCC::Ordered,
        FCmp::UEq => FloatCC::UnorderedOrEqual,
        FCmp::UNe => FloatCC::NotEqual,
        FCmp::ULt => FloatCC::UnorderedOrLessThan,
        FCmp::ULe => FloatCC::UnorderedOrLessThanOrEqual,
        FCmp::UGt => FloatCC::UnorderedOrGreaterThan,
        FCmp::UGe => FloatCC::UnorderedOrGreaterThanOrEqual,
        FCmp::Uno => FloatCC::Unordered,
    };
    b.ins().fcmp(cc, x, y)
}

fn icc(op: &sic_ir::CmpOp) -> IntCC {
    use sic_ir::CmpOp::*;
    match op {
        IEq => IntCC::Equal, INe => IntCC::NotEqual,
        ISLt => IntCC::SignedLessThan, ISLe => IntCC::SignedLessThanOrEqual,
        ISGt => IntCC::SignedGreaterThan, ISGe => IntCC::SignedGreaterThanOrEqual,
        IULt => IntCC::UnsignedLessThan, IULe => IntCC::UnsignedLessThanOrEqual,
        IUGt => IntCC::UnsignedGreaterThan, IUGe => IntCC::UnsignedGreaterThanOrEqual,
        _ => IntCC::Equal,
    }
}

/// Emit `op` on the operands `a` (already of [`operand_type`]); `at`/`rt` are
/// the operand and result IR types.
pub(crate) fn emit(b: &mut FunctionBuilder<'_>, op: &SimdOp, a: &[cir::Value], at: &Type, rt: &Type) -> cir::Value {
    let vt = vector_clty(at).unwrap_or(ct::I8X16);
    let rvt = vector_clty(rt);
    let x = || a[0];
    match op {
        SimdOp::Add => b.ins().iadd(a[0], a[1]),
        SimdOp::Sub => b.ins().isub(a[0], a[1]),
        SimdOp::Mul => b.ins().imul(a[0], a[1]),
        SimdOp::And => b.ins().band(a[0], a[1]),
        SimdOp::Or => b.ins().bor(a[0], a[1]),
        SimdOp::Xor => b.ins().bxor(a[0], a[1]),
        SimdOp::AndNot => b.ins().band_not(a[0], a[1]),
        SimdOp::SAddSat => b.ins().sadd_sat(a[0], a[1]),
        SimdOp::UAddSat => b.ins().uadd_sat(a[0], a[1]),
        SimdOp::SSubSat => b.ins().ssub_sat(a[0], a[1]),
        SimdOp::USubSat => b.ins().usub_sat(a[0], a[1]),
        SimdOp::SMin => b.ins().smin(a[0], a[1]),
        SimdOp::SMax => b.ins().smax(a[0], a[1]),
        SimdOp::UMin => b.ins().umin(a[0], a[1]),
        SimdOp::UMax => b.ins().umax(a[0], a[1]),
        SimdOp::AvgRound => b.ins().avg_round(a[0], a[1]),
        SimdOp::SMulHi | SimdOp::UMulHi => mul_hi(b, a[0], a[1], *op == SimdOp::SMulHi),
        SimdOp::MulHrs => {
            // Exact in i32: (a*b + 0x4000) >> 15, keeping the low 16 bits (x86
            // wraps -32768 * -32768 to -32768 rather than saturating).
            let half = |b: &mut FunctionBuilder<'_>, hi: bool| {
                let (p, q) = if hi { (b.ins().swiden_high(a[0]), b.ins().swiden_high(a[1])) }
                             else { (b.ins().swiden_low(a[0]), b.ins().swiden_low(a[1])) };
                let m = b.ins().imul(p, q);
                let r = splat_bits(b, ct::I32X4, 0x4000);
                let m = b.ins().iadd(m, r);
                let m = b.ins().sshr_imm_u(m, 15);
                bitcast(b, m, ct::I8X16)
            };
            let lo = half(b, false);
            let hi = half(b, true);
            let mask = [0u8, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29];
            let imm = b.func.dfg.immediates.push(mask.to_vec().into());
            let r = b.ins().shuffle(lo, hi, imm);
            bitcast(b, r, ct::I16X8)
        }
        SimdOp::FAdd => b.ins().fadd(a[0], a[1]),
        SimdOp::FSub => b.ins().fsub(a[0], a[1]),
        SimdOp::FMul => b.ins().fmul(a[0], a[1]),
        SimdOp::FDiv => b.ins().fdiv(a[0], a[1]),
        SimdOp::FMin | SimdOp::FMax => {
            let cc = if *op == SimdOp::FMin { FloatCC::LessThan } else { FloatCC::GreaterThan };
            let m = b.ins().fcmp(cc, a[0], a[1]);
            let m = bitcast(b, m, vt);
            b.ins().bitselect(m, a[0], a[1])
        }
        SimdOp::AddPairwise => b.ins().iadd_pairwise(a[0], a[1]),
        SimdOp::Abs => b.ins().iabs(x()),
        SimdOp::Neg => b.ins().ineg(x()),
        SimdOp::Not => b.ins().bnot(x()),
        SimdOp::Popcnt => b.ins().popcnt(x()),
        SimdOp::FSqrt => b.ins().sqrt(x()),
        SimdOp::FAbs => b.ins().fabs(x()),
        SimdOp::FNeg => b.ins().fneg(x()),
        SimdOp::FNearest => b.ins().nearest(x()),
        SimdOp::FFloor => b.ins().floor(x()),
        SimdOp::FCeil => b.ins().ceil(x()),
        SimdOp::FTrunc => b.ins().trunc(x()),
        SimdOp::Shl => b.ins().ishl(a[0], a[1]),
        SimdOp::LShr => b.ins().ushr(a[0], a[1]),
        SimdOp::AShr => b.ins().sshr(a[0], a[1]),
        SimdOp::ICmp(c) => b.ins().icmp(icc(c), a[0], a[1]),
        SimdOp::FCmp(k) => fcmp(b, *k, a[0], a[1]),
        SimdOp::SWidenLow => b.ins().swiden_low(x()),
        SimdOp::SWidenHigh => b.ins().swiden_high(x()),
        SimdOp::UWidenLow => b.ins().uwiden_low(x()),
        SimdOp::UWidenHigh => b.ins().uwiden_high(x()),
        SimdOp::SNarrow => b.ins().snarrow(a[0], a[1]),
        SimdOp::UNarrow => b.ins().unarrow(a[0], a[1]),
        SimdOp::SIToFP => b.ins().fcvt_from_sint(rvt.unwrap_or(ct::F32X4), x()),
        SimdOp::FPToSI => fp_to_si(b, x(), vt, rvt.unwrap_or(ct::I32X4)),
        SimdOp::FPromoteLow => b.ins().fvpromote_low(x()),
        SimdOp::FDemote => b.ins().fvdemote(x()),
        SimdOp::Shuffle(mask) => {
            let p = bitcast(b, a[0], ct::I8X16);
            let q = bitcast(b, a[1], ct::I8X16);
            let imm = b.func.dfg.immediates.push(mask.to_vec().into());
            let r = b.ins().shuffle(p, q, imm);
            bitcast(b, r, rvt.unwrap_or(vt))
        }
        SimdOp::Swizzle => {
            let p = bitcast(b, a[0], ct::I8X16);
            let q = bitcast(b, a[1], ct::I8X16);
            let r = b.ins().swizzle(p, q);
            bitcast(b, r, rvt.unwrap_or(vt))
        }
        SimdOp::Splat => {
            let t = rvt.unwrap_or(ct::I32X4);
            let s = scalar(b, a[0], t.lane_type());
            b.ins().splat(t, s)
        }
        SimdOp::Extract(n) => b.ins().extractlane(a[0], *n),
        SimdOp::Insert(n) => {
            let s = scalar(b, a[1], vt.lane_type());
            b.ins().insertlane(a[0], s, *n)
        }
        SimdOp::Select => {
            let m = bitcast(b, a[0], vt);
            let y = bitcast(b, a[1], vt);
            let z = bitcast(b, a[2], vt);
            b.ins().bitselect(m, y, z)
        }
        SimdOp::Bitcast => bitcast(b, x(), rvt.unwrap_or(vt)),
        SimdOp::Fma => b.ins().fma(a[0], a[1], a[2]),
        SimdOp::MoveMask => b.ins().vhigh_bits(ct::I32, x()),
        SimdOp::Const(bytes) => {
            let t = rvt.unwrap_or(ct::I8X16);
            vconst(b, t, bytes)
        }
    }
}

/// The high halves of the i16 lane products (x86 `pmulhw`/`pmulhuw`): the
/// products in i32, then their upper 16 bits.
fn mul_hi(b: &mut FunctionBuilder<'_>, x: cir::Value, y: cir::Value, signed: bool) -> cir::Value {
    let x = bitcast(b, x, ct::I16X8);
    let y = bitcast(b, y, ct::I16X8);
    let half = |b: &mut FunctionBuilder<'_>, hi: bool| {
        let (p, q) = match (signed, hi) {
            (true, false) => (b.ins().swiden_low(x), b.ins().swiden_low(y)),
            (true, true) => (b.ins().swiden_high(x), b.ins().swiden_high(y)),
            (false, false) => (b.ins().uwiden_low(x), b.ins().uwiden_low(y)),
            (false, true) => (b.ins().uwiden_high(x), b.ins().uwiden_high(y)),
        };
        let m = b.ins().imul(p, q);
        bitcast(b, m, ct::I8X16)
    };
    let lo = half(b, false);
    let hi = half(b, true);
    let mask = [2u8, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31];
    let imm = b.func.dfg.immediates.push(mask.to_vec().into());
    let r = b.ins().shuffle(lo, hi, imm);
    bitcast(b, r, ct::I16X8)
}

/// Truncating float→int with x86's out-of-range result (the minimum integer)
/// instead of saturation. `ft` is the float vector type, `it` the result.
fn fp_to_si(b: &mut FunctionBuilder<'_>, v: cir::Value, ft: cir::Type, it: cir::Type) -> cir::Value {
    if ft == ct::F32X4 && it == ct::I32X4 {
        let sat = b.ins().fcvt_to_sint_sat(ct::I32X4, v);
        // In range: -2^31 <= v < 2^31 (false for NaN).
        let lo = splat_bits(b, ct::F32X4, (-2147483648.0f32).to_bits() as u64);
        let hi = splat_bits(b, ct::F32X4, 2147483648.0f32.to_bits() as u64);
        let ge = b.ins().fcmp(FloatCC::GreaterThanOrEqual, v, lo);
        let lt = b.ins().fcmp(FloatCC::LessThan, v, hi);
        let ok = b.ins().band(ge, lt);
        let min = splat_bits(b, ct::I32X4, 0x8000_0000);
        return b.ins().bitselect(ok, sat, min);
    }
    // Lane by lane: f64x2 to i32x4 (high lanes zero) or i64x2.
    let lanes = ft.lane_count();
    let lt = it.lane_type();
    let mut r = splat_bits(b, it, 0);
    let (min_f, max_f) = if lt == ct::I32 { (-2147483648.0f64, 2147483648.0f64) }
                         else { (-9223372036854775808.0f64, 9223372036854775808.0f64) };
    let fl = ft.lane_type();
    for i in 0..lanes.min(it.lane_count()) {
        let e = b.ins().extractlane(v, i as u8);
        let sat = b.ins().fcvt_to_sint_sat(lt, e);
        let (lo, hi) = if fl == ct::F32 {
            (b.ins().f32const(min_f as f32), b.ins().f32const(max_f as f32))
        } else {
            (b.ins().f64const(min_f), b.ins().f64const(max_f))
        };
        let ge = b.ins().fcmp(FloatCC::GreaterThanOrEqual, e, lo);
        let below = b.ins().fcmp(FloatCC::LessThan, e, hi);
        let ok = b.ins().band(ge, below);
        let min = b.ins().iconst(lt, if lt == ct::I32 { i32::MIN as i64 } else { i64::MIN });
        let s = b.ins().select(ok, sat, min);
        r = b.ins().insertlane(r, s, i as u8);
    }
    r
}
