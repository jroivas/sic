//! `Instr::Simd`: portable 128-bit vector operations as LLVM vector instructions,
//! with the lane semantics of sic_ir::SimdOp.

use crate::func::Fx;
use crate::R;
use inkwell::types::{BasicTypeEnum, VectorType};
use inkwell::values::{BasicValueEnum, IntValue, VectorValue};
use inkwell::{FloatPredicate, IntPredicate};
use sic_ir::{CmpOp, FCmp, SimdOp, Type, Val};

fn int_pred(op: &CmpOp) -> IntPredicate {
    match op {
        CmpOp::INe => IntPredicate::NE,
        CmpOp::ISLt => IntPredicate::SLT, CmpOp::ISLe => IntPredicate::SLE,
        CmpOp::ISGt => IntPredicate::SGT, CmpOp::ISGe => IntPredicate::SGE,
        CmpOp::IULt => IntPredicate::ULT, CmpOp::IULe => IntPredicate::ULE,
        CmpOp::IUGt => IntPredicate::UGT, CmpOp::IUGe => IntPredicate::UGE,
        _ => IntPredicate::EQ,
    }
}

fn float_pred(k: FCmp) -> FloatPredicate {
    match k {
        FCmp::Eq => FloatPredicate::OEQ, FCmp::Ne => FloatPredicate::ONE,
        FCmp::Lt => FloatPredicate::OLT, FCmp::Le => FloatPredicate::OLE,
        FCmp::Gt => FloatPredicate::OGT, FCmp::Ge => FloatPredicate::OGE,
        FCmp::Ord => FloatPredicate::ORD,
        FCmp::UEq => FloatPredicate::UEQ, FCmp::UNe => FloatPredicate::UNE,
        FCmp::ULt => FloatPredicate::ULT, FCmp::ULe => FloatPredicate::ULE,
        FCmp::UGt => FloatPredicate::UGT, FCmp::UGe => FloatPredicate::UGE,
        FCmp::Uno => FloatPredicate::UNO,
    }
}

impl<'ctx> Fx<'ctx, '_, '_> {
    fn v16i8(&self) -> VectorType<'ctx> { self.cx.ctx.i8_type().vec_type(16) }

    fn bits(&self, v: BasicValueEnum<'ctx>, t: VectorType<'ctx>) -> R<VectorValue<'ctx>> {
        Ok(self.b().build_bit_cast(v, t, "")?.into_vector_value())
    }

    /// The integer vector of `v`'s shape: lane masks, and float lanes as bits.
    fn int_shape(&self, t: VectorType<'ctx>) -> VectorType<'ctx> {
        let lanes = t.get_size();
        self.cx.int_type(128 / lanes).vec_type(lanes)
    }

    fn i32s(&self, idx: &[u32]) -> VectorValue<'ctx> {
        let i32t = self.cx.ctx.i32_type();
        let c: Vec<IntValue> = idx.iter().map(|i| i32t.const_int(*i as u64, false)).collect();
        VectorType::const_vector(&c)
    }

    fn shuffle(&self, a: VectorValue<'ctx>, b: VectorValue<'ctx>, idx: &[u32]) -> R<VectorValue<'ctx>> {
        Ok(self.b().build_shuffle_vector(a, b, self.i32s(idx), "")?)
    }

    fn splat(&self, s: BasicValueEnum<'ctx>, t: VectorType<'ctx>) -> R<VectorValue<'ctx>> {
        let i32t = self.cx.ctx.i32_type();
        let one = t.get_undef();
        let ins = self.b().build_insert_element(one, s, i32t.const_zero(), "")?;
        self.shuffle(ins, ins, &vec![0; t.get_size() as usize])
    }

    /// Each lane of the vector mask `m` to all ones or zeros, in `t`.
    fn lane_mask(&self, m: VectorValue<'ctx>, t: VectorType<'ctx>) -> R<VectorValue<'ctx>> {
        let it = self.int_shape(t);
        Ok(self.b().build_int_s_extend(m, it, "")?)
    }

    fn bitselect(&self, m: VectorValue<'ctx>, y: VectorValue<'ctx>, z: VectorValue<'ctx>) -> R<VectorValue<'ctx>> {
        let b = self.b();
        let t = y.get_type();
        let it = self.int_shape(t);
        let (m, p, q) = (self.bits(m.into(), it)?, self.bits(y.into(), it)?, self.bits(z.into(), it)?);
        let on = b.build_and(m, p, "")?;
        let off = b.build_and(b.build_not(m, "")?, q, "")?;
        let r = b.build_or(on, off, "")?;
        self.bits(r.into(), t)
    }

    /// Half the lanes of `x` (the high ones or the low) at twice the width.
    fn widen(&self, x: VectorValue<'ctx>, high: bool, signed: bool) -> R<VectorValue<'ctx>> {
        let n = x.get_type().get_size();
        let idx: Vec<u32> = (0..n / 2).map(|i| if high { i + n / 2 } else { i }).collect();
        let half = self.shuffle(x, x, &idx)?;
        let t = self.cx.int_type(2 * 128 / n).vec_type(n / 2);
        let b = self.b();
        Ok(if signed { b.build_int_s_extend(half, t, "")? } else { b.build_int_z_extend(half, t, "")? })
    }

    /// All lanes of `x` at twice the width.
    fn extend_all(&self, x: VectorValue<'ctx>, signed: bool) -> R<VectorValue<'ctx>> {
        let n = x.get_type().get_size();
        let t = self.cx.int_type(2 * 128 / n).vec_type(n);
        let b = self.b();
        Ok(if signed { b.build_int_s_extend(x, t, "")? } else { b.build_int_z_extend(x, t, "")? })
    }

    /// `a` then `b` at half the lane width, saturated to the lane's range.
    fn narrow(&self, a: VectorValue<'ctx>, b_: VectorValue<'ctx>, unsigned: bool) -> R<VectorValue<'ctx>> {
        let t = a.get_type();
        let n = t.get_size();
        let w = 128 / n;
        let h = w / 2;
        let lane = self.cx.int_type(w);
        let (lo, hi) = if unsigned { (0u64, (1u64 << h) - 1) } else { ((-(1i64 << (h - 1))) as u64, (1u64 << (h - 1)) - 1) };
        let (vlo, vhi) = (self.splat(lane.const_int(lo, true).into(), t)?, self.splat(lane.const_int(hi, false).into(), t)?);
        let clamp = |v: VectorValue<'ctx>| -> R<VectorValue<'ctx>> {
            let up = self.call_intrinsic("llvm.smax", &[t.into()], &[v.into(), vlo.into()])?;
            let d = self.call_intrinsic("llvm.smin", &[t.into()], &[up.into(), vhi.into()])?;
            Ok(self.b().build_int_truncate(d.into_vector_value(), self.cx.int_type(h).vec_type(n), "")?)
        };
        let (p, q) = (clamp(a)?, clamp(b_)?);
        let idx: Vec<u32> = (0..2 * n).collect();
        self.shuffle(p, q, &idx)
    }

    /// x86's `cvtt`: out of range and NaN give the minimum integer, lane by lane;
    /// lanes past the source's are zero.
    fn fp_to_si(&self, v: VectorValue<'ctx>, it: VectorType<'ctx>) -> R<VectorValue<'ctx>> {
        let (b, cx) = (self.b(), self.cx);
        let lane = it.get_element_type().into_int_type();
        let bits = lane.get_bit_width();
        let min = lane.const_int(1u64 << (bits - 1), false);
        let i32t = cx.ctx.i32_type();
        let mut r = it.const_zero();
        for i in 0..v.get_type().get_size().min(it.get_size()) {
            let e = b.build_extract_element(v, i32t.const_int(i as u64, false), "")?.into_float_value();
            let ft = e.get_type();
            let limit = 2f64.powi(bits as i32 - 1);
            let ge = b.build_float_compare(FloatPredicate::OGE, e, ft.const_float(-limit), "")?;
            let lt = b.build_float_compare(FloatPredicate::OLT, e, ft.const_float(limit), "")?;
            let ok = b.build_and(ge, lt, "")?;
            let sat = self.sat("llvm.fptosi.sat", e.into(), lane.into())?;
            let s = b.build_select(ok, sat, min.into(), "")?;
            r = b.build_insert_element(r, s, i32t.const_int(i as u64, false), "")?;
        }
        Ok(r)
    }

    fn operand(&self, op: &SimdOp, i: usize, a: &Val, at: &Type, rt: &Type) -> R<BasicValueEnum<'ctx>> {
        let cx = self.cx;
        let lane = |t: &Type| cx.vector_type(t).map_or(cx.ctx.i32_type().into(), |v| v.into_vector_type().get_element_type());
        let t: BasicTypeEnum = match (op, i) {
            (SimdOp::Splat, 0) | (SimdOp::Insert(_), 1) => lane(rt),
            (SimdOp::Shl | SimdOp::LShr | SimdOp::AShr, 1) => cx.ctx.i32_type().into(),
            _ => cx.vector_type(at).unwrap_or(self.v16i8().into()),
        };
        let v = self.val(a, t);
        if v.get_type() == t { return Ok(v); }
        // A scalar may be wider or narrower than the lane, and of its size a float.
        match (v, t) {
            (BasicValueEnum::IntValue(_), BasicTypeEnum::IntType(_)) => self.coerce(v, t),
            _ => Ok(self.b().build_bit_cast(v, t, "")?),
        }
    }

    pub fn simd(&mut self, op: &SimdOp, args: &[Val], at: &Type, rt: &Type) -> R<BasicValueEnum<'ctx>> {
        let cx = self.cx;
        let vt = cx.vector_type(at).map_or(self.v16i8(), |t| t.into_vector_type());
        let rvt = cx.vector_type(rt).map(|t| t.into_vector_type());
        let a: Vec<BasicValueEnum> = args.iter().enumerate().map(|(i, v)| self.operand(op, i, v, at, rt)).collect::<R<_>>()?;
        let vec = |i: usize| a[i].into_vector_value();
        let b = self.b();
        // Bitwise on float lanes: the same bits as integers.
        if matches!(op, SimdOp::And | SimdOp::Or | SimdOp::Xor | SimdOp::AndNot | SimdOp::Not) && vt.get_element_type().is_float_type() {
            let it = self.int_shape(vt);
            let p = self.bits(a[0], it)?;
            let r: VectorValue = match op {
                SimdOp::Not => b.build_not(p, "")?,
                SimdOp::AndNot => { let q = self.bits(a[1], it)?; b.build_and(p, b.build_not(q, "")?, "")? }
                SimdOp::And => b.build_and(p, self.bits(a[1], it)?, "")?,
                SimdOp::Or => b.build_or(p, self.bits(a[1], it)?, "")?,
                _ => b.build_xor(p, self.bits(a[1], it)?, "")?,
            };
            return Ok(self.bits(r.into(), rvt.unwrap_or(vt))?.into());
        }
        let two = |name: &str| -> R<BasicValueEnum<'ctx>> {
            self.call_intrinsic(name, &[vt.into()], &[a[0].into(), a[1].into()])
        };
        let one = |name: &str| -> R<BasicValueEnum<'ctx>> { self.call_intrinsic(name, &[vt.into()], &[a[0].into()]) };
        let no = cx.ctx.bool_type().const_zero();
        let r: BasicValueEnum = match op {
            SimdOp::Add => b.build_int_add(vec(0), vec(1), "")?.into(),
            SimdOp::Sub => b.build_int_sub(vec(0), vec(1), "")?.into(),
            SimdOp::Mul => b.build_int_mul(vec(0), vec(1), "")?.into(),
            SimdOp::And => b.build_and(vec(0), vec(1), "")?.into(),
            SimdOp::Or => b.build_or(vec(0), vec(1), "")?.into(),
            SimdOp::Xor => b.build_xor(vec(0), vec(1), "")?.into(),
            SimdOp::AndNot => b.build_and(vec(0), b.build_not(vec(1), "")?, "")?.into(),
            SimdOp::SAddSat => two("llvm.sadd.sat")?,
            SimdOp::UAddSat => two("llvm.uadd.sat")?,
            SimdOp::SSubSat => two("llvm.ssub.sat")?,
            SimdOp::USubSat => two("llvm.usub.sat")?,
            SimdOp::SMin => two("llvm.smin")?,
            SimdOp::SMax => two("llvm.smax")?,
            SimdOp::UMin => two("llvm.umin")?,
            SimdOp::UMax => two("llvm.umax")?,
            // (a | b) - ((a ^ b) >> 1) cannot overflow the lane.
            SimdOp::AvgRound => {
                let one = self.splat(vt.get_element_type().into_int_type().const_int(1, false).into(), vt)?;
                let or = b.build_or(vec(0), vec(1), "")?;
                let xor = b.build_xor(vec(0), vec(1), "")?;
                b.build_int_sub(or, b.build_right_shift(xor, one, false, "")?, "")?.into()
            }
            SimdOp::SMulHi | SimdOp::UMulHi => {
                let signed = *op == SimdOp::SMulHi;
                let i16s = cx.ctx.i16_type().vec_type(8);
                let (x, y) = (self.bits(a[0], i16s)?, self.bits(a[1], i16s)?);
                let m = b.build_int_mul(self.extend_all(x, signed)?, self.extend_all(y, signed)?, "")?;
                let sh = self.splat(cx.ctx.i32_type().const_int(16, false).into(), m.get_type())?;
                let hi = b.build_right_shift(m, sh, false, "")?;
                b.build_int_truncate(hi, i16s, "")?.into()
            }
            // Exact in i32; -32768 * -32768 wraps, as on x86.
            SimdOp::MulHrs => {
                let i16s = cx.ctx.i16_type().vec_type(8);
                let (x, y) = (self.bits(a[0], i16s)?, self.bits(a[1], i16s)?);
                let m = b.build_int_mul(self.extend_all(x, true)?, self.extend_all(y, true)?, "")?;
                let i32t = cx.ctx.i32_type();
                let m = b.build_int_add(m, self.splat(i32t.const_int(0x4000, false).into(), m.get_type())?, "")?;
                let m = b.build_right_shift(m, self.splat(i32t.const_int(15, false).into(), m.get_type())?, true, "")?;
                b.build_int_truncate(m, i16s, "")?.into()
            }
            SimdOp::FAdd => b.build_float_add(vec(0), vec(1), "")?.into(),
            SimdOp::FSub => b.build_float_sub(vec(0), vec(1), "")?.into(),
            SimdOp::FMul => b.build_float_mul(vec(0), vec(1), "")?.into(),
            SimdOp::FDiv => b.build_float_div(vec(0), vec(1), "")?.into(),
            SimdOp::FMin | SimdOp::FMax => {
                let p = if *op == SimdOp::FMin { FloatPredicate::OLT } else { FloatPredicate::OGT };
                let m = b.build_float_compare(p, vec(0), vec(1), "")?;
                b.build_select(m, a[0], a[1], "")?
            }
            SimdOp::AddPairwise => {
                let n = vt.get_size();
                let even: Vec<u32> = (0..n).map(|i| 2 * i).collect();
                let odd: Vec<u32> = (0..n).map(|i| 2 * i + 1).collect();
                let (p, q) = (self.shuffle(vec(0), vec(1), &even)?, self.shuffle(vec(0), vec(1), &odd)?);
                b.build_int_add(p, q, "")?.into()
            }
            SimdOp::Abs => self.call_intrinsic("llvm.abs", &[vt.into()], &[a[0].into(), no.into()])?,
            SimdOp::Neg => b.build_int_neg(vec(0), "")?.into(),
            SimdOp::Not => b.build_not(vec(0), "")?.into(),
            SimdOp::Popcnt => one("llvm.ctpop")?,
            SimdOp::FSqrt => one("llvm.sqrt")?,
            SimdOp::FAbs => one("llvm.fabs")?,
            SimdOp::FNeg => b.build_float_neg(vec(0), "")?.into(),
            SimdOp::FNearest => one("llvm.roundeven")?,
            SimdOp::FFloor => one("llvm.floor")?,
            SimdOp::FCeil => one("llvm.ceil")?,
            SimdOp::FTrunc => one("llvm.trunc")?,
            SimdOp::Shl | SimdOp::LShr | SimdOp::AShr => {
                let lane = vt.get_element_type().into_int_type();
                let w = lane.get_bit_width() as u64;
                let n = self.coerce(a[1], lane.into())?.into_int_value();
                let n = b.build_and(n, lane.const_int(w - 1, false), "")?;
                let n = self.splat(n.into(), vt)?;
                match op {
                    SimdOp::Shl => b.build_left_shift(vec(0), n, "")?.into(),
                    _ => b.build_right_shift(vec(0), n, *op == SimdOp::AShr, "")?.into(),
                }
            }
            SimdOp::ICmp(c) => self.lane_mask(b.build_int_compare(int_pred(c), vec(0), vec(1), "")?, vt)?.into(),
            SimdOp::FCmp(k) => self.lane_mask(b.build_float_compare(float_pred(*k), vec(0), vec(1), "")?, vt)?.into(),
            SimdOp::SWidenLow => self.widen(vec(0), false, true)?.into(),
            SimdOp::SWidenHigh => self.widen(vec(0), true, true)?.into(),
            SimdOp::UWidenLow => self.widen(vec(0), false, false)?.into(),
            SimdOp::UWidenHigh => self.widen(vec(0), true, false)?.into(),
            SimdOp::SNarrow => self.narrow(vec(0), vec(1), false)?.into(),
            SimdOp::UNarrow => self.narrow(vec(0), vec(1), true)?.into(),
            SimdOp::SIToFP => {
                let t = rvt.unwrap_or(cx.ctx.f32_type().vec_type(4));
                b.build_signed_int_to_float(vec(0), t, "")?.into()
            }
            SimdOp::FPToSI => self.fp_to_si(vec(0), rvt.unwrap_or(cx.ctx.i32_type().vec_type(4)))?.into(),
            SimdOp::FPromoteLow => {
                let low = self.shuffle(vec(0), vec(0), &[0, 1])?;
                b.build_float_ext(low, cx.ctx.f64_type().vec_type(2), "")?.into()
            }
            SimdOp::FDemote => {
                let t = cx.ctx.f32_type().vec_type(2);
                let d = b.build_float_trunc(vec(0), t, "")?;
                self.shuffle(d, t.const_zero(), &[0, 1, 2, 3])?.into()
            }
            SimdOp::Shuffle(mask) => {
                let (p, q) = (self.bits(a[0], self.v16i8())?, self.bits(a[1], self.v16i8())?);
                let idx: Vec<u32> = mask.iter().map(|m| *m as u32).collect();
                self.shuffle(p, q, &idx)?.into()
            }
            // An index of 16 or more gives zero.
            SimdOp::Swizzle => {
                let (p, q) = (self.bits(a[0], self.v16i8())?, self.bits(a[1], self.v16i8())?);
                let (i8t, i32t) = (cx.ctx.i8_type(), cx.ctx.i32_type());
                let mut r = self.v16i8().const_zero();
                for i in 0..16u64 {
                    let at = i32t.const_int(i, false);
                    let k = b.build_extract_element(q, at, "")?.into_int_value();
                    let wide = b.build_int_z_extend(k, i32t, "")?;
                    let in_range = b.build_int_compare(IntPredicate::ULT, k, i8t.const_int(16, false), "")?;
                    let masked = b.build_and(wide, i32t.const_int(15, false), "")?;
                    let e = b.build_extract_element(p, masked, "")?;
                    let s = b.build_select(in_range, e, i8t.const_zero().into(), "")?;
                    r = b.build_insert_element(r, s, at, "")?;
                }
                r.into()
            }
            SimdOp::Splat => self.splat(a[0], rvt.unwrap_or(cx.ctx.i32_type().vec_type(4)))?.into(),
            SimdOp::Extract(n) => b.build_extract_element(vec(0), cx.ctx.i32_type().const_int(*n as u64, false), "")?,
            SimdOp::Insert(n) => b.build_insert_element(vec(0), a[1], cx.ctx.i32_type().const_int(*n as u64, false), "")?.into(),
            SimdOp::Select => self.bitselect(vec(0), vec(1), vec(2))?.into(),
            SimdOp::Bitcast => self.bits(a[0], rvt.unwrap_or(vt))?.into(),
            SimdOp::Fma => self.call_intrinsic("llvm.fma", &[vt.into()], &[a[0].into(), a[1].into(), a[2].into()])?,
            SimdOp::MoveMask => self.move_mask(vec(0))?.into(),
            SimdOp::Const(bytes) => {
                let i8t = cx.ctx.i8_type();
                let c: Vec<IntValue> = bytes.iter().map(|x| i8t.const_int(*x as u64, false)).collect();
                self.bits(VectorType::const_vector(&c).into(), rvt.unwrap_or(self.v16i8()))?.into()
            }
        };
        // The same 128 bits at the result's lanes, whatever computed them.
        Ok(match (r, rvt) {
            (BasicValueEnum::VectorValue(_), Some(t)) if r.get_type() != t.into() => self.bits(r, t)?.into(),
            _ => r,
        })
    }

    /// The high bit of each lane, packed into an i32.
    pub fn move_mask(&self, v: VectorValue<'ctx>) -> R<IntValue<'ctx>> {
        let b = self.b();
        let t = v.get_type();
        let it = self.int_shape(t);
        let i = self.bits(v.into(), it)?;
        let neg = b.build_int_compare(IntPredicate::SLT, i, it.const_zero(), "")?;
        let m = b.build_bit_cast(neg, self.cx.int_type(t.get_size()), "")?.into_int_value();
        Ok(b.build_int_z_extend(m, self.cx.ctx.i32_type(), "")?)
    }
}
