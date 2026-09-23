use crate::ast::{Expr, BinOpKind};
use crate::{Result, CompileError};
use sic_ir::*;
use super::super::func::FuncCtx;
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    /// Address of `base + off` bytes (off is a compile-time constant).
    fn vec_at(&mut self, base: &Val, off: i64) -> Val {
        if off == 0 { return base.clone(); }
        let d = self.alloc_val();
        self.push_instr(Instr::PtrOffset { dest: d, base: base.clone(), offset: Constant::int(off) });
        Val::Local(d)
    }

    /// Load a scalar of `ty` at `base + off`.
    fn vec_load(&mut self, base: &Val, off: i64, ty: Type) -> Val {
        let addr = self.vec_at(base, off);
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: addr, ty });
        Val::Local(d)
    }

    /// Store `val` at `base + off`.
    fn vec_store(&mut self, base: &Val, off: i64, val: Val) {
        let addr = self.vec_at(base, off);
        self.push_instr(Instr::Store { val, ptr: addr });
    }

    fn vec_bin(&mut self, op: BinOp, lhs: Val, rhs: Val, ty: Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: d, op, lhs, rhs, ty });
        Val::Local(d)
    }

    /// Fresh stack slot holding a vector of type `vty`; returns a pointer to it.
    fn vec_alloca(&mut self, vty: Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: d, ty: vty, align: None });
        Val::Local(d)
    }

    /// Element-wise binary op on two vector (`vector_size`) operands. Operates
    /// lane-by-lane over the vector's element type into a fresh result vector.
    /// Comparisons yield an all-ones (`-1`) / all-zeros lane per GCC semantics.
    pub(crate) fn lower_vector_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr, vty: Type) -> Result<Val> {
        let (elem, lanes) = match &vty {
            Type::Array { elem, len } => ((**elem).clone(), *len),
            _ => return Err(CompileError::new("vector binop on non-array type")),
        };
        let signed = matches!(&elem, Type::Int { signed: true, .. });
        let is_float = elem.is_float();

        // Fast path: when the vector maps to a hardware SIMD register (128-bit,
        // `Type::simd128`) and the operator is one Cranelift lowers to a single
        // packed instruction, emit ONE whole-vector load/op/store instead of the
        // lane-by-lane loop below. The back end (`vector_clty`) recognizes the same
        // (element, lane) layouts, so this never emits an op it can't lower.
        //   - add/sub/and/or/xor: all integer lanes; add/sub/mul/div: float lanes.
        //   - mul: 16/32/64-bit integer lanes (x86 has no packed byte multiply).
        //   - int div/rem, shifts (per-lane amount), and comparisons (mask
        //     semantics) have no single packed form here → fall through to scalar.
        let fast_op = if vty.simd128().is_some() {
            match op {
                BinOpKind::Add => Some(if is_float { BinOp::FAdd } else { BinOp::Add }),
                BinOpKind::Sub => Some(if is_float { BinOp::FSub } else { BinOp::Sub }),
                BinOpKind::Mul if is_float => Some(BinOp::FMul),
                BinOpKind::Mul => match &elem {
                    Type::Int { bits, .. } if *bits >= 16 => Some(BinOp::Mul),
                    _ => None,
                },
                BinOpKind::Div if is_float => Some(BinOp::FDiv),
                BinOpKind::BitAnd if !is_float => Some(BinOp::And),
                BinOpKind::BitOr if !is_float => Some(BinOp::Or),
                BinOpKind::BitXor if !is_float => Some(BinOp::Xor),
                _ => None,
            }
        } else {
            None
        };
        if let Some(vop) = fast_op {
            let lp = self.lower_aggregate_ptr(lhs)?;
            let rp = self.lower_aggregate_ptr(rhs)?;
            let lv = self.vec_load(&lp, 0, vty.clone());
            let rv = self.vec_load(&rp, 0, vty.clone());
            let res = self.vec_bin(vop, lv, rv, vty.clone());
            let rp_out = self.vec_alloca(vty.clone());
            self.vec_store(&rp_out, 0, res);
            return Ok(rp_out);
        }

        // Scalar fallback (lane-by-lane): either an arithmetic/bitwise op, or a
        // comparison predicate.
        let arith = match op {
            BinOpKind::BitOr => Some(BinOp::Or),
            BinOpKind::BitAnd => Some(BinOp::And),
            BinOpKind::BitXor => Some(BinOp::Xor),
            BinOpKind::Add => Some(if is_float { BinOp::FAdd } else { BinOp::Add }),
            BinOpKind::Sub => Some(if is_float { BinOp::FSub } else { BinOp::Sub }),
            BinOpKind::Mul => Some(if is_float { BinOp::FMul } else { BinOp::Mul }),
            BinOpKind::Div => Some(if is_float { BinOp::FDiv } else if signed { BinOp::SDiv } else { BinOp::UDiv }),
            BinOpKind::Rem => Some(if is_float { BinOp::FRem } else if signed { BinOp::SRem } else { BinOp::URem }),
            BinOpKind::Shl => Some(BinOp::Shl),
            BinOpKind::Shr => Some(if signed { BinOp::AShr } else { BinOp::LShr }),
            _ => None,
        };
        let cmp = match op {
            BinOpKind::Eq => Some(CmpOp::IEq),
            BinOpKind::Ne => Some(CmpOp::INe),
            BinOpKind::Lt => Some(if signed { CmpOp::ISLt } else { CmpOp::IULt }),
            BinOpKind::Le => Some(if signed { CmpOp::ISLe } else { CmpOp::IULe }),
            BinOpKind::Gt => Some(if signed { CmpOp::ISGt } else { CmpOp::IUGt }),
            BinOpKind::Ge => Some(if signed { CmpOp::ISGe } else { CmpOp::IUGe }),
            _ => None,
        };
        if arith.is_none() && cmp.is_none() {
            return Err(CompileError::new(format!("unsupported vector operator {:?}", op)));
        }
        let lp = self.lower_aggregate_ptr(lhs)?;
        let rp = self.lower_aggregate_ptr(rhs)?;
        let rp_out = self.vec_alloca(vty.clone());
        let esz = elem.size_of(self.ptr_size()) as i64;
        for i in 0..lanes {
            let off = i as i64 * esz;
            let x = self.vec_load(&lp, off, elem.clone());
            let y = self.vec_load(&rp, off, elem.clone());
            let v = if let Some(irop) = arith {
                self.vec_bin(irop, x, y, elem.clone())
            } else {
                let c = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: c, op: cmp.unwrap(), lhs: x, rhs: y, ty: elem.clone() });
                let s = self.alloc_val();
                self.push_instr(Instr::Select { dest: s, cond: Val::Local(c), on_true: Constant::int(-1), on_false: Constant::int(0), ty: elem.clone() });
                Val::Local(s)
            };
            self.vec_store(&rp_out, off, v);
        }
        Ok(rp_out)
    }

    /// `__builtin_ia32_pmovmskb128/256`: pack the high bit of each byte into an int.
    pub(crate) fn lower_vec_pmovmskb(&mut self, arg: &Expr, n: usize) -> Result<Val> {
        let vp = self.lower_aggregate_ptr(arg)?;
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut mask = Constant::int(0);
        for i in 0..n {
            let b = self.vec_load(&vp, i as i64, u8t.clone());
            let b32 = self.coerce(b, &i32t)?;
            let sh = self.vec_bin(BinOp::LShr, b32, Constant::int(7), i32t.clone());
            let bit = self.vec_bin(BinOp::And, sh, Constant::int(1), i32t.clone());
            let shifted = self.vec_bin(BinOp::Shl, bit, Constant::int(i as i64), i32t.clone());
            mask = self.vec_bin(BinOp::Or, mask, shifted, i32t.clone());
        }
        Ok(mask)
    }

    /// `__builtin_ia32_pcmpeqb128/256`: per-byte equality → 0xFF/0x00 lanes.
    pub(crate) fn lower_vec_pcmpeqb(&mut self, a: &Expr, b: &Expr, n: usize) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let vty = self.infer_expr_type(a)?;
        let rp = self.vec_alloca(vty);
        let u8t = Type::u8();
        for i in 0..n {
            let x = self.vec_load(&ap, i as i64, u8t.clone());
            let y = self.vec_load(&bp, i as i64, u8t.clone());
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: x, rhs: y, ty: u8t.clone() });
            let val = self.alloc_val();
            self.push_instr(Instr::Select { dest: val, cond: Val::Local(eq), on_true: Constant::int(0xFF), on_false: Constant::int(0), ty: u8t.clone() });
            self.vec_store(&rp, i as i64, Val::Local(val));
        }
        Ok(rp)
    }

    /// `__builtin_ia32_pshufb128`: byte shuffle `r[i] = (b[i]&0x80) ? 0 : a[b[i]&0x0F]`.
    pub(crate) fn lower_vec_pshufb(&mut self, a: &Expr, b: &Expr, n: usize) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let vty = self.infer_expr_type(a)?;
        let rp = self.vec_alloca(vty);
        let u8t = Type::u8();
        let i64t = Type::i64();
        for i in 0..n {
            let idx = self.vec_load(&bp, i as i64, u8t.clone());
            let idx64 = self.coerce(idx, &i64t)?;
            // lo = idx & 0x0F  → offset into `a`
            let lo = self.vec_bin(BinOp::And, idx64.clone(), Constant::int(0x0F), i64t.clone());
            let srcaddr = self.alloc_val();
            self.push_instr(Instr::PtrOffset { dest: srcaddr, base: ap.clone(), offset: lo });
            let src = self.alloc_val();
            self.push_instr(Instr::Load { dest: src, ptr: Val::Local(srcaddr), ty: u8t.clone() });
            // high bit set → zero the lane
            let hib = self.vec_bin(BinOp::And, idx64, Constant::int(0x80), i64t.clone());
            let clr = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: clr, op: CmpOp::INe, lhs: hib, rhs: Constant::int(0), ty: i64t.clone() });
            let val = self.alloc_val();
            self.push_instr(Instr::Select { dest: val, cond: Val::Local(clr), on_true: Constant::int(0), on_false: Val::Local(src), ty: u8t.clone() });
            self.vec_store(&rp, i as i64, Val::Local(val));
        }
        Ok(rp)
    }

    /// `__builtin_ia32_pclmulqdq128`: carry-less multiply of two selected 64-bit
    /// halves → a 128-bit result. `imm` selects which halves (bit0 of a, bit4 of b).
    pub(crate) fn lower_vec_pclmulqdq(&mut self, a: &Expr, b: &Expr, imm: &Expr) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let immv = crate::lower::eval_const_expr(imm, &self.lowerer.enum_consts).unwrap_or(0);
        let u64t = Type::u64();
        let i128t = Type::Int { bits: 128, signed: false };
        let a_off = if immv & 0x01 != 0 { 8 } else { 0 };
        let b_off = if immv & 0x10 != 0 { 8 } else { 0 };
        let x = self.vec_load(&ap, a_off, u64t.clone());
        let y = self.vec_load(&bp, b_off, u64t.clone());
        let xext = self.coerce(x, &i128t)?;
        let mut res = Constant::int(0);
        for j in 0..64 {
            // bit j of y set?  term = bit ? (xext << j) : 0 ; res ^= term
            let yj = self.vec_bin(BinOp::LShr, y.clone(), Constant::int(j), u64t.clone());
            let ybit = self.vec_bin(BinOp::And, yj, Constant::int(1), u64t.clone());
            let set = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: set, op: CmpOp::INe, lhs: ybit, rhs: Constant::int(0), ty: u64t.clone() });
            let shifted = self.vec_bin(BinOp::Shl, xext.clone(), Constant::int(j), i128t.clone());
            let term = self.alloc_val();
            self.push_instr(Instr::Select { dest: term, cond: Val::Local(set), on_true: shifted, on_false: Constant::int(0), ty: i128t.clone() });
            res = self.vec_bin(BinOp::Xor, res, Val::Local(term), i128t.clone());
        }
        let vty = self.infer_expr_type(a).unwrap_or(Type::Array { elem: Box::new(Type::i64()), len: 2 });
        let rp = self.vec_alloca(vty);
        self.vec_store(&rp, 0, res);
        Ok(rp)
    }

    /// Pointer to the first byte of the (lazily-created) AES S-box / inverse
    /// S-box global constant.
    fn aes_sbox_ptr(&mut self, inverse: bool) -> Val {
        let name = if inverse { ".sic_aes_inv_sbox" } else { ".sic_aes_sbox" };
        let gref = if let Some(i) = self.lowerer.module.globals.iter().position(|g| g.name == name) {
            sic_ir::GlobalRef(i as u32)
        } else {
            let bytes = if inverse { AES_INV_SBOX.to_vec() } else { AES_SBOX.to_vec() };
            self.lowerer.module.add_global(sic_ir::Global {
                name: name.to_string(),
                ty: Type::Array { elem: Box::new(Type::u8()), len: 256 },
                init: Some(Constant::Bytes(bytes)),
                linkage: Linkage::Private,
                constant: true,
                thread_local: false,
            })
        };
        let ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: ptr, base: Val::Global(gref), index: Constant::zero(),
            elem_size: 1, result_ty: Type::ptr(Type::u8()),
        });
        Val::Local(ptr)
    }

    /// GF(2^8) `xtime` (multiply by 2 modulo the AES polynomial 0x11B), on a
    /// byte held in an i32.
    fn aes_xtime(&mut self, x: Val) -> Val {
        let i32t = Type::i32();
        let sh = self.vec_bin(BinOp::Shl, x.clone(), Constant::int(1), i32t.clone());
        let hi = self.vec_bin(BinOp::LShr, x, Constant::int(7), i32t.clone());
        let hi1 = self.vec_bin(BinOp::And, hi, Constant::int(1), i32t.clone());
        let red = self.vec_bin(BinOp::Mul, hi1, Constant::int(0x1b), i32t.clone());
        let xored = self.vec_bin(BinOp::Xor, sh, red, i32t.clone());
        self.vec_bin(BinOp::And, xored, Constant::int(0xff), i32t)
    }

    /// GF(2^8) multiply of byte `x` by a compile-time constant `c`.
    fn aes_gmul(&mut self, x: Val, c: u8) -> Val {
        let i32t = Type::i32();
        let mut pow = x;                 // xtime^0(x) = x
        let mut acc: Option<Val> = None;
        let mut cc = c;
        while cc != 0 {
            if cc & 1 != 0 {
                acc = Some(match acc {
                    None => pow.clone(),
                    Some(a) => self.vec_bin(BinOp::Xor, a, pow.clone(), i32t.clone()),
                });
            }
            cc >>= 1;
            if cc != 0 { pow = self.aes_xtime(pow); }
        }
        acc.unwrap_or(Constant::int(0))
    }

    /// SubBytes / InvSubBytes: replace each byte with its S-box image.
    fn aes_sub_bytes(&mut self, s: Vec<Val>, inverse: bool) -> Result<Vec<Val>> {
        let tbl = self.aes_sbox_ptr(inverse);
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut out = Vec::with_capacity(16);
        for b in s {
            let idx = self.coerce(b, &Type::i64())?;
            let addr = self.alloc_val();
            self.push_instr(Instr::PtrOffset { dest: addr, base: tbl.clone(), offset: idx });
            let v = self.alloc_val();
            self.push_instr(Instr::Load { dest: v, ptr: Val::Local(addr), ty: u8t.clone() });
            out.push(self.coerce(Val::Local(v), &i32t)?);
        }
        Ok(out)
    }

    /// MixColumns / InvMixColumns over the four 4-byte columns.
    fn aes_mix_columns(&mut self, s: Vec<Val>, inverse: bool) -> Vec<Val> {
        let m: [[u8; 4]; 4] = if inverse {
            [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
        } else {
            [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        };
        let i32t = Type::i32();
        let mut out: Vec<Val> = vec![Constant::int(0); 16];
        for col in 0..4 {
            let a = [
                s[col * 4].clone(), s[col * 4 + 1].clone(),
                s[col * 4 + 2].clone(), s[col * 4 + 3].clone(),
            ];
            for r in 0..4 {
                let mut acc: Option<Val> = None;
                for j in 0..4 {
                    let term = self.aes_gmul(a[j].clone(), m[r][j]);
                    acc = Some(match acc {
                        None => term,
                        Some(x) => self.vec_bin(BinOp::Xor, x, term, i32t.clone()),
                    });
                }
                out[col * 4 + r] = acc.unwrap();
            }
        }
        out
    }

    /// Emulate an AES-NI round intrinsic over the 16-byte state.
    pub(crate) fn lower_aes(&mut self, state: &Expr, key: Option<&Expr>, mode: AesMode) -> Result<Val> {
        // Byte permutations for (Inv)ShiftRows: out[i] = in[MAP[i]].
        const SHR: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        const INV_SHR: [usize; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

        let sp = self.lower_aggregate_ptr(state)?;
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut s: Vec<Val> = Vec::with_capacity(16);
        for i in 0..16 {
            let b = self.vec_load(&sp, i as i64, u8t.clone());
            s.push(self.coerce(b, &i32t)?);
        }
        match mode {
            AesMode::Enc | AesMode::EncLast => {
                s = SHR.iter().map(|&j| s[j].clone()).collect();
                s = self.aes_sub_bytes(s, false)?;
                if matches!(mode, AesMode::Enc) { s = self.aes_mix_columns(s, false); }
            }
            AesMode::Dec | AesMode::DecLast => {
                s = INV_SHR.iter().map(|&j| s[j].clone()).collect();
                s = self.aes_sub_bytes(s, true)?;
                if matches!(mode, AesMode::Dec) { s = self.aes_mix_columns(s, true); }
            }
            AesMode::Imc => {
                s = self.aes_mix_columns(s, true);
            }
        }
        if let Some(k) = key {
            let kp = self.lower_aggregate_ptr(k)?;
            for i in 0..16 {
                let kb = self.vec_load(&kp, i as i64, u8t.clone());
                let kb32 = self.coerce(kb, &i32t)?;
                s[i] = self.vec_bin(BinOp::Xor, s[i].clone(), kb32, i32t.clone());
            }
        }
        let vty = self.infer_expr_type(state)
            .unwrap_or(Type::Array { elem: Box::new(Type::i64()), len: 2 });
        let rp = self.vec_alloca(vty);
        for i in 0..16 {
            let b = self.coerce(s[i].clone(), &u8t)?;
            self.vec_store(&rp, i as i64, b);
        }
        Ok(rp)
    }
}
