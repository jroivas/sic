//! x86 SIMD builtins (`__builtin_ia32_*`, what GCC's `<immintrin.h>` calls)
//! lowered to the portable vector operations of [`Instr::Simd`].
//!
//! A vector operand is held as its 128-bit parts: one for `__m128`, two for
//! `__m256` (whose operations, AVX2's integer ones included, mostly work on each
//! 128-bit lane separately), and one for a 64-bit MMX `__m64`, which occupies
//! the low half. Parts are untyped 128-bit values; each operation reads them as
//! the lanes it needs. Immediate operands must be constant expressions, as GCC
//! requires.

use crate::ast::Expr;
use crate::{Result, CompileError};
use super::super::func::FuncCtx;
use sic_ir::{FCmp, SimdOp};
#[allow(unused_imports)]
use super::*;

fn int(bits: u32, signed: bool) -> Type { Type::Int { bits, signed } }
fn vec(elem: Type, len: u64) -> Type { Type::Array { elem: Box::new(elem), len: len as usize } }
fn v128(elem: Type) -> Type {
    let n = 16 / elem.size_of(8);
    vec(elem, n)
}

/// The lane type a builtin's name suffix denotes (`b`/`w`/`d`/`q` integers,
/// `ps`/`pd` floats).
fn lane_of(c: &str) -> Type {
    match c {
        "b" => int(8, true), "ub" => int(8, false),
        "w" => int(16, true), "uw" => int(16, false),
        "d" => int(32, true), "ud" => int(32, false),
        "q" => int(64, true), "uq" => int(64, false),
        "ps" | "ss" => Type::Float32,
        _ => Type::Float64,
    }
}

/// Strip the width suffix: `paddsb128` → (`paddsb`, 16), `256` → 32; the MMX
/// forms have none (8 bytes).
fn split_width(n: &str) -> (&str, u64) {
    if let Some(b) = n.strip_suffix("128") { (b, 16) }
    else if let Some(b) = n.strip_suffix("256") { (b, 32) }
    else { (n, 8) }
}

/// Element-wise two-operand builtins: base name → (operation, lane type).
fn lanewise2(base: &str) -> Option<(SimdOp, Type)> {
    use sic_ir::CmpOp::*;
    let l = lane_of;
    Some(match base {
        "paddb" => (SimdOp::Add, l("b")), "paddw" => (SimdOp::Add, l("w")),
        "paddd" => (SimdOp::Add, l("d")), "paddq" => (SimdOp::Add, l("q")),
        "psubb" => (SimdOp::Sub, l("b")), "psubw" => (SimdOp::Sub, l("w")),
        "psubd" => (SimdOp::Sub, l("d")), "psubq" => (SimdOp::Sub, l("q")),
        "pmullw" => (SimdOp::Mul, l("w")), "pmulld" => (SimdOp::Mul, l("d")),
        "paddsb" => (SimdOp::SAddSat, l("b")), "paddsw" => (SimdOp::SAddSat, l("w")),
        "paddusb" => (SimdOp::UAddSat, l("ub")), "paddusw" => (SimdOp::UAddSat, l("uw")),
        "psubsb" => (SimdOp::SSubSat, l("b")), "psubsw" => (SimdOp::SSubSat, l("w")),
        "psubusb" => (SimdOp::USubSat, l("ub")), "psubusw" => (SimdOp::USubSat, l("uw")),
        "pavgb" => (SimdOp::AvgRound, l("ub")), "pavgw" => (SimdOp::AvgRound, l("uw")),
        "pmaxsb" => (SimdOp::SMax, l("b")), "pmaxsw" => (SimdOp::SMax, l("w")), "pmaxsd" => (SimdOp::SMax, l("d")),
        "pmaxub" => (SimdOp::UMax, l("ub")), "pmaxuw" => (SimdOp::UMax, l("uw")), "pmaxud" => (SimdOp::UMax, l("ud")),
        "pminsb" => (SimdOp::SMin, l("b")), "pminsw" => (SimdOp::SMin, l("w")), "pminsd" => (SimdOp::SMin, l("d")),
        "pminub" => (SimdOp::UMin, l("ub")), "pminuw" => (SimdOp::UMin, l("uw")), "pminud" => (SimdOp::UMin, l("ud")),
        "pmulhw" => (SimdOp::SMulHi, l("w")), "pmulhuw" => (SimdOp::UMulHi, l("uw")),
        "pmulhrsw" => (SimdOp::MulHrs, l("w")),
        "pcmpeqb" => (SimdOp::ICmp(IEq), l("b")), "pcmpeqw" => (SimdOp::ICmp(IEq), l("w")),
        "pcmpeqd" => (SimdOp::ICmp(IEq), l("d")), "pcmpeqq" => (SimdOp::ICmp(IEq), l("q")),
        "pcmpgtb" => (SimdOp::ICmp(ISGt), l("b")), "pcmpgtw" => (SimdOp::ICmp(ISGt), l("w")),
        "pcmpgtd" => (SimdOp::ICmp(ISGt), l("d")), "pcmpgtq" => (SimdOp::ICmp(ISGt), l("q")),
        "pand" | "andps" | "andpd" => (SimdOp::And, l("q")),
        "por" | "orps" | "orpd" => (SimdOp::Or, l("q")),
        "pxor" | "xorps" | "xorpd" => (SimdOp::Xor, l("q")),
        "addps" => (SimdOp::FAdd, l("ps")), "addpd" => (SimdOp::FAdd, l("pd")),
        "subps" => (SimdOp::FSub, l("ps")), "subpd" => (SimdOp::FSub, l("pd")),
        "mulps" => (SimdOp::FMul, l("ps")), "mulpd" => (SimdOp::FMul, l("pd")),
        "divps" => (SimdOp::FDiv, l("ps")), "divpd" => (SimdOp::FDiv, l("pd")),
        "maxps" => (SimdOp::FMax, l("ps")), "maxpd" => (SimdOp::FMax, l("pd")),
        "minps" => (SimdOp::FMin, l("ps")), "minpd" => (SimdOp::FMin, l("pd")),
        _ => return None,
    })
}

/// The scalar (`ss`/`sd`) forms: lane 0 of the operation, the other lanes of
/// the first operand.
fn scalar2(n: &str) -> Option<(SimdOp, Type)> {
    let (op, rest) = [("add", SimdOp::FAdd), ("sub", SimdOp::FSub), ("mul", SimdOp::FMul),
                      ("div", SimdOp::FDiv), ("max", SimdOp::FMax), ("min", SimdOp::FMin)]
        .into_iter().find_map(|(p, op)| n.strip_prefix(p).map(|r| (op, r)))?;
    match rest { "ss" => Some((op, Type::Float32)), "sd" => Some((op, Type::Float64)), _ => None }
}

/// `cmp<pred>{ps,pd,ss,sd}` predicates (SSE spellings) → the comparison, or
/// `None` for an unknown spelling.
fn cmp_pred(p: &str) -> Option<FCmp> {
    Some(match p {
        "eq" => FCmp::Eq, "lt" => FCmp::Lt, "le" => FCmp::Le, "gt" => FCmp::Gt, "ge" => FCmp::Ge,
        "unord" => FCmp::Uno, "ord" => FCmp::Ord, "neq" => FCmp::UNe,
        "nlt" => FCmp::UGe, "nle" => FCmp::UGt, "ngt" => FCmp::ULe, "nge" => FCmp::ULt,
        _ => return None,
    })
}

/// The comparison an AVX predicate immediate (0..31) selects; the signaling
/// forms (16..31) compare the same.
enum ImmCmp { Cmp(FCmp), False, True }

fn imm_cmp(imm: i64) -> ImmCmp {
    match imm & 15 {
        0 => ImmCmp::Cmp(FCmp::Eq), 1 => ImmCmp::Cmp(FCmp::Lt), 2 => ImmCmp::Cmp(FCmp::Le),
        3 => ImmCmp::Cmp(FCmp::Uno), 4 => ImmCmp::Cmp(FCmp::UNe), 5 => ImmCmp::Cmp(FCmp::UGe),
        6 => ImmCmp::Cmp(FCmp::UGt), 7 => ImmCmp::Cmp(FCmp::Ord), 8 => ImmCmp::Cmp(FCmp::UEq),
        9 => ImmCmp::Cmp(FCmp::ULt), 10 => ImmCmp::Cmp(FCmp::ULe), 11 => ImmCmp::False,
        12 => ImmCmp::Cmp(FCmp::Ne), 13 => ImmCmp::Cmp(FCmp::Ge), 14 => ImmCmp::Cmp(FCmp::Gt),
        _ => ImmCmp::True,
    }
}

/// Byte indices taking lane `src` of `lanes` lanes (of `lb` bytes) into lane
/// `dst` of a shuffle mask (`src` ≥ the lane count picks from the second
/// operand; `ZERO_LANE` picks a zero lane from it, see [`FuncCtx::shuffle`]).
fn put_lane(mask: &mut [u8; 16], dst: usize, src: usize, lb: usize) {
    for k in 0..lb { mask[dst * lb + k] = (src * lb + k) as u8; }
}

impl FuncCtx<'_> {
    // ---- parts ------------------------------------------------------------

    fn sv(&mut self, op: SimdOp, args: Vec<Val>, arg_ty: Type, ty: Type) -> Val {
        let dest = self.alloc_val();
        self.push_instr(Instr::Simd { dest, op, args, arg_ty, ty });
        Val::Local(dest)
    }

    fn sv_zero(&mut self) -> Val {
        self.sv(SimdOp::Const(Box::new([0; 16])), vec![], v128(int(8, false)), v128(int(8, false)))
    }

    fn sv_const(&mut self, bytes: [u8; 16]) -> Val {
        self.sv(SimdOp::Const(Box::new(bytes)), vec![], v128(int(8, false)), v128(int(8, false)))
    }

    /// The bytes of `a` (0..16) and `b` (16..32) picked by `mask`.
    fn shuffle(&mut self, a: Val, b: Val, mask: [u8; 16]) -> Val {
        let t = v128(int(8, false));
        self.sv(SimdOp::Shuffle(Box::new(mask)), vec![a, b], t.clone(), t)
    }

    /// The 128-bit parts of the `width`-byte vector at `ptr`.
    pub(super) fn load_parts(&mut self, ptr: Val, width: u64) -> Vec<Val> {
        let t = v128(int(64, true));
        if width == 8 {
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr, ty: int(64, true) });
            let z = self.sv_zero();
            return vec![self.sv(SimdOp::Insert(0), vec![z, Val::Local(d)], t.clone(), t)];
        }
        (0..width / 16).map(|k| {
            let p = if k == 0 { ptr.clone() } else {
                let d = self.alloc_val();
                self.push_instr(Instr::PtrOffset { dest: d, base: ptr.clone(), offset: Constant::int(16 * k as i64) });
                Val::Local(d)
            };
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: p, ty: t.clone() });
            Val::Local(d)
        }).collect()
    }

    /// Store `parts` to `ptr` as a `width`-byte vector.
    fn store_parts(&mut self, ptr: Val, parts: &[Val], width: u64) {
        let t = v128(int(64, true));
        if width == 8 {
            let lo = self.sv(SimdOp::Extract(0), vec![parts[0].clone()], t, int(64, true));
            self.push_instr(Instr::Store { val: lo, ptr });
            return;
        }
        for (k, p) in parts.iter().enumerate() {
            let at = if k == 0 { ptr.clone() } else {
                let d = self.alloc_val();
                self.push_instr(Instr::PtrOffset { dest: d, base: ptr.clone(), offset: Constant::int(16 * k as i64) });
                Val::Local(d)
            };
            // Typed as the part's lanes so the store writes the whole vector.
            let v = self.sv(SimdOp::Bitcast, vec![p.clone()], t.clone(), t.clone());
            self.push_instr(Instr::Store { val: v, ptr: at });
        }
    }

    /// A vector operand's parts and byte width.
    fn vec_arg(&mut self, e: &Expr) -> Result<(Vec<Val>, u64)> {
        let ty = self.infer_expr_type(e)?;
        let width = match &ty {
            Type::Array { .. } => ty.size_of(self.ptr_size()),
            _ => return Err(CompileError::new(format!("a vector operand is needed, found `{}`", ty))),
        };
        if !matches!(width, 8 | 16 | 32) {
            return Err(CompileError::new(format!("unsupported vector width of {} bytes", width)));
        }
        let p = self.lower_aggregate_ptr(e)?;
        Ok((self.load_parts(p, width), width))
    }

    /// A fresh vector of type `ty` holding `parts`; the builtin's value.
    pub(super) fn vec_result(&mut self, parts: &[Val], ty: Type) -> Val {
        let width = ty.size_of(self.ptr_size());
        let d = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: d, ty, align: None });
        self.store_parts(Val::Local(d), parts, width);
        Val::Local(d)
    }

    fn imm(&self, e: &Expr, name: &str) -> Result<i64> {
        self.lowerer.eval_const_int(e).ok_or_else(|| CompileError::new(format!(
            "the last argument of `{}` must be a constant integer", name)))
    }

    fn scalar_arg(&mut self, e: &Expr, ty: &Type) -> Result<Val> {
        let v = self.lower_expr(e)?;
        self.coerce(v, ty)
    }

    /// `op` applied to each part pair of `a` and `b`.
    fn per_part2(&mut self, op: SimdOp, a: &[Val], b: &[Val], lane: &Type) -> Vec<Val> {
        let t = v128(lane.clone());
        a.iter().zip(b).map(|(x, y)| self.sv(op.clone(), vec![x.clone(), y.clone()], t.clone(), t.clone())).collect()
    }

    pub(super) fn per_part1(&mut self, op: SimdOp, a: &[Val], lane: &Type) -> Vec<Val> {
        let t = v128(lane.clone());
        a.iter().map(|x| self.sv(op.clone(), vec![x.clone()], t.clone(), t.clone())).collect()
    }

    /// Lane 0 of `r`, lanes 1.. of `a` (the scalar `ss`/`sd` forms).
    fn merge_low(&mut self, a: Val, r: Val, lane: &Type) -> Val {
        let lb = lane.size_of(8) as usize;
        let mut m = [0u8; 16];
        for (i, x) in m.iter_mut().enumerate() { *x = i as u8; }
        for k in 0..lb { m[k] = (16 + k) as u8; }
        self.shuffle(a, r, m)
    }

    /// A vector with every lane all ones where `cond` (a scalar bool/int) is
    /// non-zero, else zero.
    fn mask_from(&mut self, cond: Val) -> Val {
        let s = self.alloc_val();
        self.push_instr(Instr::Select { dest: s, cond, on_true: Constant::int(-1), on_false: Constant::int(0), ty: int(64, true) });
        self.sv(SimdOp::Splat, vec![Val::Local(s)], v128(int(64, true)), v128(int(64, true)))
    }

    /// x86 shift by a count: `count` ≥ the lane width gives zero for the
    /// logical shifts and fills with the sign for the arithmetic one (which
    /// then shifts by width − 1).
    fn shift_by(&mut self, op: SimdOp, a: &[Val], lane: &Type, count: Val) -> Vec<Val> {
        let bits = lane.size_of(8) * 8;
        let t = v128(lane.clone());
        if let Some(c) = self.int_const_of(&count) {
            if op == SimdOp::AShr {
                let c = c.min(bits - 1) as i64;
                return a.iter().map(|x| self.sv(op.clone(), vec![x.clone(), Constant::int(c)], t.clone(), t.clone())).collect();
            }
            if c >= bits { return a.iter().map(|_| self.sv_zero()).collect(); }
            return a.iter().map(|x| self.sv(op.clone(), vec![x.clone(), Constant::int(c as i64)], t.clone(), t.clone())).collect();
        }
        // Runtime count: compare unsigned against the width.
        let c64 = self.coerce(count, &int(64, false)).unwrap_or_else(|_| Constant::int(0));
        let big = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: big, op: CmpOp::IUGe, lhs: c64.clone(), rhs: Constant::int(bits as i64), ty: int(64, false) });
        let clamped = self.alloc_val();
        self.push_instr(Instr::Select { dest: clamped, cond: Val::Local(big), on_true: Constant::int(bits as i64 - 1), on_false: c64, ty: int(64, false) });
        let amt = self.coerce(Val::Local(clamped), &int(32, false)).unwrap_or_else(|_| Constant::int(0));
        let shifted: Vec<Val> = a.iter().map(|x| self.sv(op.clone(), vec![x.clone(), amt.clone()], t.clone(), t.clone())).collect();
        if op == SimdOp::AShr { return shifted; }
        let m = self.mask_from(Val::Local(big));
        let z = self.sv_zero();
        shifted.into_iter().map(|s| self.sv(SimdOp::Select, vec![m.clone(), z.clone(), s], t.clone(), t.clone())).collect()
    }

    /// The count operand of the vector-count shifts (`psllw128(a, count)`):
    /// the low 64 bits of the vector.
    fn shift_count_vec(&mut self, e: &Expr) -> Result<Val> {
        let (p, _) = self.vec_arg(e)?;
        Ok(self.sv(SimdOp::Extract(0), vec![p[0].clone()], v128(int(64, false)), int(64, false)))
    }

    /// Interleave the low (or high) lanes of each 64-bit half … of `a` and `b`
    /// (`unpcklps`, `punpcklbw`, …), within each part.
    fn unpack(&mut self, a: &[Val], b: &[Val], lb: usize, high: bool, width: u64) -> Vec<Val> {
        // An MMX vector's lanes are its low 8 bytes.
        let span = if width == 8 { 8 } else { 16 };
        let half = span / 2;
        let start = if high { half } else { 0 };
        let mut m = [0u8; 16];
        let mut d = 0;
        for i in (0..half).step_by(lb) {
            for k in 0..lb { m[d + k] = (start + i + k) as u8; }
            for k in 0..lb { m[d + lb + k] = (16 + start + i + k) as u8; }
            d += 2 * lb;
        }
        a.iter().zip(b).map(|(x, y)| self.shuffle(x.clone(), y.clone(), m)).collect()
    }

    /// Byte shift of each 128-bit part by `n` bytes (`pslldq` left = toward
    /// higher bytes), zero filled.
    fn byte_shift(&mut self, a: &[Val], n: i64, left: bool) -> Vec<Val> {
        let mut m = [0u8; 16];
        for (i, x) in m.iter_mut().enumerate() {
            let src = if left { i as i64 - n } else { i as i64 + n };
            *x = if (0..16).contains(&src) { src as u8 } else { 16 };
        }
        let z = self.sv_zero();
        a.iter().map(|x| self.shuffle(x.clone(), z.clone(), m)).collect()
    }

    /// The even and the odd `lb`-byte lanes of `a` followed by those of `b`
    /// (horizontal adds): for 128-bit parts, `[a0, a2, …, b0, b2, …]` and
    /// `[a1, a3, …, b1, b3, …]`. MMX operands are concatenated first.
    fn evens_odds(&mut self, a: &Val, b: &Val, lb: usize, width: u64) -> (Val, Val) {
        let (a, b) = if width == 8 {
            let ab = self.shuffle(a.clone(), b.clone(), std::array::from_fn(|i| if i < 8 { i as u8 } else { 8 + i as u8 }));
            (ab, self.sv_zero())
        } else { (a.clone(), b.clone()) };
        let lanes = 16 / lb;
        let mut ev = [0u8; 16];
        let mut od = [0u8; 16];
        for d in 0..lanes {
            let src = if d < lanes / 2 { 2 * d } else { lanes + 2 * (d - lanes / 2) };
            put_lane(&mut ev, d, src, lb);
            put_lane(&mut od, d, src + 1, lb);
        }
        (self.shuffle(a.clone(), b.clone(), ev), self.shuffle(a, b, od))
    }

    /// Bytes `i..i+8` of `a` as eight u16 lanes.
    fn bytes_u16(&mut self, a: &Val, i: usize) -> Val {
        let z = self.sv_zero();
        let m: [u8; 16] = std::array::from_fn(|k| if k < 8 { (i + k) as u8 } else { 16 });
        let s = self.shuffle(a.clone(), z, m);
        self.sv(SimdOp::UWidenLow, vec![s], v128(int(8, false)), v128(int(16, false)))
    }

    /// The 256-entry CRC-32C (Castagnoli, reflected 0x82F63B78) table.
    fn crc32c_table(&mut self) -> Val {
        let name = ".sic_crc32c_table";
        let gref = if let Some(i) = self.lowerer.module.globals.iter().position(|g| g.name == name) {
            sic_ir::GlobalRef(i as u32)
        } else {
            let mut bytes = Vec::with_capacity(1024);
            for i in 0..256u32 {
                let mut c = i;
                for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 }; }
                bytes.extend_from_slice(&c.to_le_bytes());
            }
            self.lowerer.module.add_global(sic_ir::Global {
                name: name.to_string(),
                ty: Type::Array { elem: Box::new(Type::u32()), len: 256 },
                init: Some(Constant::Bytes(bytes)),
                linkage: Linkage::Private,
                constant: true,
                thread_local: false,
            })
        };
        Val::Global(gref)
    }

    /// `crc32{qi,hi,si,di}(crc, v)`: CRC-32C of `v`'s bytes, low first.
    fn lower_crc32(&mut self, n: &str, args: &[Expr]) -> Result<Val> {
        let bytes = match n { "crc32qi" => 1, "crc32hi" => 2, "crc32si" => 4, _ => 8 };
        let t32 = int(32, false);
        let t64 = int(64, false);
        let crc = self.scalar_arg(&args[0], &t64)?;
        let v = self.scalar_arg(&args[1], &t64)?;
        let tab = self.crc32c_table();
        let bin = |me: &mut Self, op: BinOp, l: Val, r: Val| {
            let d = me.alloc_val();
            me.push_instr(Instr::BinOp { dest: d, op, lhs: l, rhs: r, ty: t64.clone() });
            Val::Local(d)
        };
        let mut c = crc;
        for k in 0..bytes {
            let byte = bin(self, BinOp::LShr, v.clone(), Constant::int(8 * k));
            let x = bin(self, BinOp::Xor, c.clone(), byte);
            let idx = bin(self, BinOp::And, x, Constant::int(0xff));
            let ep = self.alloc_val();
            self.push_instr(Instr::GetElemPtr { dest: ep, base: tab.clone(), index: idx, elem_size: 4, result_ty: Type::ptr(t32.clone()) });
            let e = self.alloc_val();
            self.push_instr(Instr::Load { dest: e, ptr: Val::Local(ep), ty: t32.clone() });
            let e = self.coerce(Val::Local(e), &t64)?;
            let sh = bin(self, BinOp::LShr, c, Constant::int(8));
            let sh = bin(self, BinOp::And, sh, Constant::int(0x00ff_ffff));
            c = bin(self, BinOp::Xor, sh, e);
        }
        let rt = if n == "crc32di" { t64 } else { t32 };
        self.coerce(c, &rt)
    }

    /// `pcmp{e,i}str{i,m,a,c,o,s,z}128`: a call of the prepended
    /// `__sic_pcmpstr` runtime (sic/src/pcmpstr_runtime.c).
    fn lower_pcmpstr(&mut self, name: &str, n: &str, args: &[Expr], rty: &Type) -> Result<Val> {
        let explicit = n.starts_with("pcmpestr");
        let want = if explicit { 5 } else { 3 };
        if args.len() != want {
            return Err(CompileError::new(format!("`{}` takes {} arguments, but {} were given", name, want, args.len())));
        }
        // `i` index, `m` mask, `ia`/`ic`/`io`/`is`/`iz` one flag.
        let what = match &n[8..n.len() - 3] {
            "i" => 0, "m" => 1, "ic" => 2, "iz" => 3, "is" => 4, "io" => 5, "ia" => 6,
            _ => return Err(CompileError::new(format!("unknown string comparison `{}`", name))),
        };
        let func = match self.lookup("__sic_pcmpstr") {
            Some(super::super::func::LookupResult::Func(f)) => f,
            _ => return Err(CompileError::new("the string-comparison runtime `__sic_pcmpstr` is missing".to_string())),
        };
        let i32t = Type::i32();
        let vp = Type::void_ptr();
        let (a, la, b, lb, imm) = if explicit {
            (&args[0], Some(&args[1]), &args[2], Some(&args[3]), &args[4])
        } else {
            (&args[0], None, &args[1], None, &args[2])
        };
        let imm = self.imm(imm, name)?;
        let ap = self.lower_aggregate_ptr(a)?;
        let ap = self.coerce(ap, &vp)?;
        let la = match la { Some(e) => self.scalar_arg(e, &i32t)?, None => Constant::int(0) };
        let bp = self.lower_aggregate_ptr(b)?;
        let bp = self.coerce(bp, &vp)?;
        let lb = match lb { Some(e) => self.scalar_arg(e, &i32t)?, None => Constant::int(0) };
        let out = if what == 1 {
            let d = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: d, ty: rty.clone(), align: None });
            Some(Val::Local(d))
        } else { None };
        let mp = match &out { Some(p) => self.coerce(p.clone(), &vp)?, None => Constant::null() };
        let r = self.alloc_val();
        self.push_instr(Instr::Call {
            dest: Some(r), func,
            args: vec![ap, la, bp, lb, Constant::int(!explicit as i64), Constant::int(imm), Constant::int(what), mp],
            ret_ty: i32t,
        });
        Ok(out.unwrap_or(Val::Local(r)))
    }

    /// Lower `__builtin_ia32_<n>`; `None` when `n` is not handled here.
    pub(crate) fn lower_ia32(&mut self, name: &str, args: &[Expr]) -> Result<Option<Val>> {
        let Some(n) = name.strip_prefix("__builtin_ia32_") else { return Ok(None) };
        let Some(rty) = self.ia32_result_type(name, args) else { return Ok(None) };
        let want = |k: usize| -> Result<()> {
            if args.len() == k { Ok(()) } else {
                Err(CompileError::new(format!("`{}` takes {} arguments, but {} were given", name, k, args.len())))
            }
        };
        let (base, _) = split_width(n);

        if let Some((op, lane)) = lanewise2(base) {
            want(2)?;
            let (a, _) = self.vec_arg(&args[0])?;
            let (b, _) = self.vec_arg(&args[1])?;
            let r = self.per_part2(op, &a, &b, &lane);
            return Ok(Some(self.vec_result(&r, rty)));
        }
        if let Some((op, lane)) = scalar2(n) {
            want(2)?;
            let (a, _) = self.vec_arg(&args[0])?;
            let (b, _) = self.vec_arg(&args[1])?;
            let r = self.per_part2(op, &a, &b, &lane);
            let m = self.merge_low(a[0].clone(), r[0].clone(), &lane);
            return Ok(Some(self.vec_result(&[m], rty)));
        }
        // cmp<pred>ps / pd / ss / sd
        if let Some(rest) = n.strip_prefix("cmp") {
            let (pred, kind) = rest.split_at(rest.len().saturating_sub(2));
            if let (Some(k), true) = (cmp_pred(pred), matches!(kind, "ps" | "pd" | "ss" | "sd")) {
                want(2)?;
                let lane = lane_of(kind);
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let it = v128(lane.clone());
                let r: Vec<Val> = a.iter().zip(&b).map(|(x, y)| self.sv(SimdOp::FCmp(k), vec![x.clone(), y.clone()], it.clone(), it.clone())).collect();
                let r = if kind.starts_with('s') { vec![self.merge_low(a[0].clone(), r[0].clone(), &lane)] } else { r };
                return Ok(Some(self.vec_result(&r, rty)));
            }
        }

        let lane = |s: &str| lane_of(s);
        if (n.starts_with("pcmpestr") || n.starts_with("pcmpistr")) && n.ends_with("128") {
            return self.lower_pcmpstr(name, n, args, &rty).map(Some);
        }
        let parts = match n {
            "crc32qi" | "crc32hi" | "crc32si" | "crc32di" => {
                want(2)?;
                return self.lower_crc32(n, args).map(Some);
            }
            // a - b in the even lanes, a + b in the odd ones.
            "addsubps" | "addsubpd" | "addsubps256" | "addsubpd256" => {
                want(2)?;
                let l = if n.contains("pd") { Type::Float64 } else { Type::Float32 };
                let lb = l.size_of(8) as usize;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let sub = self.per_part2(SimdOp::FSub, &a, &b, &l);
                let add = self.per_part2(SimdOp::FAdd, &a, &b, &l);
                let mut m = [0u8; 16];
                for d in 0..16 / lb { put_lane(&mut m, d, if d % 2 == 0 { d } else { 16 / lb + d }, lb); }
                sub.iter().zip(&add).map(|(x, y)| self.shuffle(x.clone(), y.clone(), m)).collect()
            }
            // Horizontal add/sub of adjacent lanes: evens op odds.
            "haddps" | "haddpd" | "hsubps" | "hsubpd" | "haddps256" | "haddpd256" | "hsubps256" | "hsubpd256"
            | "phaddw" | "phaddw128" | "phaddd" | "phaddd128" | "phaddsw" | "phaddsw128"
            | "phsubw" | "phsubw128" | "phsubd" | "phsubd128" | "phsubsw" | "phsubsw128"
            | "phaddw256" | "phaddd256" | "phaddsw256" | "phsubw256" | "phsubd256" | "phsubsw256" => {
                want(2)?;
                let b0 = split_width(n).0;
                let (l, op) = match b0 {
                    "haddps" => (Type::Float32, SimdOp::FAdd), "hsubps" => (Type::Float32, SimdOp::FSub),
                    "haddpd" => (Type::Float64, SimdOp::FAdd), "hsubpd" => (Type::Float64, SimdOp::FSub),
                    "phaddw" => (lane("w"), SimdOp::Add), "phaddd" => (lane("d"), SimdOp::Add),
                    "phaddsw" => (lane("w"), SimdOp::SAddSat), "phsubw" => (lane("w"), SimdOp::Sub),
                    "phsubd" => (lane("d"), SimdOp::Sub), _ => (lane("w"), SimdOp::SSubSat),
                };
                let (a, w) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let t = v128(l.clone());
                let lb = l.size_of(8) as usize;
                a.iter().zip(&b).map(|(x, y)| {
                    let (e, o) = self.evens_odds(x, y, lb, w);
                    self.sv(op.clone(), vec![e, o], t.clone(), t.clone())
                }).collect()
            }
            "movshdup" | "movsldup" | "movshdup256" | "movsldup256" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let off = if n.starts_with("movsh") { 1 } else { 0 };
                let mut m = [0u8; 16];
                for d in 0..4 { put_lane(&mut m, d, (d & !1) + off, 4); }
                a.iter().map(|x| self.shuffle(x.clone(), x.clone(), m)).collect()
            }
            // Plain loads.
            "lddqu" | "lddqu256" | "movntdqa" | "movntdqa256" => {
                want(1)?;
                let p = self.lower_expr(&args[0])?;
                let w = rty.size_of(self.ptr_size());
                self.load_parts(p, w)
            }
            // Lane i from b where immediate bit i is set (per 128-bit part for
            // the 256-bit word blend, which repeats its 8 bits).
            "blendps" | "blendpd" | "pblendw128" | "blendps256" | "blendpd256" | "pblendw256" | "pblendd128" | "pblendd256" => {
                want(3)?;
                let lb = match split_width(n).0 { "blendps" | "pblendd" => 4, "blendpd" => 8, _ => 2 };
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let imm = self.imm(&args[2], name)? as usize;
                let per = 16 / lb;
                a.iter().zip(&b).enumerate().map(|(k, (x, y))| {
                    let bits = if lb == 2 { imm } else { imm >> (per * k) };
                    let mut m = [0u8; 16];
                    for d in 0..per { put_lane(&mut m, d, if bits >> d & 1 != 0 { per + d } else { d }, lb); }
                    self.shuffle(x.clone(), y.clone(), m)
                }).collect()
            }
            // Lane from b where the mask lane's sign bit is set.
            "blendvps" | "blendvpd" | "pblendvb128" | "blendvps256" | "blendvpd256" | "pblendvb256" => {
                want(3)?;
                let l = match split_width(n).0 { "blendvps" => lane("d"), "blendvpd" => lane("q"), _ => lane("b") };
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let (m, _) = self.vec_arg(&args[2])?;
                let t = v128(l.clone());
                let z = self.sv_zero();
                a.iter().zip(&b).zip(&m).map(|((x, y), mk)| {
                    let neg = self.sv(SimdOp::ICmp(CmpOp::ISLt), vec![mk.clone(), z.clone()], t.clone(), t.clone());
                    self.sv(SimdOp::Select, vec![neg, y.clone(), x.clone()], t.clone(), t.clone())
                }).collect()
            }
            // Dot product of the lanes chosen by imm[7:4], into the lanes of imm[3:0].
            "dpps" | "dppd" | "dpps256" => {
                want(3)?;
                let pd = n == "dppd";
                let (l, lb) = if pd { (Type::Float64, 8usize) } else { (Type::Float32, 4) };
                let lanes = 16 / lb;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let imm = self.imm(&args[2], name)? as usize;
                let t = v128(l.clone());
                let lane_mask = |bits: usize| -> [u8; 16] { std::array::from_fn(|i| if bits >> (i / lb) & 1 != 0 { 0xff } else { 0 }) };
                a.iter().zip(&b).map(|(x, y)| {
                    let p = self.sv(SimdOp::FMul, vec![x.clone(), y.clone()], t.clone(), t.clone());
                    let mk = self.sv_const(lane_mask(imm >> 4));
                    let p = self.sv(SimdOp::And, vec![p, mk], t.clone(), t.clone());
                    // Pairwise sums: (t0 + t1) + (t2 + t3), in every lane.
                    let mut sw = [0u8; 16];
                    for d in 0..lanes { put_lane(&mut sw, d, d ^ 1, lb); }
                    let ps = self.shuffle(p.clone(), p.clone(), sw);
                    let mut s1 = self.sv(SimdOp::FAdd, vec![p, ps], t.clone(), t.clone());
                    if lanes == 4 {
                        let mut sw2 = [0u8; 16];
                        for d in 0..4 { put_lane(&mut sw2, d, d ^ 2, 4); }
                        let s1s = self.shuffle(s1.clone(), s1.clone(), sw2);
                        s1 = self.sv(SimdOp::FAdd, vec![s1, s1s], t.clone(), t.clone());
                    }
                    let rm = self.sv_const(lane_mask(imm & 15));
                    self.sv(SimdOp::And, vec![s1, rm], t.clone(), t.clone())
                }).collect()
            }
            // Lane imm[7:6] of b into lane imm[5:4] of a, then zero the lanes in imm[3:0].
            "insertps128" => {
                want(3)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let imm = self.imm(&args[2], name)? as usize;
                let mut m: [u8; 16] = std::array::from_fn(|i| i as u8);
                put_lane(&mut m, (imm >> 4) & 3, 4 + ((imm >> 6) & 3), 4);
                let r = self.shuffle(a[0].clone(), b[0].clone(), m);
                let z = self.sv_zero();
                let mut zm: [u8; 16] = std::array::from_fn(|i| i as u8);
                for d in 0..4 { if imm >> d & 1 != 0 { put_lane(&mut zm, d, 4, 4); } }
                vec![self.shuffle(r, z, zm)]
            }
            // Eight sums of absolute differences of 4-byte windows of a against
            // the 4 bytes of b at imm[1:0], windows starting at imm[2]·4.
            "mpsadbw128" | "mpsadbw256" => {
                want(3)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let imm = self.imm(&args[2], name)? as usize;
                let u16t = v128(int(16, false));
                a.iter().zip(&b).enumerate().map(|(k, (x, y))| {
                    let sel = if k == 0 { imm } else { imm >> 3 };
                    let (ao, bo) = (((sel >> 2) & 1) * 4, (sel & 3) * 4);
                    let yb = y.clone();
                    let mut acc: Option<Val> = None;
                    for j in 0..4 {
                        let aw = self.bytes_u16(x, ao + j);
                        let bb = self.shuffle(yb.clone(), yb.clone(), std::array::from_fn(|i| if i % 2 == 0 { (bo + j) as u8 } else { 16 }));
                        let z = self.sv_zero();
                        let bw = self.shuffle(bb, z, std::array::from_fn(|i| if i % 2 == 0 { i as u8 } else { 16 }));
                        let hi = self.sv(SimdOp::UMax, vec![aw.clone(), bw.clone()], u16t.clone(), u16t.clone());
                        let lo = self.sv(SimdOp::UMin, vec![aw, bw], u16t.clone(), u16t.clone());
                        let d = self.sv(SimdOp::Sub, vec![hi, lo], u16t.clone(), u16t.clone());
                        acc = Some(match acc { None => d, Some(p) => self.sv(SimdOp::Add, vec![p, d], u16t.clone(), u16t.clone()) });
                    }
                    acc.unwrap()
                }).collect()
            }
            "pabsb" | "pabsb128" | "pabsw" | "pabsw128" | "pabsd" | "pabsd128" | "pabsb256" | "pabsw256" | "pabsd256" => {
                want(1)?;
                let l = lane(&split_width(n).0[4..]);
                let (a, _) = self.vec_arg(&args[0])?;
                self.per_part1(SimdOp::Abs, &a, &l)
            }
            // (b:a) >> n bytes (GCC passes the count in bits), per 128-bit part.
            "palignr" | "palignr128" | "palignr256" => {
                want(3)?;
                let (a, w) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let by = (self.imm(&args[2], name)? / 8) as usize;
                if w == 8 {
                    // a:b as one 16-byte value, shifted, low 8 bytes kept.
                    let ab = self.shuffle(b[0].clone(), a[0].clone(), std::array::from_fn(|i| if i < 8 { i as u8 } else { 8 + i as u8 }));
                    let z = self.sv_zero();
                    let m: [u8; 16] = std::array::from_fn(|i| if i + by < 16 { (i + by) as u8 } else { 16 });
                    vec![self.shuffle(ab, z, m)]
                } else {
                    a.iter().zip(&b).map(|(x, y)| {
                        if by >= 32 { return self.sv_zero(); }
                        if by >= 16 {
                            let z = self.sv_zero();
                            let m: [u8; 16] = std::array::from_fn(|i| if i + by - 16 < 16 { (i + by - 16) as u8 } else { 16 });
                            return self.shuffle(x.clone(), z, m);
                        }
                        self.shuffle(y.clone(), x.clone(), std::array::from_fn(|i| (i + by) as u8))
                    }).collect()
                }
            }
            // Byte shuffle: index bit 7 zeroes the byte, else the low 4 bits
            // (3 for MMX) pick it, within each 128-bit part.
            "pshufb" | "pshufb128" | "pshufb256" => {
                want(2)?;
                let (a, w) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let keep = if w == 8 { 0x87 } else { 0x8f };
                let km = self.sv_const([keep; 16]);
                let t = v128(int(8, false));
                a.iter().zip(&b).map(|(x, y)| {
                    let idx = self.sv(SimdOp::And, vec![y.clone(), km.clone()], t.clone(), t.clone());
                    self.sv(SimdOp::Swizzle, vec![x.clone(), idx], t.clone(), t.clone())
                }).collect()
            }
            // a negated, zeroed or kept as b is negative, zero or positive.
            "psignb" | "psignb128" | "psignw" | "psignw128" | "psignd" | "psignd128" | "psignb256" | "psignw256" | "psignd256" => {
                want(2)?;
                let l = lane(&split_width(n).0[5..]);
                let t = v128(l.clone());
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let z = self.sv_zero();
                a.iter().zip(&b).map(|(x, y)| {
                    let neg = self.sv(SimdOp::Neg, vec![x.clone()], t.clone(), t.clone());
                    let lt = self.sv(SimdOp::ICmp(CmpOp::ISLt), vec![y.clone(), z.clone()], t.clone(), t.clone());
                    let eq = self.sv(SimdOp::ICmp(CmpOp::IEq), vec![y.clone(), z.clone()], t.clone(), t.clone());
                    let r = self.sv(SimdOp::Select, vec![lt, neg, x.clone()], t.clone(), t.clone());
                    self.sv(SimdOp::AndNot, vec![r, eq], t.clone(), t.clone())
                }).collect()
            }
            // u8 × s8 products, adjacent pairs added with saturation into i16.
            "pmaddubsw" | "pmaddubsw128" | "pmaddubsw256" => {
                want(2)?;
                let (a, w) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let (t8u, t8s, t16) = (v128(int(8, false)), v128(int(8, true)), v128(int(16, true)));
                a.iter().zip(&b).map(|(x, y)| {
                    let al = self.sv(SimdOp::UWidenLow, vec![x.clone()], t8u.clone(), t16.clone());
                    let ah = self.sv(SimdOp::UWidenHigh, vec![x.clone()], t8u.clone(), t16.clone());
                    let bl = self.sv(SimdOp::SWidenLow, vec![y.clone()], t8s.clone(), t16.clone());
                    let bh = self.sv(SimdOp::SWidenHigh, vec![y.clone()], t8s.clone(), t16.clone());
                    let pl = self.sv(SimdOp::Mul, vec![al, bl], t16.clone(), t16.clone());
                    let ph = self.sv(SimdOp::Mul, vec![ah, bh], t16.clone(), t16.clone());
                    let (e, o) = self.evens_odds(&pl, &ph, 2, if w == 8 { 16 } else { w });
                    self.sv(SimdOp::SAddSat, vec![e, o], t16.clone(), t16.clone())
                }).collect()
            }
            // Sign/zero extension of the low lanes.
            _ if extend_kind(n).is_some() => {
                want(1)?;
                let (from, steps, signed) = extend_kind(n).unwrap();
                let (a, _) = self.vec_arg(&args[0])?;
                let mut v = a[0].clone();
                let mut bits = from;
                let op = if signed { SimdOp::SWidenLow } else { SimdOp::UWidenLow };
                if rty.size_of(self.ptr_size()) == 32 {
                    // 256-bit result: the low and high halves of one more widening.
                    for _ in 0..steps - 1 {
                        v = self.sv(op.clone(), vec![v], v128(int(bits, signed)), v128(int(bits * 2, signed)));
                        bits *= 2;
                    }
                    let hop = if signed { SimdOp::SWidenHigh } else { SimdOp::UWidenHigh };
                    let lo = self.sv(op, vec![v.clone()], v128(int(bits, signed)), v128(int(bits * 2, signed)));
                    let hi = self.sv(hop, vec![v], v128(int(bits, signed)), v128(int(bits * 2, signed)));
                    vec![lo, hi]
                } else {
                    for _ in 0..steps {
                        v = self.sv(op.clone(), vec![v], v128(int(bits, signed)), v128(int(bits * 2, signed)));
                        bits *= 2;
                    }
                    vec![v]
                }
            }
            // Minimum u16 lane in lane 0, its (lowest) index in lane 1.
            "phminposuw128" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let u16t = int(16, false);
                let i32t = int(32, false);
                let best = self.sv(SimdOp::Extract(0), vec![a[0].clone()], v128(u16t.clone()), u16t.clone());
                let mut best = self.coerce(best.clone(), &i32t).unwrap_or(best);
                let mut idx: Val = Constant::int(0);
                for k in 1..8u8 {
                    let e = self.sv(SimdOp::Extract(k), vec![a[0].clone()], v128(u16t.clone()), u16t.clone());
                    let e = self.coerce(e, &i32t)?;
                    let lt = self.alloc_val();
                    self.push_instr(Instr::Cmp { dest: lt, op: CmpOp::IULt, lhs: e.clone(), rhs: best.clone(), ty: i32t.clone() });
                    let nb = self.alloc_val();
                    self.push_instr(Instr::Select { dest: nb, cond: Val::Local(lt), on_true: e, on_false: best, ty: i32t.clone() });
                    let ni = self.alloc_val();
                    self.push_instr(Instr::Select { dest: ni, cond: Val::Local(lt), on_true: Constant::int(k as i64), on_false: idx, ty: i32t.clone() });
                    best = Val::Local(nb);
                    idx = Val::Local(ni);
                }
                let z = self.sv_zero();
                let t = v128(u16t);
                let r = self.sv(SimdOp::Insert(0), vec![z, best], t.clone(), t.clone());
                vec![self.sv(SimdOp::Insert(1), vec![r, idx], t.clone(), t)]
            }
            // ptestz: (a & b) == 0; ptestc: (!a & b) == 0; ptestnzc: neither.
            "ptestz128" | "ptestc128" | "ptestnzc128" | "ptestz256" | "ptestc256" | "ptestnzc256"
            | "vtestzps" | "vtestcps" | "vtestnzcps" | "vtestzpd" | "vtestcpd" | "vtestnzcpd"
            | "vtestzps256" | "vtestcps256" | "vtestnzcps256" | "vtestzpd256" | "vtestcpd256" | "vtestnzcpd256" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                // vtest looks only at the lanes' sign bits.
                let sign = if n.starts_with("vtest") {
                    let lb = if n.contains("pd") { 8 } else { 4 };
                    let bits = if lb == 8 { 0x8000_0000_0000_0000u64 } else { 0x8000_0000_8000_0000 };
                    Some(self.sv_const(std::array::from_fn(|i| (bits >> (8 * (i % 8))) as u8)))
                } else { None };
                let q = v128(int(64, false));
                let zero_of = |me: &mut Self, parts: Vec<Val>| -> Val {
                    let mut acc: Option<Val> = None;
                    for p in parts {
                        let p = match &sign { Some(m) => me.sv(SimdOp::And, vec![p, m.clone()], q.clone(), q.clone()), None => p };
                        acc = Some(match acc { None => p, Some(x) => me.sv(SimdOp::Or, vec![x, p], q.clone(), q.clone()) });
                    }
                    let v = acc.unwrap();
                    let lo = me.sv(SimdOp::Extract(0), vec![v.clone()], q.clone(), int(64, false));
                    let hi = me.sv(SimdOp::Extract(1), vec![v], q.clone(), int(64, false));
                    let o = me.alloc_val();
                    me.push_instr(Instr::BinOp { dest: o, op: BinOp::Or, lhs: lo, rhs: hi, ty: int(64, false) });
                    let c = me.alloc_val();
                    me.push_instr(Instr::Cmp { dest: c, op: CmpOp::IEq, lhs: Val::Local(o), rhs: Constant::int(0), ty: int(64, false) });
                    Val::Local(c)
                };
                let and = self.per_part2(SimdOp::And, &a, &b, &int(64, false));
                let andn = self.per_part2(SimdOp::AndNot, &b, &a, &int(64, false));
                let r = if n.contains("nzc") {
                    let z = zero_of(self, and);
                    let c = zero_of(self, andn);
                    let either = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: either, op: BinOp::Or, lhs: z, rhs: c, ty: Type::Bool });
                    let r = self.alloc_val();
                    self.push_instr(Instr::UnaryOp { dest: r, op: UnOp::BoolNot, val: Val::Local(either), ty: Type::Bool });
                    Val::Local(r)
                } else if n.contains("testz") {
                    zero_of(self, and)
                } else {
                    zero_of(self, andn)
                };
                return Ok(Some(self.coerce(r, &Type::i32())?));
            }
            // imm[1:0]: nearest, floor, ceil, truncate; imm[2] selects the
            // current mode instead (round to nearest).
            "roundps" | "roundpd" | "roundps256" | "roundpd256" | "roundss" | "roundsd" => {
                let scalar = n.ends_with("ss") || n.ends_with("sd");
                want(if scalar { 3 } else { 2 })?;
                let l = if n.contains("pd") || n.ends_with("sd") { Type::Float64 } else { Type::Float32 };
                let (a, _) = self.vec_arg(&args[0])?;
                let (src, ii) = if scalar { (self.vec_arg(&args[1])?.0, 2) } else { (a.clone(), 1) };
                let imm = self.imm(&args[ii], name)?;
                let op = if imm & 4 != 0 { SimdOp::FNearest } else {
                    match imm & 3 { 0 => SimdOp::FNearest, 1 => SimdOp::FFloor, 2 => SimdOp::FCeil, _ => SimdOp::FTrunc }
                };
                let r = self.per_part1(op, &src, &l);
                if scalar { vec![self.merge_low(a[0].clone(), r[0].clone(), &l)] } else { r }
            }
            // Compare with a predicate immediate.
            "cmpps" | "cmppd" | "cmpss" | "cmpsd" | "cmpps256" | "cmppd256" => {
                want(3)?;
                let l = lane_of(&n[3..5]);
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let imm = self.imm(&args[2], name)?;
                let t = v128(l.clone());
                let r: Vec<Val> = match imm_cmp(imm) {
                    ImmCmp::Cmp(k) => a.iter().zip(&b).map(|(x, y)| self.sv(SimdOp::FCmp(k), vec![x.clone(), y.clone()], t.clone(), t.clone())).collect(),
                    ImmCmp::False => a.iter().map(|_| self.sv_zero()).collect(),
                    ImmCmp::True => a.iter().map(|_| self.sv_const([0xff; 16])).collect(),
                };
                if n.starts_with("cmps") { vec![self.merge_low(a[0].clone(), r[0].clone(), &l)] } else { r }
            }
            // MMX conversions: two 32-bit integer lanes in a 64-bit vector.
            "cvtps2pi" | "cvttps2pi" | "cvtpd2pi" | "cvttpd2pi" => {
                want(1)?;
                let f = if n.contains("pd") { v128(Type::Float64) } else { v128(Type::Float32) };
                let (a, _) = self.vec_arg(&args[0])?;
                let x = if n.starts_with("cvtt") { a[0].clone() } else { self.sv(SimdOp::FNearest, vec![a[0].clone()], f.clone(), f.clone()) };
                vec![self.sv(SimdOp::FPToSI, vec![x], f, v128(lane("d")))]
            }
            "cvtpi2ps" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let c = self.sv(SimdOp::SIToFP, vec![b[0].clone()], v128(lane("d")), v128(Type::Float32));
                let mut m: [u8; 16] = std::array::from_fn(|i| i as u8);
                for i in 0..8 { m[i] = 16 + i as u8; }
                vec![self.shuffle(a[0].clone(), c, m)]
            }
            "cvtpi2pd" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (i, f) = (v128(lane("d")), v128(Type::Float64));
                let mut r = self.sv_zero();
                for k in 0..2u8 {
                    let e = self.sv(SimdOp::Extract(k), vec![a[0].clone()], i.clone(), int(32, true));
                    let c = self.alloc_val();
                    self.push_instr(Instr::Cast { dest: c, op: CastOp::SIToFP, val: e, to_ty: Type::Float64 });
                    r = self.sv(SimdOp::Insert(k), vec![r, Val::Local(c)], f.clone(), f.clone());
                }
                vec![r]
            }
            // MMX vectors from their lanes, lowest first.
            "vec_init_v2si" | "vec_init_v4hi" | "vec_init_v8qi" => {
                let l = match n { "vec_init_v2si" => lane("d"), "vec_init_v4hi" => lane("w"), _ => lane("b") };
                want(8 / l.size_of(8) as usize)?;
                let t = v128(l.clone());
                let mut r = self.sv_zero();
                for (k, e) in args.iter().enumerate() {
                    let v = self.scalar_arg(e, &l)?;
                    r = self.sv(SimdOp::Insert(k as u8), vec![r, v], t.clone(), t.clone());
                }
                vec![r]
            }
            // MMX state is never in the x87 registers here.
            "emms" | "femms" => {
                want(0)?;
                return Ok(Some(Constant::zero()));
            }
            // ~a & b
            "andnps" | "andnpd" | "pandn" | "pandn128" | "andnps256" | "andnpd256" | "andnotsi256" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                self.per_part2(SimdOp::AndNot, &b, &a, &lane("q"))
            }
            "sqrtps" | "sqrtpd" | "sqrtps256" | "sqrtpd256" | "sqrtps_nr" | "sqrtps_nr256" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                self.per_part1(SimdOp::FSqrt, &a, &lane(if n.contains("pd") { "pd" } else { "ps" }))
            }
            "sqrtss" | "sqrtsd" => {
                want(1)?;
                let l = lane(&n[4..]);
                let (a, _) = self.vec_arg(&args[0])?;
                let r = self.per_part1(SimdOp::FSqrt, &a, &l);
                vec![self.merge_low(a[0].clone(), r[0].clone(), &l)]
            }
            // The reciprocal estimates, computed exactly (well within the 1.5·2⁻¹²
            // relative error the instructions promise).
            "rcpps" | "rsqrtps" | "rcpps256" | "rsqrtps256" | "rcpss" | "rsqrtss" => {
                want(1)?;
                let l = Type::Float32;
                let t = v128(l.clone());
                let (a, _) = self.vec_arg(&args[0])?;
                let bits = 1.0f32.to_bits();
                let one = self.sv_const(std::array::from_fn(|i| (bits >> (8 * (i % 4))) as u8));
                let r: Vec<Val> = a.iter().map(|x| {
                    let d = if n.starts_with("rsqrt") { self.sv(SimdOp::FSqrt, vec![x.clone()], t.clone(), t.clone()) } else { x.clone() };
                    self.sv(SimdOp::FDiv, vec![one.clone(), d], t.clone(), t.clone())
                }).collect();
                if n.ends_with("ss") { vec![self.merge_low(a[0].clone(), r[0].clone(), &l)] } else { r }
            }
            "movmskps" | "movmskpd" | "pmovmskb" | "pmovmskb128" | "movmskps256" | "movmskpd256" | "pmovmskb256" => {
                want(1)?;
                let l = if n.contains("ps") { lane("ud") } else if n.contains("pd") { lane("uq") } else { lane("ub") };
                let (a, width) = self.vec_arg(&args[0])?;
                let t = v128(l.clone());
                let per = 16 / l.size_of(8) as i64;
                let mut acc: Option<Val> = None;
                for (k, p) in a.iter().enumerate() {
                    let m = self.sv(SimdOp::MoveMask, vec![p.clone()], t.clone(), int(32, true));
                    acc = Some(match acc {
                        None => m,
                        Some(prev) => {
                            let sh = self.alloc_val();
                            self.push_instr(Instr::BinOp { dest: sh, op: BinOp::Shl, lhs: m, rhs: Constant::int(per * k as i64), ty: int(32, true) });
                            let o = self.alloc_val();
                            self.push_instr(Instr::BinOp { dest: o, op: BinOp::Or, lhs: prev, rhs: Val::Local(sh), ty: int(32, true) });
                            Val::Local(o)
                        }
                    });
                }
                let mut v = acc.unwrap();
                if width == 8 {
                    // An MMX vector's high (zero) bytes contribute nothing.
                    let d = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: d, op: BinOp::And, lhs: v, rhs: Constant::int(0xff), ty: int(32, true) });
                    v = Val::Local(d);
                }
                return Ok(Some(v));
            }
            // Pack with saturation: a's lanes then b's, narrowed.
            "packsswb" | "packsswb128" | "packssdw" | "packssdw128" | "packuswb" | "packuswb128"
            | "packusdw128" | "packsswb256" | "packssdw256" | "packuswb256" | "packusdw256" => {
                want(2)?;
                let (b0, w) = split_width(n);
                let from = if b0.ends_with("wb") { lane("w") } else { lane("d") };
                let op = if b0.starts_with("packus") { SimdOp::UNarrow } else { SimdOp::SNarrow };
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let t = v128(from.clone());
                if w == 8 {
                    // MMX: the two 64-bit operands as one 128-bit vector, narrowed.
                    let ab = self.shuffle(a[0].clone(), b[0].clone(), std::array::from_fn(|i| if i < 8 { i as u8 } else { 8 + i as u8 }));
                    let z = self.sv_zero();
                    vec![self.sv(op, vec![ab, z], t.clone(), t)]
                } else {
                    a.iter().zip(&b).map(|(x, y)| self.sv(op.clone(), vec![x.clone(), y.clone()], t.clone(), t.clone())).collect()
                }
            }
            "pmaddwd" | "pmaddwd128" | "pmaddwd256" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let (w16, w32) = (v128(lane("w")), v128(lane("d")));
                a.iter().zip(&b).map(|(x, y)| {
                    let xl = self.sv(SimdOp::SWidenLow, vec![x.clone()], w16.clone(), w32.clone());
                    let yl = self.sv(SimdOp::SWidenLow, vec![y.clone()], w16.clone(), w32.clone());
                    let xh = self.sv(SimdOp::SWidenHigh, vec![x.clone()], w16.clone(), w32.clone());
                    let yh = self.sv(SimdOp::SWidenHigh, vec![y.clone()], w16.clone(), w32.clone());
                    let lo = self.sv(SimdOp::Mul, vec![xl, yl], w32.clone(), w32.clone());
                    let hi = self.sv(SimdOp::Mul, vec![xh, yh], w32.clone(), w32.clone());
                    self.sv(SimdOp::AddPairwise, vec![lo, hi], w32.clone(), w32.clone())
                }).collect()
            }
            // u32 lanes 0 and 2 (of each 64-bit lane) multiplied to u64.
            "pmuludq" | "pmuludq128" | "pmuludq256" | "pmuldq128" | "pmuldq256" => {
                want(2)?;
                let signed = n.starts_with("pmuldq");
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let q = v128(lane("q"));
                let low32 = |me: &mut Self, v: Val| {
                    if signed {
                        let s = me.sv(SimdOp::Shl, vec![v, Constant::int(32)], q.clone(), q.clone());
                        me.sv(SimdOp::AShr, vec![s, Constant::int(32)], q.clone(), q.clone())
                    } else {
                        let m = me.sv_const(std::array::from_fn(|i| if i % 8 < 4 { 0xff } else { 0 }));
                        me.sv(SimdOp::And, vec![v, m], q.clone(), q.clone())
                    }
                };
                a.iter().zip(&b).map(|(x, y)| {
                    let x = low32(self, x.clone());
                    let y = low32(self, y.clone());
                    self.sv(SimdOp::Mul, vec![x, y], q.clone(), q.clone())
                }).collect()
            }
            // Sum of absolute byte differences per 8 bytes, in each 64-bit lane.
            "psadbw" | "psadbw128" | "psadbw256" => {
                want(2)?;
                let (a, w) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let (u8t, u16t) = (v128(lane("ub")), v128(lane("uw")));
                a.iter().zip(&b).map(|(x, y)| {
                    let p = self.sv(SimdOp::USubSat, vec![x.clone(), y.clone()], u8t.clone(), u8t.clone());
                    let q = self.sv(SimdOp::USubSat, vec![y.clone(), x.clone()], u8t.clone(), u8t.clone());
                    let d = self.sv(SimdOp::Or, vec![p, q], u8t.clone(), u8t.clone());
                    let lo = self.sv(SimdOp::UWidenLow, vec![d.clone()], u8t.clone(), u16t.clone());
                    let hi = self.sv(SimdOp::UWidenHigh, vec![d], u8t.clone(), u16t.clone());
                    let s = self.sv(SimdOp::AddPairwise, vec![lo, hi], u16t.clone(), u16t.clone());
                    let s = self.sv(SimdOp::AddPairwise, vec![s.clone(), s], u16t.clone(), u16t.clone());
                    let s = self.sv(SimdOp::AddPairwise, vec![s.clone(), s], u16t.clone(), u16t.clone());
                    // Sums of bytes 0..8 and 8..16 are 16-bit lanes 0 and 1.
                    let z = self.sv_zero();
                    let mut m = [16u8; 16];
                    m[0] = 0; m[1] = 1;
                    if w != 8 { m[8] = 2; m[9] = 3; }
                    self.shuffle(s, z, m)
                }).collect()
            }
            // Shifts by an immediate-or-int count, and by a vector's low 64 bits.
            _ if shift_kind(base).is_some() => {
                let (op, l, by_vec) = shift_kind(base).unwrap();
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let count = if by_vec { self.shift_count_vec(&args[1])? } else { self.scalar_arg(&args[1], &int(32, true))? };
                self.shift_by(op, &a, &l, count)
            }
            // Whole-register byte shifts; GCC passes the count in bits.
            "pslldqi128" | "psrldqi128" | "pslldqi256" | "psrldqi256" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let bits = self.imm(&args[1], name)?;
                let by = bits / 8;
                if by > 15 { a.iter().map(|_| self.sv_zero()).collect() } else { self.byte_shift(&a, by, n.starts_with("psll")) }
            }
            "punpcklbw" | "punpcklbw128" | "punpcklwd" | "punpcklwd128" | "punpckldq" | "punpckldq128" | "punpcklqdq128"
            | "punpckhbw" | "punpckhbw128" | "punpckhwd" | "punpckhwd128" | "punpckhdq" | "punpckhdq128" | "punpckhqdq128"
            | "punpcklbw256" | "punpcklwd256" | "punpckldq256" | "punpcklqdq256"
            | "punpckhbw256" | "punpckhwd256" | "punpckhdq256" | "punpckhqdq256"
            | "unpcklps" | "unpckhps" | "unpcklpd" | "unpckhpd" | "unpcklps256" | "unpckhps256" | "unpcklpd256" | "unpckhpd256" => {
                want(2)?;
                let (b0, _) = split_width(n);
                let high = b0.contains("unpckh");
                let lb = if b0.ends_with("qdq") || b0.ends_with("pd") { 8 } else if b0.ends_with("dq") || b0.ends_with("ps") { 4 }
                         else if b0.ends_with("wd") { 2 } else { 1 };
                let (a, w) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                self.unpack(&a, &b, lb, high, w)
            }
            // [b2, b3, a2, a3] / [a0, a1, b0, b1] / [b0, a1, a2, a3] / [b0, a1]
            "movhlps" | "movlhps" | "movss" | "movsd" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let mut m = [0u8; 16];
                let pick: [usize; 4] = match n { "movhlps" => [6, 7, 2, 3], "movlhps" => [0, 1, 4, 5], "movss" => [4, 1, 2, 3], _ => [4, 5, 2, 3] };
                for (d, s) in pick.iter().enumerate() { put_lane(&mut m, d, *s, 4); }
                vec![self.shuffle(a[0].clone(), b[0].clone(), m)]
            }
            "shufps" | "shufps256" | "shufpd" | "shufpd256" => {
                want(3)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let imm = self.imm(&args[2], name)? as usize;
                let pd = n.starts_with("shufpd");
                a.iter().zip(&b).enumerate().map(|(k, (x, y))| {
                    let mut m = [0u8; 16];
                    if pd {
                        let sel = imm >> (2 * k);
                        put_lane(&mut m, 0, sel & 1, 8);
                        put_lane(&mut m, 1, 2 + ((sel >> 1) & 1), 8);
                    } else {
                        put_lane(&mut m, 0, imm & 3, 4);
                        put_lane(&mut m, 1, (imm >> 2) & 3, 4);
                        put_lane(&mut m, 2, 4 + ((imm >> 4) & 3), 4);
                        put_lane(&mut m, 3, 4 + ((imm >> 6) & 3), 4);
                    }
                    self.shuffle(x.clone(), y.clone(), m)
                }).collect()
            }
            "pshufd" | "pshufd256" | "pshuflw" | "pshuflw256" | "pshufhw" | "pshufhw256" | "pshufw" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let imm = self.imm(&args[1], name)? as usize;
                let mut m: [u8; 16] = std::array::from_fn(|i| i as u8);
                match split_width(n).0 {
                    "pshufd" => for d in 0..4 { put_lane(&mut m, d, (imm >> (2 * d)) & 3, 4) },
                    "pshuflw" | "pshufw" => for d in 0..4 { put_lane(&mut m, d, (imm >> (2 * d)) & 3, 2) },
                    _ => for d in 0..4 { put_lane(&mut m, 4 + d, 4 + ((imm >> (2 * d)) & 3), 2) },
                }
                a.iter().map(|x| self.shuffle(x.clone(), x.clone(), m)).collect()
            }
            "vec_ext_v4si" | "vec_ext_v8hi" | "vec_ext_v4hi" | "vec_ext_v2di" | "vec_ext_v16qi" | "vec_ext_v4sf" | "vec_ext_v2df" | "vec_ext_v2si" => {
                want(2)?;
                let l = ext_lane(n);
                let (a, _) = self.vec_arg(&args[0])?;
                let lanes = 16 / l.size_of(8);
                let i = self.imm(&args[1], name)? as u64 % lanes;
                return Ok(Some(self.sv(SimdOp::Extract(i as u8), vec![a[0].clone()], v128(l.clone()), l)));
            }
            "vec_set_v8hi" | "vec_set_v4hi" | "vec_set_v4si" | "vec_set_v2di" | "vec_set_v16qi" => {
                want(3)?;
                let l = ext_lane(n);
                let (a, _) = self.vec_arg(&args[0])?;
                let v = self.scalar_arg(&args[1], &l)?;
                let lanes = 16 / l.size_of(8);
                let i = self.imm(&args[2], name)? as u64 % lanes;
                vec![self.sv(SimdOp::Insert(i as u8), vec![a[0].clone(), v], v128(l.clone()), v128(l))]
            }
            // Conversions.
            "cvtdq2ps" | "cvtdq2ps256" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (i, f) = (v128(lane("d")), v128(Type::Float32));
                a.iter().map(|x| self.sv(SimdOp::SIToFP, vec![x.clone()], i.clone(), f.clone())).collect()
            }
            "cvttps2dq" | "cvtps2dq" | "cvttps2dq256" | "cvtps2dq256" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (i, f) = (v128(lane("d")), v128(Type::Float32));
                a.iter().map(|x| {
                    let x = if n.starts_with("cvtt") { x.clone() } else { self.sv(SimdOp::FNearest, vec![x.clone()], f.clone(), f.clone()) };
                    self.sv(SimdOp::FPToSI, vec![x], f.clone(), i.clone())
                }).collect()
            }
            "cvttpd2dq" | "cvtpd2dq" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (i, f) = (v128(lane("d")), v128(Type::Float64));
                let x = if n.starts_with("cvtt") { a[0].clone() } else { self.sv(SimdOp::FNearest, vec![a[0].clone()], f.clone(), f.clone()) };
                vec![self.sv(SimdOp::FPToSI, vec![x], f, i)]
            }
            "cvtps2pd" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                vec![self.sv(SimdOp::FPromoteLow, vec![a[0].clone()], v128(Type::Float32), v128(Type::Float64))]
            }
            "cvtpd2ps" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                vec![self.sv(SimdOp::FDemote, vec![a[0].clone()], v128(Type::Float64), v128(Type::Float32))]
            }
            "cvtdq2pd" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let (i, f) = (v128(lane("d")), v128(Type::Float64));
                let mut r = self.sv_zero();
                for k in 0..2u8 {
                    let e = self.sv(SimdOp::Extract(k), vec![a[0].clone()], i.clone(), int(32, true));
                    let c = self.alloc_val();
                    self.push_instr(Instr::Cast { dest: c, op: CastOp::SIToFP, val: e, to_ty: Type::Float64 });
                    r = self.sv(SimdOp::Insert(k), vec![r, Val::Local(c)], f.clone(), f.clone());
                }
                vec![r]
            }
            // Scalar conversions of lane 0.
            "cvtss2si" | "cvtss2si64" | "cvttss2si" | "cvttss2si64" | "cvtsd2si" | "cvtsd2si64" | "cvttsd2si" | "cvttsd2si64" => {
                want(1)?;
                let f = if n.contains("ss") { v128(Type::Float32) } else { v128(Type::Float64) };
                let it = if n.ends_with("64") { v128(lane("q")) } else { v128(lane("d")) };
                let (a, _) = self.vec_arg(&args[0])?;
                let x = if n.starts_with("cvtt") { a[0].clone() } else { self.sv(SimdOp::FNearest, vec![a[0].clone()], f.clone(), f.clone()) };
                let r = self.sv(SimdOp::FPToSI, vec![x], f, it.clone());
                let st = if n.ends_with("64") { int(64, true) } else { int(32, true) };
                return Ok(Some(self.sv(SimdOp::Extract(0), vec![r], it, st)));
            }
            "cvtsi2ss" | "cvtsi642ss" | "cvtsi2sd" | "cvtsi642sd" => {
                want(2)?;
                let (ft, it) = if n.ends_with("ss") { (Type::Float32, int(32, true)) } else { (Type::Float64, int(64, true)) };
                let st = if n.contains("64") { int(64, true) } else { int(32, true) };
                let _ = it;
                let (a, _) = self.vec_arg(&args[0])?;
                let v = self.scalar_arg(&args[1], &st)?;
                let c = self.alloc_val();
                self.push_instr(Instr::Cast { dest: c, op: CastOp::SIToFP, val: v, to_ty: ft.clone() });
                vec![self.sv(SimdOp::Insert(0), vec![a[0].clone(), Val::Local(c)], v128(ft.clone()), v128(ft))]
            }
            "cvtsd2ss" | "cvtss2sd" => {
                want(2)?;
                let (from, to, op) = if n == "cvtsd2ss" { (Type::Float64, Type::Float32, CastOp::FPTrunc) } else { (Type::Float32, Type::Float64, CastOp::FPExt) };
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let e = self.sv(SimdOp::Extract(0), vec![b[0].clone()], v128(from.clone()), from);
                let c = self.alloc_val();
                self.push_instr(Instr::Cast { dest: c, op, val: e, to_ty: to.clone() });
                vec![self.sv(SimdOp::Insert(0), vec![a[0].clone(), Val::Local(c)], v128(to.clone()), v128(to))]
            }
            // Ordered / unordered scalar compares of lane 0, as 0 or 1.
            _ if comi(n).is_some() => {
                want(2)?;
                let (k, l) = comi(n).unwrap();
                let (a, _) = self.vec_arg(&args[0])?;
                let (b, _) = self.vec_arg(&args[1])?;
                let t = v128(l);
                let m = self.sv(SimdOp::FCmp(k), vec![a[0].clone(), b[0].clone()], t.clone(), t.clone());
                let e = self.sv(SimdOp::Extract(0), vec![m], v128(int(32, true)), int(32, true));
                let r = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: r, op: BinOp::And, lhs: e, rhs: Constant::int(1), ty: int(32, true) });
                return Ok(Some(Val::Local(r)));
            }
            // Low 64 bits kept, high zeroed.
            "movq128" => {
                want(1)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let z = self.sv_zero();
                vec![self.shuffle(a[0].clone(), z, std::array::from_fn(|i| if i < 8 { i as u8 } else { 16 }))]
            }
            // Half-register loads and stores through a 64-bit pointer.
            "loadhps" | "loadlps" | "loadhpd" | "loadlpd" => {
                want(2)?;
                let (a, _) = self.vec_arg(&args[0])?;
                let p = self.lower_expr(&args[1])?;
                let d = self.alloc_val();
                self.push_instr(Instr::Load { dest: d, ptr: p, ty: int(64, true) });
                let q = v128(lane("q"));
                let at = if n.starts_with("loadh") { 1 } else { 0 };
                vec![self.sv(SimdOp::Insert(at), vec![a[0].clone(), Val::Local(d)], q.clone(), q)]
            }
            "storehps" | "storelps" => {
                want(2)?;
                let p = self.lower_expr(&args[0])?;
                let (a, _) = self.vec_arg(&args[1])?;
                let i = if n == "storehps" { 1 } else { 0 };
                let e = self.sv(SimdOp::Extract(i), vec![a[0].clone()], v128(lane("q")), int(64, true));
                self.push_instr(Instr::Store { val: e, ptr: p });
                return Ok(Some(Constant::zero()));
            }
            // Non-temporal stores: ordinary stores.
            "movntps" | "movntpd" | "movntdq" | "movntps256" | "movntpd256" | "movntdq256" => {
                want(2)?;
                let p = self.lower_expr(&args[0])?;
                let (a, w) = self.vec_arg(&args[1])?;
                self.store_parts(p, &a, w);
                return Ok(Some(Constant::zero()));
            }
            "movnti" | "movnti64" | "movntq" => {
                want(2)?;
                let p = self.lower_expr(&args[0])?;
                let t = if n == "movnti" { int(32, true) } else { int(64, true) };
                let v = self.scalar_arg(&args[1], &t)?;
                self.push_instr(Instr::Store { val: v, ptr: p });
                return Ok(Some(Constant::zero()));
            }
            // Ordering: a full fence covers the load/store-only ones.
            "mfence" | "lfence" | "sfence" => {
                want(0)?;
                self.push_instr(Instr::Fence);
                return Ok(Some(Constant::zero()));
            }
            // Hints with no effect on the program's result.
            "pause" | "clflush" | "prefetch" => {
                for a in args { self.lower_expr(a)?; }
                return Ok(Some(Constant::zero()));
            }
            _ => return Ok(None),
        };
        Ok(Some(self.vec_result(&parts, rty)))
    }

    /// The type of `__builtin_ia32_<n>(args)`, when lowered by [`lower_ia32`].
    pub(crate) fn ia32_result_type(&self, name: &str, args: &[Expr]) -> Option<Type> {
        let n = name.strip_prefix("__builtin_ia32_")?;
        let arg = |i: usize| args.get(i).and_then(|a| self.infer_expr_type(a).ok());
        let (base, w) = split_width(n);
        // The width of the first (vector) operand; the name's suffix when it
        // is not one (SSE2's `cvtdq2ps` has none, yet is 128-bit).
        let w = match arg(0) { Some(t @ Type::Array { .. }) => t.size_of(8), _ => w };
        let wide = |e: Type| { let lanes = w / e.size_of(8); vec(e, lanes.max(1)) };
        if lanewise2(base).is_some() || scalar2(n).is_some() { return arg(0); }
        if let Some(rest) = n.strip_prefix("cmp") {
            let (p, k) = rest.split_at(rest.len().saturating_sub(2));
            if cmp_pred(p).is_some() && matches!(k, "ps" | "pd" | "ss" | "sd") { return arg(0); }
        }
        if shift_kind(base).is_some() { return arg(0); }
        if comi(n).is_some() { return Some(Type::i32()); }
        Some(match n {
            "cmpps" | "cmppd" | "cmpss" | "cmpsd" | "cmpps256" | "cmppd256" | "cvtpi2ps" => arg(0)?,
            _ if (n.starts_with("pcmpestr") || n.starts_with("pcmpistr")) && n.ends_with("128") => {
                if &n[8..n.len() - 3] == "m" { v128(int(8, true)) } else { Type::i32() }
            }
            "crc32qi" | "crc32hi" | "crc32si" => Type::u32(),
            "crc32di" => Type::u64(),
            "addsubps" | "addsubpd" | "addsubps256" | "addsubpd256"
            | "haddps" | "haddpd" | "hsubps" | "hsubpd" | "haddps256" | "haddpd256" | "hsubps256" | "hsubpd256"
            | "phaddw" | "phaddw128" | "phaddd" | "phaddd128" | "phaddsw" | "phaddsw128"
            | "phsubw" | "phsubw128" | "phsubd" | "phsubd128" | "phsubsw" | "phsubsw128"
            | "phaddw256" | "phaddd256" | "phaddsw256" | "phsubw256" | "phsubd256" | "phsubsw256"
            | "movshdup" | "movsldup" | "movshdup256" | "movsldup256"
            | "blendps" | "blendpd" | "pblendw128" | "blendps256" | "blendpd256" | "pblendw256" | "pblendd128" | "pblendd256"
            | "blendvps" | "blendvpd" | "pblendvb128" | "blendvps256" | "blendvpd256" | "pblendvb256"
            | "dpps" | "dppd" | "dpps256" | "insertps128"
            | "pabsb" | "pabsb128" | "pabsw" | "pabsw128" | "pabsd" | "pabsd128" | "pabsb256" | "pabsw256" | "pabsd256"
            | "palignr" | "palignr128" | "palignr256" | "pshufb" | "pshufb128" | "pshufb256"
            | "psignb" | "psignb128" | "psignw" | "psignw128" | "psignd" | "psignd128" | "psignb256" | "psignw256" | "psignd256"
            | "phminposuw128" | "roundps" | "roundpd" | "roundps256" | "roundpd256" | "roundss" | "roundsd" => arg(0)?,
            "mpsadbw128" | "mpsadbw256" | "pmaddubsw" | "pmaddubsw128" | "pmaddubsw256" => wide(int(16, true)),
            "lddqu" | "movntdqa" => v128(int(8, true)),
            "lddqu256" | "movntdqa256" => vec(int(8, true), 32),
            "ptestz128" | "ptestc128" | "ptestnzc128" | "ptestz256" | "ptestc256" | "ptestnzc256"
            | "vtestzps" | "vtestcps" | "vtestnzcps" | "vtestzpd" | "vtestcpd" | "vtestnzcpd"
            | "vtestzps256" | "vtestcps256" | "vtestnzcps256" | "vtestzpd256" | "vtestcpd256" | "vtestnzcpd256" => Type::i32(),
            _ if extend_kind(n).is_some() => {
                let (from, steps, signed) = extend_kind(n).unwrap();
                let to = from << steps;
                let w = if n.ends_with("256") { 32 } else { 16 };
                vec(int(to, signed), w / (to as u64 / 8))
            }
            "cvtps2pi" | "cvttps2pi" | "cvtpd2pi" | "cvttpd2pi" => vec(int(32, true), 2),
            "cvtpi2pd" => v128(Type::Float64),
            "vec_init_v2si" => vec(int(32, true), 2),
            "vec_init_v4hi" => vec(int(16, true), 4),
            "vec_init_v8qi" => vec(int(8, true), 8),
            "emms" | "femms" => Type::Void,
            "andnps" | "andnpd" | "pandn" | "pandn128" | "andnps256" | "andnpd256" | "andnotsi256"
            | "sqrtps" | "sqrtpd" | "sqrtps256" | "sqrtpd256" | "sqrtps_nr" | "sqrtps_nr256" | "sqrtss" | "sqrtsd"
            | "rcpps" | "rsqrtps" | "rcpps256" | "rsqrtps256" | "rcpss" | "rsqrtss"
            | "pslldqi128" | "psrldqi128" | "pslldqi256" | "psrldqi256"
            | "movhlps" | "movlhps" | "movss" | "movsd" | "shufps" | "shufps256" | "shufpd" | "shufpd256"
            | "pshufd" | "pshufd256" | "pshuflw" | "pshuflw256" | "pshufhw" | "pshufhw256" | "pshufw"
            | "vec_set_v8hi" | "vec_set_v4hi" | "vec_set_v4si" | "vec_set_v2di" | "vec_set_v16qi"
            | "cvtsi2ss" | "cvtsi642ss" | "cvtsi2sd" | "cvtsi642sd" | "cvtsd2ss" | "cvtss2sd"
            | "movq128" | "loadhps" | "loadlps" | "loadhpd" | "loadlpd" => arg(0)?,
            _ if n.starts_with("punpck") || n.starts_with("unpck") => arg(0)?,
            "movmskps" | "movmskpd" | "pmovmskb" | "pmovmskb128" | "movmskps256" | "movmskpd256" | "pmovmskb256" => Type::i32(),
            "packsswb" | "packsswb128" | "packuswb" | "packuswb128" | "packsswb256" | "packuswb256" => wide(int(8, true)),
            "packssdw" | "packssdw128" | "packusdw128" | "packssdw256" | "packusdw256" => wide(int(16, true)),
            "pmaddwd" | "pmaddwd128" | "pmaddwd256" => wide(int(32, true)),
            "pmuludq" | "pmuludq128" | "pmuludq256" | "pmuldq128" | "pmuldq256" | "psadbw" | "psadbw128" | "psadbw256" => wide(int(64, true)),
            "vec_ext_v4si" | "vec_ext_v8hi" | "vec_ext_v4hi" | "vec_ext_v2di" | "vec_ext_v16qi" | "vec_ext_v4sf" | "vec_ext_v2df" | "vec_ext_v2si" => ext_lane(n),
            "cvtdq2ps" | "cvtdq2ps256" => wide(Type::Float32),
            "cvttps2dq" | "cvtps2dq" | "cvttps2dq256" | "cvtps2dq256" => wide(int(32, true)),
            "cvttpd2dq" | "cvtpd2dq" => v128(int(32, true)),
            "cvtps2pd" | "cvtdq2pd" => v128(Type::Float64),
            "cvtpd2ps" => v128(Type::Float32),
            "cvtss2si" | "cvttss2si" | "cvtsd2si" | "cvttsd2si" => Type::i32(),
            "cvtss2si64" | "cvttss2si64" | "cvtsd2si64" | "cvttsd2si64" => Type::i64(),
            "storehps" | "storelps" | "movntps" | "movntpd" | "movntdq" | "movntps256" | "movntpd256" | "movntdq256"
            | "movntq" | "movnti" | "movnti64" | "mfence" | "lfence" | "sfence" | "pause" | "clflush" | "prefetch" => Type::Void,
            _ => return None,
        })
    }
}

/// `psllw`… → (operation, lane, count-is-a-vector). `psllwi` takes an int,
/// `psllw` a vector whose low 64 bits are the count.
fn shift_kind(base: &str) -> Option<(SimdOp, Type, bool)> {
    let (op, rest) = if let Some(r) = base.strip_prefix("psll") { (SimdOp::Shl, r) }
        else if let Some(r) = base.strip_prefix("psrl") { (SimdOp::LShr, r) }
        else if let Some(r) = base.strip_prefix("psra") { (SimdOp::AShr, r) }
        else { return None };
    let (l, imm) = match rest {
        "w" => ("w", false), "d" => ("d", false), "q" => ("q", false),
        "wi" => ("w", true), "di" => ("d", true), "qi" => ("q", true),
        _ => return None,
    };
    if op == SimdOp::AShr && l == "q" { return None; }
    Some((op, lane_of(l), !imm))
}

/// `vec_ext_v4si` → the lane type.
fn ext_lane(n: &str) -> Type {
    match &n[n.len() - 4..] {
        "v4si" | "v2si" => int(32, true),
        "v8hi" | "v4hi" => int(16, true),
        "v2di" => int(64, true),
        "16qi" => int(8, true),
        "v4sf" => Type::Float32,
        _ => Type::Float64,
    }
}

/// `comieq`, `ucomisdlt`, … → (comparison, lane type). Equality is ordered
/// (0 for NaN) and inequality unordered (1 for NaN), as x86 defines them.
fn comi(n: &str) -> Option<(FCmp, Type)> {
    let r = n.strip_prefix("ucomi").or_else(|| n.strip_prefix("comi"))?;
    let (r, l) = match r.strip_prefix("sd") { Some(r) => (r, Type::Float64), None => (r, Type::Float32) };
    Some((match r {
        "eq" => FCmp::Eq, "lt" => FCmp::Lt, "le" => FCmp::Le, "gt" => FCmp::Gt, "ge" => FCmp::Ge,
        "neq" => FCmp::UNe,
        _ => return None,
    }, l))
}

/// `pmovsxbd128` → (source lane bits, widenings, signed): b→d is two steps.
fn extend_kind(n: &str) -> Option<(u32, u32, bool)> {
    let r = n.strip_prefix("pmovsx").map(|r| (r, true)).or_else(|| n.strip_prefix("pmovzx").map(|r| (r, false)))?;
    let (r, signed) = r;
    let r = r.strip_suffix("128").or_else(|| r.strip_suffix("256"))?;
    let bits = |c: char| match c { 'b' => Some(8), 'w' => Some(16), 'd' => Some(32), 'q' => Some(64), _ => None };
    let mut cs = r.chars();
    let (f, t) = (bits(cs.next()?)?, bits(cs.next()?)?);
    if cs.next().is_some() || t <= f { return None; }
    Some((f, (t / f).trailing_zeros(), signed))
}
