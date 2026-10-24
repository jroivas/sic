//! GCC/Clang builtins beyond the core set in `calls.rs`: hints, signaling NaNs,
//! bit reversal, the type-generic bit builtins (`__builtin_clzg`, C23's
//! `__builtin_stdc_*`), typed overflow checks, atomic NAND, the call-site
//! builtins (`__builtin_FILE`), `__builtin_classify_type`, CPU feature tests
//! and Clang's rotate/alignment builtins.

use crate::ast::{Expr, ExprKind};
use crate::{Result, CompileError};
use super::super::func::FuncCtx;
#[allow(unused_imports)]
use super::*;

/// Every builtin name lowered here (for `__has_builtin`).
pub(crate) fn extra_builtin_names() -> Vec<String> {
    let mut v: Vec<String> = [
        "__builtin_cpu_init", "__builtin_FILE", "__builtin_LINE", "__builtin_FUNCTION", "__builtin_COLUMN",
        "__builtin_assume", "__builtin_unpredictable", "__builtin_nans", "__builtin_nansf", "__builtin_nansl",
        "__builtin_issignaling", "__builtin_bswap128", "__builtin_isnanf", "__builtin_isnanl",
        "__builtin_isinff", "__builtin_isinfl", "__builtin_finite", "__builtin_finitef", "__builtin_finitel",
        "__builtin_classify_type", "__builtin_cpu_supports", "__builtin_cpu_is", "__builtin_popcountg",
        "__builtin_parityg", "__builtin_ffsg", "__builtin_clrsbg", "__builtin_clzg", "__builtin_ctzg",
        "__builtin_speculation_safe_value", "__builtin___clear_cache", "__builtin_powi", "__builtin_powif",
        "__builtin_powil", "__builtin_iseqsig", "__sync_swap", "__builtin_is_aligned", "__builtin_align_up",
        "__builtin_align_down", "__builtin_memcpy_inline", "__builtin_memset_inline",
        "__atomic_fetch_nand", "__atomic_nand_fetch", "__sync_fetch_and_nand", "__sync_nand_and_fetch",
        "__builtin_shufflevector", "__builtin_shuffle", "__builtin_convertvector",
    ].iter().map(|s| s.to_string()).collect();
    for s in ["s", "u"] { for o in ["add", "sub", "mul"] { for w in ["", "l", "ll"] {
        v.push(format!("__builtin_{}{}{}_overflow", s, o, w));
    } } }
    for n in STDC_BIT { v.push(format!("__builtin_stdc_{}", n)); }
    v.push("__builtin_stdc_rotate_left".into());
    v.push("__builtin_stdc_rotate_right".into());
    for w in ["8", "16", "32", "64"] {
        for p in ["__builtin_rotateleft", "__builtin_rotateright", "__builtin_bitreverse"] { v.push(format!("{}{}", p, w)); }
    }
    v
}

/// The `(min, max)` argument counts of the builtins lowered here.
pub(crate) fn extra_builtin_arity(name: &str) -> Option<(usize, usize)> {
    if typed_overflow(name).is_some() { return Some((3, 3)); }
    if let Some(rest) = name.strip_prefix("__builtin_stdc_") {
        return match rest {
            "rotate_left" | "rotate_right" => Some((2, 2)),
            _ if STDC_BIT.contains(&rest) => Some((1, 1)),
            _ => None,
        };
    }
    let rot = |p: &str| name.strip_prefix(p).map_or(false, |w| matches!(w, "8" | "16" | "32" | "64"));
    if rot("__builtin_rotateleft") || rot("__builtin_rotateright") { return Some((2, 2)); }
    if name.strip_prefix("__builtin_bitreverse").map_or(false, |w| matches!(w, "8" | "16" | "32" | "64")) {
        return Some((1, 1));
    }
    Some(match name {
        "__builtin_cpu_init" | "__builtin_FILE" | "__builtin_LINE" | "__builtin_FUNCTION"
        | "__builtin_COLUMN" => (0, 0),
        "__builtin_assume" | "__builtin_unpredictable" | "__builtin_nans" | "__builtin_nansf"
        | "__builtin_nansl" | "__builtin_issignaling" | "__builtin_bswap128"
        | "__builtin_isnanf" | "__builtin_isnanl" | "__builtin_isinff" | "__builtin_isinfl"
        | "__builtin_finite" | "__builtin_finitef" | "__builtin_finitel"
        | "__builtin_classify_type" | "__builtin_cpu_supports" | "__builtin_cpu_is"
        | "__builtin_popcountg" | "__builtin_parityg" | "__builtin_ffsg" | "__builtin_clrsbg" => (1, 1),
        "__builtin_clzg" | "__builtin_ctzg" | "__builtin_speculation_safe_value" => (1, 2),
        "__builtin___clear_cache" | "__builtin_powi" | "__builtin_powif" | "__builtin_powil"
        | "__builtin_iseqsig" | "__sync_swap" | "__builtin_is_aligned" | "__builtin_align_up"
        | "__builtin_align_down" => (2, 2),
        "__builtin_memcpy_inline" | "__builtin_memset_inline" => (3, 3),
        "__builtin_shufflevector" => (2, usize::MAX),
        "__builtin_shuffle" => (2, 3),
        "__builtin_convertvector" => (2, 2),
        "__atomic_fetch_nand" | "__atomic_nand_fetch" => (3, 3),
        "__sync_fetch_and_nand" | "__sync_nand_and_fetch" => (2, usize::MAX),
        _ => return None,
    })
}

/// The C23 `<stdbit.h>` builtins GCC provides, taking one unsigned operand.
const STDC_BIT: &[&str] = &[
    "bit_ceil", "bit_floor", "bit_width", "count_ones", "count_zeros", "first_leading_one",
    "first_leading_zero", "first_trailing_one", "first_trailing_zero", "has_single_bit",
    "leading_ones", "leading_zeros", "trailing_ones", "trailing_zeros",
];

/// `__builtin_{s,u}{add,sub,mul}{,l,ll}_overflow`: the operation and the type
/// its operands and result have.
fn typed_overflow(name: &str) -> Option<(BinOp, Type)> {
    let rest = name.strip_prefix("__builtin_")?.strip_suffix("_overflow")?;
    let (signed, rest) = match rest.as_bytes().first()? { b's' => (true, &rest[1..]), b'u' => (false, &rest[1..]), _ => return None };
    let (op, width) = if let Some(w) = rest.strip_prefix("add") { (BinOp::Add, w) }
        else if let Some(w) = rest.strip_prefix("sub") { (BinOp::Sub, w) }
        else if let Some(w) = rest.strip_prefix("mul") { (BinOp::Mul, w) }
        else { return None };
    let bits = match width { "" => 32, "l" | "ll" => 64, _ => return None };
    Some((op, Type::Int { bits, signed }))
}

/// The x86 CPU features `__builtin_cpu_supports` knows: the CPUID leaf, its
/// subleaf, the result register (0 = eax … 3 = edx) and bit, and the XCR0
/// state bits the OS must enable for it (AVX's YMM, AVX-512's ZMM state).
fn cpu_feature(name: &str) -> Option<(u32, u32, u32, u32, u32)> {
    const AVX: u32 = 0x6;
    const AVX512: u32 = 0xE6;
    Some(match name {
        "cmov" => (1, 0, 3, 15, 0), "mmx" => (1, 0, 3, 23, 0), "sse" => (1, 0, 3, 25, 0),
        "sse2" => (1, 0, 3, 26, 0), "sse3" => (1, 0, 2, 0, 0), "pclmul" => (1, 0, 2, 1, 0),
        "ssse3" => (1, 0, 2, 9, 0), "fma" => (1, 0, 2, 12, AVX), "cmpxchg16b" => (1, 0, 2, 13, 0),
        "sse4.1" => (1, 0, 2, 19, 0), "sse4.2" => (1, 0, 2, 20, 0), "movbe" => (1, 0, 2, 22, 0),
        "popcnt" => (1, 0, 2, 23, 0), "aes" => (1, 0, 2, 25, 0), "xsave" => (1, 0, 2, 26, 0),
        "osxsave" => (1, 0, 2, 27, 0), "avx" => (1, 0, 2, 28, AVX), "f16c" => (1, 0, 2, 29, AVX),
        "rdrnd" => (1, 0, 2, 30, 0),
        "bmi" => (7, 0, 1, 3, 0), "avx2" => (7, 0, 1, 5, AVX), "bmi2" => (7, 0, 1, 8, 0),
        "avx512f" => (7, 0, 1, 16, AVX512), "avx512dq" => (7, 0, 1, 17, AVX512),
        "rdseed" => (7, 0, 1, 18, 0), "adx" => (7, 0, 1, 19, 0),
        "avx512ifma" => (7, 0, 1, 21, AVX512), "avx512cd" => (7, 0, 1, 28, AVX512),
        "sha" => (7, 0, 1, 29, 0), "avx512bw" => (7, 0, 1, 30, AVX512),
        "avx512vl" => (7, 0, 1, 31, AVX512), "avx512vbmi" => (7, 0, 2, 1, AVX512),
        "avx512vbmi2" => (7, 0, 2, 6, AVX512), "gfni" => (7, 0, 2, 8, 0),
        "vaes" => (7, 0, 2, 9, AVX), "vpclmulqdq" => (7, 0, 2, 10, AVX),
        "avx512vnni" => (7, 0, 2, 11, AVX512), "avx512bitalg" => (7, 0, 2, 12, AVX512),
        "avx512vpopcntdq" => (7, 0, 2, 14, AVX512),
        "lzcnt" | "abm" => (0x8000_0001, 0, 2, 5, 0), "sse4a" => (0x8000_0001, 0, 2, 6, 0),
        _ => return None,
    })
}

impl<'m> FuncCtx<'m> {
    /// Lower one of the builtins of this file, or `None` when `name` is none of
    /// them (its argument count has been checked).
    pub(crate) fn lower_extra_builtin(&mut self, name: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Option<Val>> {
        let err = |m: String| CompileError::at(m, sp.file.clone(), sp.line, sp.col);
        if let Some((op, ty)) = typed_overflow(name) {
            let a = self.lower_expr(&args[0])?;
            let a = self.coerce(a, &ty)?;
            let b = self.lower_expr(&args[1])?;
            let b = self.coerce(b, &ty)?;
            let res = self.lower_expr(&args[2])?;
            return self.overflow_same_type(op, a, b, res, &ty).map(Some);
        }
        if let Some(rest) = name.strip_prefix("__builtin_stdc_") {
            if STDC_BIT.contains(&rest) || rest.starts_with("rotate_") {
                return self.lower_stdc_bit(name, rest, args).map(Some);
            }
        }
        for (prefix, op) in [("__builtin_rotateleft", BinOp::Rotl), ("__builtin_rotateright", BinOp::Rotr)] {
            if let Some(bits) = name.strip_prefix(prefix).and_then(|w| w.parse::<u32>().ok()) {
                let ty = Type::Int { bits, signed: false };
                let x = self.lower_expr(&args[0])?;
                let x = self.coerce(x, &ty)?;
                let n = self.lower_expr(&args[1])?;
                let n = self.coerce(n, &ty)?;
                return Ok(Some(self.bin(op, x, n, &ty)));
            }
        }
        if let Some(bits) = name.strip_prefix("__builtin_bitreverse").and_then(|w| w.parse::<u32>().ok()) {
            let ty = Type::Int { bits, signed: false };
            let x = self.lower_expr(&args[0])?;
            let x = self.coerce(x, &ty)?;
            return Ok(Some(self.bit_reverse(x, bits)));
        }
        Ok(Some(match name {
            // A hint the optimizer may use; its operand is not evaluated.
            "__builtin_assume" => Constant::zero(),
            // The value itself: sic has no speculation barriers to add or branch
            // weights to record.
            "__builtin_unpredictable" | "__builtin_speculation_safe_value" => self.lower_expr(&args[0])?,
            // x86 keeps instruction and data caches coherent: nothing to flush.
            "__builtin___clear_cache" => {
                self.lower_expr(&args[0])?;
                self.lower_expr(&args[1])?;
                Constant::zero()
            }
            "__builtin_cpu_init" => Constant::zero(),
            "__builtin_cpu_supports" | "__builtin_cpu_is" => {
                let ExprKind::StringLit(s) = &args[0].kind else {
                    return Err(err(format!("the argument of `{}` must be a string literal", name)));
                };
                let f = self.cpu_runtime_fn(name)?;
                let args = if name == "__builtin_cpu_is" {
                    let v = match s.as_str() { "intel" => 1, "amd" => 2,
                        _ => return Err(err(format!("`__builtin_cpu_is(\"{}\")`: sic knows only \"intel\" and \"amd\"", s))) };
                    vec![self.coerce(Constant::int(v), &Type::i32())?]
                } else {
                    let Some((leaf, sub, reg, bit, xcr0)) = cpu_feature(s) else {
                        return Err(err(format!("`__builtin_cpu_supports`: unknown CPU feature \"{}\"", s)));
                    };
                    let mut v = Vec::new();
                    for n in [leaf, sub, reg, bit, xcr0] { v.push(self.coerce(Constant::uint(n as u64), &Type::u32())?); }
                    v
                };
                let d = self.alloc_val();
                self.push_instr(Instr::Call { dest: Some(d), func: f, args, ret_ty: Type::i32() });
                Val::Local(d)
            }
            "__builtin_nans" | "__builtin_nansf" | "__builtin_nansl" => {
                // A signaling NaN: exponent all ones, quiet bit clear, payload 1.
                if name == "__builtin_nansf" { self.float_from_bits(0x7FA0_0000, 32)? }
                else { self.float_from_bits(0x7FF4_0000_0000_0000, 64)? }
            }
            "__builtin_issignaling" => {
                let x = self.lower_expr(&args[0])?;
                let (bits, quiet, expo) = if self.val_type(&x) == Type::Float32 {
                    (32, 0x0040_0000u64, 0x7F80_0000u64)
                } else {
                    (64, 0x0008_0000_0000_0000, 0x7FF0_0000_0000_0000)
                };
                let ity = Type::Int { bits, signed: false };
                let fty = if bits == 32 { Type::Float32 } else { Type::Float64 };
                let x = self.coerce(x, &fty)?;
                let w = self.bits_of_float(x, &fty, &ity);
                // exponent all ones, quiet bit clear, some other mantissa bit set
                let ex = self.bin(BinOp::And, w.clone(), Constant::uint(expo), &ity);
                let all = self.cmp(CmpOp::IEq, ex, Constant::uint(expo), &ity);
                let q = self.bin(BinOp::And, w.clone(), Constant::uint(quiet), &ity);
                let noq = self.cmp(CmpOp::IEq, q, Constant::uint(0), &ity);
                let m = self.bin(BinOp::And, w, Constant::uint(quiet - 1), &ity);
                let pay = self.cmp(CmpOp::INe, m, Constant::uint(0), &ity);
                let a = self.bin(BinOp::And, all, noq, &Type::Bool);
                let r = self.bin(BinOp::And, a, pay, &Type::Bool);
                self.coerce(r, &Type::i32())?
            }
            "__builtin_isnanf" | "__builtin_isnanl" => self.lower_fp_classify("__builtin_isnan", &args[0])?,
            "__builtin_isinff" | "__builtin_isinfl" => self.lower_fp_classify("__builtin_isinf", &args[0])?,
            "__builtin_finite" | "__builtin_finitef" | "__builtin_finitel" =>
                self.lower_fp_classify("__builtin_isfinite", &args[0])?,
            // C23 `iseqsig`: equality (sic raises no floating-point exceptions).
            "__builtin_iseqsig" => {
                let a = self.lower_expr(&args[0])?;
                let b = self.lower_expr(&args[1])?;
                let fty = match (self.val_type(&a), self.val_type(&b)) {
                    (Type::Float32, Type::Float32) => Type::Float32, _ => Type::Float64 };
                let a = self.coerce(a, &fty)?;
                let b = self.coerce(b, &fty)?;
                let e = self.cmp(CmpOp::FOEq, a, b, &fty);
                self.coerce(e, &Type::i32())?
            }
            "__builtin_bswap128" => {
                let ty = Type::Int { bits: 128, signed: false };
                let u64t = Type::Int { bits: 64, signed: false };
                let x = self.lower_expr(&args[0])?;
                let x = self.coerce(x, &ty)?;
                let lo = self.coerce(x.clone(), &u64t)?;
                let hi = self.bin(BinOp::LShr, x, Constant::int(64), &ty);
                let hi = self.coerce(hi, &u64t)?;
                let (slo, shi) = (self.alloc_val(), self.alloc_val());
                self.push_instr(Instr::BSwap { dest: slo, val: lo, ty: u64t.clone() });
                self.push_instr(Instr::BSwap { dest: shi, val: hi, ty: u64t.clone() });
                let nhi = self.coerce(Val::Local(slo), &ty)?;
                let nhi = self.bin(BinOp::Shl, nhi, Constant::int(64), &ty);
                let nlo = self.coerce(Val::Local(shi), &ty)?;
                self.bin(BinOp::Or, nhi, nlo, &ty)
            }
            "__builtin_clzg" | "__builtin_ctzg" | "__builtin_popcountg" | "__builtin_parityg"
            | "__builtin_ffsg" | "__builtin_clrsbg" => return self.lower_bit_g(name, args, sp).map(Some),
            // The call site: its file, line and column, and the function it is in.
            "__builtin_FILE" => {
                let f = sp.file.clone().unwrap_or_default();
                self.emit_cstring(&f)
            }
            "__builtin_LINE" => self.coerce(Constant::int(sp.line as i64), &Type::i32())?,
            "__builtin_COLUMN" => self.coerce(Constant::int(sp.col as i64), &Type::i32())?,
            "__builtin_FUNCTION" => {
                let f = self.func_ref().name.clone();
                self.emit_cstring(&f)
            }
            "__builtin_classify_type" => {
                let t = self.infer_expr_type(&args[0]).unwrap_or(Type::i32());
                let rt = crate::lower::types::resolve_aggregate(&t, &self.lowerer.struct_types);
                // GCC's `type_class`: an argument is promoted and decays, so a
                // character/enum/boolean is an integer and an array a pointer.
                let class = match rt {
                    Type::Void => 0,
                    Type::Int { .. } | Type::Bool => 1,
                    Type::Float32 | Type::Float64 | Type::Float80 => 8,
                    Type::Pointer(_) | Type::Array { .. } | Type::Function(_) => 5,
                    Type::Struct(_) => 12,
                    Type::Union(_) => 13,
                };
                self.coerce(Constant::int(class), &Type::i32())?
            }
            // `x` to the integer power `n`: computed by `pow`.
            "__builtin_powi" | "__builtin_powif" | "__builtin_powil" => {
                let fty = match name { "__builtin_powif" => Type::Float32, _ => Type::Float64 };
                let x = self.lower_expr(&args[0])?;
                let x = self.coerce(x, &Type::Float64)?;
                let n = self.lower_expr(&args[1])?;
                let n = self.coerce(n, &Type::i32())?;
                let n = self.coerce(n, &Type::Float64)?;
                let pow = self.lowerer.implicit_libc_decl("pow")
                    .or_else(|| self.lowerer.module.func_ref_by_name("pow"))
                    .ok_or_else(|| err("`pow` is not available".to_string()))?;
                let d = self.alloc_val();
                self.push_instr(Instr::Call { dest: Some(d), func: pow, args: vec![x, n], ret_ty: Type::Float64 });
                self.val_types.insert(d.0, Type::Float64);
                self.coerce(Val::Local(d), &fty)?
            }
            "__sync_swap" => {
                let p = self.lower_expr(&args[0])?;
                let ty = self.pointee_ty(&p);
                let v = self.lower_expr(&args[1])?;
                let v = self.coerce(v, &ty)?;
                let d = self.alloc_val();
                self.push_instr(Instr::AtomicRmw { dest: d, op: AtomicOp::Xchg, ptr: p, val: v, ty: ty.clone() });
                self.val_types.insert(d.0, ty);
                Val::Local(d)
            }
            "__atomic_fetch_nand" | "__atomic_nand_fetch" | "__sync_fetch_and_nand" | "__sync_nand_and_fetch" => {
                let ret_new = matches!(name, "__atomic_nand_fetch" | "__sync_nand_and_fetch");
                return self.lower_atomic_nand(&args[0], &args[1], ret_new).map(Some);
            }
            // Clang's alignment builtins (the alignment is a power of two).
            "__builtin_is_aligned" | "__builtin_align_up" | "__builtin_align_down" => {
                let x = self.lower_expr(&args[0])?;
                let xt = self.val_type(&x);
                let ut = Type::Int { bits: self.ptr_size() * 8, signed: false };
                let xi = if matches!(xt, Type::Pointer(_)) {
                    let d = self.alloc_val();
                    self.push_instr(Instr::Cast { dest: d, op: CastOp::PtrToInt, val: x.clone(), to_ty: ut.clone() });
                    Val::Local(d)
                } else { self.coerce(x.clone(), &ut)? };
                let a = self.lower_expr(&args[1])?;
                let a = self.coerce(a, &ut)?;
                let m = self.bin(BinOp::Sub, a, Constant::uint(1), &ut);
                if name == "__builtin_is_aligned" {
                    let low = self.bin(BinOp::And, xi, m, &ut);
                    let z = self.cmp(CmpOp::IEq, low, Constant::uint(0), &ut);
                    self.coerce(z, &Type::Bool)?
                } else {
                    let up = if name == "__builtin_align_up" { self.bin(BinOp::Add, xi, m.clone(), &ut) } else { xi };
                    let nm = self.alloc_val();
                    self.push_instr(Instr::UnaryOp { dest: nm, op: UnOp::Not, val: m, ty: ut.clone() });
                    let r = self.bin(BinOp::And, up, Val::Local(nm), &ut);
                    if matches!(xt, Type::Pointer(_)) {
                        let d = self.alloc_val();
                        self.push_instr(Instr::Cast { dest: d, op: CastOp::IntToPtr, val: r, to_ty: xt.clone() });
                        self.val_types.insert(d.0, xt);
                        Val::Local(d)
                    } else { self.coerce(r, &xt)? }
                }
            }
            "__builtin_shufflevector" => return self.lower_shufflevector(args, sp).map(Some),
            "__builtin_shuffle" => return self.lower_shuffle(args, sp).map(Some),
            "__builtin_convertvector" => return self.lower_convertvector(args, sp).map(Some),
            // Clang's always-inlined copies: the builtin copy, expanded inline
            // up to 64 bytes like any constant-size one.
            "__builtin_memcpy_inline" | "__builtin_memset_inline" => {
                let plain = if name == "__builtin_memcpy_inline" { "__builtin_memcpy" } else { "__builtin_memset" };
                let callee = Expr { kind: ExprKind::Ident(plain.to_string()), span: sp.clone() };
                self.lower_call(&callee, args, sp)?;
                Constant::zero()
            }
            _ => return Ok(None),
        }))
    }

    /// The result type of the builtin `name` called with `args` (as GCC types
    /// it), or `None` when it is none sic lowers itself.
    pub(crate) fn builtin_result_type(&self, name: &str, args: &[Expr]) -> Option<Type> {
        if let Some(t) = self.ia32_result_type(name, args) { return Some(t); }
        let arg = |i: usize| args.get(i).and_then(|a| self.infer_expr_type(a).ok());
        let pointee = || match arg(0) { Some(Type::Pointer(t)) => Some(crate::lower::types::resolve_aggregate(&t, &self.lowerer.struct_types)), _ => None };
        let u = |bits| Type::Int { bits, signed: false };
        let bits_of = |w: &str| w.parse::<u32>().ok();
        if typed_overflow(name).is_some() { return Some(Type::Bool); }
        if let Some(rest) = name.strip_prefix("__builtin_stdc_") {
            return match rest {
                "bit_floor" | "bit_ceil" | "rotate_left" | "rotate_right" => arg(0),
                "has_single_bit" => Some(Type::Bool),
                _ if STDC_BIT.contains(&rest) => Some(Type::u32()),
                _ => None,
            };
        }
        for p in ["__builtin_bitreverse", "__builtin_rotateleft", "__builtin_rotateright"] {
            if let Some(b) = name.strip_prefix(p).and_then(bits_of) { return Some(u(b)); }
        }
        if let Some(rest) = name.strip_prefix("__builtin_") {
            for base in ["clz", "ctz", "popcount", "ffs", "clrsb", "parity"] {
                if rest.strip_prefix(base).map_or(false, |s| matches!(s, "" | "l" | "ll" | "g")) { return Some(Type::i32()); }
            }
        }
        if super::atomic_rmw_op(name).is_some() { return pointee(); }
        let f80 = Type::Float80;
        Some(match name {
            "__builtin_bswap16" => u(16), "__builtin_bswap32" => u(32), "__builtin_bswap64" => u(64),
            "__builtin_bswap128" => u(128),
            "__builtin_expect" | "__builtin_expect_with_probability" => Type::i64(),
            "__builtin_object_size" | "__builtin_dynamic_object_size" => u(self.ptr_size() * 8),
            "__builtin_alloca" | "__builtin_alloca_with_align" | "__builtin_frame_address"
            | "__builtin_return_address" | "__builtin_extract_return_addr" | "__builtin_frob_return_addr"
            | "__builtin_dwarf_cfa" | "__builtin_assume_aligned" => Type::void_ptr(),
            "__builtin_inf" | "__builtin_huge_val" | "__builtin_nan" | "__builtin_nans"
            | "__builtin_powi" => Type::Float64,
            "__builtin_inff" | "__builtin_huge_valf" | "__builtin_nanf" | "__builtin_nansf"
            | "__builtin_powif" => Type::Float32,
            "__builtin_infl" | "__builtin_huge_vall" | "__builtin_nanl" | "__builtin_nansl"
            | "__builtin_powil" => f80,
            "__builtin_add_overflow" | "__builtin_sub_overflow" | "__builtin_mul_overflow"
            | "__atomic_compare_exchange" | "__atomic_compare_exchange_n" | "__atomic_test_and_set"
            | "__atomic_always_lock_free" | "__atomic_is_lock_free" | "__builtin_is_aligned" => Type::Bool,
            "__sync_bool_compare_and_swap" => Type::Bool,
            "__builtin_addc" | "__builtin_subc" => u(32),
            "__builtin_addcl" | "__builtin_subcl" | "__builtin_addcll" | "__builtin_subcll" => u(64),
            "__atomic_load_n" | "__atomic_exchange_n" | "__sync_val_compare_and_swap"
            | "__sync_lock_test_and_set" | "__sync_swap" | "__atomic_fetch_nand" | "__atomic_nand_fetch"
            | "__sync_fetch_and_nand" | "__sync_nand_and_fetch" => return pointee(),
            "__atomic_load" | "__atomic_store" | "__atomic_store_n" | "__atomic_exchange"
            | "__atomic_clear" | "__atomic_thread_fence" | "__atomic_signal_fence" | "__sync_synchronize"
            | "__sync_lock_release" | "__builtin_prefetch" | "__builtin_trap" | "__builtin_unreachable"
            | "__builtin_assume" | "__builtin___clear_cache" | "__builtin_cpu_init"
            | "__builtin_memcpy_inline" | "__builtin_memset_inline" => Type::Void,
            "__builtin_unpredictable" | "__builtin_speculation_safe_value" | "__builtin_align_up"
            | "__builtin_align_down" => return arg(0),
            "__builtin_FILE" | "__builtin_FUNCTION" => Type::char_ptr(),
            "__builtin_constant_p" | "__builtin_LINE" | "__builtin_COLUMN" | "__builtin_classify_type"
            | "__builtin_cpu_supports" | "__builtin_cpu_is" | "__builtin_isnan" | "__builtin_isinf"
            | "__builtin_isinf_sign" | "__builtin_isfinite" | "__builtin_isnormal" | "__builtin_signbit"
            | "__builtin_signbitf" | "__builtin_signbitl" | "__builtin_fpclassify" | "__builtin_isgreater"
            | "__builtin_isgreaterequal" | "__builtin_isless" | "__builtin_islessequal"
            | "__builtin_islessgreater" | "__builtin_isunordered" | "__builtin_issignaling"
            | "__builtin_iseqsig" | "__builtin_isnanf" | "__builtin_isnanl" | "__builtin_isinff"
            | "__builtin_isinfl" | "__builtin_finite" | "__builtin_finitef" | "__builtin_finitel" => Type::i32(),
            "__builtin_shufflevector" => return self.shufflevector_type(args),
            "__builtin_shuffle" | "__builtin_convertvector" if name == "__builtin_shuffle" => return arg(0),
            "__builtin_convertvector" => return match args.get(1).map(|a| &a.kind) {
                Some(ExprKind::TypeIdOf(qt)) => self.lower_type(qt).ok(),
                _ => None,
            },
            _ => {
                // `__builtin_<libc function>`: the function's return type.
                let libc = name.strip_prefix("__builtin_")?;
                if let Some(super::super::func::LookupResult::Func(f)) = self.lookup(libc) {
                    return Some(self.lowerer.module.func_sig(f).ret.clone());
                }
                return self.lowerer.libc_proto_sig(libc).map(|s| s.ret);
            }
        })
    }

    /// `__builtin_shufflevector(a, b, i…)`: a vector of `a`'s element type with
    /// one lane per index.
    fn shufflevector_type(&self, args: &[Expr]) -> Option<Type> {
        match self.infer_expr_type(args.first()?).ok()? {
            Type::Array { elem, .. } => Some(Type::Array { elem, len: args.len().saturating_sub(2) }),
            _ => None,
        }
    }

    /// The element type and lane count of a vector operand.
    fn vector_lanes(&self, e: &Expr, name: &str, sp: &crate::lexer::Span) -> Result<(Type, usize)> {
        match self.infer_expr_type(e)? {
            Type::Array { elem, len } => Ok(((*elem).clone(), len)),
            _ => Err(CompileError::at(format!("`{}` needs a vector operand", name), sp.file.clone(), sp.line, sp.col)),
        }
    }

    /// Lane `i` (a value) of the vector at `p`.
    fn lane_ptr(&mut self, p: &Val, i: Val, esz: u64) -> Val {
        let off = self.bin(BinOp::Mul, i, Constant::int(esz as i64), &Type::i64());
        let d = self.alloc_val();
        self.push_instr(Instr::PtrOffset { dest: d, base: p.clone(), offset: off });
        Val::Local(d)
    }

    /// `__builtin_shufflevector(a, b, i0, i1, …)` (Clang): lane `k` of the result
    /// is lane `ik` of `a ++ b` (constant indices; -1 leaves the lane zero).
    fn lower_shufflevector(&mut self, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let name = "__builtin_shufflevector";
        let (elem, n) = self.vector_lanes(&args[0], name, sp)?;
        let (_, nb) = self.vector_lanes(&args[1], name, sp)?;
        let esz = elem.size_of(self.ptr_size());
        let ap = self.lower_aggregate_ptr(&args[0])?;
        let bp = self.lower_aggregate_ptr(&args[1])?;
        let rty = Type::Array { elem: Box::new(elem.clone()), len: args.len() - 2 };
        let r = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: r, ty: rty.clone(), align: None });
        let r = Val::Local(r);
        for (k, ie) in args[2..].iter().enumerate() {
            let Some(i) = self.lowerer.eval_const_int(ie) else {
                return Err(CompileError::at(format!("`{}`: index {} is not a constant", name, k), sp.file.clone(), sp.line, sp.col));
            };
            if i < -1 || i >= (n + nb) as i64 {
                return Err(CompileError::at(format!("`{}`: index {} is out of range", name, i), sp.file.clone(), sp.line, sp.col));
            }
            let v = if i < 0 { self.coerce(Constant::zero(), &elem)? } else {
                let (src, j) = if (i as usize) < n { (&ap, i) } else { (&bp, i - n as i64) };
                let p = self.lane_ptr(src, Constant::int(j), esz);
                let d = self.alloc_val();
                self.push_instr(Instr::Load { dest: d, ptr: p, ty: elem.clone() });
                Val::Local(d)
            };
            let dst = self.lane_ptr(&r, Constant::int(k as i64), esz);
            self.push_instr(Instr::Store { val: v, ptr: dst });
        }
        self.val_types.insert(match &r { Val::Local(id) => id.0, _ => 0 }, rty);
        Ok(r)
    }

    /// `__builtin_shuffle(a, mask)` / `(a, b, mask)` (GCC): lane `k` is lane
    /// `mask[k]` of `a` (or of `a ++ b`), the index taken modulo the lane count.
    fn lower_shuffle(&mut self, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let name = "__builtin_shuffle";
        let (elem, n) = self.vector_lanes(&args[0], name, sp)?;
        let mask_e = args.last().unwrap();
        let (melem, mn) = self.vector_lanes(mask_e, name, sp)?;
        if mn != n || !n.is_power_of_two() {
            return Err(CompileError::at(format!("`{}`: the mask needs one lane per element", name), sp.file.clone(), sp.line, sp.col));
        }
        let vty = self.infer_expr_type(&args[0])?;
        let esz = elem.size_of(self.ptr_size());
        let msz = melem.size_of(self.ptr_size());
        let ap = self.lower_aggregate_ptr(&args[0])?;
        let bp = if args.len() == 3 { self.lower_aggregate_ptr(&args[1])? } else { ap.clone() };
        let mp = self.lower_aggregate_ptr(mask_e)?;
        let r = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: r, ty: vty.clone(), align: None });
        let r = Val::Local(r);
        let i64t = Type::i64();
        for k in 0..n {
            let mptr = self.lane_ptr(&mp, Constant::int(k as i64), msz);
            let m = self.alloc_val();
            self.push_instr(Instr::Load { dest: m, ptr: mptr, ty: melem.clone() });
            let m = self.coerce(Val::Local(m), &i64t)?;
            let j = self.bin(BinOp::And, m.clone(), Constant::int(n as i64 - 1), &i64t);
            let pa = self.lane_ptr(&ap, j.clone(), esz);
            let va = self.alloc_val();
            self.push_instr(Instr::Load { dest: va, ptr: pa, ty: elem.clone() });
            let v = if args.len() == 3 {
                let pb = self.lane_ptr(&bp, j, esz);
                let vb = self.alloc_val();
                self.push_instr(Instr::Load { dest: vb, ptr: pb, ty: elem.clone() });
                let hi = self.bin(BinOp::And, m, Constant::int(n as i64), &i64t);
                let from_b = self.cmp(CmpOp::INe, hi, Constant::int(0), &i64t);
                self.select(from_b, Val::Local(vb), Val::Local(va), &elem)
            } else { Val::Local(va) };
            let dst = self.lane_ptr(&r, Constant::int(k as i64), esz);
            self.push_instr(Instr::Store { val: v, ptr: dst });
        }
        self.val_types.insert(match &r { Val::Local(id) => id.0, _ => 0 }, vty);
        Ok(r)
    }

    /// `__builtin_convertvector(v, T)`: each lane converted as a scalar
    /// conversion to `T`'s element type (the lane counts match).
    fn lower_convertvector(&mut self, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let name = "__builtin_convertvector";
        let (elem, n) = self.vector_lanes(&args[0], name, sp)?;
        let ExprKind::TypeIdOf(qt) = &args[1].kind else {
            return Err(CompileError::at(format!("`{}` needs a vector type", name), sp.file.clone(), sp.line, sp.col));
        };
        let tty = self.lower_type(qt)?;
        let Type::Array { elem: telem, len } = &tty else {
            return Err(CompileError::at(format!("`{}` needs a vector type", name), sp.file.clone(), sp.line, sp.col));
        };
        if *len != n {
            return Err(CompileError::at(format!("`{}`: {} lanes cannot convert to {}", name, n, len), sp.file.clone(), sp.line, sp.col));
        }
        let telem = (**telem).clone();
        let (esz, tsz) = (elem.size_of(self.ptr_size()), telem.size_of(self.ptr_size()));
        let vp = self.lower_aggregate_ptr(&args[0])?;
        let r = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: r, ty: tty.clone(), align: None });
        let r = Val::Local(r);
        for k in 0..n {
            let p = self.lane_ptr(&vp, Constant::int(k as i64), esz);
            let x = self.alloc_val();
            self.push_instr(Instr::Load { dest: x, ptr: p, ty: elem.clone() });
            self.val_types.insert(x.0, elem.clone());
            let y = self.coerce(Val::Local(x), &telem)?;
            let dst = self.lane_ptr(&r, Constant::int(k as i64), tsz);
            self.push_instr(Instr::Store { val: y, ptr: dst });
        }
        self.val_types.insert(match &r { Val::Local(id) => id.0, _ => 0 }, tty);
        Ok(r)
    }

    fn bin(&mut self, op: BinOp, a: Val, b: Val, ty: &Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: d, op, lhs: a, rhs: b, ty: ty.clone() });
        self.val_types.insert(d.0, ty.clone());
        Val::Local(d)
    }

    fn cmp(&mut self, op: CmpOp, a: Val, b: Val, ty: &Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: d, op, lhs: a, rhs: b, ty: ty.clone() });
        self.val_types.insert(d.0, Type::Bool);
        Val::Local(d)
    }

    fn select(&mut self, c: Val, a: Val, b: Val, ty: &Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::Select { dest: d, cond: c, on_true: a, on_false: b, ty: ty.clone() });
        self.val_types.insert(d.0, ty.clone());
        Val::Local(d)
    }

    fn unop(&mut self, op: UnOp, a: Val, ty: &Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::UnaryOp { dest: d, op, val: a, ty: ty.clone() });
        self.val_types.insert(d.0, ty.clone());
        Val::Local(d)
    }

    /// The bits of the float `x` (through a stack slot).
    fn bits_of_float(&mut self, x: Val, fty: &Type, ity: &Type) -> Val {
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: ity.clone(), align: None });
        let _ = fty;
        self.push_instr(Instr::Store { val: x, ptr: Val::Local(slot) });
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: Val::Local(slot), ty: ity.clone() });
        Val::Local(d)
    }

    /// The float (`bits` 32 or 64 wide) with exactly these bits.
    fn float_from_bits(&mut self, v: u64, bits: u32) -> Result<Val> {
        let ity = Type::Int { bits, signed: false };
        let fty = if bits == 32 { Type::Float32 } else { Type::Float64 };
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: ity.clone(), align: None });
        let c = self.coerce(Constant::uint(v), &ity)?;
        self.push_instr(Instr::Store { val: c, ptr: Val::Local(slot) });
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: Val::Local(slot), ty: fty.clone() });
        self.val_types.insert(d.0, fty);
        Ok(Val::Local(d))
    }

    /// `x` with its `bits` bits in reverse order: swap ever larger groups.
    fn bit_reverse(&mut self, x: Val, bits: u32) -> Val {
        let ty = Type::Int { bits, signed: false };
        let mut v = x;
        let mut shift = 1u32;
        let masks: [u64; 6] = [0x5555_5555_5555_5555, 0x3333_3333_3333_3333, 0x0F0F_0F0F_0F0F_0F0F,
            0x00FF_00FF_00FF_00FF, 0x0000_FFFF_0000_FFFF, 0x0000_0000_FFFF_FFFF];
        let all = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        for m in masks {
            if shift >= bits { break; }
            let m = m & all;
            let lo = self.bin(BinOp::And, v.clone(), Constant::uint(m), &ty);
            let lo = self.bin(BinOp::Shl, lo, Constant::int(shift as i64), &ty);
            let hi = self.bin(BinOp::LShr, v, Constant::int(shift as i64), &ty);
            let hi = self.bin(BinOp::And, hi, Constant::uint(m), &ty);
            v = self.bin(BinOp::Or, lo, hi, &ty);
            shift *= 2;
        }
        v
    }

    /// An integer operand of a type-generic bit builtin: its value and type
    /// (no promotion: `unsigned char` stays 8 bits wide). `signed` says which
    /// kind the builtin takes.
    fn bit_operand(&mut self, name: &str, e: &Expr, signed: bool, sp: &crate::lexer::Span) -> Result<(Val, Type, u32)> {
        let t = self.infer_expr_type(e).unwrap_or(Type::i32());
        let (bits, s) = match t {
            Type::Int { bits, signed } => (bits, signed),
            Type::Bool => (1, false),
            _ => return Err(CompileError::at(format!("`{}` needs an integer argument", name), sp.file.clone(), sp.line, sp.col)),
        };
        if s != signed {
            return Err(CompileError::at(format!("`{}` needs {} integer argument, not `{}`", name,
                if signed { "a signed" } else { "an unsigned" }, self.type_name_of(&t)), sp.file.clone(), sp.line, sp.col));
        }
        let ty = Type::Int { bits: bits.max(8), signed };
        let v = self.lower_expr(e)?;
        let v = self.coerce(v, &ty)?;
        Ok((v, ty, bits))
    }

    /// `__builtin_{clz,ctz,popcount,parity,ffs,clrsb}g`: the bit counts of any
    /// integer width; `clzg`/`ctzg` take the value for 0 as a second argument.
    fn lower_bit_g(&mut self, name: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let signed = matches!(name, "__builtin_ffsg" | "__builtin_clrsbg");
        let (x, ty, _) = self.bit_operand(name, &args[0], signed, sp)?;
        let ity = Type::i32();
        let r = match name {
            "__builtin_clzg" | "__builtin_ctzg" => {
                let op = if name == "__builtin_clzg" { UnOp::Clz } else { UnOp::Ctz };
                let c = self.unop(op, x.clone(), &ty);
                let c = self.coerce(c, &ity)?;
                if let Some(fb) = args.get(1) {
                    let fb = self.lower_expr(fb)?;
                    let fb = self.coerce(fb, &ity)?;
                    let z = self.cmp(CmpOp::IEq, x, Constant::uint(0), &ty);
                    self.select(z, fb, c, &ity)
                } else { c }
            }
            "__builtin_popcountg" | "__builtin_parityg" => {
                let c = self.unop(UnOp::Popcnt, x, &ty);
                let c = if name == "__builtin_parityg" { self.bin(BinOp::And, c, Constant::uint(1), &ty) } else { c };
                self.coerce(c, &ity)?
            }
            "__builtin_ffsg" => {
                let c = self.unop(UnOp::Ctz, x.clone(), &ty);
                let c1 = self.bin(BinOp::Add, c, Constant::uint(1), &ty);
                let z = self.cmp(CmpOp::IEq, x, Constant::uint(0), &ty);
                let r = self.select(z, Constant::uint(0), c1, &ty);
                self.coerce(r, &ity)?
            }
            _ => {
                // clrsb: leading bits equal to the sign bit, minus the sign bit.
                let bits = match ty { Type::Int { bits, .. } => bits, _ => 32 };
                let sgn = self.bin(BinOp::AShr, x.clone(), Constant::int(bits as i64 - 1), &ty);
                let y = self.bin(BinOp::Xor, x, sgn, &ty);
                let c = self.unop(UnOp::Clz, y, &ty);
                let c = self.bin(BinOp::Sub, c, Constant::uint(1), &ty);
                self.coerce(c, &ity)?
            }
        };
        Ok(r)
    }

    /// C23 `<stdbit.h>`'s `__builtin_stdc_*` (GCC): counts are `unsigned int`,
    /// `bit_floor`/`bit_ceil`/rotations keep the operand's type, `has_single_bit`
    /// is a `bool`. Every operand is an unsigned integer of any width.
    fn lower_stdc_bit(&mut self, name: &str, op: &str, args: &[Expr]) -> Result<Val> {
        let sp = args[0].span.clone();
        let (x, ty, w) = self.bit_operand(name, &args[0], false, &sp)?;
        let ut = Type::u32();
        let width = |fc: &mut Self| fc.coerce(Constant::uint(w as u64), &ut);
        // Counts on the operand's real width (`ty` may be wider for a 1-bit bool).
        let lz = |fc: &mut Self, v: Val| -> Result<Val> {
            let c = fc.unop(UnOp::Clz, v, &ty);
            let c = fc.coerce(c, &ut)?;
            let extra = match ty { Type::Int { bits, .. } => bits - w, _ => 0 };
            Ok(if extra > 0 { fc.bin(BinOp::Sub, c, Constant::uint(extra as u64), &ut) } else { c })
        };
        let tz = |fc: &mut Self, v: Val| -> Result<Val> {
            let c = fc.unop(UnOp::Ctz, v, &ty);
            let c = fc.coerce(c, &ut)?;
            let wv = fc.coerce(Constant::uint(w as u64), &ut)?;
            let gt = fc.cmp(CmpOp::IUGt, c.clone(), wv.clone(), &ut);
            Ok(fc.select(gt, wv, c, &ut))
        };
        let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
        let not = |fc: &mut Self, v: Val| -> Val {
            let n = fc.unop(UnOp::Not, v, &ty);
            fc.bin(BinOp::And, n, Constant::uint(mask), &ty)
        };
        // 1-based position, or 0 when the count is the full width.
        let first = |fc: &mut Self, c: Val| -> Result<Val> {
            let wv = width(fc)?;
            let full = fc.cmp(CmpOp::IEq, c.clone(), wv, &ut);
            let p = fc.bin(BinOp::Add, c, Constant::uint(1), &ut);
            Ok(fc.select(full, Constant::uint(0), p, &ut))
        };
        Ok(match op {
            "leading_zeros" => lz(self, x)?,
            "leading_ones" => { let n = not(self, x); lz(self, n)? }
            "trailing_zeros" => tz(self, x)?,
            "trailing_ones" => { let n = not(self, x); tz(self, n)? }
            "first_leading_zero" => { let n = not(self, x); let c = lz(self, n)?; first(self, c)? }
            "first_leading_one" => { let c = lz(self, x)?; first(self, c)? }
            "first_trailing_zero" => { let n = not(self, x); let c = tz(self, n)?; first(self, c)? }
            "first_trailing_one" => { let c = tz(self, x)?; first(self, c)? }
            "count_ones" => { let c = self.unop(UnOp::Popcnt, x, &ty); self.coerce(c, &ut)? }
            "count_zeros" => {
                let c = self.unop(UnOp::Popcnt, x, &ty);
                let c = self.coerce(c, &ut)?;
                let wv = width(self)?;
                self.bin(BinOp::Sub, wv, c, &ut)
            }
            "has_single_bit" => {
                let c = self.unop(UnOp::Popcnt, x, &ty);
                let one = self.cmp(CmpOp::IEq, c, Constant::uint(1), &ty);
                self.coerce(one, &Type::Bool)?
            }
            "bit_width" => {
                let c = lz(self, x)?;
                let wv = width(self)?;
                self.bin(BinOp::Sub, wv, c, &ut)
            }
            "bit_floor" => {
                // x == 0 ? 0 : 1 << (bit_width(x) - 1)
                let c = lz(self, x.clone())?;
                let sh = self.bin(BinOp::Sub, Constant::uint(w as u64 - 1), c, &ut);
                let sh = self.coerce(sh, &ty)?;
                let p = self.bin(BinOp::Shl, Constant::uint(1), sh, &ty);
                let z = self.cmp(CmpOp::IEq, x, Constant::uint(0), &ty);
                self.select(z, Constant::uint(0), p, &ty)
            }
            "bit_ceil" => {
                // x <= 1 ? 1 : 1 << bit_width(x - 1), 0 when that does not fit
                let m1 = self.bin(BinOp::Sub, x.clone(), Constant::uint(1), &ty);
                let c = lz(self, m1)?;
                let wv = width(self)?;
                let bw = self.bin(BinOp::Sub, wv.clone(), c, &ut);
                let over = self.cmp(CmpOp::IUGe, bw.clone(), wv, &ut);
                let sh = self.coerce(bw, &ty)?;
                let p = self.bin(BinOp::Shl, Constant::uint(1), sh, &ty);
                let p = self.select(over, Constant::uint(0), p, &ty);
                let small = self.cmp(CmpOp::IULe, x, Constant::uint(1), &ty);
                self.select(small, Constant::uint(1), p, &ty)
            }
            _ => {
                // rotate_left / rotate_right by `n` modulo the width.
                let n = self.lower_expr(&args[1])?;
                let n = self.coerce(n, &ty)?;
                if w == match ty { Type::Int { bits, .. } => bits, _ => 0 } {
                    let op = if op == "rotate_left" { BinOp::Rotl } else { BinOp::Rotr };
                    self.bin(op, x, n, &ty)
                } else {
                    let n = self.bin(BinOp::URem, n, Constant::uint(w as u64), &ty);
                    let back = self.bin(BinOp::Sub, Constant::uint(w as u64), n.clone(), &ty);
                    let back = self.bin(BinOp::URem, back, Constant::uint(w as u64), &ty);
                    let (l, r) = if op == "rotate_left" { (n, back) } else { (back, n) };
                    let a = self.bin(BinOp::Shl, x.clone(), l, &ty);
                    let b = self.bin(BinOp::LShr, x, r, &ty);
                    let o = self.bin(BinOp::Or, a, b, &ty);
                    self.bin(BinOp::And, o, Constant::uint(mask), &ty)
                }
            }
        })
    }

    /// `old = *p; *p = ~(old & v)` atomically (a compare-and-swap loop); the
    /// old or the new value.
    fn lower_atomic_nand(&mut self, p_expr: &Expr, v_expr: &Expr, ret_new: bool) -> Result<Val> {
        let p = self.lower_expr(p_expr)?;
        let ty = self.pointee_ty(&p);
        let v = self.lower_expr(v_expr)?;
        let v = self.coerce(v, &ty)?;
        let cur = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: cur, ty: ty.clone(), align: None });
        let first = self.alloc_val();
        self.push_instr(Instr::Load { dest: first, ptr: p.clone(), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(first), ptr: Val::Local(cur) });
        let lp = self.new_block_after_current();
        let done = self.new_block_after_current();
        self.set_terminator(Terminator::Jump(lp));
        self.switch_to_block(lp);
        let old = self.alloc_val();
        self.push_instr(Instr::Load { dest: old, ptr: Val::Local(cur), ty: ty.clone() });
        let a = self.bin(BinOp::And, Val::Local(old), v, &ty);
        let new = self.unop(UnOp::Not, a, &ty);
        let (seen, ok) = if atomic_lock_free_type(&ty, self.ptr_size()) {
            self.emit_atomic_cas(p, Val::Local(old), new.clone(), &ty)
        } else {
            self.push_instr(Instr::Store { val: new.clone(), ptr: p });
            (Val::Local(old), Constant::int(1))
        };
        self.push_instr(Instr::Store { val: seen, ptr: Val::Local(cur) });
        self.set_terminator(Terminator::CondJump { cond: ok, then_bb: done, else_bb: lp });
        self.switch_to_block(done);
        let r = if ret_new { new } else { Val::Local(old) };
        self.val_types.insert(match &r { Val::Local(id) => id.0, _ => 0 }, ty);
        Ok(r)
    }

    /// The CPU runtime's `__sic_cpu_supports` / `__sic_cpu_is` (cpu_runtime.c).
    fn cpu_runtime_fn(&mut self, name: &str) -> Result<FuncRef> {
        let (f, n) = if name == "__builtin_cpu_is" { ("__sic_cpu_is", 1) } else { ("__sic_cpu_supports", 5) };
        if let Some(r) = self.lowerer.module.func_ref_by_name(f) { return Ok(r); }
        let params = if n == 1 { vec![Type::i32()] } else { vec![Type::u32(); 5] };
        Ok(self.lowerer.module.add_extern(ExternFunc { name: f.to_string(),
            sig: FunctionType { ret: Type::i32(), params, variadic: false } }))
    }

    /// `__builtin_{add,sub,mul}_overflow` on operands already of the result type
    /// `ty`: the wrapped result through `res`, and whether it overflowed.
    pub(crate) fn overflow_same_type(&mut self, op: BinOp, a: Val, b: Val, res: Val, ty: &Type) -> Result<Val> {
        let result = self.bin(op, a.clone(), b.clone(), ty);
        self.push_instr(Instr::Store { val: result.clone(), ptr: res });
        Ok(self.emit_overflow_flag(op, &a, &b, &result, ty))
    }
}

impl FuncCtx<'_> {
    /// `memcpy`/`memmove`/`memset` (plain or `__builtin_`) with a constant size
    /// of at most 64 bytes become the IR's `MemCopy`/`MemSet`, which the backend
    /// expands to loads and stores, as GCC and Clang do. ggml reads every f16
    /// through `memcpy(&s, &f, 2)`; a call per element made its dot products
    /// 25x slower. `callee` is the name as written, `args` the call's final,
    /// converted arguments; returns the call's value (the destination) when it
    /// was expanded. The plain names keep the library call under `-fno-builtin`.
    pub(crate) fn expand_mem_call(&mut self, callee: &str, fref: FuncRef, args: &[Val], ret_ty: &Type) -> Result<Option<Val>> {
        if !fref.is_extern() || args.len() != 3 { return Ok(None); }
        let lib = self.lowerer.module.externs[fref.index()].name.clone();
        let base = callee.strip_prefix("__builtin_");
        if base.is_none() && !self.lowerer.builtin_mem { return Ok(None); }
        if base.unwrap_or(callee) != lib || !matches!(lib.as_str(), "memcpy" | "memmove" | "memset") {
            return Ok(None);
        }
        let Some(n) = self.int_const_of(&args[2]) else { return Ok(None) };
        if n > 64 { return Ok(None); }
        let dst = args[0].clone();
        if lib == "memset" {
            let byte = self.coerce(args[1].clone(), &Type::Int { bits: 8, signed: false })?;
            self.push_instr(Instr::MemSet { dst: dst.clone(), val: byte, size: n, align: 1 });
        } else {
            self.push_instr(Instr::MemCopy { dst: dst.clone(), src: args[1].clone(), size: n, align: 1 });
        }
        Ok(Some(self.coerce(dst, ret_ty)?))
    }

    /// The value of an integer constant, also through the widening casts
    /// that type it (`sizeof` is a `size_t` zero-extension of its constant),
    /// when they were just emitted in the current block.
    pub(crate) fn int_const_of(&mut self, v: &Val) -> Option<u64> {
        match v {
            Val::Const(Constant::Int(n)) => Some(*n as u64),
            Val::Const(Constant::UInt(n)) => Some(*n),
            Val::Local(id) => {
                let id = *id;
                let src = self.current_block_mut().instrs.iter().rev().find_map(|i| match i {
                    Instr::Cast { dest, op: CastOp::ZExt | CastOp::SExt, val, .. } if *dest == id => Some(val.clone()),
                    _ => None,
                })?;
                self.int_const_of(&src)
            }
            _ => None,
        }
    }
}
