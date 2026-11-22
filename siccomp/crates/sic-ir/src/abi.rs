//! x86-64 aggregate argument/return classification: System V, and the
//! Microsoft x64 convention (`ms_abi`) — see `classify_param_cc`.
//!
//! This is the one part of the C ABI that Cranelift does not do for us: it has
//! no notion of C structs, so the frontend must decide how each by-value
//! aggregate maps onto registers / the stack. See `siccomp/ABI.md`.
//!
//! Kept in `sic-ir` (not the backend) because both the frontend — which decides
//! whether a return uses the hidden sret pointer (`ret_is_sret`) — and the
//! Cranelift backend — which builds signatures and marshals the pieces — need
//! the same answer.
//!
//! Only `Struct`/`Union` are classified here. Scalars keep their natural
//! mapping; `Array` (sic's `vector_size` SIMD representation) is intentionally
//! left on the by-pointer path for now (a documented follow-up in ABI.md), so
//! SIMD lowering is untouched.

use crate::types::{CallConv, Type};

/// Which register bank an eightbyte is passed in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegClass {
    /// General-purpose register (rdi, rsi, …).
    Int,
    /// Vector register (xmm0, …).
    Sse,
}

/// One eightbyte of an aggregate passed in a register.
#[derive(Clone, Copy, Debug)]
pub struct Chunk {
    pub class: RegClass,
    /// Byte offset of this eightbyte within the aggregate (0, 8).
    pub offset: u32,
    /// Number of valid bytes in this eightbyte (1..=8); the tail eightbyte of
    /// a non-multiple-of-8 aggregate is partial.
    pub bytes: u32,
}

/// How a Struct/Union is passed under System V x86-64.
#[derive(Clone, Debug)]
pub enum AggClass {
    /// In registers, one value per eightbyte (at most two).
    Regs(Vec<Chunk>),
    /// MEMORY class: by value on the stack (args) / via sret pointer (returns).
    /// Carries the byte size.
    Memory(u32),
}

/// The largest aggregate (bytes) that can be passed in registers.
const MAX_REG_AGG: u64 = 16;

/// Classify a `Struct`/`Union` under the System V x86-64 ABI. Panics if given a
/// non-aggregate (callers gate on the type).
pub fn classify_struct_union(ty: &Type, ptr_size: u32) -> AggClass {
    debug_assert!(matches!(ty, Type::Struct(_) | Type::Union(_)));
    let size = ty.size_of(ptr_size);
    // i386 (System V i386 ABI, Linux): every aggregate is passed on the stack and
    // returned through the hidden pointer, but for `_Complex float`, which comes
    // back in `edx:eax` (as clang; on the stack, it is the same 8 bytes).
    if ptr_size == 4 {
        if is_complex_f32(ty) {
            return AggClass::Regs(vec![Chunk { class: RegClass::Int, offset: 0, bytes: 8 }]);
        }
        return AggClass::Memory(size as u32);
    }
    // Empty aggregate (GNU extension): treat as MEMORY(0) — harmless, avoids
    // producing zero register chunks.
    if size == 0 {
        return AggClass::Memory(0);
    }
    // Too big, or contains an x87 `long double` (X87 class → always MEMORY).
    if size > MAX_REG_AGG || contains_x87(ty) {
        return AggClass::Memory(size as u32);
    }

    let n = ((size + 7) / 8) as usize; // 1 or 2 eightbytes
    let mut classes: Vec<Option<RegClass>> = vec![None; n];
    if !classify_into(ty, 0, &mut classes, ptr_size) {
        // Unaligned / unclassifiable field → MEMORY.
        return AggClass::Memory(size as u32);
    }

    let chunks = (0..n)
        .map(|i| {
            let offset = (i as u64) * 8;
            Chunk {
                // A NO_CLASS eightbyte can't occur for a non-empty aggregate's
                // covered bytes; default to Int.
                class: classes[i].unwrap_or(RegClass::Int),
                offset: offset as u32,
                bytes: (size - offset).min(8) as u32,
            }
        })
        .collect();
    AggClass::Regs(chunks)
}

/// The name prefix of the frontend's `_Complex T` structs (`{ re, im }`).
pub const COMPLEX_PREFIX: &str = "_Complex ";

/// `_Complex long double`: System V's COMPLEX_X87 class. Passed in memory like
/// any x87 aggregate, but returned in `st(0)` (real part) and `st(1)` (imaginary).
pub fn is_complex_x87(ty: &Type) -> bool {
    matches!(ty, Type::Struct(s) if s.name.as_deref().map_or(false, |n| n.starts_with(COMPLEX_PREFIX))
        && s.fields.len() == 2 && s.fields.iter().all(|(_, t)| *t == Type::Float80))
}

/// A `_Complex long double` return in `st(0)`/`st(1)`: x86-64 only (i386 returns
/// it through the hidden pointer).
pub fn ret_in_x87_pair(ty: &Type, ptr_size: u32) -> bool { ptr_size == 8 && is_complex_x87(ty) }

/// `_Complex float`.
fn is_complex_f32(ty: &Type) -> bool {
    matches!(ty, Type::Struct(s) if s.name.as_deref().map_or(false, |n| n.starts_with(COMPLEX_PREFIX))
        && s.fields.len() == 2 && s.fields.iter().all(|(_, t)| *t == Type::Float32))
}

/// True if the aggregate's SysV return uses the hidden sret pointer (MEMORY
/// class). `Array` (vectors) keep the sret path for now.
pub fn ret_in_memory(ty: &Type, ptr_size: u32) -> bool {
    match ty {
        Type::Array { .. } => true,
        _ if is_complex_x87(ty) && ptr_size == 8 => false,
        Type::Struct(_) | Type::Union(_) => {
            matches!(classify_struct_union(ty, ptr_size), AggClass::Memory(_))
        }
        _ => false,
    }
}

/// Merge each field's class into the eightbytes it overlaps. Returns false if a
/// field straddles an eightbyte boundary while misaligned (SysV → MEMORY).
fn classify_into(ty: &Type, offset: u64, classes: &mut [Option<RegClass>], ptr_size: u32) -> bool {
    match ty {
        Type::Void | Type::Function(_) => {}
        Type::Bool | Type::Int { .. } | Type::Pointer(_) => {
            merge(classes, offset, ty.size_of(ptr_size), RegClass::Int);
        }
        Type::Float32 | Type::Float64 => {
            merge(classes, offset, ty.size_of(ptr_size), RegClass::Sse);
        }
        Type::Float80 => return false, // x87 (also caught by contains_x87)
        Type::Array { elem, len } => {
            let esz = elem.size_of(ptr_size);
            for i in 0..*len as u64 {
                if !classify_into(elem, offset + i * esz, classes, ptr_size) {
                    return false;
                }
            }
        }
        Type::Struct(s) => {
            let (offs, _) = s.layout(ptr_size);
            for (i, (_, fty)) in s.fields.iter().enumerate() {
                if !classify_into(fty, offset + offs[i], classes, ptr_size) {
                    return false;
                }
            }
        }
        Type::Union(u) => {
            // All members overlay offset 0 (relative to the union).
            for (_, fty) in &u.fields {
                if !classify_into(fty, offset, classes, ptr_size) {
                    return false;
                }
            }
        }
    }
    true
}

/// Merge `cls` into every eightbyte overlapped by `[offset, offset+size)`.
/// Merge rule: INTEGER wins over SSE; SSE only if all contributors are SSE.
fn merge(classes: &mut [Option<RegClass>], offset: u64, size: u64, cls: RegClass) {
    if size == 0 {
        return;
    }
    let first = (offset / 8) as usize;
    let last = ((offset + size - 1) / 8) as usize;
    for c in classes.iter_mut().take(last + 1).skip(first) {
        *c = Some(match (*c, cls) {
            (Some(RegClass::Int), _) | (_, RegClass::Int) => RegClass::Int,
            _ => RegClass::Sse,
        });
    }
}

fn contains_x87(ty: &Type) -> bool {
    match ty {
        Type::Float80 => true,
        Type::Array { elem, .. } => contains_x87(elem),
        Type::Struct(s) => s.fields.iter().any(|(_, t)| contains_x87(t)),
        Type::Union(u) => u.fields.iter().any(|(_, t)| contains_x87(t)),
        _ => false,
    }
}

/// How one IR parameter is passed.
#[derive(Clone, Debug)]
pub enum ParamPass {
    /// A scalar, or an `Array` (vector, kept on the pointer path): one value.
    Scalar,
    /// A small aggregate in registers: one value per eightbyte.
    Direct(Vec<Chunk>),
    /// A MEMORY-class aggregate, by value on the stack; the value at the boundary
    /// is a pointer. `(size, align)`.
    ByValStack(u32, u32),
    /// `long double` (X87 class → MEMORY): 16 bytes on the stack, 16-aligned, in
    /// x87 format. The IR value is an `f64`; the boundary converts (`f80`).
    X87,
    /// Microsoft x64: an aggregate that is not 1, 2, 4 or 8 bytes is passed by
    /// reference — the caller makes a copy and passes its address in the
    /// argument's slot. The IR value is the aggregate's address. `(size, align)`.
    ByRef(u32, u32),
}

/// Classify one IR parameter type for the System V ABI.
pub fn classify_param(ty: &Type, ptr_size: u32) -> ParamPass {
    match ty {
        Type::Struct(_) | Type::Union(_) => match classify_struct_union(ty, ptr_size) {
            AggClass::Regs(chunks) => ParamPass::Direct(chunks),
            AggClass::Memory(size) => ParamPass::ByValStack(size, ty.align_of(ptr_size) as u32),
        },
        // i386: on the stack, 12 bytes, 4-aligned.
        Type::Float80 => ParamPass::X87,
        _ => ParamPass::Scalar,
    }
}

/// Classifies a call's arguments in order, as the registers run out: under
/// System V an aggregate whose eightbytes do not all fit in the integer and
/// SSE argument registers still free goes, whole, on the stack (it is never
/// split), and the registers it would have used stay free for the arguments
/// after it. (Microsoft x64 assigns registers by position: nothing to track.)
pub struct ArgRegs { gp: u32, fp: u32, cc: CallConv, ptr_size: u32 }

impl ArgRegs {
    pub fn new(ptr_size: u32, cc: CallConv) -> Self { ArgRegs { gp: 6, fp: 8, cc, ptr_size } }

    /// A variadic scalar argument (its type known only to the back end): it
    /// takes an SSE register when `float`, else an integer one.
    pub fn note_scalar(&mut self, float: bool) {
        if float { self.fp = self.fp.saturating_sub(1) } else { self.gp = self.gp.saturating_sub(1) }
    }

    /// How the next argument, of type `ty`, is passed.
    pub fn next(&mut self, ty: &Type) -> ParamPass {
        let pass = classify_param_cc(ty, self.ptr_size, self.cc);
        if self.cc != CallConv::SysV || self.ptr_size != 8 { return pass; }
        match &pass {
            ParamPass::Direct(chunks) => {
                let gp = chunks.iter().filter(|c| c.class == RegClass::Int).count() as u32;
                let fp = chunks.len() as u32 - gp;
                if gp > self.gp || fp > self.fp {
                    return ParamPass::ByValStack(ty.size_of(self.ptr_size) as u32, ty.align_of(self.ptr_size) as u32);
                }
                self.gp -= gp;
                self.fp -= fp;
            }
            ParamPass::Scalar => match ty {
                Type::Float32 | Type::Float64 => self.fp = self.fp.saturating_sub(1),
                Type::Int { bits, .. } if *bits > 64 => self.gp = self.gp.saturating_sub(2),
                _ => self.gp = self.gp.saturating_sub(1),
            },
            ParamPass::ByValStack(..) | ParamPass::X87 | ParamPass::ByRef(..) => {}
        }
        pass
    }
}

/// How each of `tys` is passed, in order (see [`ArgRegs`]).
pub fn classify_params<'a>(tys: impl IntoIterator<Item = &'a Type>, ptr_size: u32, cc: CallConv) -> Vec<ParamPass> {
    let mut regs = ArgRegs::new(ptr_size, cc);
    tys.into_iter().map(|t| regs.next(t)).collect()
}

/// Microsoft x64: an aggregate of 1, 2, 4 or 8 bytes is passed and returned in
/// one integer register (whatever its fields are); any other size by
/// reference, or through the hidden result pointer.
fn win64_in_reg(size: u64) -> bool { matches!(size, 1 | 2 | 4 | 8) }

/// Classify one IR parameter type for the convention `cc`. Microsoft x64
/// passes each of the first four arguments in a register by position (rcx,
/// rdx, r8, r9, or xmm0–3 for a float) — the back end's part; here only how an
/// aggregate or a vector travels: in one integer register when it is 1, 2, 4
/// or 8 bytes, else by reference. (`long double` is rejected for `ms_abi` by
/// the front end.)
pub fn classify_param_cc(ty: &Type, ptr_size: u32, cc: CallConv) -> ParamPass {
    match cc {
        CallConv::SysV => classify_param(ty, ptr_size),
        CallConv::Win64 => match ty {
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => {
                let size = ty.size_of(ptr_size);
                if win64_in_reg(size) {
                    ParamPass::Direct(vec![Chunk { class: RegClass::Int, offset: 0, bytes: size as u32 }])
                } else {
                    ParamPass::ByRef(size as u32, ty.align_of(ptr_size) as u32)
                }
            }
            _ => ParamPass::Scalar,
        },
    }
}

/// How a `Struct`/`Union` result comes back under `cc` (System V: its class;
/// Microsoft x64: 1, 2, 4 or 8 bytes in rax, else through the result pointer).
pub fn classify_ret_cc(ty: &Type, ptr_size: u32, cc: CallConv) -> AggClass {
    match cc {
        CallConv::SysV => classify_struct_union(ty, ptr_size),
        CallConv::Win64 => {
            let size = ty.size_of(ptr_size);
            if win64_in_reg(size) {
                AggClass::Regs(vec![Chunk { class: RegClass::Int, offset: 0, bytes: size as u32 }])
            } else {
                AggClass::Memory(size as u32)
            }
        }
    }
}

/// True if a result of type `ty` uses the hidden result pointer under `cc`.
pub fn ret_in_memory_cc(ty: &Type, ptr_size: u32, cc: CallConv) -> bool {
    match cc {
        CallConv::SysV => ret_in_memory(ty, ptr_size),
        CallConv::Win64 => match ty {
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => !win64_in_reg(ty.size_of(ptr_size)),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{StructType, UnionType};

    fn field(t: Type) -> (String, Type) { (String::new(), t) }
    fn st(fields: Vec<Type>) -> Type {
        Type::Struct(StructType::plain(None, fields.into_iter().map(field).collect(), false))
    }
    fn un(fields: Vec<Type>) -> Type {
        Type::Union(UnionType { pack_limit: None, packed: false, field_packed: Vec::new(), name: None, fields: fields.into_iter().map(field).collect(),
                                field_aligns: vec![], min_align: None })
    }
    fn i(bits: u32) -> Type { Type::Int { bits, signed: true } }

    fn regs(ty: &Type) -> Vec<(RegClass, u32)> {
        match classify_struct_union(ty, 8) {
            AggClass::Regs(cs) => cs.iter().map(|c| (c.class, c.bytes)).collect(),
            AggClass::Memory(_) => panic!("expected Regs, got Memory"),
        }
    }
    fn is_mem(ty: &Type) -> bool { matches!(classify_struct_union(ty, 8), AggClass::Memory(_)) }

    #[test]
    fn small_int_struct_one_int_reg() {
        // { int; int } -> one INTEGER eightbyte (8 bytes)
        assert_eq!(regs(&st(vec![i(32), i(32)])), vec![(RegClass::Int, 8)]);
    }
    #[test]
    fn eight_byte_union_int() {
        // union { void*; u64 } -> one INTEGER reg
        assert_eq!(regs(&un(vec![Type::ptr(Type::Void), i(64)])), vec![(RegClass::Int, 8)]);
    }
    #[test]
    fn two_doubles_two_sse() {
        assert_eq!(regs(&st(vec![Type::Float64, Type::Float64])),
                   vec![(RegClass::Sse, 8), (RegClass::Sse, 8)]);
    }
    #[test]
    fn int_then_double_mixed() {
        // { i64; double } -> INTEGER eightbyte + SSE eightbyte
        assert_eq!(regs(&st(vec![i(64), Type::Float64])),
                   vec![(RegClass::Int, 8), (RegClass::Sse, 8)]);
    }
    #[test]
    fn int_and_float_same_eightbyte_is_integer() {
        // { int; float } both in first eightbyte -> INTEGER wins
        assert_eq!(regs(&st(vec![i(32), Type::Float32])), vec![(RegClass::Int, 8)]);
    }
    #[test]
    fn twelve_bytes_int_tail() {
        // { i32; i32; i32 } is 12 bytes (align 4) -> INTEGER(8) + INTEGER(4 tail)
        assert_eq!(regs(&st(vec![i(32), i(32), i(32)])),
                   vec![(RegClass::Int, 8), (RegClass::Int, 4)]);
    }
    #[test]
    fn over_16_is_memory() {
        assert!(is_mem(&st(vec![i(64), i(64), i(64)]))); // 24 bytes
    }
    #[test]
    fn x87_forces_memory() {
        assert!(is_mem(&st(vec![Type::Float80]))); // long double
    }
    #[test]
    fn win64_sizes() {
        let w = CallConv::Win64;
        // 8 bytes, even of floats: one integer register.
        assert!(matches!(classify_param_cc(&st(vec![Type::Float32, Type::Float32]), 8, w),
            ParamPass::Direct(ref c) if c.len() == 1 && c[0].class == RegClass::Int && c[0].bytes == 8));
        // 3, 12 and 16 bytes: by reference.
        assert!(matches!(classify_param_cc(&st(vec![i(8), i(8), i(8)]), 8, w), ParamPass::ByRef(3, 1)));
        assert!(matches!(classify_param_cc(&st(vec![i(32), i(32), i(32)]), 8, w), ParamPass::ByRef(12, 4)));
        assert!(matches!(classify_param_cc(&st(vec![i(64), i(64)]), 8, w), ParamPass::ByRef(16, 8)));
        assert!(!ret_in_memory_cc(&st(vec![i(32)]), 8, w));
        assert!(ret_in_memory_cc(&st(vec![i(64), i(64)]), 8, w));
        assert!(!ret_in_memory(&st(vec![i(64), i(64)]), 8)); // System V: two registers
    }
    #[test]
    fn three_byte_struct_one_partial_int() {
        // { i8; i8; i8 } is 3 bytes (align 1) -> INTEGER(3 tail)
        assert_eq!(regs(&st(vec![i(8), i(8), i(8)])), vec![(RegClass::Int, 3)]);
    }
}
