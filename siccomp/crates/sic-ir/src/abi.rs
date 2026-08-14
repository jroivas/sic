//! System V x86-64 aggregate argument/return classification.
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

use crate::types::Type;

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

/// True if the aggregate's SysV return uses the hidden sret pointer (MEMORY
/// class). `Array` (vectors) keep the sret path for now.
pub fn ret_in_memory(ty: &Type, ptr_size: u32) -> bool {
    match ty {
        Type::Array { .. } => true,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{StructType, UnionType};

    fn field(t: Type) -> (String, Type) { (String::new(), t) }
    fn st(fields: Vec<Type>) -> Type {
        Type::Struct(StructType::plain(None, fields.into_iter().map(field).collect(), false))
    }
    fn un(fields: Vec<Type>) -> Type {
        Type::Union(UnionType { name: None, fields: fields.into_iter().map(field).collect(),
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
    fn three_byte_struct_one_partial_int() {
        // { i8; i8; i8 } is 3 bytes (align 1) -> INTEGER(3 tail)
        assert_eq!(regs(&st(vec![i(8), i(8), i(8)])), vec![(RegClass::Int, 3)]);
    }
}
