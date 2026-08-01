use cranelift_codegen::ir::types as ct;
use cranelift_codegen::ir::Type as ClType;
use sic_ir::Type;

/// Map an IR type to a Cranelift type. Returns None for void / aggregates that
/// live in memory (those are passed by pointer).
pub fn cl_type(ty: &Type, ptr_size: u32) -> Option<ClType> {
    match ty {
        Type::Void => None,
        Type::Bool => Some(ct::I8), // booleans are i8 in Cranelift
        Type::Int { bits, .. } => Some(match bits {
            1..=8   => ct::I8,
            9..=16  => ct::I16,
            17..=32 => ct::I32,
            33..=64 => ct::I64,
            65..=128 => ct::I128,
            _       => ct::I64,
        }),
        Type::Float32 => Some(ct::F32),
        Type::Float64 => Some(ct::F64),
        // No x87/f80 support in Cranelift; long double is computed as f64.
        Type::Float80 => Some(ct::F64),
        Type::Pointer(_) | Type::Function(_) => Some(ptr_cl(ptr_size)),
        // Arrays and structs: passed in memory (by pointer) when needed.
        // In our IR they're always stored on the stack and accessed via ptr.
        Type::Array { .. } | Type::Struct(_) | Type::Union(_) => Some(ptr_cl(ptr_size)),
    }
}

pub fn ptr_cl(ptr_size: u32) -> ClType {
    if ptr_size >= 8 { ct::I64 } else { ct::I32 }
}
