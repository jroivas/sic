use std::collections::HashMap;
use crate::ast::*;
use crate::Result;
use crate::CompileError;
use sic_ir::{Type, StructType, UnionType, FunctionType};

/// Convert an AST type to an IR type.
pub fn lower_type(qt: &QualType, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    lower_ast_type(&qt.ty, named, ptr_size)
}

/// Like lower_type, but array parameters decay to pointer-to-element (C semantics).
pub fn lower_param_type(qt: &QualType, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    let ty = lower_type(qt, named, ptr_size)?;
    Ok(match ty {
        Type::Array { elem, .. } => Type::Pointer(elem),
        other => other,
    })
}

pub fn lower_ast_type(ty: &AstType, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    Ok(match ty {
        AstType::Void        => Type::Void,
        AstType::Bool        => Type::Bool,
        AstType::Char { signed } => {
            Type::Int { bits: 8, signed: signed.unwrap_or(true) }
        }
        AstType::Short { signed } => Type::Int { bits: 16, signed: *signed },
        AstType::Int   { signed } => Type::Int { bits: 32, signed: *signed },
        AstType::Long  { signed } => {
            // On 64-bit, long is 64 bits; on 32-bit it would be 32.
            Type::Int { bits: if ptr_size >= 8 { 64 } else { 32 }, signed: *signed }
        }
        AstType::LongLong { signed } => Type::Int { bits: 64, signed: *signed },
        AstType::Float       => Type::Float32,
        AstType::Double | AstType::LongDouble => Type::Float64,
        AstType::Complex     => Type::Float64, // simplified
        AstType::Pointer { base, .. } => {
            let inner = lower_type(base, named, ptr_size)?;
            Type::Pointer(Box::new(inner))
        }
        AstType::Array { base, size } => {
            let elem = lower_type(base, named, ptr_size)?;
            let len = if let Some(sz) = size {
                match &sz.kind {
                    crate::ast::ExprKind::IntLit(v) => *v as usize,
                    crate::ast::ExprKind::UIntLit(v) => *v as usize,
                    _ => 0, // variable-length array — treat as 0
                }
            } else {
                0 // incomplete array type
            };
            Type::Array { elem: Box::new(elem), len }
        }
        AstType::Function { ret, params, variadic } => {
            let ret_ty = lower_type(ret, named, ptr_size)?;
            let param_tys: crate::Result<Vec<_>> = params.iter().map(|p| {
                lower_type(&p.ty, named, ptr_size)
            }).collect();
            Type::Function(Box::new(FunctionType { ret: ret_ty, params: param_tys?, variadic: *variadic }))
        }
        AstType::Struct(s) => lower_struct(s, named, ptr_size)?,
        AstType::Union(u)  => lower_union(u, named, ptr_size)?,
        AstType::Enum(_)   => Type::Int { bits: 32, signed: true }, // enum → i32
        AstType::Named(n) | AstType::Builtin(n) => {
            if n == "__builtin_va_list" {
                return Ok(Type::Pointer(Box::new(Type::Void)));
            }
            // sic/Rust-style primitive type aliases
            match n.as_str() {
                "int8"   | "i8"   => return Ok(Type::Int { bits: 8,   signed: true  }),
                "int16"  | "i16"  => return Ok(Type::Int { bits: 16,  signed: true  }),
                "int32"  | "i32"  => return Ok(Type::Int { bits: 32,  signed: true  }),
                "int64"  | "i64"  => return Ok(Type::Int { bits: 64,  signed: true  }),
                "int128" | "i128" => return Ok(Type::Int { bits: 128, signed: true  }),
                "uint8"  | "u8"   => return Ok(Type::Int { bits: 8,   signed: false }),
                "uint16" | "u16"  => return Ok(Type::Int { bits: 16,  signed: false }),
                "uint32" | "u32"  => return Ok(Type::Int { bits: 32,  signed: false }),
                "uint64" | "u64"  => return Ok(Type::Int { bits: 64,  signed: false }),
                "uint128"| "u128" => return Ok(Type::Int { bits: 128, signed: false }),
                "isize"           => return Ok(Type::Int { bits: ptr_size * 8, signed: true  }),
                "usize"           => return Ok(Type::Int { bits: ptr_size * 8, signed: false }),
                _ => {}
            }
            named.get(n).cloned().ok_or_else(|| {
                CompileError::new(format!("unknown type '{}'", n))
            })?
        }
    })
}

fn lower_struct(s: &StructDef, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    // Check if it's a forward reference (just a name, no fields)
    if s.fields.is_none() {
        if let Some(name) = &s.name {
            if let Some(ty) = named.get(name) {
                return Ok(ty.clone());
            }
        }
        // Forward declaration — use an opaque struct
        return Ok(Type::Struct(StructType {
            name: s.name.clone(), fields: vec![], packed: false,
        }));
    }
    let fields = s.fields.as_ref().unwrap();
    let mut ir_fields = Vec::new();
    for f in fields {
        let fname = f.name.clone().unwrap_or_default();
        let fty = lower_type(&f.ty, named, ptr_size)?;
        ir_fields.push((fname, fty));
    }
    Ok(Type::Struct(StructType { name: s.name.clone(), fields: ir_fields, packed: false }))
}

fn lower_union(u: &UnionDef, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    if u.fields.is_none() {
        if let Some(name) = &u.name {
            if let Some(ty) = named.get(name) {
                return Ok(ty.clone());
            }
        }
        return Ok(Type::Union(UnionType { name: u.name.clone(), fields: vec![] }));
    }
    let fields = u.fields.as_ref().unwrap();
    let mut ir_fields = Vec::new();
    for f in fields {
        let fname = f.name.clone().unwrap_or_default();
        let fty = lower_type(&f.ty, named, ptr_size)?;
        ir_fields.push((fname, fty));
    }
    Ok(Type::Union(UnionType { name: u.name.clone(), fields: ir_fields }))
}
