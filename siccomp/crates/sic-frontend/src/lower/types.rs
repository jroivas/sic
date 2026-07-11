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
        AstType::Double      => Type::Float64,
        AstType::LongDouble  => Type::Float80,
        AstType::Complex     => Type::Float64, // simplified
        AstType::Pointer { base, .. } => {
            let inner = lower_type(base, named, ptr_size)?;
            Type::Pointer(Box::new(inner))
        }
        AstType::Array { base, size } => {
            let elem = lower_type(base, named, ptr_size)?;
            let len = if let Some(sz) = size {
                // Fold the (constant) length expression — handles arithmetic like
                // `3 << 27` or `800 * 512 * 4`, not just bare literals. Genuine
                // VLAs / non-constant sizes evaluate to 0, as before. (Enum
                // constants aren't in scope here, so those still fall back to 0.)
                super::eval_const_expr(sz, &HashMap::new())
                    .ok()
                    .filter(|&v| v >= 0)
                    .map(|v| v as usize)
                    .unwrap_or(0)
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
        AstType::Typeof(e) => typeof_expr_type(e, named, ptr_size),
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

/// Best-effort standalone type of a `typeof(expr)` operand, used when resolving
/// types outside a function body (typedefs, globals) where no variable scope is
/// available. Covers the constant/literal cases that appear in system headers
/// (notably `typeof(nullptr)` in C23 `<stddef.h>`); unknown expressions fall
/// back to `int`.
fn typeof_expr_type(e: &Expr, named: &HashMap<String, Type>, ptr_size: u32) -> Type {
    match &e.kind {
        ExprKind::Nullptr => Type::void_ptr(),
        ExprKind::CharLit(_) => Type::i32(),
        ExprKind::IntLit(_, is64) => if *is64 { Type::i64() } else { Type::i32() },
        ExprKind::UIntLit(_, is64) => if *is64 { Type::Int { bits: 64, signed: false } } else { Type::u32() },
        ExprKind::FloatLit(_) => Type::Float64,
        ExprKind::StringLit(_) => Type::char_ptr(),
        ExprKind::Cast { ty, .. } => lower_type(ty, named, ptr_size).unwrap_or_else(|_| Type::i32()),
        ExprKind::SizeofType(_) | ExprKind::SizeofExpr(_) => Type::u64(),
        ExprKind::Unary { op: UnOpKind::Addr, expr } => {
            Type::Pointer(Box::new(typeof_expr_type(expr, named, ptr_size)))
        }
        ExprKind::Unary { op: UnOpKind::Deref, expr } => {
            match typeof_expr_type(expr, named, ptr_size) {
                Type::Pointer(inner) => *inner,
                other => other,
            }
        }
        _ => Type::i32(),
    }
}
