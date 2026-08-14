use std::collections::HashMap;
use std::cell::RefCell;
use crate::ast::*;
use crate::Result;
use crate::CompileError;
use sic_ir::{Type, StructType, UnionType, FunctionType};

thread_local! {
    /// File-scope enum constants, published by the Lowerer so that array
    /// dimensions like `T arr[MODULE_INIT_MAX]` (an enum constant) resolve during
    /// the scope-less `lower_type` path. Without this a global array sized by an
    /// enum comes out length 0 — QEMU's `init_type_list[MODULE_INIT_MAX]` then
    /// overlaps the next global and crashes at startup.
    static ENUM_CONSTS: RefCell<HashMap<String, i64>> = RefCell::new(HashMap::new());
}

/// Publish the current file-scope enum constants for array-dimension folding.
pub fn set_enum_consts(m: &HashMap<String, i64>) {
    ENUM_CONSTS.with(|c| *c.borrow_mut() = m.clone());
}

/// The x86-64 System V `__builtin_va_list`: `__va_list_tag[1]`, where the tag is
/// `{u32 gp_offset; u32 fp_offset; void* overflow_arg_area; void* reg_save_area;}`
/// (24 bytes). Modeling it as a one-element array gives the correct C decay:
/// passing `ap` yields `&ap[0]`, matching what glibc's `vfprintf` expects.
pub fn va_list_type() -> Type {
    let tag = Type::Struct(StructType::plain(
        Some("__va_list_tag".to_string()),
        vec![
            ("gp_offset".to_string(), Type::Int { bits: 32, signed: false }),
            ("fp_offset".to_string(), Type::Int { bits: 32, signed: false }),
            ("overflow_arg_area".to_string(), Type::Pointer(Box::new(Type::Void))),
            ("reg_save_area".to_string(), Type::Pointer(Box::new(Type::Void))),
        ],
        false,
    ));
    Type::Array { elem: Box::new(tag), len: 1 }
}

/// Convert an AST type to an IR type.
/// Type equality for `_Generic` association matching (file-scope variant of the
/// FuncCtx `generic_type_eq`): named aggregates compare by name, since a pointee
/// may be stored opaque in one place and fully populated in another.
pub fn type_matches_generic(a: &Type, b: &Type) -> bool {
    match (a, b) {
        (Type::Pointer(x), Type::Pointer(y)) => type_matches_generic(x, y),
        (Type::Struct(s1), Type::Struct(s2)) => match (&s1.name, &s2.name) {
            (Some(n1), Some(n2)) => n1 == n2,
            _ => a == b,
        },
        (Type::Union(u1), Type::Union(u2)) => match (&u1.name, &u2.name) {
            (Some(n1), Some(n2)) => n1 == n2,
            _ => a == b,
        },
        _ => a == b,
    }
}

/// An enum's underlying integer type is signed only if some enumerator is
/// negative; otherwise it is unsigned (matching GCC/Clang). Enumerator values
/// are auto-incremented from 0, so a negative value can only come from an
/// explicit negative initializer — evaluate those; unresolvable ones are assumed
/// non-negative (the common case).
fn enum_is_signed(e: &EnumDef) -> bool {
    let Some(variants) = &e.variants else { return false };
    let empty = HashMap::new();
    let mut next: i64 = 0;
    for v in variants {
        let val = match &v.value {
            Some(expr) => match super::eval_const_expr(expr, &empty) {
                Ok(n) => n,
                Err(_) => { next = next.saturating_add(1); continue; }
            },
            None => next,
        };
        if val < 0 { return true; }
        next = val.saturating_add(1);
    }
    false
}

/// The underlying integer type of an enum. Normally `int` (32-bit); a
/// `__attribute__((packed))` enum uses the smallest standard integer that holds
/// every enumerator (1/2/4/8 bytes), which shrinks any struct containing it
/// (QEMU's `FloatClass` is packed → 1 byte → `FloatParts128` is 24 not 32).
fn enum_int_type(e: &EnumDef) -> Type {
    let signed = enum_is_signed(e);
    if !e.packed {
        return Type::Int { bits: 32, signed };
    }
    // Compute the value range to pick the smallest fitting width.
    let empty = HashMap::new();
    let (mut lo, mut hi): (i64, i64) = (0, 0);
    let mut next: i64 = 0;
    if let Some(variants) = &e.variants {
        for v in variants {
            let val = match &v.value {
                Some(expr) => match super::eval_const_expr(expr, &empty) {
                    Ok(n) => n,
                    Err(_) => { next = next.saturating_add(1); continue; }
                },
                None => next,
            };
            lo = lo.min(val);
            hi = hi.max(val);
            next = val.saturating_add(1);
        }
    }
    let bits = if signed {
        if lo >= i8::MIN as i64 && hi <= i8::MAX as i64 { 8 }
        else if lo >= i16::MIN as i64 && hi <= i16::MAX as i64 { 16 }
        else if lo >= i32::MIN as i64 && hi <= i32::MAX as i64 { 32 }
        else { 64 }
    } else if hi <= u8::MAX as i64 { 8 }
    else if hi <= u16::MAX as i64 { 16 }
    else if hi <= u32::MAX as i64 { 32 }
    else { 64 };
    Type::Int { bits, signed }
}

pub fn lower_type(qt: &QualType, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    lower_ast_type(&qt.ty, named, ptr_size)
}

/// Like lower_type, but array parameters decay to pointer-to-element (C semantics).
pub fn lower_param_type(qt: &QualType, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    let ty = lower_type(qt, named, ptr_size)?;
    // Only a *syntactic* array parameter (`T a[N]`) decays to a pointer. A vector
    // (`vector_size`) type is written as a typedef name that merely *resolves* to
    // an array; it is passed by value like a struct and must not decay.
    let syntactic_array = matches!(qt.ty, AstType::Array { .. });
    Ok(match ty {
        Type::Array { elem, .. } if syntactic_array => Type::Pointer(elem),
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
            // Keep pointee aggregates *opaque* (name only, no fields). A pointer
            // is always `ptr_size` bytes, so the pointee's layout is not needed
            // here — and fully expanding it makes densely pointer-connected
            // struct graphs blow up (each shared pointee is cloned into every
            // referrer, an exponential in the DAG). Field access / sizeof of the
            // pointee re-resolves the full definition by name via `named`.
            Type::Pointer(Box::new(opaque_aggregate(inner)))
        }
        AstType::Array { base, size } => {
            let elem = lower_type(base, named, ptr_size)?;
            let len = if let Some(sz) = size {
                // Fold the (constant) length expression — handles arithmetic like
                // `3 << 27` or `800 * 512 * 4`, and `sizeof(T)` / `offsetof(...)`
                // (needed for e.g. `u8 space[offsetof(SrcList,a)+sizeof(SrcItem)]`).
                // Genuine VLAs / non-constant sizes evaluate to 0, as before.
                // Enum constants resolve via the published `ENUM_CONSTS`.
                ENUM_CONSTS.with(|ec| {
                    eval_const_size(sz, named, ptr_size, &ec.borrow())
                        .filter(|&v| v >= 0)
                        .map(|v| v as usize)
                })
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
            // Apply the aggregate-return sret ABI so function-pointer types match
            // the (sret-lowered) functions assigned to them and called indirectly.
            Type::Function(Box::new(super::build_fn_sig(ret_ty, param_tys?, *variadic)))
        }
        AstType::Struct(s) => lower_struct(s, named, ptr_size)?,
        AstType::Union(u)  => lower_union(u, named, ptr_size)?,
        // An enum's underlying type is unsigned when every enumerator is
        // non-negative (GCC/Clang behaviour), signed otherwise. This matters for
        // enum-typed bit-fields: QEMU's TCGTemp has `TCGTempKind kind:3`, and a
        // value like `TEMP_CONST` (4 = 0b100) must read back as 4, not sign-extend
        // to -4 (which made TCG liveness analysis hit g_assert_not_reached).
        AstType::Enum(e)   => enum_int_type(e),
        AstType::Typeof(e) => typeof_expr_type(e, named, ptr_size),
        AstType::Named(n) | AstType::Builtin(n) => {
            if n == "__builtin_va_list" {
                return Ok(va_list_type());
            }
            // sic/Rust-style primitive type aliases
            match n.as_str() {
                "int8"   | "i8"   => return Ok(Type::Int { bits: 8,   signed: true  }),
                "int16"  | "i16"  => return Ok(Type::Int { bits: 16,  signed: true  }),
                "int32"  | "i32"  => return Ok(Type::Int { bits: 32,  signed: true  }),
                "int64"  | "i64"  => return Ok(Type::Int { bits: 64,  signed: true  }),
                "int128" | "i128" | "__int128" | "__int128_t" => return Ok(Type::Int { bits: 128, signed: true  }),
                "__uint128_t" => return Ok(Type::Int { bits: 128, signed: false }),
                "uint8"  | "u8"   => return Ok(Type::Int { bits: 8,   signed: false }),
                "uint16" | "u16"  => return Ok(Type::Int { bits: 16,  signed: false }),
                "uint32" | "u32"  => return Ok(Type::Int { bits: 32,  signed: false }),
                "uint64" | "u64"  => return Ok(Type::Int { bits: 64,  signed: false }),
                "uint128"| "u128" => return Ok(Type::Int { bits: 128, signed: false }),
                "isize"           => return Ok(Type::Int { bits: ptr_size * 8, signed: true  }),
                "usize"           => return Ok(Type::Int { bits: ptr_size * 8, signed: false }),
                // Extended float types. sic has no true 128/80-bit float codegen,
                // so these share `Float80` (16 bytes, computed as f64) — enough to
                // compile code that merely passes them around. `_Float16` is 2
                // bytes, `_Float32`/`_Float64` map to float/double.
                "__float128" | "_Float128" | "_Float128x" | "__float80" | "__ibm128"
                | "_Float64x"     => return Ok(Type::Float80),
                "_Float64"        => return Ok(Type::Float64),
                "_Float32" | "_Float32x" => return Ok(Type::Float32),
                // 16-bit floats: sic has no half/bfloat16 codegen, so carry them
                // as a 2-byte scalar (enough to parse & pass around intrinsics).
                "_Float16" | "__bf16" | "__fp16" => return Ok(Type::Int { bits: 16, signed: false }),
                _ => {}
            }
            named.get(n).cloned().ok_or_else(|| {
                CompileError::new(format!("unknown type '{}'", n))
            })?
        }
    })
}

/// Reduce a named struct/union to an opaque (field-less) reference. Used for
/// pointer pointees so the type graph stays small; the full definition is
/// recovered on demand with [`resolve_aggregate`].
pub fn opaque_aggregate(t: Type) -> Type {
    match t {
        Type::Struct(st) if st.name.is_some() =>
            Type::Struct(StructType::plain(st.name, vec![], st.packed)),
        Type::Union(u) if u.name.is_some() =>
            Type::Union(UnionType { name: u.name, fields: vec![], field_aligns: vec![], min_align: u.min_align }),
        other => other,
    }
}

/// If `ty` is an opaque (field-less) named struct/union, return its full
/// definition from the type table; otherwise return `ty` unchanged.
pub fn resolve_aggregate(ty: &Type, named: &HashMap<String, Type>) -> Type {
    let name = match ty {
        Type::Struct(st) if st.fields.is_empty() && st.name.is_some() => st.name.as_ref().unwrap(),
        Type::Union(u)  if u.fields.is_empty()  && u.name.is_some()  => u.name.as_ref().unwrap(),
        _ => return ty.clone(),
    };
    named.get(name).cloned().unwrap_or_else(|| ty.clone())
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
        return Ok(Type::Struct(StructType::plain(s.name.clone(), vec![], false)));
    }
    let fields = s.fields.as_ref().unwrap();
    let mut ir_fields = Vec::new();
    let mut bitfields = Vec::new();
    let mut field_aligns = Vec::new();
    let mut any_bitfield = false;
    let mut any_align = false;
    for f in fields {
        let fname = f.name.clone().unwrap_or_default();
        let fty = lower_type(&f.ty, named, ptr_size)?;
        let bw = f.bit_width.as_ref().map(|e| eval_bit_width(e));
        if bw.is_some() { any_bitfield = true; }
        if f.align.is_some() { any_align = true; }
        ir_fields.push((fname, fty));
        bitfields.push(bw);
        field_aligns.push(f.align);
    }
    Ok(Type::Struct(StructType {
        name: s.name.clone(),
        fields: ir_fields,
        packed: false,
        bitfields: if any_bitfield { bitfields } else { Vec::new() },
        field_aligns: if any_align { field_aligns } else { Vec::new() },
        min_align: s.align,
    }))
}

/// Type-aware constant folder for array dimensions. Extends the plain integer
/// arithmetic of [`super::eval_const_expr`] with `sizeof(T)` and
/// `__builtin_offsetof(T, ...)`, which need the type table and pointer width.
/// Returns `None` for non-constant (e.g. VLA) expressions.
pub fn eval_const_size(
    e: &Expr,
    named: &HashMap<String, Type>,
    ptr_size: u32,
    enum_consts: &HashMap<String, i64>,
) -> Option<i64> {
    use crate::ast::{ExprKind, UnOpKind, BinOpKind, OffsetDesignator};
    match &e.kind {
        ExprKind::IntLit(v, _) => Some(*v),
        ExprKind::UIntLit(v, _) => Some(*v as i64),
        ExprKind::CharLit(v) => Some(*v as i64),
        ExprKind::Ident(name) => enum_consts.get(name.as_str()).copied(),
        ExprKind::SizeofType(qt) => {
            let t = lower_ast_type(&qt.ty, named, ptr_size).ok()?;
            Some(t.size_of(ptr_size) as i64)
        }
        ExprKind::AlignofType(qt) => {
            let t = lower_ast_type(&qt.ty, named, ptr_size).ok()?;
            Some(t.align_of(ptr_size) as i64)
        }
        ExprKind::OffsetOf { ty, designators } => {
            let mut cur = lower_ast_type(&ty.ty, named, ptr_size).ok()?;
            let mut offset: i64 = 0;
            for d in designators {
                match d {
                    OffsetDesignator::Field(name) => {
                        // Use the offset-aware resolver so a member reached
                        // through an anonymous struct/union counts its enclosing
                        // member's offset too. QEMU's VirtIODevice wraps
                        // `host_features` in an anonymous union, and
                        // `offsetof(VirtIODevice, host_features)` in the static
                        // `virtio_properties[]` initializer failed to fold with the
                        // plain direct-field lookup — zeroing the whole array.
                        let resolved = resolve_aggregate(&cur, named);
                        let (foff, fty, _bf) =
                            super::expr::resolve_field_access(&resolved, name, ptr_size, named)?;
                        offset += foff as i64;
                        cur = fty;
                    }
                    OffsetDesignator::Index(ie) => {
                        let i = eval_const_size(ie, named, ptr_size, enum_consts)?;
                        let elem = match &cur {
                            Type::Array { elem, .. } => *elem.clone(),
                            Type::Pointer(t) => *t.clone(),
                            other => other.clone(),
                        };
                        offset += i.wrapping_mul(elem.size_of(ptr_size) as i64);
                        cur = elem;
                    }
                }
            }
            Some(offset)
        }
        ExprKind::Unary { op: UnOpKind::Neg, expr } =>
            Some(eval_const_size(expr, named, ptr_size, enum_consts)?.wrapping_neg()),
        ExprKind::Unary { op: UnOpKind::BitNot, expr } =>
            Some(!eval_const_size(expr, named, ptr_size, enum_consts)?),
        ExprKind::Unary { op: UnOpKind::Not, expr } =>
            Some(if eval_const_size(expr, named, ptr_size, enum_consts)? == 0 { 1 } else { 0 }),
        ExprKind::BinOp { op, lhs, rhs } => {
            let l = eval_const_size(lhs, named, ptr_size, enum_consts)?;
            let r = eval_const_size(rhs, named, ptr_size, enum_consts)?;
            Some(match op {
                BinOpKind::Add => l.wrapping_add(r),
                BinOpKind::Sub => l.wrapping_sub(r),
                BinOpKind::Mul => l.wrapping_mul(r),
                BinOpKind::Div if r != 0 => l / r,
                BinOpKind::Rem if r != 0 => l % r,
                BinOpKind::BitAnd => l & r,
                BinOpKind::BitOr  => l | r,
                BinOpKind::BitXor => l ^ r,
                BinOpKind::Shl    => l << (r & 63),
                BinOpKind::Shr    => l >> (r & 63),
                BinOpKind::Eq     => (l == r) as i64,
                BinOpKind::Ne     => (l != r) as i64,
                BinOpKind::Lt     => (l < r) as i64,
                BinOpKind::Le     => (l <= r) as i64,
                BinOpKind::Gt     => (l > r) as i64,
                BinOpKind::Ge     => (l >= r) as i64,
                BinOpKind::LogAnd => (l != 0 && r != 0) as i64,
                BinOpKind::LogOr  => (l != 0 || r != 0) as i64,
                // Div/Rem by zero fall through here.
                BinOpKind::Div | BinOpKind::Rem => return None,
            })
        }
        ExprKind::Ternary { cond, then, else_ } => {
            if eval_const_size(cond, named, ptr_size, enum_consts)? != 0 {
                eval_const_size(then, named, ptr_size, enum_consts)
            } else {
                eval_const_size(else_, named, ptr_size, enum_consts)
            }
        }
        ExprKind::Cast { expr, .. } => eval_const_size(expr, named, ptr_size, enum_consts),
        // Fall back to the plain integer evaluator for anything else.
        _ => super::eval_const_expr(e, enum_consts).ok(),
    }
}

/// Evaluate a bit-field width (a constant integer expression).
fn eval_bit_width(e: &crate::ast::Expr) -> u32 {
    use crate::ast::ExprKind;
    match &e.kind {
        ExprKind::IntLit(v, _) => *v as u32,
        ExprKind::UIntLit(v, _) => *v as u32,
        _ => super::eval_const_expr(e, &HashMap::new()).unwrap_or(0) as u32,
    }
}

fn lower_union(u: &UnionDef, named: &HashMap<String, Type>, ptr_size: u32) -> crate::Result<Type> {
    if u.fields.is_none() {
        if let Some(name) = &u.name {
            if let Some(ty) = named.get(name) {
                return Ok(ty.clone());
            }
        }
        return Ok(Type::Union(UnionType { name: u.name.clone(), fields: vec![], field_aligns: vec![], min_align: None }));
    }
    let fields = u.fields.as_ref().unwrap();
    let mut ir_fields = Vec::new();
    let mut field_aligns = Vec::new();
    let mut any_align = false;
    for f in fields {
        let fname = f.name.clone().unwrap_or_default();
        let fty = lower_type(&f.ty, named, ptr_size)?;
        if f.align.is_some() { any_align = true; }
        ir_fields.push((fname, fty));
        field_aligns.push(f.align);
    }
    Ok(Type::Union(UnionType {
        name: u.name.clone(),
        fields: ir_fields,
        field_aligns: if any_align { field_aligns } else { Vec::new() },
        min_align: u.align,
    }))
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
        ExprKind::SizeofType(_) | ExprKind::SizeofExpr(_)
        | ExprKind::AlignofType(_) | ExprKind::AlignofExpr(_) => Type::u64(),
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
