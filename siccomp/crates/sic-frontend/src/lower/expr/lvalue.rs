use crate::ast::{Expr, ExprKind, UnOpKind};
use crate::{Result, CompileError};
use sic_ir::*;
use super::super::func::{FuncCtx, LookupResult};
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    pub(crate) fn lower_lvalue(&mut self, expr: &Expr) -> Result<LValue> {
        match &expr.kind {
            // sic (sic.md §"Namespace"): `N::member` as an lvalue is the member's
            // mangled global.
            ExprKind::EnumVariant { enum_name, variant }
                if self.is_sic()
                    && self.lowerer.namespace_members.contains_key(&(enum_name.clone(), variant.clone())) =>
            {
                let mangled = self.lowerer.namespace_members[&(enum_name.clone(), variant.clone())].clone();
                self.lower_lvalue(&Expr { kind: ExprKind::Ident(mangled), span: expr.span.clone() })
            }
            ExprKind::Ident(name) => {
                let atomic = self.is_atomic_name(name);
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, vid)) => {
                        let ty = ty.clone();
                        Ok(LValue { atomic, ..LValue::plain(Val::Local(vid), ty) })
                    }
                    Some(LookupResult::Global(ty, gref)) => {
                        let ty = ty.clone();
                        Ok(LValue { atomic, ..LValue::plain(Val::Global(gref), ty) })
                    }
                    _ => Err(CompileError::at(
                        format!("'{}' is not an lvalue", name),
                        expr.span.file.clone(), expr.span.line, expr.span.col,
                    ))
                }
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let ptr = self.lower_expr(inner)?;
                let ptr_ty = self.val_type(&ptr);
                // `*x`: if `x` is an array it decays to a pointer to its element, so
                // the deref yields the element (`*arr` == `arr[0]`); if `x` is a
                // pointer-to-array it yields the whole array. The C type of `x`
                // disambiguates (both are `Pointer(Array)` in the IR).
                let inner_ty = match self.infer_expr_type(inner) {
                    Ok(Type::Array { elem, .. }) => {
                        super::super::types::resolve_aggregate(&elem, &self.lowerer.struct_types)
                    }
                    Ok(Type::Pointer(t)) => {
                        super::super::types::resolve_aggregate(&t, &self.lowerer.struct_types)
                    }
                    _ => self.pointee_of(&ptr_ty),
                };
                Ok(LValue::plain(ptr, inner_ty))
            }
            ExprKind::Index { base, index } => self.lower_lvalue_index(base, index),
            ExprKind::Field { base, name } => self.lower_lvalue_field(base, name),
            ExprKind::Arrow { base, name }  => self.lower_lvalue_arrow(base, name),
            ExprKind::CompoundLiteral { ty, .. } => {
                // A compound literal is an lvalue: materialize the temporary and
                // use its address (its rvalue lowering already yields that pointer).
                let ir_ty = self.lower_type(ty)?;
                let ptr = self.lower_expr(expr)?;
                Ok(LValue::plain(ptr, ir_ty))
            }
            _ => {
                // Not a simple lvalue.
                Err(CompileError::at(
                    "expression is not an lvalue",
                    expr.span.file.clone(), expr.span.line, expr.span.col,
                ))
            }
        }
    }

    pub(crate) fn lower_lvalue_index(&mut self, base: &Expr, index: &Expr) -> Result<LValue> {
        // C subscript is commutative: `a[b]` == `*(a + b)` == `b[a]`. When the
        // "base" is a plain integer and the "index" is the pointer/array (`3[arr]`,
        // `i[p]`), swap them so the pointer is the base — otherwise the address
        // arithmetic uses the integer as the base and dereferences garbage. Guarded
        // so the ordinary `arr[i]` / `p[i]` forms are untouched.
        let (base, index) = if self.index_operands_reversed(base, index) {
            (index, base)
        } else {
            (base, index)
        };

        // sic tuple element access `t[const]` (sic.md §"Tuples").
        if self.is_sic() {
            if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_tuple(&t)) {
                return self.tuple_field_lvalue(base, index, &base.span);
            }
            // sic `va_array` element `va[i]` (sic.md std): a pointer to the i-th
            // boxed `any` (also the lvalue used by `lower_aggregate_ptr`).
            if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_va_array(&t)) {
                let elem = self.lower_va_array_index(base, index, &base.span)?;
                return Ok(LValue::plain(elem, super::super::types::any_type()));
            }
            // sic `u8char[]` element `cps[i]` (from `string.utf8`).
            if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_u8char_arr(&t)) {
                let elem = self.lower_u8char_arr_index(base, index, &base.span)?;
                return Ok(LValue::plain(elem, super::super::types::u8char_type()));
            }
            // sic `dict[key]` whose value is an aggregate (`string`, a struct, `any`):
            // the dict-get result is a pointer to the value, usable as a (read)
            // lvalue so `d[k].field` works. (A write `d[k] = v` is intercepted in
            // `lower_assign`, so this read-lvalue is never used for assignment.)
            if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_dict(&t)
                || matches!(&t, Type::Pointer(i) if super::super::types::is_dict(i)))
            {
                let (_k, v) = self.dict_kv_of(base);
                if matches!(v, Type::Struct(_) | Type::Union(_)) {
                    let ptr = self.lower_dict_get(base, index, &base.span)?;
                    return Ok(LValue::plain(ptr, v));
                }
            }
            // sic `list[i]` whose element is an aggregate — a read-lvalue for
            // `l[i].field` (sic.md §"List").
            if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_list(&t)
                || matches!(&t, Type::Pointer(i) if super::super::types::is_list(i)))
            {
                let v = self.list_elem_of(base);
                if matches!(v, Type::Struct(_) | Type::Union(_)) {
                    let ptr = self.lower_list_get(base, index, &base.span)?;
                    return Ok(LValue::plain(ptr, v));
                }
            }
        }
        let base_val = self.lower_expr(base)?;
        let idx_val = self.lower_expr(index)?;
        let idx_i64 = self.coerce(idx_val, &Type::i64())?;

        let base_ty = self.val_type(&base_val);

        // sic fat-pointer bounds check: for `name[i]` where `name` is a
        // never-moved `new`/`@` pointer, verify `i*elem_size < header.size`.
        if self.is_sic() {
            if let ExprKind::Ident(name) = &base.kind {
                // sic loop bounds-check elimination: skip the per-access check when
                // an enclosing counting loop already proved this exact `arr[index]`
                // in-bounds via a hoisted check on the loop's index extremes.
                let proven = { let key = super::super::func::bce_index_key(index);
                    self.bce_proven.iter().any(|(a, k)| a == name && *k == key) };
                if self.fat_locals.contains(name) && !proven {
                    let elem = match &base_ty {
                        Type::Pointer(t) => super::super::types::resolve_aggregate(t, &self.lowerer.struct_types),
                        _ => Type::i32(),
                    };
                    let esz = elem.size_of(self.ptr_size()).max(1);
                    self.emit_bounds_check(base_val.clone(), idx_i64.clone(), esz)?;
                }
            }
        }

        // `Pointer(Array[T;N])` is ambiguous in the IR: it is both the address of
        // an array *variable* `T v[N]` (where `v[i]` is a `T`) and the value of a
        // pointer-to-array `T (*e)[N]` (where `e[i]` is the whole `T[N]`). The C
        // type of `base` disambiguates: an array-typed base indexes to its element,
        // a pointer-typed base dereferences one level.
        let logical = self.infer_expr_type(base).ok();
        let elem_ty = match &base_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { .. } if matches!(logical, Some(Type::Pointer(_))) => {
                    // pointer-to-array: one index yields the whole array element
                    super::super::types::resolve_aggregate(t, &self.lowerer.struct_types)
                }
                Type::Array { elem, .. } => *elem.clone(),
                other => super::super::types::resolve_aggregate(other, &self.lowerer.struct_types),
            },
            Type::Array { elem, .. } => *elem.clone(),
            _ => Type::i32(),
        };

        let elem_size = elem_ty.size_of(self.ptr_size());
        let dest = self.alloc_val();
        let result_ty = Type::Pointer(Box::new(elem_ty.clone()));
        self.push_instr(Instr::GetElemPtr { dest, base: base_val, index: idx_i64, elem_size, result_ty });
        Ok(LValue::plain(Val::Local(dest), elem_ty))
    }

    /// True for the commutative subscript form `int[ptr]` (e.g. `3[arr]`): the
    /// base is an integer/bool and the index is a pointer/array, so the two must be
    /// swapped. The ordinary `arr[i]`/`p[i]` forms (pointer/array base) return false.
    fn index_operands_reversed(&mut self, base: &Expr, index: &Expr) -> bool {
        let base_is_int = matches!(self.infer_expr_type(base), Ok(Type::Int { .. } | Type::Bool));
        let index_is_ptr = matches!(self.infer_expr_type(index), Ok(Type::Pointer(_) | Type::Array { .. }));
        base_is_int && index_is_ptr
    }

    /// sic (sic.md §"Match"): true if `ty` is a pointer to a *plain* aggregate — a
    /// user `struct`/`union`, not one of sic's built-in pointer-shaped aggregates
    /// (string/tuple/fixed/bigint/dict/list/set/…). Such a pointer auto-derefs under
    /// `.`/`?.`, so `p.field` means `p->field` (the `->` form still works too).
    pub(crate) fn is_plain_aggregate_ptr(&self, ty: &Type) -> bool {
        if let Type::Pointer(inner) = ty {
            let special = super::super::types::is_sic_string(ty) || super::super::types::is_tuple(ty)
                || super::super::types::is_fixed(ty) || super::super::types::is_bigint(ty)
                || super::super::types::is_dict(ty) || super::super::types::is_list(ty)
                || super::super::types::is_va_array(ty) || super::super::types::is_any(ty)
                || super::super::types::is_u8char(ty) || super::super::types::is_type_info(ty)
                || super::super::types::is_task(ty);
            if special { return false; }
            let resolved = super::super::types::resolve_aggregate(inner, &self.lowerer.struct_types);
            return matches!(resolved, Type::Struct(_) | Type::Union(_));
        }
        false
    }

    /// Whether `base.field` should auto-deref (sic): `base` is a plain-aggregate
    /// pointer, so `.` behaves like `->`.
    fn field_auto_derefs(&self, base: &Expr) -> bool {
        self.is_sic() && matches!(self.infer_expr_type(base), Ok(t) if self.is_plain_aggregate_ptr(&t))
    }

    pub(crate) fn lower_lvalue_field(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // sic `module.var` (sic.md §"Imports"): an imported module's exported global
        // is an lvalue over the module's extern symbol (readable and writable).
        if self.is_sic() && self.is_module_global(base, name) {
            if let ExprKind::Ident(m) = &base.kind {
                if let Some((g, ty)) = self.resolve_module_global(&m.clone(), name) {
                    return Ok(LValue::plain(Val::Global(g), ty));
                }
            }
        }
        // sic: `.` on a plain-struct pointer auto-derefs (like `->`), so `p.field`
        // and `p->field` are interchangeable (sic.md §"Match").
        if self.field_auto_derefs(base) {
            return self.lower_lvalue_arrow(base, name);
        }
        // base is normally a struct lvalue; but it can also be a struct *rvalue*
        // (e.g. `f().field` where `f` returns a struct by value), whose address is
        // the materialized temporary.
        let lv = match self.lower_lvalue(base) {
            Ok(lv) => lv,
            Err(_) => {
                let ptr = self.lower_aggregate_ptr(base)?;
                let ty = self.infer_expr_type(base)?;
                LValue::plain(ptr, ty)
            }
        };
        self.field_ptr_from(lv, name, false, &base.span)
    }

    pub(crate) fn lower_lvalue_arrow(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base is a pointer to struct — or an array, which decays to a pointer
        // to its first element (`arr->field` ≡ `arr[0].field`).
        let ptr = self.lower_expr(base)?;
        let ptr_ty = self.val_type(&ptr);
        let struct_ty = match &ptr_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { elem, .. } => (**elem).clone(),
                _ => (**t).clone(),
            },
            Type::Array { elem, .. } => (**elem).clone(),
            _ => return Err(CompileError::at(
                format!("-> applied to non-pointer (field '{}')", name),
                base.span.file.clone(), base.span.line, base.span.col)),
        };
        let lv = LValue::plain(ptr, struct_ty);
        self.field_ptr_from(lv, name, true, &base.span)
    }

    pub(crate) fn field_ptr_from(&mut self, lv: LValue, field_name: &str, via_ptr: bool, sp: &crate::lexer::Span) -> Result<LValue> {
        let struct_ty = if via_ptr {
            match &lv.ty {
                Type::Pointer(t) => *t.clone(),
                other => other.clone(),
            }
        } else {
            lv.ty.clone()
        };

        // Resolve the member — including through anonymous struct/union members —
        // to a cumulative byte offset, type, and (if any) bit-field descriptor.
        let (byte_offset, field_ty, bitfield) =
            resolve_field_access(&struct_ty, field_name, self.ptr_size(), &self.lowerer.struct_types)
                .ok_or_else(|| CompileError::at(
                    format!("no field '{}' in type", field_name),
                    sp.file.clone(), sp.line, sp.col,
                ))?;

        let base_ptr = lv.ptr;
        let dest = self.alloc_val();
        let result_ty = Type::Pointer(Box::new(field_ty.clone()));
        self.push_instr(Instr::GetFieldPtr {
            dest, base: base_ptr, field_idx: 0, struct_name: None, byte_offset, result_ty,
        });
        Ok(LValue { ptr: Val::Local(dest), ty: field_ty, bitfield, atomic: false })
    }

    // ─── Type inference ───────────────────────────────────────────────────────

    /// Resolve a `_Generic` selection to the index of the matching association.
    /// The controlling expression's type undergoes lvalue conversion (array /
    /// function decay); it is compared against each association's lowered type,
    /// falling back to the `default` association. Matching is done on the IR
    /// `Type`, which is qualifier-insensitive — adequate because only the
    /// selected branch is ever lowered.
    pub(crate) fn select_generic(&self, controlling: &Expr, assocs: &[(Option<crate::ast::QualType>, Box<Expr>)]) -> Result<usize> {
        fn decay(t: Type) -> Type {
            match t {
                Type::Array { elem, .. } => Type::Pointer(elem),
                Type::Function(_) => Type::void_ptr(),
                other => other,
            }
        }
        let ctrl_ty = decay(self.infer_expr_type(controlling)?);
        let mut default_idx = None;
        for (i, (aty, _)) in assocs.iter().enumerate() {
            match aty {
                None => default_idx = Some(i),
                Some(qt) => {
                    if generic_type_eq(&decay(self.lower_type(qt)?), &ctrl_ty) {
                        return Ok(i);
                    }
                }
            }
        }
        let sp = &controlling.span;
        default_idx.ok_or_else(|| CompileError::at(
            "no matching association in _Generic selection",
            sp.file.clone(), sp.line, sp.col,
        ))
    }

    /// Compute the byte offset of a member designator within a type, for
    /// `__builtin_offsetof`. Walks `.field` (struct/union) and `[index]` (array)
    /// steps, summing struct field offsets and array element strides.
    /// Lower `offsetof(T, ...designators...)` to a `size_t` value. A constant
    /// index folds into the constant offset; a NON-constant array index (a GCC
    /// extension, e.g. `offsetof(CPU, segs[i].base)`) makes offsetof a runtime
    /// value `const_offset + index * elem_size`. QEMU registers its per-segment
    /// TCG globals in a loop with exactly this form; treating the index as 0
    /// pointed every segment base at segs[0], breaking CS-relative addressing.
    pub(crate) fn lower_offsetof(&mut self, ty: &crate::ast::QualType, designators: &[crate::ast::OffsetDesignator]) -> Result<Val> {
        use crate::ast::OffsetDesignator;
        let mut cur = self.lower_type(ty)?;
        let mut const_off: u64 = 0;
        let mut runtime: Option<Val> = None; // accumulated runtime byte offset
        for d in designators {
            match d {
                OffsetDesignator::Field(name) => {
                    let resolved = super::super::types::resolve_aggregate(&cur, &self.lowerer.struct_types);
                    let (off, fty, _) = resolve_field_access(&resolved, name, self.ptr_size(), &self.lowerer.struct_types)
                        .ok_or_else(|| CompileError::new(format!("no field '{}' in offsetof", name)))?;
                    const_off += off;
                    cur = fty;
                }
                OffsetDesignator::Index(e) => {
                    let elem = match &cur {
                        Type::Array { elem, .. } => *elem.clone(),
                        Type::Pointer(t) => *t.clone(),
                        other => other.clone(),
                    };
                    let esz = elem.size_of(self.ptr_size());
                    if let Ok(i) = super::super::eval_const_expr(e, &self.lowerer.enum_consts) {
                        const_off += (i as u64).wrapping_mul(esz);
                    } else {
                        // Runtime index: emit `index * elem_size` and add it.
                        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
                        let iv = self.lower_expr(e)?;
                        let iv = self.coerce(iv, &usize_ty)?;
                        let term = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: term, op: BinOp::Mul, lhs: iv, rhs: Constant::uint(esz), ty: usize_ty.clone() });
                        runtime = Some(match runtime {
                            None => Val::Local(term),
                            Some(acc) => {
                                let s = self.alloc_val();
                                self.push_instr(Instr::BinOp { dest: s, op: BinOp::Add, lhs: acc, rhs: Val::Local(term), ty: usize_ty.clone() });
                                Val::Local(s)
                            }
                        });
                    }
                    cur = elem;
                }
            }
        }
        match runtime {
            None => self.coerce(Constant::uint(const_off), &Type::u64()),
            Some(rt) => {
                let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
                let dest = self.alloc_val();
                self.push_instr(Instr::BinOp { dest, op: BinOp::Add, lhs: rt, rhs: Constant::uint(const_off), ty: usize_ty });
                Ok(Val::Local(dest))
            }
        }
    }
}
