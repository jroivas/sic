use crate::ast::{self, Expr, ExprKind, BinOpKind, UnOpKind};
use crate::{Result, CompileError};
use super::super::func::{FuncCtx, LookupResult};
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    pub fn infer_expr_type(&self, expr: &Expr) -> Result<Type> {
        match &expr.kind {
            ExprKind::Generic { controlling, assocs } => {
                let idx = self.select_generic(controlling, assocs)?;
                self.infer_expr_type(&assocs[idx].1)
            }
            ExprKind::OffsetOf { .. } => Ok(Type::u64()),
            ExprKind::CharLit(_) => Ok(Type::i32()),
            // sic `true`/`false` is `bool` (so `any b = true` boxes with BOOL kind).
            ExprKind::BoolLit(_) => Ok(Type::Bool),
            ExprKind::IntLit(_, is64) => Ok(if *is64 { Type::i64() } else { Type::i32() }),
            ExprKind::UIntLit(_, is64) => Ok(if *is64 { Type::Int { bits: 64, signed: false } } else { Type::u32() }),
            ExprKind::BigIntLit(_) => Ok(super::super::types::bigint_type()),
            // A bare decimal literal defaults to `double`; in a fixed context it is
            // intercepted before inference is consulted.
            ExprKind::DecimalLit(_) => Ok(Type::Float64),
            ExprKind::TypeId(_) | ExprKind::TypeIdOf(_) => Ok(super::super::types::type_info_type()),
            // A guard block yields an `int` status (0 clean / 1 caught).
            ExprKind::Guard { .. } => Ok(Type::i32()),
            // sic lambda (sic.md §"Lambdas"): a function-pointer value. Return-type
            // inference needs the params in scope (a `&mut` scratch context), which
            // this `&self` inferer can't build — so an unannotated lambda reports a
            // `void` return here. That is enough for the always-target-typed inline
            // positions this is used in; `auto x = <lambda>` infers precisely in the
            // declaration path instead.
            ExprKind::Lambda { params, ret, .. } => {
                let mut ir_params = Vec::new();
                for p in params {
                    ir_params.push(super::super::types::lower_param_type(
                        &p.ty, &self.lowerer.struct_types, self.lowerer.ptr_size)?);
                }
                let ir_ret = match ret {
                    Some(r) => super::super::types::lower_type(r, &self.lowerer.struct_types, self.lowerer.ptr_size)?,
                    None => Type::Void,
                };
                let sig = super::super::build_fn_sig(ir_ret, ir_params, false, self.lowerer.ptr_size);
                Ok(Type::Pointer(Box::new(Type::Function(Box::new(sig)))))
            }
            ExprKind::FloatLit(_) => Ok(Type::Float64),
            // sic (sic.md §"Strings"): a string literal is a native `string` (a view
            // over the static bytes) by default; it decays to `char*` only where a
            // `char*` is expected. C keeps it a `char*`.
            ExprKind::StringLit(_) => Ok(if self.is_sic() {
                super::super::types::sic_string_type(self.ptr_size())
            } else {
                Type::char_ptr()
            }),
            ExprKind::Nullptr => Ok(Type::void_ptr()),
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, _)) => Ok(ty.clone()),
                    Some(LookupResult::Global(ty, _)) => Ok(ty.clone()),
                    Some(LookupResult::EnumConst(_)) => Ok(Type::i32()),
                    Some(LookupResult::Func(_)) => Ok(Type::void_ptr()),
                    None => Ok(Type::i32()),
                }
            }
            ExprKind::Cast { ty, .. } => self.lower_type(ty),
            // `sizeof((int[]){1, 2, 3})` is the whole array (it used to be `int`).
            ExprKind::CompoundLiteral { ty, init } => Ok(self.lowerer.compound_literal_type(self.lower_type(ty)?, init)),
            ExprKind::ChooseExpr { cond, then, else_ } => {
                if self.eval_choose_cond(cond) != 0 { self.infer_expr_type(then) }
                else { self.infer_expr_type(else_) }
            }
            ExprKind::TypesCompatible(..) => Ok(Type::i32()),
            ExprKind::SizeofType(_) | ExprKind::SizeofExpr(_)
            | ExprKind::AlignofType(_) | ExprKind::AlignofExpr(_) => Ok(Type::u64()),
            // sic bigint `-a` / `~a` keep the bigint type.
            ExprKind::Unary { op: UnOpKind::Neg | UnOpKind::BitNot, expr: inner }
                if self.is_sic() && self.is_bigint_operand(inner) =>
            {
                Ok(super::super::types::bigint_type())
            }
            ExprKind::Unary { op: UnOpKind::Addr, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                // `&container` ≡ the container handle (`dict* ≡ dict`; see lower_unary).
                if self.is_sic() && (super::super::types::is_dict(&inner_ty)
                    || super::super::types::is_list(&inner_ty) || super::super::types::is_set(&inner_ty)) {
                    return Ok(inner_ty);
                }
                Ok(Type::Pointer(Box::new(inner_ty)))
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                // `*container` ≡ the container handle (the `dict* ≡ dict` collapse).
                if self.is_sic() && (super::super::types::is_dict(&inner_ty)
                    || super::super::types::is_list(&inner_ty) || super::super::types::is_set(&inner_ty)) {
                    return Ok(inner_ty);
                }
                Ok(match inner_ty {
                    Type::Pointer(t) => self.pointee_of(&Type::Pointer(t)),
                    // An array decays to a pointer to its element, so `*arr` is
                    // the element type — `sizeof(*arr)` must be the element size,
                    // not the default i32 (QEMU's `qsort(cmds, .., sizeof(*cmds), ..)`
                    // over a `static HMPCommand cmds[]` gave size 4 → memory
                    // corruption during the sort).
                    Type::Array { elem, .. } => super::super::types::resolve_aggregate(&elem, &self.lowerer.struct_types),
                    _ => Type::i32(),
                })
            }
            ExprKind::Field { base, name } => {
                // sic weak `.get` (sic.md §"Weak"): upgrades to the strong container type.
                if self.is_sic() && name == "get" {
                    if let Some(cty) = self.weak_ref_container_type(base) { return Ok(cty); }
                }
                // sic `module.var` (sic.md §"Imports"): an imported module global has
                // its exported value type (checked before base inference — the base
                // is a module name).
                if self.is_sic() && self.is_module_global(base, name) {
                    if let ExprKind::Ident(m) = &base.kind {
                        if let Some((_, ty)) = self.lowerer.imported_modules.get(m).and_then(|e| e.get(name)) {
                            return Ok(ty.clone());
                        }
                    }
                }
                let base_ty = self.infer_expr_type(base)?;
                // sic native-string computed accessors: `.ptr` (and its alias
                // `.str`) is a `char*`, `.length` is a `usize` (sic.md §"Built-in
                // string").
                if self.is_sic() && super::super::types::is_sic_string(&base_ty) {
                    if name == "ptr" || name == "str" { return Ok(Type::char_ptr()); }
                    if name == "length" { return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false }); }
                    if name == "dup" { return Ok(super::super::types::sic_string_type(self.ptr_size())); }
                    if name == "utf8" { return Ok(super::super::types::u8char_arr_type(self.ptr_size())); }
                }
                // sic `u8char.size` is a `usize` (UTF-8 encoded length).
                if self.is_sic() && name == "size" && super::super::types::is_u8char(&base_ty) {
                    return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false });
                }
                // sic `enumvalue.str` is a native `string` — for a payload-less
                // enum variable/constant, or any tagged-enum value.
                if self.is_sic() && name == "str" {
                    if let ExprKind::Ident(id) = &base.kind {
                        if self.enum_locals.contains_key(id)
                            || self.lowerer.c_enum_variant.contains_key(id) {
                            return Ok(super::super::types::sic_string_type(self.ptr_size()));
                        }
                    }
                    if self.is_tagged_enum_struct(&base_ty) {
                        return Ok(super::super::types::sic_string_type(self.ptr_size()));
                    }
                }
                // `s.dup` on a C string (`char*`/`char[]`) is an owned `string`.
                if self.is_sic() && name == "dup"
                    && (matches!(&base_ty, Type::Pointer(i) if matches!(i.as_ref(), Type::Int { bits: 8, .. }))
                        || matches!(&base_ty, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }))) {
                    return Ok(super::super::types::sic_string_type(self.ptr_size()));
                }
                // sic array / va_array `.length` / `.size` are `usize`.
                if self.is_sic() && (matches!(base_ty, Type::Array { .. }) || super::super::types::is_va_array(&base_ty)
                        || super::super::types::is_tuple(&base_ty))
                    && (name == "length" || name == "size") {
                    return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false });
                }
                // sic bigint `.str` is a `char*`, `.int` an `i64` (sic.md §"Integer sizes").
                if self.is_sic() && super::super::types::is_bigint(&base_ty) {
                    if name == "str" { return Ok(Type::char_ptr()); }
                    if name == "int" { return Ok(Type::i64()); }
                }
                // sic fixed `.str` is a `char*` (sic.md §"Built-in fixed point").
                if self.is_sic() && super::super::types::is_fixed(&base_ty) && name == "str" {
                    return Ok(Type::char_ptr());
                }
                // sic container accessors (sic.md §"Iterators"): dict/set/list
                // `.size`/`.length` = usize; `.keys`/`.values` = a `list<T>`.
                if self.is_sic() {
                    // A container value is `Pointer(marker)`; a `dict*`/`list*` is
                    // `Pointer(Pointer(marker))` — recognize the direct form first.
                    let is_container = |t: &Type| super::super::types::is_dict(t)
                        || super::super::types::is_list(t) || super::super::types::is_set(t);
                    let cty = if is_container(&base_ty) {
                        Some(base_ty.clone())
                    } else if let Type::Pointer(i) = &base_ty {
                        if is_container(i) { Some((**i).clone()) } else { None }
                    } else { None };
                    if let Some(cty) = cty {
                        if name == "size" || name == "length" {
                            return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false });
                        }
                        let is_set = super::super::types::is_set(&cty);
                        // A set has only elements: both `.keys` and `.values` yield
                        // them (the element is reported as the dict key). For a dict,
                        // `.keys`/`.values` split; for a list, `.keys` are indices.
                        if name == "keys" || (is_set && name == "values") {
                            let elem = if super::super::types::is_list(&cty) {
                                Type::Int { bits: self.ptr_size() * 8, signed: false }
                            } else {
                                super::super::types::dict_kv(&cty, self.ptr_size()).map(|(k, _)| k).unwrap_or_else(super::super::types::any_type)
                            };
                            return Ok(super::super::types::list_type(&elem));
                        }
                        if name == "values" {
                            let elem = if super::super::types::is_list(&cty) {
                                super::super::types::list_elem(&cty, self.ptr_size())
                            } else {
                                super::super::types::dict_kv(&cty, self.ptr_size()).map(|(_, v)| v).unwrap_or_else(super::super::types::any_type)
                            };
                            return Ok(super::super::types::list_type(&elem));
                        }
                    }
                }
                // sic `.` on a plain-struct pointer auto-derefs (like `->`).
                let lookup_ty = if self.is_sic() && self.is_plain_aggregate_ptr(&base_ty) {
                    match &base_ty { Type::Pointer(inner) => (**inner).clone(), _ => base_ty.clone() }
                } else {
                    base_ty.clone()
                };
                if let Some((_, fty, _)) = resolve_field_access(&lookup_ty, name, self.ptr_size(), &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            ExprKind::Arrow { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                let struct_ty = match base_ty {
                    Type::Pointer(t) => *t,
                    other => other,
                };
                if let Some((_, fty, _)) = resolve_field_access(&struct_ty, name, self.ptr_size(), &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            // `base?.field` (sic.md §"Match") has the field's type — the zero value
            // on the absent path shares it.
            ExprKind::OptField { base, name } => {
                let bty = self.infer_expr_type(base)?;
                let struct_ty = match &bty {
                    Type::Pointer(p) => (**p).clone(),
                    t if self.is_tagged_enum_struct(t) =>
                        self.enum_present_variant(t).and_then(|(_, v)| v.payload).unwrap_or_else(|| Type::i32()),
                    other => other.clone(),
                };
                Ok(self.opt_field_type(&struct_ty, name).unwrap_or_else(|| Type::i32()))
            }
            ExprKind::Index { base, index } => {
                let bt = self.infer_expr_type(base)?;
                // sic `dict[key]` yields the value type V (sic.md §"Dict").
                if self.is_sic() {
                    let dt = if super::super::types::is_dict(&bt) {
                        Some(bt.clone())
                    } else if let Type::Pointer(i) = &bt {
                        if super::super::types::is_dict(i) { Some((**i).clone()) } else { None }
                    } else { None };
                    if let Some(dt) = dt {
                        if let Some((_, v)) = super::super::types::dict_kv(&dt, self.ptr_size()) {
                            return Ok(v);
                        }
                    }
                    // sic `list[i]` yields the element type T (sic.md §"List").
                    let lt = if super::super::types::is_list(&bt) { Some(bt.clone()) }
                        else if let Type::Pointer(i) = &bt {
                            if super::super::types::is_list(i) { Some((**i).clone()) } else { None }
                        } else { None };
                    if let Some(lt) = lt {
                        return Ok(super::super::types::list_elem(&lt, self.ptr_size()));
                    }
                }
                // sic `va_array` element `va[i]` is an `any` (sic.md std).
                if self.is_sic() && super::super::types::is_va_array(&bt) {
                    return Ok(super::super::types::any_type());
                }
                // sic `u8char[]` element `cps[i]` is a `u8char`.
                if self.is_sic() && super::super::types::is_u8char_arr(&bt) {
                    return Ok(super::super::types::u8char_type());
                }
                // sic `string[i]` is the byte (a `char`).
                if self.is_sic() && super::super::types::is_sic_string(&bt) {
                    return Ok(Type::i8());
                }
                // sic tuple element `t[const]` has the field's type (deref the
                // tuple pointer to its layout struct).
                if self.is_sic() {
                    if let Some(Type::Struct(st)) = super::super::types::tuple_layout_of(&bt) {
                        if let Some(i) = self.const_index(index) {
                            if let Some((_, fty)) = st.fields.get(i as usize) {
                                return Ok(fty.clone());
                            }
                        }
                    }
                }
                // `p[i]` is `*(p + i)`: for `T *p` it is a `T` — also when `T` is
                // itself an array (`int (*q)[4]` → a row; a `vector_size` vector,
                // whose `v2di *p` → `p[i]` used to be typed `long long`, so vector
                // init/assign/ops took the scalar path on its address).
                let elem = match bt {
                    Type::Pointer(t) => *t,
                    Type::Array { elem, .. } => *elem,
                    _ => Type::i32(),
                };
                // The element of a pointer-to-opaque-aggregate (e.g. `p->aCol[0]`
                // where `aCol` is `Column*`) must be resolved to its full
                // definition, or `sizeof` sees an empty struct and returns 0.
                Ok(super::super::types::resolve_aggregate(&elem, &self.lowerer.struct_types))
            }
            // A tuple pack has the anonymous positional-struct type of its elements.
            ExprKind::TupleExpr(elems) => {
                let mut tys = Vec::with_capacity(elems.len());
                for e in elems {
                    tys.push(self.infer_expr_type(e).unwrap_or_else(|_| Type::i32()));
                }
                Ok(super::super::types::tuple_type(tys))
            }
            // A tagged-enum variant path is a value of that enum's struct type.
            ExprKind::EnumVariant { enum_name, variant } => {
                // sic `module::var` (sic.md §"Imports"): imported module global's type.
                if self.is_sic() && self.lowerer.imported_modules.contains_key(enum_name) {
                    if let Some((_, ty)) = self.lowerer.imported_modules.get(enum_name).and_then(|e| e.get(variant)) {
                        if !matches!(ty, Type::Function(_)) { return Ok(ty.clone()); }
                    }
                }
                // sic namespace member `N::member` → the mangled global's type.
                if self.is_sic() {
                    if let Some(mangled) = self.lowerer.namespace_members.get(&(enum_name.clone(), variant.clone())).cloned() {
                        return self.infer_expr_type(&Expr { kind: ExprKind::Ident(mangled), span: expr.span.clone() });
                    }
                }
                // A plain C-enum variant `E::VARIANT` is an integer discriminant.
                if self.is_sic() && self.resolve_plain_enum_const(enum_name, variant).is_some() {
                    return Ok(Type::i32());
                }
                // A generic constructor (`Option::None`) resolves via the expected
                // target type (sic.md §"Match").
                let resolved = self.resolve_generic_ctor(enum_name, &expr.span).ok().flatten();
                let ename0 = resolved.as_deref().unwrap_or(enum_name);
                // A module/namespace-qualified enum (`mod::Enum`) is keyed by its
                // last segment.
                let ename = if self.lowerer.enum_defs.contains_key(ename0) { ename0 }
                            else { ename0.rsplit("::").next().unwrap_or(ename0) };
                self.lowerer.enum_defs.get(ename).map(|i| i.struct_type.clone())
                    .ok_or_else(|| CompileError::new(format!("'{}' is not a tagged enum", enum_name)))
            }
            ExprKind::Call { func, args } => {
                // sic closure call (sic.md §"Lambdas"): the result is the callable's
                // return type — the `__code` field's function return (dropping the
                // hidden environment parameter).
                if self.is_sic() {
                    if let Ok(Type::Pointer(inner)) = self.infer_expr_type(func) {
                        if let Type::Struct(st) = inner.as_ref() {
                            if st.name.as_deref().map_or(false, |n| n.starts_with(super::super::types::CLOSURE_ENV_PREFIX)) {
                                if let Some((_, Type::Pointer(code))) = st.fields.get(0) {
                                    if let Type::Function(ft) = code.as_ref() {
                                        return Ok(ft.ret.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                // `string.create(bytes, len)` builds a `string` (see lower_call).
                if self.is_sic() {
                    if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func.kind {
                        if name == "create" && (matches!(&base.kind, ExprKind::Ident(n) if n == "string")
                            || matches!(&base.kind, ExprKind::TypeIdOf(qt)
                                if matches!(&qt.ty, crate::ast::AstType::Named(n) if n == "string")))
                        {
                            return Ok(super::super::types::sic_string_type(self.ptr_size()));
                        }
                    }
                }
                // sic `string` methods (sic.md §"Built-in string"): `.contains` →
                // bool; `.split`/`.rsplit` → `tuple(string, string)`.
                if self.is_sic() {
                    if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func.kind {
                        if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_sic_string(&t)) {
                            let s = super::super::types::sic_string_type(self.ptr_size());
                            match name.as_str() {
                                "contains" | "starts_with" | "ends_with" => return Ok(Type::Bool),
                                "find" => return Ok(Type::i64()),
                                "trim" | "ltrim" | "rtrim" => return Ok(s),
                                "split" | "rsplit" => return Ok(super::super::types::tuple_type(vec![s.clone(), s])),
                                _ => {}
                            }
                        }
                    }
                }
                // sic tagged-enum constructor / unwrap.
                if let ExprKind::EnumVariant { enum_name, variant } = &func.kind {
                    let resolved = self.resolve_generic_ctor(enum_name, &expr.span).ok().flatten();
                    let enum_name0 = resolved.as_deref().unwrap_or(enum_name.as_str());
                    let enum_name = if self.lowerer.enum_defs.contains_key(enum_name0) { enum_name0 }
                                    else { enum_name0.rsplit("::").next().unwrap_or(enum_name0) };
                    if let Some(info) = self.lowerer.enum_defs.get(enum_name) {
                        // `Enum::VARIANT(inst)` unwraps → payload type; otherwise
                        // it constructs → the enum struct.
                        if let Some(v) = info.variant(variant) {
                            if v.payload.is_some() && args.len() == 1 {
                                if let Ok(t) = self.infer_expr_type(&args[0]) {
                                    if self.is_enum_struct(&t, enum_name) {
                                        return Ok(v.payload.clone().unwrap());
                                    }
                                }
                            }
                        }
                        return Ok(info.struct_type.clone());
                    }
                }
                // Bare variant constructor `Ok(5)`.
                if let ExprKind::Ident(name) = &func.kind {
                    if self.is_sic() && !matches!(self.lookup(name), Some(LookupResult::Func(_))) {
                        if let Some(en) = self.lowerer.variant_enum.get(name) {
                            if let Some(info) = self.lowerer.enum_defs.get(en) {
                                return Ok(info.struct_type.clone());
                            }
                        }
                    }
                }
                // sic struct method call `obj.method(...)` → the hoisted method's
                // return type (so `auto r = it.next();` infers `Iterator<T>`).
                if self.is_sic() && !self.lowerer.struct_methods.is_empty() {
                    if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func.kind {
                        let sname = match self.infer_expr_type(base).ok() {
                            Some(Type::Struct(st)) => st.name,
                            Some(Type::Pointer(inner)) => match *inner { Type::Struct(st) => st.name, _ => None },
                            _ => None,
                        };
                        if let Some(mangled) = sname
                            .and_then(|s| self.lowerer.struct_methods.get(&(s, name.clone())).cloned())
                        {
                            if let Some(fref) = self.lowerer.module.func_ref_by_name(&mangled) {
                                return Ok(self.lowerer.module.func_sig(fref).ret.clone());
                            }
                        }
                    }
                }
                // Return type of the callee. A direct call resolves via the
                // module signature; an indirect call takes the pointee function
                // type's return. Without this a call defaults to i32 and a
                // pointer-returning call in a ternary gets truncated to 32 bits.
                if let ExprKind::Ident(name) = &func.kind {
                    if let Some(LookupResult::Func(fref)) = self.lookup(name) {
                        return Ok(self.lowerer.module.func_sig(fref).ret.clone());
                    }
                }
                // Namespaced module call `mod.fn(...)`: the result type is the export's
                // declared return (user-facing, no sret ptr). Without this a
                // string-returning `std.Fmt(...)` defaults to i32 and its initializer
                // mistakes the result for a `char*`.
                // Both spellings of a module call: `mod.fn(...)` (Field) and the
                // canonical `Module::fn(...)` (EnumVariant, sic.md §"Namespace").
                let module_sym = match &func.kind {
                    ExprKind::Field { base, name } => match &base.kind {
                        ExprKind::Ident(m) => Some((m.clone(), name.clone())),
                        _ => None,
                    },
                    // `Module::sym` (flat) or `Module::A::B::sym` (nested): the export
                    // name mangles the intra-module scope path with `__`.
                    ExprKind::EnumVariant { enum_name, variant } => match enum_name.split_once("::") {
                        Some((module, rest)) => Some((module.to_string(), format!("{}__{}", rest.replace("::", "__"), variant))),
                        None => Some((enum_name.clone(), variant.clone())),
                    },
                    _ => None,
                };
                if let Some((m, name)) = module_sym {
                    if let Some(Type::Function(ft)) = self.lowerer.imported_modules
                        .get(&m).and_then(|ex| ex.get(&name)).map(|(_, t)| t)
                    {
                        return Ok(ft.ret.clone());
                    }
                }
                let fty = self.infer_expr_type(func)?;
                Ok(match fty {
                    Type::Pointer(inner) => match *inner {
                        Type::Function(ft) => ft.ret.clone(),
                        _ => Type::i32(),
                    },
                    Type::Function(ft) => ft.ret.clone(),
                    _ => Type::i32(),
                })
            }
            // sic Option/Result unwrap-or-default `opt ?: default` — the result is
            // the payload type (sic.md §"Match").
            ExprKind::Elvis { cond, else_: _ }
                if self.is_sic() && matches!(self.infer_expr_type(cond), Ok(t) if self.is_tagged_enum_struct(&t)) =>
            {
                let t = self.infer_expr_type(cond)?;
                match self.enum_present_variant(&t).and_then(|(_, v)| v.payload) {
                    Some(pty) => Ok(pty),
                    None => Ok(Type::i32()),
                }
            }
            // An expression `match` has the type of its value arms.
            ExprKind::Match { arms, .. } => Ok(self.match_result_type(arms)),
            ExprKind::Ternary { then, else_, .. }
            | ExprKind::Elvis { cond: then, else_ } => {
                // Mirror lower_ternary/lower_elvis's result-type selection.
                let tty = self.infer_expr_type(then).unwrap_or_else(|_| Type::i32());
                let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());
                Ok(match (&tty, &ety) {
                    (Type::Pointer(_), _) | (Type::Void, _) => tty,
                    (_, Type::Pointer(_)) => ety,
                    _ if tty.is_float() => tty,
                    _ if ety.is_float() => ety,
                    _ if ety.size_of(self.ptr_size()) > tty.size_of(self.ptr_size()) => ety,
                    _ => tty,
                })
            }
            ExprKind::Assign { lhs, .. } => self.infer_expr_type(lhs),
            // A substring slice is itself a `string` (sic.md §"Built-in string").
            ExprKind::Slice { .. } => Ok(super::super::types::sic_string_type(self.ptr_size())),
            // `new T` / `new T(n)` yields `T*`.
            ExprKind::New { ty, .. } => {
                let elem = self.lower_type(ty)?;
                // `new dict<…>` / `new set<…>` / `new list<…>` yield the container
                // handle itself (already a heap pointer), not a pointer to it.
                if super::super::types::is_dict(&elem) || super::super::types::is_list(&elem) { Ok(elem) }
                else { Ok(Type::Pointer(Box::new(elem))) }
            }
            // `@expr` has the referent's (pointer) type.
            ExprKind::Ref { expr, .. } => self.infer_expr_type(expr),
            ExprKind::Comma(_, rhs) => self.infer_expr_type(rhs),
            // GCC statement expression `({ ...; expr; })` has the type of its last
            // statement when that is an expression statement, else void. Needed so
            // `typeof(({...; p;}))` (QEMU's nested qobject_ref) keeps `p`'s type.
            // A trailing bare identifier is usually a temporary declared inside the
            // block (`typeof(x) _o = x; _o;`), invisible to the outer scope, so
            // resolve such declarators here.
            ExprKind::StmtExpr(stmts) => {
                match stmts.last() {
                    Some(ast::Stmt::Expr(e, _)) => {
                        if let ExprKind::Ident(name) = &e.kind {
                            for stmt in stmts {
                                if let ast::Stmt::Decl(ast::Decl::Var { declarators, .. }) = stmt {
                                    if let Some(d) = declarators.iter().find(|d| &d.name == name) {
                                        return self.lower_type(&d.ty);
                                    }
                                }
                            }
                        }
                        self.infer_expr_type(e)
                    }
                    _ => Ok(Type::Void),
                }
            }
            ExprKind::BinOp { op, lhs, rhs } => {
                use BinOpKind::*;
                // Infer each operand's type ONCE and reuse it for every predicate
                // below. Re-inferring per predicate (bigint/fixed/string checks
                // each call `infer_expr_type` again) turned a left-associative
                // chain like `a + b + c + …` into O(4^n) — each BinOp re-walked
                // each child roughly four times.
                let lt = self.infer_expr_type(lhs).unwrap_or_else(|_| Type::i32());
                let rt = self.infer_expr_type(rhs).unwrap_or_else(|_| Type::i32());
                // GCC vector extension: an arithmetic/bitwise/comparison operator on
                // two vector (array) operands is element-wise and yields a vector of
                // the same shape (a comparison yields a same-width integer mask
                // vector). This mirrors the dispatch to `lower_vector_binop` and must
                // run before `arith_result_type`/the relational arm below, which would
                // otherwise decay the arrays to a pointer or report `int`. Excludes
                // the `is_sic && Add` case, which `lower_binop` routes to array
                // concatenation (handled by the `Add` arm below) rather than an
                // element-wise vector add.
                if !matches!(op, LogAnd | LogOr) && !(self.is_sic() && matches!(op, Add)) {
                    if let (Type::Array { .. }, Type::Array { .. }) = (&lt, &rt) {
                        return Ok(lt);
                    }
                }
                // sic `bigint` arithmetic yields a bigint; comparisons yield int.
                if self.is_sic() && matches!(op, Add | Sub | Mul | Div | Rem | BitAnd | BitOr | BitXor | Shl | Shr)
                    && (super::super::types::is_bigint(&lt) || super::super::types::is_bigint(&rt))
                {
                    return Ok(super::super::types::bigint_type());
                }
                // sic `fixed` arithmetic yields a fixed<I,F> (comparisons yield int,
                // handled below). I/F combine per `fixed_result_dims`.
                if self.is_sic() && matches!(op, Add | Sub | Mul | Div | Rem)
                    && (super::super::types::is_fixed(&lt) || super::super::types::is_fixed(&rt))
                {
                    let da = self.fixed_expr_dims(lhs).unwrap_or((20, 0));
                    let db = self.fixed_expr_dims(rhs).unwrap_or((20, 0));
                    let (i, f) = Self::fixed_result_dims(*op, da, db);
                    return Ok(super::super::types::fixed_type(i, f));
                }
                match op {
                    // Relational/logical operators yield int.
                    Eq | Ne | Lt | Le | Gt | Ge | LogAnd | LogOr => Ok(Type::i32()),
                    // sic string concatenation yields a `string` (either side a
                    // `string` — a literal already infers as `string` in sic).
                    Add if self.is_sic()
                        && (super::super::types::is_sic_string(&lt) || super::super::types::is_sic_string(&rt)) =>
                        Ok(super::super::types::sic_string_type(self.ptr_size())),
                    // sic array concatenation yields an array of the combined
                    // length (sic.md §"Arrays and lists").
                    Add if self.is_sic() => {
                        match (&lt, &rt) {
                            (Type::Array { elem, len: la }, Type::Array { len: lb, .. }) =>
                                Ok(Type::Array { elem: elem.clone(), len: la + lb }),
                            _ => Ok(self.arith_result_type(op, lt, rt)),
                        }
                    }
                    // Arithmetic: pointer/array ± integer keeps the pointer type
                    // (pointer arithmetic; arrays decay to pointer-to-element).
                    // `ptr - ptr` is ptrdiff_t. Otherwise pick the "richer" operand
                    // type so float/wider integer results survive.
                    _ => Ok(self.arith_result_type(op, lt, rt)),
                }
            }
            _ => Ok(Type::i32()),
        }
    }

    /// Result type of an arithmetic binary operator (the C usual-arithmetic /
    /// pointer-arithmetic rules), factored out so the sic array/string special
    /// cases can fall back to it.
    fn arith_result_type(&self, op: &BinOpKind, lt: Type, rt: Type) -> Type {
        let decay = |t: Type| match t {
            Type::Array { elem, .. } => Type::Pointer(elem),
            other => other,
        };
        let lt = decay(lt);
        let rt = decay(rt);
        match (&lt, &rt) {
            (Type::Pointer(_), Type::Pointer(_)) if *op == BinOpKind::Sub => Type::i64(),
            (Type::Pointer(_), _) => lt,
            (_, Type::Pointer(_)) => rt,
            _ if lt.is_float() => lt,
            _ if rt.is_float() => rt,
            _ if rt.size_of(self.ptr_size()) > lt.size_of(self.ptr_size()) => rt,
            _ => lt,
        }
    }

    /// Lower a `va_list` operand to the address of its `__va_list_tag`. A local
    /// `va_list` (the builtin array, or a user-defined struct aliased to
    /// `va_list`) needs its own address; a `va_list` *parameter* has already
    /// decayed to a `__va_list_tag*`, so its value is that address.
    pub(crate) fn lower_va_list_ptr(&mut self, list: &Expr) -> Result<Val> {
        let ty = self.infer_expr_type(list).unwrap_or_else(|_| Type::void_ptr());
        if matches!(ty, Type::Array { .. } | Type::Struct(_) | Type::Union(_)) {
            if let Ok(lv) = self.lower_lvalue(list) {
                return Ok(lv.ptr);
            }
        }
        self.lower_expr(list)
    }

    /// Lower an expression expecting it to produce a pointer (for va_list etc).
    #[allow(dead_code)]
    fn lower_expr_as_ptr(&mut self, expr: &Expr) -> Result<Val> {
        match self.lower_lvalue(expr) {
            Ok(lv) => Ok(lv.ptr),
            Err(_) => self.lower_expr(expr),
        }
    }
}
