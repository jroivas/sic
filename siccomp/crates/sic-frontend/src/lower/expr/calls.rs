use crate::ast::{Expr, ExprKind};
use crate::{Result, CompileError};
use super::super::func::{FuncCtx, LookupResult};
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    /// Resolve a namespaced module call `module.sym` to a mangled extern FuncRef,
    /// creating the extern on first use. Errors if the module has no such export.
    /// A pointer/scalar argument for a UNION parameter: only legal C for a GCC
    /// `transparent_union` (glibc's `__SOCKADDR_ARG` of bind/connect/accept…,
    /// with _GNU_SOURCE), which takes the value as that member. Build the union
    /// in a temporary with the value at offset 0 and pass it (by-value ABI). It
    /// used to treat the pointer as the union's ADDRESS and copy 8 bytes from
    /// what it points at — `bind(fd, (struct sockaddr *)&un, len)` passed the
    /// sockaddr's contents as the pointer (EFAULT: QEMU's sockets all failed).
    fn transparent_union_arg(&mut self, pval: &mut Val, pty: &Type, arg: Option<&Expr>) -> Result<bool> {
        let Type::Union(u) = pty else { return Ok(false) };
        let Some(arg) = arg else { return Ok(false) };
        let aty = match self.infer_expr_type(arg) { Ok(t) => t, Err(_) => return Ok(false) };
        if matches!(aty, Type::Struct(_) | Type::Union(_) | Type::Array { .. } | Type::Void) { return Ok(false); }
        let Some((_, first)) = u.fields.first() else { return Ok(false) };
        let first = first.clone();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: pty.clone(), align: None });
        let size = pty.size_of(self.ptr_size());
        if size > 0 {
            self.push_instr(Instr::MemSet { dst: Val::Local(slot), val: Constant::zero(), size, align: pty.align_of(self.ptr_size()) });
        }
        let v = self.coerce(pval.clone(), &first)?;
        self.push_instr(Instr::Store { val: v, ptr: Val::Local(slot) });
        *pval = Val::Local(slot);
        Ok(true)
    }

    fn resolve_module_call(&mut self, module: &str, sym: &str, sp: &crate::lexer::Span) -> Result<FuncRef> {
        let (symbol, ty) = self.lowerer.imported_modules
            .get(module)
            .and_then(|m| m.get(sym))
            .cloned()
            .ok_or_else(|| CompileError::at(
                format!("module '{}' has no exported symbol '{}'", module, sym),
                sp.file.clone(), sp.line, sp.col,
            ))?;
        self.module_extern(&symbol, &ty, sp)
    }

    /// Resolve a selectively/renamed-imported bare name to its mangled extern.
    fn resolve_module_call_bare(&mut self, name: &str, sp: &crate::lexer::Span) -> Result<FuncRef> {
        let (symbol, ty) = self.lowerer.imported_syms.get(name).cloned()
            .expect("caller checked imported_syms");
        self.module_extern(&symbol, &ty, sp)
    }

    /// Resolve `module.var` / `module::var` — an imported module's exported GLOBAL
    /// (a non-function export, sic.md §"Imports") — to a get-or-created extern global
    /// `(ref, type)`. Returns `None` if `module` isn't imported or `var` isn't an
    /// exported non-function symbol (a function member is handled as a call instead).
    pub(crate) fn resolve_module_global(&mut self, module: &str, sym: &str) -> Option<(GlobalRef, Type)> {
        let (symbol, ty) = self.lowerer.imported_modules.get(module)?.get(sym)?.clone();
        if matches!(ty, Type::Function(_)) { return None; }
        if let Some((t, g)) = self.lowerer.globals_map.get(&symbol) {
            return Some((*g, t.clone()));
        }
        // `Import`, not `External`: this is an undefined reference to the module's
        // definition elsewhere — an `External` global with no initializer would
        // become a tentative (BSS) definition in this object and shadow the real
        // value at link time.
        let g = self.lowerer.module.add_global(sic_ir::Global {
            name: symbol.clone(), ty: ty.clone(), init: None,
            linkage: sic_ir::Linkage::Import, constant: false, thread_local: false,
        });
        self.lowerer.globals_map.insert(symbol.clone(), (ty.clone(), g));
        Some((g, ty))
    }

    /// True if `base.name` (or `base::name`) names an imported module's exported
    /// global variable — a `module` identifier and an exported non-function `name`.
    pub(crate) fn is_module_global(&self, base: &Expr, name: &str) -> bool {
        if let ExprKind::Ident(m) = &base.kind {
            if let Some(exports) = self.lowerer.imported_modules.get(m) {
                return matches!(exports.get(name), Some((_, ty)) if !matches!(ty, Type::Function(_)));
            }
        }
        false
    }

    /// Get-or-create the extern for an imported function symbol.
    fn module_extern(&mut self, symbol: &str, ty: &Type, sp: &crate::lexer::Span) -> Result<FuncRef> {
        let mut ft = match ty {
            Type::Function(ft) => (**ft).clone(),
            _ => return Err(CompileError::at(
                format!("imported symbol '{}' is not a function", symbol),
                sp.file.clone(), sp.line, sp.col,
            )),
        };
        // A struct/union return uses the sret ABI: the callee's real IR signature has
        // a hidden pointer as param 0 (the frontend prepends it for local functions).
        // The stored export type is user-facing (no sret), so prepend it here so the
        // extern's cranelift signature matches the definition across objects.
        if super::super::ret_is_sret(&ft.ret, self.ptr_size()) {
            ft.params.insert(0, Type::Pointer(Box::new(ft.ret.clone())));
        }
        Ok(self.lowerer.module.func_ref_by_name(symbol).unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc { name: symbol.to_string(), sig: ft })
        }))
    }

    /// sic atomic pseudo-methods (sic.md §"Atomics") on an atomic lvalue `base`:
    ///   `base.swap(v)`      → atomic exchange, yields the previous value
    ///   `base.cas(exp, des)`→ compare-and-swap, yields `bool` success
    fn lower_atomic_method(&mut self, base: &Expr, name: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let lv = self.lower_lvalue(base)?;
        let ty = lv.ty.clone();
        match name {
            "swap" => {
                if args.len() != 1 {
                    return Err(CompileError::at(
                        "`.swap` takes one argument: the value to store".to_string(),
                        sp.file.clone(), sp.line, sp.col));
                }
                let v = self.lower_expr(&args[0])?;
                let v = self.coerce(v, &ty)?;
                let old = self.alloc_val();
                self.push_instr(Instr::AtomicRmw { dest: old, op: AtomicOp::Xchg, ptr: lv.ptr.clone(), val: v, ty });
                Ok(Val::Local(old))
            }
            "cas" => {
                if args.len() != 2 {
                    return Err(CompileError::at(
                        "`.cas` takes two arguments: `.cas(expected, desired)`".to_string(),
                        sp.file.clone(), sp.line, sp.col));
                }
                let exp = self.lower_expr(&args[0])?;
                let exp = self.coerce(exp, &ty)?;
                let des = self.lower_expr(&args[1])?;
                let des = self.coerce(des, &ty)?;
                // Success ⇔ the observed old value equals `expected`.
                let (_old, ok) = self.emit_atomic_cas(lv.ptr.clone(), exp, des, &ty);
                Ok(ok)
            }
            _ => unreachable!("atomic method dispatch"),
        }
    }

    pub(crate) fn lower_call(&mut self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // Canonicalize a plain module call `Module::sym(args)` (EnumVariant form) to
        // the `module.sym(args)` (Field) form FIRST, so default-argument filling and
        // named-argument handling below see one canonical callee shape and run
        // exactly once (the keyword-only default fill is not idempotent). Only a
        // bare imported-module name that is NOT itself an enum is rewritten here;
        // generic/nested/namespace/tagged-enum `::` forms fall through unchanged.
        if self.is_sic() {
            if let ExprKind::EnumVariant { enum_name, variant } = &func_expr.kind {
                if self.lowerer.imported_modules.contains_key(enum_name)
                    && !self.lowerer.generic_fn_defs.contains_key(variant)
                    && !self.lowerer.enum_defs.contains_key(enum_name)
                    && self.resolve_plain_enum_const(enum_name, variant).is_none()
                {
                    let callee = Expr { kind: ExprKind::Field {
                        base: Box::new(Expr { kind: ExprKind::Ident(enum_name.clone()), span: sp.clone() }),
                        name: variant.clone(),
                    }, span: sp.clone() };
                    return self.lower_call(&callee, args, sp);
                }
            }
        }

        // sic default arguments (sic.md §"Default parameters"): complete the call's
        // argument list with any omitted defaults. Done before named-arg handling so
        // a `name = value` that targets a defaulted parameter binds to it rather than
        // spilling into a `va_dict`.
        let filled = self.fill_default_args(func_expr, args, sp)?;
        let args: &[Expr] = filled.as_deref().unwrap_or(args);

        // sic named parameters (sic.md §"Named parameters"): if any argument is
        // `name = value`, map every argument to the callee's parameters — reordering,
        // filling, and (for a variadic) dropping unmatched names to the tail — then
        // re-enter with a purely positional list.
        if args.iter().any(|a| matches!(a.kind, ExprKind::NamedArg { .. })) {
            // If the callee has a `va_dict` parameter, the named arguments are kept
            // (not flattened) and packed into it during argument lowering below.
            if !self.callee_has_va_dict(func_expr) {
                let reordered = self.resolve_named_args(func_expr, args, sp)?;
                return self.lower_call(func_expr, &reordered, sp);
            }
        }

        // `string.create(bytes, len)` (SIC): build a `string` from an explicit
        // pointer and byte length — a NON-owning VIEW (rc = null), with no copy and
        // no `strlen`, so it works on non-NUL-terminated buffers and binary data
        // with embedded NULs. The view borrows `bytes`; the caller keeps the backing
        // alive (or `.dup`s it). `string` is a reserved type name, so `string.create`
        // is unambiguous. Used by std's `Buffer::Value` to expose bytes as a string.
        if self.is_sic() {
            // `string` in expression position parses as either `Ident("string")` or
            // `TypeIdOf(Named("string"))` depending on context.
            let is_string_base = |b: &Expr| matches!(&b.kind,
                ExprKind::Ident(n) if n == "string")
                || matches!(&b.kind, ExprKind::TypeIdOf(qt)
                    if matches!(&qt.ty, crate::ast::AstType::Named(n) if n == "string"));
            if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func_expr.kind {
                if name == "create" && is_string_base(base) {
                    let [ptr_e, len_e] = args else {
                        return Err(CompileError::at(
                            "string.create(bytes, len) takes two arguments".to_string(),
                            sp.file.clone(), sp.line, sp.col));
                    };
                    let ptr = self.lower_expr(ptr_e)?;
                    let len = self.lower_expr(len_e)?;
                    let v = self.make_string_val(ptr, len, Constant::int(0))?;
                    // Tag the result as a `string` so a consumer recognizes it as an
                    // already-built descriptor (not a raw `char*` to re-wrap).
                    if let Val::Local(id) = &v {
                        let sty = super::super::types::sic_string_type(self.ptr_size());
                        self.val_types.insert(id.0, sty);
                    }
                    return Ok(v);
                }
            }
        }

        // sic generic call with explicit type arguments (turbofish), `add<int>(…)`
        // (sic.md §"Generics"): monomorphize with the written types (no inference).
        if let ExprKind::GenericRef { name, type_args } = &func_expr.kind {
            return self.lower_generic_call_explicit(name, type_args, args, sp);
        }
        // sic tagged-enum constructor `Enum::Variant(args)` (sic.md §"Match").
        // (Unwrap `Enum::VARIANT(inst)` is handled inside `construct_enum`.)
        if let ExprKind::EnumVariant { enum_name, variant } = &func_expr.kind {
            // sic (sic.md §"Imports"): `module::generic(args)` — a namespaced generic
            // template of an imported module. It has no importable symbol (re-
            // instantiated locally), so dispatch it as a generic call by its name.
            if self.is_sic() && self.lowerer.imported_modules.contains_key(enum_name)
                && self.lowerer.generic_fn_defs.contains_key(variant)
            {
                return self.lower_generic_call(variant, args, sp);
            }
            // sic (sic.md §"Namespace"): `Module::sym(args)` is the canonical scope
            // form of a module call — resolve it like `module.sym(args)`.
            if self.is_sic() && self.lowerer.imported_modules.contains_key(enum_name) {
                let callee = Expr { kind: ExprKind::Field {
                    base: Box::new(Expr { kind: ExprKind::Ident(enum_name.clone()), span: sp.clone() }),
                    name: variant.clone(),
                }, span: sp.clone() };
                return self.lower_call(&callee, args, sp);
            }
            // sic nested module member `mod::A::B::sym(args)` (sic.md §"Namespace"):
            // the module exports namespace members mangled `A__B__sym`. But a
            // qualified *enum* path `mod::Enum::Variant(x)` is a construct/unwrap, not
            // a member call — let it fall through to `construct_enum`.
            if self.is_sic() {
                let leaf = enum_name.rsplit("::").next().unwrap_or(enum_name);
                let is_enum = self.lowerer.enum_defs.contains_key(leaf)
                    || self.resolve_plain_enum_const(enum_name, variant).is_some();
                if let Some((module, rest)) = enum_name.split_once("::") {
                    if !is_enum && self.lowerer.imported_modules.contains_key(module) {
                        let export = format!("{}__{}", rest.replace("::", "__"), variant);
                        let callee = Expr { kind: ExprKind::Field {
                            base: Box::new(Expr { kind: ExprKind::Ident(module.to_string()), span: sp.clone() }),
                            name: export,
                        }, span: sp.clone() };
                        return self.lower_call(&callee, args, sp);
                    }
                }
            }
            // sic (sic.md §"Namespace"): `N::member(args)` calls a namespace member.
            if self.is_sic() {
                if let Some(mangled) = self.lowerer.namespace_members.get(&(enum_name.clone(), variant.clone())).cloned() {
                    let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
                    return self.lower_call(&callee, args, sp);
                }
            }
            return self.construct_enum(enum_name, variant, args, sp);
        }
        // Bare variant constructor `Variant(args)` (`Ok(5)`), resolved from the
        // owning enum unless a real function/variable of that name shadows it.
        if let ExprKind::Ident(name) = &func_expr.kind {
            if self.is_sic() && self.lowerer.variant_enum.contains_key(name)
                && !matches!(self.lookup(name),
                    Some(LookupResult::Func(_)) | Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)))
            {
                let en = self.lowerer.variant_enum.get(name).cloned().unwrap();
                return self.construct_enum(&en, name, args, sp);
            }
        }

        // sic generic functions (sic.md §"Generics"): a call to a `name<T,…>`
        // template — infer the type arguments from the argument types, monomorphize,
        // and dispatch to the concrete instance. A real local/global of that name
        // shadows the template.
        if let ExprKind::Ident(name) = &func_expr.kind {
            if self.is_sic() && self.lowerer.generic_fn_defs.contains_key(name)
                && !matches!(self.lookup(name),
                    Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)))
            {
                self.gate_qualified(name, sp)?;   // bare use of an imported generic → error
                return self.lower_generic_call(name, args, sp);
            }
        }

        // sic `string` methods (sic.md §"Built-in string"): `s.contains(sub)` (a
        // substring test — a single-char `sub` is a character search), and
        // Built-in `string` methods (sic.md §"Built-in string").
        if self.is_sic() {
            if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func_expr.kind {
                if matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_sic_string(&t)) {
                    // No-argument methods: whitespace trimming → a borrowed view.
                    match name.as_str() {
                        "trim"  => return self.lower_string_trim(base, true, true),
                        "ltrim" => return self.lower_string_trim(base, true, false),
                        "rtrim" => return self.lower_string_trim(base, false, true),
                        _ => {}
                    }
                    // One-argument methods over another string.
                    if matches!(name.as_str(),
                        "contains" | "split" | "rsplit" | "starts_with" | "ends_with" | "find")
                    {
                        let arg = args.first().ok_or_else(|| CompileError::at(
                            format!("`.{}` takes one string argument", name),
                            sp.file.clone(), sp.line, sp.col))?;
                        return match name.as_str() {
                            "contains"    => self.lower_string_contains(base, arg),
                            "split"       => self.lower_string_split(base, arg, false, sp),
                            "rsplit"      => self.lower_string_split(base, arg, true, sp),
                            "starts_with" => self.lower_string_starts_with(base, arg, false),
                            "ends_with"   => self.lower_string_starts_with(base, arg, true),
                            _ /* find */  => { let (idx, _, _, _, _) = self.lower_string_find(base, arg, false)?; Ok(idx) }
                        };
                    }
                }
            }
        }

        // sic `set` methods (sic.md §"Set"): `s.add(x)`, `s.contains(x)` / `s.has(x)`,
        // `s.remove(x)` — thin sugar over the underlying `dict<T, bool>`.
        if self.is_sic() {
            if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func_expr.kind {
                if matches!(name.as_str(), "add" | "contains" | "has" | "remove")
                    && matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_set(&t)
                        || matches!(&t, Type::Pointer(i) if super::super::types::is_set(i)))
                {
                    let key = args.first().ok_or_else(|| CompileError::at(
                        format!("`.{}` takes one element argument", name),
                        sp.file.clone(), sp.line, sp.col))?;
                    return match name.as_str() {
                        "add" => {
                            let t = Expr::new(ExprKind::BoolLit(true), sp.clone());
                            self.lower_dict_set(base, key, &t, sp)?;
                            Ok(Constant::zero())
                        }
                        "remove" => { self.lower_dict_del(base, key, sp)?; Ok(Constant::zero()) }
                        _ => self.lower_dict_get(base, key, sp), // contains / has → bool
                    };
                }
            }
        }

        // sic `list` methods (sic.md §"List"): `l.add(x)` / `l.push(x)` /
        // `l.append(x)` append an element.
        if self.is_sic() {
            if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func_expr.kind {
                if matches!(name.as_str(), "add" | "push" | "append")
                    && matches!(self.infer_expr_type(base), Ok(t) if super::super::types::is_list(&t)
                        || matches!(&t, Type::Pointer(i) if super::super::types::is_list(i)))
                {
                    let v = args.first().ok_or_else(|| CompileError::at(
                        format!("`.{}` takes one element argument", name),
                        sp.file.clone(), sp.line, sp.col))?;
                    self.lower_list_push(base, v, sp)?;
                    return Ok(Constant::zero());
                }
            }
        }

        // sic atomic methods (sic.md §"Atomics"): `a.swap(v)` and `a.cas(e, d)`,
        // allowed only on an atomic lvalue (never on an ordinary value).
        if self.is_sic() {
            let recv = match &func_expr.kind {
                ExprKind::Field { base, name } | ExprKind::Arrow { base, name }
                    if name == "cas" || name == "swap" => Some((base.as_ref(), name.as_str())),
                _ => None,
            };
            if let Some((base, name)) = recv {
                if matches!(&base.kind, ExprKind::Ident(n) if self.is_atomic_name(n)) {
                    return self.lower_atomic_method(base, name, args, sp);
                }
                // `.cas`/`.swap` on a non-atomic is an error (they only exist on atomics).
                if matches!(&base.kind, ExprKind::Ident(_)) {
                    return Err(CompileError::at(
                        format!("`.{}` is only available on an `atomic` value", name),
                        sp.file.clone(), sp.line, sp.col));
                }
            }
        }

        // sic struct method call (sic.md §"Memory safety" / §"Iterators"):
        // `obj.method(args)` / `p->method(args)` desugars to the hoisted free
        // function `__sic_m_<Struct>_<method>(self, args)`, with `self` the receiver
        // as a pointer (`&obj` for a value receiver, the pointer itself otherwise).
        // Recursing through `lower_call` reuses arg coercion + the sret ABI (the
        // method may return an aggregate such as `Iterator<T>`).
        if self.is_sic() && !self.lowerer.struct_methods.is_empty() {
            let recv = match &func_expr.kind {
                ExprKind::Field { base, name } | ExprKind::Arrow { base, name } =>
                    Some((base.as_ref(), name.clone())),
                _ => None,
            };
            if let Some((base, mname)) = recv {
                let (sname, recv_is_ptr) = match self.infer_expr_type(base).ok() {
                    Some(Type::Struct(st)) => (st.name, false),
                    Some(Type::Pointer(inner)) => match *inner {
                        Type::Struct(st) => (st.name, true),
                        _ => (None, false),
                    },
                    _ => (None, false),
                };
                if let Some(mangled) = sname
                    .and_then(|s| self.lowerer.struct_methods.get(&(s, mname)).cloned())
                {
                    let self_arg = if recv_is_ptr {
                        base.clone()
                    } else {
                        Expr { kind: ExprKind::Unary { op: crate::ast::UnOpKind::Addr, expr: Box::new(base.clone()) }, span: base.span.clone() }
                    };
                    let mut new_args = Vec::with_capacity(args.len() + 1);
                    new_args.push(self_arg);
                    new_args.extend_from_slice(args);
                    let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
                    return self.lower_call(&callee, &new_args, sp);
                }
            }
        }

        // A `_Generic(...)` selection used as the callee resolves to the chosen
        // association's expression, which may itself be a builtin name (e.g.
        // QEMU's `bswaps` macro: `_Generic(x, uint16_t: __builtin_bswap16, ...)(x)`).
        if let ExprKind::Generic { controlling, assocs } = &func_expr.kind {
            let idx = self.select_generic(controlling, assocs)?;
            return self.lower_call(&assocs[idx].1, args, sp);
        }

        // Handle __builtin_bswap* before evaluating args
        if let ExprKind::Ident(name) = &func_expr.kind {
            let bits: Option<u32> = match name.as_str() {
                "__builtin_bswap16" => Some(16),
                "__builtin_bswap32" => Some(32),
                "__builtin_bswap64" => Some(64),
                _ => None,
            };
            if let Some(bits) = bits {
                if let Some(arg) = args.first() {
                    let v = self.lower_expr(arg)?;
                    let ty = Type::Int { bits, signed: false };
                    let dest = self.alloc_val();
                    self.push_instr(Instr::BSwap { dest, val: v, ty });
                    return Ok(Val::Local(dest));
                }
            }

            // Overflow-checked arithmetic builtins:
            //   bool __builtin_{add,mul}_overflow(a, b, *res)
            // Compute `a op b`, store the wrapped result through `*res`, and
            // return whether the mathematical result overflowed the result type.
            let ovf_op = match name.as_str() {
                "__builtin_add_overflow" => Some(BinOp::Add),
                "__builtin_sub_overflow" => Some(BinOp::Sub),
                "__builtin_mul_overflow" => Some(BinOp::Mul),
                _ => None,
            };
            if let (Some(op), [a_expr, b_expr, res_expr]) = (ovf_op, args) {
                return self.lower_overflow_builtin(op, a_expr, b_expr, res_expr);
            }

            // Multiprecision add/subtract with carry:
            //   T __builtin_{add,sub}c[l|ll](T a, T b, T carryin, T *carryout)
            // Returns `a ± b ± carryin` (wrapped) and stores the outgoing
            // carry/borrow (0 or 1) through `*carryout`.
            let carry_sub = match name.as_str() {
                "__builtin_addc" | "__builtin_addcl" | "__builtin_addcll" => Some(false),
                "__builtin_subc" | "__builtin_subcl" | "__builtin_subcll" => Some(true),
                _ => None,
            };
            if let (Some(is_sub), [a_expr, b_expr, cin_expr, cout_expr]) = (carry_sub, args) {
                return self.lower_carry_builtin(is_sub, a_expr, b_expr, cin_expr, cout_expr);
            }

            // Atomic builtins. A 1/2/4/8-byte integer/bool/pointer operand uses
            // sic's real atomic instructions (AtomicLoad/Store/Rmw/Cas — the same
            // ones behind the `atomic` qualifier), which are sequentially
            // consistent, so every requested memory order is satisfied; fences
            // are no-ops on top of that. Wider operands (`__int128`, structs)
            // fall back to plain (single-thread-correct) code.
            match name.as_str() {
                // T __atomic_load_n(const T *ptr, int memorder)
                "__atomic_load_n" => {
                    if let Some(ptr_expr) = args.first() {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => *t,
                            _ => Type::i32(),
                        };
                        let dest = self.alloc_val();
                        if super::atomic_lock_free_type(&ty, self.ptr_size()) {
                            self.push_instr(Instr::AtomicLoad { dest, ptr, ty });
                        } else {
                            self.push_instr(Instr::Load { dest, ptr, ty });
                        }
                        return Ok(Val::Local(dest));
                    }
                }
                // void __atomic_load(const T *ptr, T *ret, int memorder): *ret = *ptr.
                "__atomic_load" => {
                    if let [ptr_expr, ret_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ret = self.lower_expr(ret_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        if super::atomic_lock_free_type(&ty, self.ptr_size()) {
                            let v = self.alloc_val();
                            self.push_instr(Instr::AtomicLoad { dest: v, ptr, ty });
                            self.push_instr(Instr::Store { val: Val::Local(v), ptr: ret });
                            return Ok(Constant::zero());
                        }
                        let size = ty.size_of(self.ptr_size());
                        let align = ty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: ret, src: ptr, size, align });
                        return Ok(Constant::zero());
                    }
                }
                // void __atomic_store(T *ptr, T *val, int memorder): *ptr = *val.
                "__atomic_store" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let val = self.lower_expr(val_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        if super::atomic_lock_free_type(&ty, self.ptr_size()) {
                            let v = self.alloc_val();
                            self.push_instr(Instr::Load { dest: v, ptr: val, ty: ty.clone() });
                            self.push_instr(Instr::AtomicStore { ptr, val: Val::Local(v), ty });
                            return Ok(Constant::zero());
                        }
                        let size = ty.size_of(self.ptr_size());
                        let align = ty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: ptr, src: val, size, align });
                        return Ok(Constant::zero());
                    }
                }
                // void __atomic_store_n(T *ptr, T val, int memorder)
                "__atomic_store_n" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let val = self.lower_expr(val_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => *t,
                            _ => self.val_type(&val),
                        };
                        let cv = self.coerce(val, &ty)?;
                        if super::atomic_lock_free_type(&ty, self.ptr_size()) {
                            self.push_instr(Instr::AtomicStore { ptr, val: cv, ty });
                        } else {
                            self.push_instr(Instr::Store { val: cv, ptr });
                        }
                        return Ok(Constant::zero());
                    }
                }
                // x86 scalar bit-scan intrinsics (from <ia32intrin.h>):
                //   bsr = index of the most-significant set bit = (bits-1) - clz
                //   bsf = index of the least-significant set bit = ctz
                "__builtin_ia32_bsrsi" | "__builtin_ia32_bsrdi"
                | "__builtin_ia32_bsfsi" | "__builtin_ia32_bsfdi" => {
                    if let Some(arg) = args.first() {
                        let bits = if name.ends_with("di") { 64 } else { 32 };
                        if name.contains("bsf") {
                            return self.lower_bit_count(arg, bits, BitOp::Ctz);
                        }
                        // bsr: (bits-1) - clz
                        let clz = self.lower_bit_count(arg, bits, BitOp::Clz)?;
                        let res = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: res, op: BinOp::Sub, lhs: Constant::int((bits - 1) as i64), rhs: clz, ty: Type::i32() });
                        return Ok(Val::Local(res));
                    }
                }
                // x86 SIMD vector intrinsics — scalar-emulated over the byte/lane
                // aggregate that a `vector_size` type lowers to.
                "__builtin_ia32_pmovmskb128" | "__builtin_ia32_pmovmskb256" => {
                    if let [v] = args {
                        let n = if name.ends_with("256") { 32 } else { 16 };
                        return self.lower_vec_pmovmskb(v, n);
                    }
                }
                "__builtin_ia32_pcmpeqb128" | "__builtin_ia32_pcmpeqb256" => {
                    if let [a, b] = args {
                        let n = if name.ends_with("256") { 32 } else { 16 };
                        return self.lower_vec_pcmpeqb(a, b, n);
                    }
                }
                "__builtin_ia32_pshufb128" => {
                    if let [a, b] = args { return self.lower_vec_pshufb(a, b, 16); }
                }
                "__builtin_ia32_pclmulqdq128" => {
                    if let [a, b, imm] = args { return self.lower_vec_pclmulqdq(a, b, imm); }
                }
                // AES-NI round intrinsics (from <wmmintrin.h>, used by QEMU's
                // host/crypto/aes-round.h). Each is a full AES round emulated with
                // the S-box tables + GF(2^8) MixColumns.
                "__builtin_ia32_aesenc128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::Enc); }
                }
                "__builtin_ia32_aesenclast128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::EncLast); }
                }
                "__builtin_ia32_aesdec128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::Dec); }
                }
                "__builtin_ia32_aesdeclast128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::DecLast); }
                }
                "__builtin_ia32_aesimc128" => {
                    if let [s] = args { return self.lower_aes(s, None, AesMode::Imc); }
                }
                // `alloca(n)` / `__builtin_alloca(n)`: sic has no dynamic stack
                // allocation (cranelift stack slots are static-size). Emulate with
                // `malloc` so the code links and yields correct storage. NOTE:
                // this leaks (the block is not freed on function return); adequate
                // for bounded uses, but a proper dynamic stack alloca is a TODO.
                "__builtin_alloca" | "alloca" | "__builtin_alloca_with_align" => {
                    if let [size_expr, ..] = args {
                        let voidp = Type::void_ptr();
                        let fref = match self.lowerer.module.func_ref_by_name("malloc") {
                            Some(f) => f,
                            None => self.lowerer.module.add_extern(ExternFunc {
                                name: "malloc".to_string(),
                                sig: FunctionType { ret: voidp.clone(), params: vec![Type::u64()], variadic: false },
                            }),
                        };
                        let sz = self.lower_expr(size_expr)?;
                        let sz = self.coerce(sz, &Type::u64())?;
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![sz], ret_ty: voidp.clone() });
                        self.val_types.insert(dest.0, voidp);
                        return Ok(Val::Local(dest));
                    }
                }
                // void __sync_synchronize(void) — full memory barrier; no-op here.
                "__sync_synchronize" => return Ok(Constant::zero()),
                // Atomic read-modify-write builtins. sic has no real atomics, so
                // these lower to a plain load / op / store (correct for a single
                // thread, which is enough to compile and run the code).
                //   __atomic_fetch_OP(ptr, val, order)  -> returns OLD value
                //   __atomic_OP_fetch(ptr, val, order)  -> returns NEW value
                //   __sync_fetch_and_OP(ptr, val)       -> returns OLD value
                //   __sync_OP_and_fetch(ptr, val)       -> returns NEW value
                n if atomic_rmw_op(n).is_some() => {
                    let (op, ret_new) = atomic_rmw_op(n).unwrap();
                    if let [ptr_expr, val_expr, ..] = args {
                        return self.lower_atomic_rmw(ptr_expr, val_expr, op, ret_new);
                    }
                }
                // Fences / barriers: no-ops for a single thread.
                "__atomic_thread_fence" | "__atomic_signal_fence" => return Ok(Constant::zero()),
                // bool __atomic_test_and_set(void *p, int order): atomically set the
                // byte at `p` to 1 (`__GCC_ATOMIC_TEST_AND_SET_TRUEVAL`) and return
                // whether it was already set. <stdatomic.h> passes the
                // `atomic_flag*` itself, so it always works on the first byte.
                "__atomic_test_and_set" => {
                    if let [ptr_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let u8t = Type::Int { bits: 8, signed: false };
                        let one = self.coerce(Constant::int(1), &u8t)?;
                        let old = self.alloc_val();
                        self.push_instr(Instr::AtomicRmw { dest: old, op: AtomicOp::Xchg, ptr, val: one, ty: u8t.clone() });
                        let was = self.alloc_val();
                        self.push_instr(Instr::Cmp { dest: was, op: CmpOp::INe, lhs: Val::Local(old), rhs: Constant::int(0), ty: u8t });
                        let r = self.alloc_val();
                        self.push_instr(Instr::Cast { dest: r, op: CastOp::ZExt, val: Val::Local(was), to_ty: Type::i32() });
                        return Ok(Val::Local(r));
                    }
                }
                // void __atomic_clear(void *p, int order): atomically store 0 to the byte.
                "__atomic_clear" => {
                    if let [ptr_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let u8t = Type::Int { bits: 8, signed: false };
                        let zero = self.coerce(Constant::int(0), &u8t)?;
                        self.push_instr(Instr::AtomicStore { ptr, val: zero, ty: u8t });
                        return Ok(Constant::zero());
                    }
                }
                // void __atomic_exchange(T *p, T *val, T *ret, int order): *ret = old
                // *p, *p = *val — one atomic exchange for a lock-free-sized T
                // (1/2/4/8-byte integer, bool, pointer), else a plain copy sequence.
                "__atomic_exchange" => {
                    if let [ptr_expr, val_expr, ret_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let valp = self.lower_expr(val_expr)?;
                        let retp = self.lower_expr(ret_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        if super::atomic_lock_free_type(&ty, self.ptr_size()) {
                            let nv = self.alloc_val();
                            self.push_instr(Instr::Load { dest: nv, ptr: valp, ty: ty.clone() });
                            let old = self.alloc_val();
                            self.push_instr(Instr::AtomicRmw { dest: old, op: AtomicOp::Xchg, ptr, val: Val::Local(nv), ty: ty.clone() });
                            self.push_instr(Instr::Store { val: Val::Local(old), ptr: retp });
                        } else {
                            let ps = self.ptr_size();
                            let (size, align) = (ty.size_of(ps), ty.align_of(ps));
                            let tmp = self.alloc_val();
                            self.push_instr(Instr::Alloca { dest: tmp, ty: ty.clone(), align: None });
                            self.push_instr(Instr::MemCopy { dst: Val::Local(tmp), src: ptr.clone(), size, align });
                            self.push_instr(Instr::MemCopy { dst: ptr, src: valp, size, align });
                            self.push_instr(Instr::MemCopy { dst: retp, src: Val::Local(tmp), size, align });
                        }
                        return Ok(Constant::zero());
                    }
                }
                // bool __atomic_{is,always}_lock_free(size_t size, void *p): sic's
                // atomics are single lock-free instructions for 1/2/4/8 bytes.
                "__atomic_is_lock_free" | "__atomic_always_lock_free" => {
                    if let [size_expr, ..] = args {
                        if let Ok(n) = crate::lower::eval_const_expr(size_expr, &self.lowerer.enum_consts) {
                            return Ok(Constant::int(matches!(n, 1 | 2 | 4 | 8) as i64));
                        }
                        let sz = self.lower_expr(size_expr)?;
                        let sz = self.coerce(sz, &Type::u64())?;
                        let mut acc: Option<Val> = None;
                        for k in [1i64, 2, 4, 8] {
                            let c = self.alloc_val();
                            self.push_instr(Instr::Cmp { dest: c, op: CmpOp::IEq, lhs: sz.clone(), rhs: Constant::int(k), ty: Type::u64() });
                            let ci = self.alloc_val();
                            self.push_instr(Instr::Cast { dest: ci, op: CastOp::ZExt, val: Val::Local(c), to_ty: Type::i32() });
                            acc = Some(match acc {
                                None => Val::Local(ci),
                                Some(a) => {
                                    let o = self.alloc_val();
                                    self.push_instr(Instr::BinOp { dest: o, op: BinOp::Or, lhs: a, rhs: Val::Local(ci), ty: Type::i32() });
                                    Val::Local(o)
                                }
                            });
                        }
                        return Ok(acc.unwrap());
                    }
                }
                // T __atomic_exchange_n(ptr, val, order) / __sync_lock_test_and_set(ptr, val)
                "__atomic_exchange_n" | "__sync_lock_test_and_set" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        return self.lower_atomic_exchange(ptr_expr, val_expr);
                    }
                }
                // void __sync_lock_release(ptr): *ptr = 0
                "__sync_lock_release" => {
                    if let [ptr_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ty = self.pointee_ty(&ptr);
                        let z = self.coerce(Constant::zero(), &ty)?;
                        self.push_instr(Instr::Store { val: z, ptr });
                        return Ok(Constant::zero());
                    }
                }
                // Compare-and-swap. GCC exposes both the type-generic form and the
                // width-suffixed `_1/_2/_4/_8/_16` forms (QEMU's atomic128 host
                // path uses `_16` for 128-bit CAS). `lower_atomic_cas` is width-
                // agnostic (it works off the pointee type, incl. i128).
                n if sync_builtin_base(n) == "__sync_val_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, false); }
                }
                n if sync_builtin_base(n) == "__sync_bool_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, true); }
                }
                // `_n` takes `desired` by value; the generic form by pointer.
                "__atomic_compare_exchange_n" | "__atomic_compare_exchange" => {
                    let by_ptr = name.as_str() == "__atomic_compare_exchange";
                    if let [p, eptr, d, ..] = args { return self.lower_atomic_compare_exchange(p, eptr, d, by_ptr); }
                }
                // Branch-prediction hints: the value is just the first argument.
                "__builtin_expect" | "__builtin_expect_with_probability" => {
                    if let Some(e) = args.first() { return self.lower_expr(e); }
                }
                // Optimizer hints with no runtime effect for us.
                "__builtin_prefetch" | "__builtin_unreachable"
                | "__builtin_assume_aligned" => {
                    // `assume_aligned(p, ...)` returns its pointer; the rest are void.
                    if name.as_str() == "__builtin_assume_aligned" {
                        if let Some(e) = args.first() { return self.lower_expr(e); }
                    }
                    return Ok(Constant::zero());
                }
                "__builtin_constant_p" => return Ok(Constant::int(0)),
                // sic does no object-size analysis; return the "size unknown"
                // sentinel so any _FORTIFY / size check falls through to the plain
                // path: type 0/1 -> (size_t)-1, type 2/3 -> 0.
                "__builtin_object_size" | "__builtin_dynamic_object_size" => {
                    let ty = args.get(1)
                        .and_then(|e| crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok())
                        .unwrap_or(0);
                    let v: u64 = if ty & 2 != 0 { 0 } else { u64::MAX };
                    return self.coerce(Constant::uint(v), &Type::Int { bits: 64, signed: false });
                }
                // `__builtin_return_address(0)` = the current function's return
                // address. Critical for QEMU's GETPC(): a faulting helper uses it
                // to restart the TB at the right guest PC. Level 0 maps to
                // Cranelift's get_return_address; deeper levels (stack walking) and
                // frame/CFA queries fall back to null (diagnostics degrade).
                "__builtin_return_address" => {
                    let level0 = args.first()
                        .and_then(|e| crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok())
                        .map(|v| v == 0)
                        .unwrap_or(true);
                    if level0 {
                        let d = self.alloc_val();
                        self.push_instr(Instr::ReturnAddress { dest: d });
                        self.val_types.insert(d.0, Type::void_ptr());
                        return Ok(Val::Local(d));
                    }
                    return Ok(Constant::zero());
                }
                "__builtin_frame_address" | "__builtin_dwarf_cfa"
                    => return Ok(Constant::zero()),
                // These identity/no-op address adjusters return their argument.
                "__builtin_extract_return_addr" | "__builtin_frob_return_addr" => {
                    if let Some(e) = args.first() { return self.lower_expr(e); }
                    return Ok(Constant::zero());
                }
                // Floating-point classification / comparison builtins.
                "__builtin_isnan" | "__builtin_isinf" | "__builtin_isinf_sign"
                | "__builtin_isfinite" | "__builtin_isnormal" => {
                    if let Some(arg) = args.first() {
                        return self.lower_fp_classify(name, arg);
                    }
                }
                "__builtin_isgreater" | "__builtin_isgreaterequal" | "__builtin_isless"
                | "__builtin_islessequal" | "__builtin_islessgreater" | "__builtin_isunordered" => {
                    if let [a, b, ..] = args {
                        return self.lower_fp_compare(name, a, b);
                    }
                }
                // __builtin_fpclassify(NAN, INF, NORMAL, SUBNORMAL, ZERO, x):
                // pick the category constant matching x. Subnormals are treated
                // as normal (sic doesn't distinguish the boundary).
                "__builtin_fpclassify" => {
                    if let [nan_v, inf_v, normal_v, _subnormal_v, zero_v, x] = args {
                        let is_nan = self.lower_fp_classify("__builtin_isnan", x)?;
                        let is_inf = self.lower_fp_classify("__builtin_isinf", x)?;
                        let xv = self.lower_expr(x)?;
                        let fty = match self.val_type(&xv) { t if t.is_float() => t, _ => Type::Float64 };
                        let xv = self.coerce(xv, &fty)?;
                        let is_zero = self.alloc_val();
                        self.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::FOEq, lhs: xv, rhs: Val::Const(Constant::Float(0.0)), ty: fty });
                        // result = isnan ? NAN : isinf ? INF : iszero ? ZERO : NORMAL
                        let nan_v = self.lower_expr(nan_v)?;
                        let inf_v = self.lower_expr(inf_v)?;
                        let normal_v = self.lower_expr(normal_v)?;
                        let zero_v = self.lower_expr(zero_v)?;
                        let ity = Type::i32();
                        let (nan_v, inf_v, normal_v, zero_v) = (
                            self.coerce(nan_v, &ity)?, self.coerce(inf_v, &ity)?,
                            self.coerce(normal_v, &ity)?, self.coerce(zero_v, &ity)?);
                        let is_nan = self.coerce(is_nan, &Type::Bool)?;
                        let is_inf = self.coerce(is_inf, &Type::Bool)?;
                        let sel_zn = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel_zn, cond: Val::Local(is_zero), on_true: zero_v, on_false: normal_v, ty: ity.clone() });
                        let sel_inf = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel_inf, cond: is_inf, on_true: inf_v, on_false: Val::Local(sel_zn), ty: ity.clone() });
                        let sel = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel, cond: is_nan, on_true: nan_v, on_false: Val::Local(sel_inf), ty: ity });
                        return Ok(Val::Local(sel));
                    }
                }
                // Infinity / huge-value constants.
                "__builtin_inf" | "__builtin_inff" | "__builtin_infl"
                | "__builtin_huge_val" | "__builtin_huge_valf" | "__builtin_huge_vall" =>
                    return Ok(Val::Const(Constant::Float(f64::INFINITY))),
                "__builtin_nan" | "__builtin_nanf" | "__builtin_nanl" =>
                    return Ok(Val::Const(Constant::Float(f64::NAN))),
                // signbit(x): nonzero iff the sign bit is set. Type-pun the float
                // through a stack slot and test the top bit (correct for -0.0).
                "__builtin_signbit" | "__builtin_signbitf" | "__builtin_signbitl" => {
                    if let Some(arg) = args.first() {
                        let v = self.lower_expr(arg)?;
                        let fty = self.val_type(&v);
                        let (fty, ity, shift) = match fty {
                            Type::Float32 => (Type::Float32, Type::Int { bits: 32, signed: false }, 31),
                            _ => (Type::Float64, Type::Int { bits: 64, signed: false }, 63),
                        };
                        let v = self.coerce(v, &fty)?;
                        let slot = self.alloc_val();
                        self.push_instr(Instr::Alloca { dest: slot, ty: ity.clone(), align: None });
                        self.push_instr(Instr::Store { val: v, ptr: Val::Local(slot) });
                        let iv = self.alloc_val();
                        self.push_instr(Instr::Load { dest: iv, ptr: Val::Local(slot), ty: ity.clone() });
                        let sh = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: sh, op: BinOp::LShr, lhs: Val::Local(iv), rhs: Constant::int(shift), ty: ity.clone() });
                        let masked = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: masked, op: BinOp::And, lhs: Val::Local(sh), rhs: Constant::int(1), ty: ity });
                        return self.coerce(Val::Local(masked), &Type::i32());
                    }
                }
                // Bit-count builtins: clz/ctz/popcount/ffs (32- and 64-bit).
                n if builtin_bit_op(n).is_some() => {
                    let (kind, bits) = builtin_bit_op(n).unwrap();
                    if let Some(arg) = args.first() {
                        return self.lower_bit_count(arg, bits, kind);
                    }
                }
                // Static assertions: accepted, not evaluated (compile-time only).
                "_Static_assert" | "static_assert" => return Ok(Constant::zero()),
                // Type-compat query: conservatively false (only affects _Generic-
                // style dispatch we don't otherwise need).
                "__builtin_types_compatible_p" => return Ok(Constant::int(0)),
                _ => {}
            }
        }

        // Evaluate arguments. Expose each parameter's type as the expected type so a
        // generic-enum constructor argument (`f(Option::Some(5))`) infers its
        // monomorph (sic.md §"Match").
        let param_types: Vec<Type> = self.callee_param_types(func_expr);
        // sic va_array / va_dict (sic.md std, §"Named parameters"): a trailing
        // `va_array` collects the positional trailing arguments (boxed into `any`);
        // a trailing `va_dict` collects the named (`name = value`) ones. The fixed
        // parameters are everything before the first such collector.
        let va_array_idx = if self.is_sic() { param_types.iter().position(super::super::types::is_va_array) } else { None };
        let va_dict_idx = if self.is_sic() { param_types.iter().position(super::super::types::is_va_dict) } else { None };
        let va_fixed = match (va_array_idx, va_dict_idx) {
            (Some(a), Some(d)) => Some(a.min(d)),
            (Some(a), None) => Some(a),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        // sic strict enum typing (sic.md §"Enums"): the callee's payload-less-enum
        // parameters reject a plain `int` or a different enum argument without a cast.
        let callee_name: Option<String> = match &func_expr.kind {
            ExprKind::Ident(n) => Some(n.clone()),
            _ => None,
        };
        let mut arg_vals = Vec::new();
        for (i, a) in args.iter().enumerate() {
            if let Some(fixed) = va_fixed {
                if i >= fixed { break; } // trailing args handled below
            }
            let mut arg_owner: Option<String> = None;
            if self.is_sic() {
                if let Some(fname) = &callee_name {
                    if let Some(dest) = self.lowerer.c_enum_param.get(&(fname.clone(), i)).cloned() {
                        self.check_enum_dest(&dest, a, "passed as")?;
                        arg_owner = Some(dest);
                    }
                    // sic bitfield param (sic.md §"Bitfields"): a bare flag argument
                    // resolves against the parameter's bitfield type.
                    if let Some(bf) = self.lowerer.bitfield_param.get(&(fname.clone(), i)).cloned() {
                        self.check_bitfield_dest(&bf, a, "passed as")?;
                        arg_owner = Some(bf);
                    }
                }
                // Reject a pointer/value aggregate mismatch on an argument, e.g.
                // passing a `File` value where the parameter is `File*` (sic.md
                // §"Memory safety").
                if let Some(pt) = param_types.get(i) {
                    self.check_ptr_value_mismatch(pt, a)?;
                }
            }
            let prev = self.expected_ty.take();
            if let Some(pt) = param_types.get(i) { self.expected_ty = Some(pt.clone()); }
            // sic shorthand context: a matching enum/bitfield param resolves a bare
            // member; a plain-integer param forbids one; a variadic slot is neutral.
            self.bf_ctx = match param_types.get(i) {
                _ if arg_owner.is_some() => super::super::func::BfCtx::Expect(arg_owner.unwrap()),
                Some(pt) => self.dest_ctx(None, pt),
                None => super::super::func::BfCtx::Any,
            };
            let mut v = self.lower_arg(a)?;
            self.expected_ty = prev;
            // sic (sic.md §"Strings"): a `string` reaching a C variadic (`printf("%s",
            // s)`) decays to its `char*` — printf reads a pointer, not a descriptor.
            // sic's own `va_array` (fixed params + boxing) is handled below, not here.
            let is_c_vararg = self.is_sic() && va_fixed.is_none() && i >= param_types.len();
            if is_c_vararg
                && matches!(self.infer_expr_type(a), Ok(t) if super::super::types::is_sic_string(&t))
            {
                v = self.string_to_cptr_val(v)?;
            }
            arg_vals.push(v);
        }
        if let Some(fixed) = va_fixed {
            let trailing = &args[fixed.min(args.len())..];
            // Classify trailing args: a named one feeds the va_dict; a plain one that
            // is itself a va_array / va_dict is *forwarded* to that slot (like
            // `f(*args, **kw)`); anything else is a plain positional → va_array.
            let mut fwd_va_array: Option<Expr> = None;
            let mut fwd_va_dict: Option<Expr> = None;
            let mut plain: Vec<Expr> = Vec::new();
            let mut named: Vec<Expr> = Vec::new();
            for a in trailing {
                if matches!(a.kind, ExprKind::NamedArg { .. }) { named.push(a.clone()); continue; }
                let t = self.infer_expr_type(a).ok();
                if va_array_idx.is_some() && fwd_va_array.is_none()
                    && matches!(&t, Some(t) if super::super::types::is_va_array(t)) {
                    fwd_va_array = Some(a.clone());
                } else if va_dict_idx.is_some() && fwd_va_dict.is_none()
                    && matches!(&t, Some(t) if super::super::types::is_va_dict(t)) {
                    fwd_va_dict = Some(a.clone());
                } else {
                    plain.push(a.clone());
                }
            }
            // Emit the collectors in signature order.
            let mut packed: Vec<(usize, Val)> = Vec::new();
            if let Some(ai) = va_array_idx {
                let va = match fwd_va_array {
                    Some(e) => self.lower_aggregate_ptr(&e)?,
                    None => self.pack_va_array(&plain, sp)?,
                };
                packed.push((ai, va));
            }
            if let Some(di) = va_dict_idx {
                let vd = match fwd_va_dict {
                    // A `va_dict` is a handle (pointer); forward its value, not its
                    // address (unlike the struct-valued `va_array`).
                    Some(e) => self.lower_expr(&e)?,
                    None => self.pack_va_dict(&named, sp)?,
                };
                packed.push((di, vd));
            }
            packed.sort_by_key(|(i, _)| *i);
            for (_, v) in packed { arg_vals.push(v); }
        }

        // sic namespaced module call `x.f(...)`: resolve `x.f` to the imported
        // module's mangled extern; feeds the shared direct-call emission below.
        let module_fref: Option<FuncRef> = match &func_expr.kind {
            ExprKind::Field { base, name } => match &base.kind {
                // An exported NON-function global (e.g. a function-pointer or closure
                // global) is called indirectly — read it as a value and fall through
                // to the indirect/closure path, not a direct module call.
                ExprKind::Ident(module) if self.lowerer.imported_modules.contains_key(module)
                    && !self.is_module_global(base, name) =>
                {
                    Some(self.resolve_module_call(module, name, sp)?)
                }
                _ => None,
            },
            _ => None,
        };

        // sic closure call (sic.md §"Lambdas"): if the callee is a closure value
        // (an environment pointer), route it specially — checked before the
        // function-reference dispatch so an `Ident` closure variable doesn't take
        // the plain function-pointer path.
        if self.is_sic() && module_fref.is_none() {
            if matches!(self.infer_expr_type(func_expr), Ok(t) if super::super::types::is_closure(&t)) {
                return self.lower_closure_call(func_expr, arg_vals, sp);
            }
        }

        // Resolve function reference
        let fref = if let Some(fr) = module_fref { fr } else {
        match &func_expr.kind {
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Func(fr)) => fr,
                    Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)) => {
                        // local/global function pointer variable: fall through to indirect call
                        let fptr = self.lower_expr(func_expr)?;
                        let fptr_ty = self.val_type(&fptr);
                        let func_ty = match &fptr_ty {
                            Type::Pointer(inner) => match inner.as_ref() {
                                Type::Function(ft) => *ft.clone(),
                                _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                            },
                            // A function-typed parameter does not decay to a
                            // pointer type in sic's IR; accept it directly.
                            Type::Function(ft) => *ft.clone(),
                            _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                        };
                        let ret_ty = func_ty.ret.clone();
                        if super::super::ret_is_sret(&ret_ty, self.ptr_size()) {
                            return self.lower_indirect_sret(fptr, func_ty, arg_vals);
                        }
                        let is_void = ret_ty == Type::Void;
                        let dest = if !is_void { Some(self.alloc_val()) } else { None };
                        self.push_instr(Instr::CallIndirect {
                            dest,
                            fptr,
                            args: arg_vals,
                            ret_ty: ret_ty.clone(),
                            func_ty: Box::new(func_ty),
                        });
                        return Ok(if let Some(d) = dest { Val::Local(d) } else { Constant::zero() });
                    }
                    _ => {
                        // sic selective/renamed import (`import x.f;` / `... as g;`):
                        // a bare call `f()`/`g()` resolves to the module's extern.
                        if self.lowerer.imported_syms.contains_key(name) {
                            self.resolve_module_call_bare(name, sp)?
                        } else
                        // Many `__builtin_<fn>` calls (memcpy, memmove, strlen, …)
                        // are just the libc function; retry resolution with the
                        // prefix stripped.
                        if let Some(libc) = name.strip_prefix("__builtin_") {
                            if let Some(LookupResult::Func(fr)) = self.lookup(libc) {
                                fr
                            } else {
                                return Err(CompileError::at(
                                    format!("unknown function '{}'", name),
                                    sp.file.clone(), sp.line, sp.col,
                                ));
                            }
                        } else {
                            return Err(CompileError::at(
                                format!("unknown function '{}'", name),
                                sp.file.clone(), sp.line, sp.col,
                            ));
                        }
                    }
                }
            }
            _ => {
                // Indirect call through function pointer expression
                let fptr = self.lower_expr(func_expr)?;
                let fptr_ty = self.val_type(&fptr);
                let func_ty = match &fptr_ty {
                    Type::Pointer(inner) => match inner.as_ref() {
                        Type::Function(ft) => *ft.clone(),
                        _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                    },
                    Type::Function(ft) => *ft.clone(),
                    _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                };
                let ret_ty = func_ty.ret.clone();
                if super::super::ret_is_sret(&ret_ty, self.ptr_size()) {
                    return self.lower_indirect_sret(fptr, func_ty, arg_vals);
                }
                // Coerce fixed args to their param types and apply the default
                // argument promotions to any `...` args (same as the direct path).
                for (i, pval) in arg_vals.iter_mut().enumerate() {
                    if let Some(pty) = func_ty.params.get(i) {
                        if matches!(pty, Type::Struct(_) | Type::Union(_)) { continue; }
                        let c = self.coerce(pval.clone(), pty)?;
                        *pval = c;
                    } else if func_ty.variadic {
                        let p = self.promote_vararg(pval.clone())?;
                        *pval = p;
                    }
                }
                let is_void = ret_ty == Type::Void;
                let dest = if !is_void { Some(self.alloc_val()) } else { None };
                self.push_instr(Instr::CallIndirect {
                    dest,
                    fptr,
                    args: arg_vals,
                    ret_ty: ret_ty.clone(),
                    func_ty: Box::new(func_ty),
                });
                return Ok(if let Some(d) = dest { Val::Local(d) } else { Constant::zero() });
            }
        }
        };

        // Argument-count check (SIC only — C allows unprototyped/K&R calls). A
        // direct call to a non-variadic function must pass exactly as many arguments
        // as it declares. Skip variadic functions and SIC `va_array`/`va_dict`
        // collectors (which absorb a variable tail); account for a hidden sret
        // pointer parameter. `args` already includes a method's prepended `self`.
        if self.is_sic() {
            let ptr_size = self.ptr_size();
            let sig = self.lowerer.module.func_sig(fref);
            let variadic = sig.variadic
                || sig.params.iter().any(|p| super::super::types::is_va_array(p)
                    || super::super::types::is_va_dict(p));
            if !variadic {
                let mut expected = sig.params.len();
                if super::super::ret_is_sret(&sig.ret, ptr_size) && expected > 0 { expected -= 1; }
                if args.len() != expected {
                    return Err(CompileError::at(
                        format!("this call passes {} argument(s), but the function expects {}",
                            args.len(), expected),
                        sp.file.clone(), sp.line, sp.col));
                }
            }
        }

        let ret_ty = self.lowerer.module.func_sig(fref).ret.clone();
        let is_void = ret_ty == Type::Void;

        // Aggregate return (sret ABI): allocate the result slot, pass its pointer
        // as the hidden first argument, and yield that pointer as the call value.
        if super::super::ret_is_sret(&ret_ty, self.ptr_size()) {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: ret_ty.clone(), align: None });
            let slot = Val::Local(slot);
            // Coerce user args against the user-facing parameter types (`param_types`
            // already has any hidden sret pointer stripped, so index directly by `i`
            // — the raw sig's sret offset differs between direct and module calls).
            let param_tys = param_types.clone();
            for (i, pval) in arg_vals.iter_mut().enumerate() {
                if let Some(pty) = param_tys.get(i) {
                    if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                        if self.transparent_union_arg(pval, pty, args.get(i))? { continue; }
                        if self.build_enum_arg(pval, pty, sp)? { continue; }
                        if self.is_sic() && super::super::types::is_sic_string(pty) {
                            *pval = self.string_param_arg(pval.clone(), args.get(i))?;
                        }
                        continue;
                    }
                    let coerced = self.coerce(pval.clone(), pty)?;
                    *pval = coerced;
                }
            }
            let mut args = Vec::with_capacity(arg_vals.len() + 1);
            args.push(slot.clone());
            args.extend(arg_vals);
            self.push_instr(Instr::Call { dest: None, func: fref, args, ret_ty: ret_ty.clone() });
            // A returned `string` temp holds a reference — release it at scope
            // exit (a binding retains it; an unused result is freed here).
            if self.is_sic() && super::super::types::is_sic_string(&ret_ty) {
                self.register_scope_exit(super::super::func::Cleanup::StringRelease { addr: slot.clone() });
            }
            return Ok(slot);
        }

        // Coerce arguments to expected param types
        let param_tys: Vec<Type> = self.lowerer.module.func_sig(fref).params.clone();
        let is_variadic = self.lowerer.module.func_sig(fref).variadic;
        for (i, pval) in arg_vals.iter_mut().enumerate() {
            if let Some(pty) = param_tys.get(i) {
                // A packed `va_array` / `va_dict` collector is already a finished
                // pointer value and has no matching `args[i]` — never coerce it.
                if super::super::types::is_va_array(pty) || super::super::types::is_va_dict(pty) {
                    continue;
                }
                // Struct/union args are already lowered to a pointer to the value
                // (by-value ABI); leave them as-is.
                if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                    if self.transparent_union_arg(pval, pty, args.get(i))? { continue; }
                    // sic: a bare (payload-less) variant discriminant passed to an
                    // enum parameter is materialized into the enum value here.
                    if self.build_enum_arg(pval, pty, sp)? { continue; }
                    // A `char*`/string-literal passed to a `string` parameter must
                    // be wrapped in a (non-owning) descriptor; a real string arg is
                    // already a descriptor pointer.
                    if self.is_sic() && super::super::types::is_sic_string(pty) {
                        *pval = self.string_param_arg(pval.clone(), args.get(i))?;
                    }
                    continue;
                }
                // sic bigint/fixed parameter: build the argument as the right
                // bignum value (a decimal/int literal lowered as a scalar must be
                // reconstructed; a matching-scale value is passed as-is). Args are
                // borrows (the callee doesn't free them).
                if self.build_bignum_arg(pval, pty, &args[i])? { continue; }
                let coerced = self.coerce(pval.clone(), pty)?;
                *pval = coerced;
            } else if is_variadic {
                // Arguments in the `...` part undergo the default argument
                // promotions (char/short→int, float→double). Without this a
                // small integer passed on the stack leaves its slot's high bits
                // uninitialized — libc printf's `%02x` of a `uint8_t` MAC byte
                // then read garbage (QEMU's default NIC MAC came out malformed).
                let p = self.promote_vararg(pval.clone())?;
                *pval = p;
            }
        }

        // x86-64 SysV: a variadic extern (libc) call carrying a float argument
        // needs `AL` set to the vector-arg count, which Cranelift never emits. Note
        // the callee so the backend routes it through an `AL`-setting trampoline.
        if is_variadic && fref.is_extern() {
            let has_float = arg_vals.iter().any(|v| self.val_type(v).is_float());
            if has_float {
                let name = self.lowerer.module.externs[fref.index()].name.clone();
                self.lowerer.float_vararg_externs.insert(name);
            }
        }

        if is_void {
            self.push_instr(Instr::Call { dest: None, func: fref, args: arg_vals, ret_ty });
            Ok(Constant::zero())
        } else {
            let returns_tuple = self.is_sic() && super::super::types::is_tuple(&ret_ty);
            let returns_bignum = self.is_sic()
                && (super::super::types::is_bigint(&ret_ty) || super::super::types::is_fixed(&ret_ty));
            let dest = self.alloc_val();
            self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: arg_vals, ret_ty });
            // sic tuple-returning call: the result carries a reference (retained by
            // the callee before return); release it at scope exit.
            if returns_tuple {
                self.register_tuple_release(Val::Local(dest))?;
            }
            // sic bigint/fixed-returning call: the callee returned an owned clone;
            // free it at statement end (value semantics, like any bigint temp).
            if returns_bignum {
                self.bigint_temps.push(Val::Local(dest));
            }
            Ok(Val::Local(dest))
        }
    }

    /// sic named parameters (sic.md §"Named parameters"): map a call's arguments
    /// (which include one or more `name = value`) onto the callee's parameters,
    /// returning a purely positional argument list. Errors on an unknown/duplicate
    /// name, a missing mandatory argument, a positional argument after a named one,
    /// or a callee whose parameters aren't known by name.
    fn resolve_named_args(&self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span) -> Result<Vec<Expr>> {
        let (param_names, variadic) = self.callee_param_info(func_expr).ok_or_else(|| {
            CompileError::at(
                "named arguments are only supported when the called function is known by name".to_string(),
                sp.file.clone(), sp.line, sp.col)
        })?;
        super::super::reorder_named_args(args, &param_names, variadic, sp)
    }

    /// The callee's IR parameter types (user-facing: any hidden sret pointer
    /// stripped). Empty when the callee isn't a statically-known function.
    fn callee_param_types(&self, func_expr: &Expr) -> Vec<Type> {
        match &func_expr.kind {
            ExprKind::Ident(name) => match self.lookup(name) {
                Some(LookupResult::Func(fr)) => {
                    let sig = self.lowerer.module.func_sig(fr);
                    let mut ps = sig.params.clone();
                    if super::super::ret_is_sret(&sig.ret, self.ptr_size()) && !ps.is_empty() {
                        ps.remove(0);
                    }
                    ps
                }
                _ => Vec::new(),
            },
            // Namespaced module call `mod.fn(...)` / `mod::fn(...)`: parameter types
            // come from the imported module's registered export signature.
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name } => match &base.kind {
                ExprKind::Ident(m) => self.lowerer.imported_modules.get(m)
                    .and_then(|ex| ex.get(name))
                    .and_then(|(_, t)| match t { Type::Function(ft) => Some(ft.params.clone()), _ => None })
                    .unwrap_or_default(),
                _ => Vec::new(),
            },
            ExprKind::EnumVariant { enum_name, variant } => self.lowerer.imported_modules.get(enum_name)
                .and_then(|ex| ex.get(variant))
                .and_then(|(_, t)| match t { Type::Function(ft) => Some(ft.params.clone()), _ => None })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// The value to pass for a `string` parameter. A real string argument is
    /// already a descriptor pointer and passes as-is; a `char*` / string literal
    /// is wrapped in a non-owning descriptor. Decided by the SOURCE type as well
    /// as the IR value type: a `string` read out of a container (`list[i]`,
    /// `dict[k]`) lowers to an untyped `void*` descriptor pointer, and wrapping
    /// THAT as a C string ran strlen over the descriptor and passed garbage.
    fn string_param_arg(&mut self, val: Val, src: Option<&Expr>) -> Result<Val> {
        let src_is_string = src
            .and_then(|a| self.infer_expr_type(a).ok())
            .is_some_and(|t| super::super::types::is_sic_string(&t));
        let vt = self.val_type(&val);
        if src_is_string || matches!(&vt, Type::Pointer(inner) if super::super::types::is_sic_string(inner)) {
            return Ok(val);
        }
        self.cstr_to_string(val)
    }

    /// Complete a call's argument list with omitted default values (sic.md
    /// §"Default parameters"). Returns `Some(new_args)` when it changes anything,
    /// else `None`. Two regimes, by whether the callee has a `va_array`/`va_dict`:
    ///
    ///  * **No va sink** — defaults fill positionally: a call shorter than the
    ///    parameter list has the trailing defaults appended (`add(2)` → `add(2,5)`).
    ///    Deferred to the named-arg path if the call already uses `name = value`.
    ///  * **With a va sink** — the defaulted parameters are KEYWORD-ONLY: the first
    ///    R positionals fill the required params, each defaulted param takes a
    ///    matching `name = value` (consumed) or its default, any remaining
    ///    positionals flow to the va sink, and leftover `name = value` go to the
    ///    `va_dict`. So `Print("x={}", x, target=stderr)` binds target by name and
    ///    sends `x` to the varargs, while `Print("x={}", x)` uses target's default.
    fn fill_default_args(&self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span)
        -> Result<Option<Vec<Expr>>>
    {
        if !self.is_sic() { return Ok(None); }
        // Resolve the callee's (param names, defaults) — from this unit for a
        // directly-named function, or from an imported module's manifest for
        // `mod::f(...)` / `mod.f(...)`. The defaults carry param names so a
        // keyword-only default can be bound by name.
        let (pnames, defs): (Vec<String>, Vec<Option<Expr>>) = match &func_expr.kind {
            ExprKind::Ident(n) => {
                let defs = match self.lowerer.fn_param_defaults.get(n) { Some(d) => d.clone(), None => return Ok(None) };
                let pnames = self.lowerer.fn_param_names.get(n).map(|(ns, _)| ns.clone()).unwrap_or_default();
                (pnames, defs)
            }
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name } => {
                match &base.kind {
                    ExprKind::Ident(m) => match self.lowerer.module_fn_defaults.get(&(m.clone(), name.clone())) {
                        Some((ns, lits)) => (ns.clone(), lits.iter().map(|l| l.map(|v| Expr::new(ExprKind::IntLit(v, false), sp.clone()))).collect()),
                        None => return Ok(None),
                    },
                    _ => return Ok(None),
                }
            }
            // `Module::sym(...)` (EnumVariant form) is canonicalized to the `Field`
            // form at the top of `lower_call` before fill runs, so it never reaches
            // here — no EnumVariant arm needed (handling it would double-fill).
            _ => return Ok(None),
        };
        if !defs.iter().any(|d| d.is_some()) { return Ok(None); }
        let has_va = self.callee_param_types(func_expr).iter()
            .any(|t| super::super::types::is_va_array(t) || super::super::types::is_va_dict(t));

        if !has_va {
            // Positional fill. Leave a call that already names arguments to the
            // named-arg path.
            if args.iter().any(|a| matches!(a.kind, ExprKind::NamedArg { .. })) { return Ok(None); }
            if args.len() < defs.len() && defs[args.len()..].iter().all(|d| d.is_some()) {
                let mut out = args.to_vec();
                for d in &defs[args.len()..] { out.push(d.clone().unwrap()); }
                return Ok(Some(out));
            }
            return Ok(None);
        }

        // va present → defaulted params are keyword-only.
        let r = defs.iter().take_while(|d| d.is_none()).count(); // required prefix
        let mut positional: Vec<Expr> = Vec::new();
        let mut named: Vec<(String, Expr)> = Vec::new();
        for a in args {
            if let ExprKind::NamedArg { name: n, value } = &a.kind { named.push((n.clone(), (**value).clone())); }
            else { positional.push(a.clone()); }
        }
        let mut out: Vec<Expr> = Vec::new();
        let mut pi = 0usize;
        for _ in 0..r { if pi < positional.len() { out.push(positional[pi].clone()); pi += 1; } }
        for i in r..defs.len() {
            let pn = pnames.get(i).cloned().unwrap_or_default();
            if let Some(k) = named.iter().position(|(n, _)| !pn.is_empty() && *n == pn) {
                out.push(named.remove(k).1);
            } else if let Some(d) = &defs[i] {
                out.push(d.clone());
            } else {
                // A required param slot in the keyword-only region with no value:
                // leave the call unchanged and let normal checking report it.
                return Ok(None);
            }
        }
        while pi < positional.len() { out.push(positional[pi].clone()); pi += 1; }
        for (n, v) in named {
            out.push(Expr::new(ExprKind::NamedArg { name: n, value: Box::new(v) }, sp.clone()));
        }
        Ok(Some(out))
    }

    /// Whether the callee declares a `va_dict` parameter (the named-varargs sink).
    fn callee_has_va_dict(&self, func_expr: &Expr) -> bool {
        self.callee_param_types(func_expr).iter().any(super::super::types::is_va_dict)
    }

    /// The callee's fixed parameter names and variadic flag, for named-argument
    /// binding. `None` when the callee isn't a statically-known function. An unknown
    /// parameter name (imported prototype) is returned as an empty string.
    fn callee_param_info(&self, func_expr: &Expr) -> Option<(Vec<String>, bool)> {
        match &func_expr.kind {
            ExprKind::Ident(name) | ExprKind::GenericRef { name, .. } => {
                if let Some(crate::ast::Decl::Func { params, variadic, .. }) =
                    self.lowerer.generic_fn_defs.get(name)
                {
                    return Some((params.iter().map(|p| p.name.clone().unwrap_or_default()).collect(), *variadic));
                }
                self.lowerer.fn_param_names.get(name).cloned()
            }
            // Module member call `mod.fn(...)` or `mod::fn(...)`: names aren't carried
            // in the manifest, but the exported signature gives the fixed arity +
            // variadic flag — enough for the variadic name-drop case
            // (`std.Print("{}", x=…)` / `std::Print(...)`).
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name } => {
                if let ExprKind::Ident(m) = &base.kind {
                    return self.module_export_param_info(m, name);
                }
                None
            }
            ExprKind::EnumVariant { enum_name, variant } => {
                self.module_export_param_info(enum_name, variant)
            }
            _ => None,
        }
    }

    /// Fixed arity + variadic flag of an imported module export `module::name`, from
    /// its exported function signature (parameter names aren't carried in a manifest,
    /// so they come back empty — enough for the variadic name-drop case).
    fn module_export_param_info(&self, module: &str, name: &str) -> Option<(Vec<String>, bool)> {
        if let Some((_, Type::Function(ft))) =
            self.lowerer.imported_modules.get(module).and_then(|e| e.get(name))
        {
            // A sic `va_array` trailing parameter (`std::Print(string, va_array)`) is
            // the Python-style varargs sink: treat it as variadic and exclude it from
            // the fixed parameters, so extra (named or positional) args drop to the
            // tail that the call site packs into the va_array.
            if let Some(last) = ft.params.last() {
                if super::super::types::is_va_array(last) {
                    return Some((vec![String::new(); ft.params.len() - 1], true));
                }
            }
            return Some((vec![String::new(); ft.params.len()], ft.variadic));
        }
        None
    }

    /// sic closure call (sic.md §"Lambdas"): invoke a capturing closure. The callee
    /// value is the environment pointer; load its `__code` field and call it,
    /// passing the environment as the hidden first argument. `arg_vals` are the
    /// already-lowered user arguments.
    fn lower_closure_call(&mut self, func_expr: &Expr, arg_vals: Vec<Val>, sp: &crate::lexer::Span) -> Result<Val> {
        let clo = self.lower_expr(func_expr)?;
        let env_ty = match self.val_type(&clo) {
            Type::Pointer(inner) => (*inner).clone(),
            _ => return Err(CompileError::at("internal: closure callee is not an environment pointer".to_string(),
                sp.file.clone(), sp.line, sp.col)),
        };
        // Load the code pointer (`__code`), whose type carries the full signature
        // (environment pointer first, then the user parameters).
        let code_lv = self.field_ptr_from(LValue::plain(clo.clone(), env_ty.clone()), "__code", false, sp)?;
        let code = self.load_lvalue(&code_lv)?;
        let func_ty = match self.val_type(&code) {
            Type::Pointer(inner) => match *inner {
                Type::Function(ft) => *ft,
                _ => return Err(CompileError::at("internal: closure `__code` is not a function pointer".to_string(),
                    sp.file.clone(), sp.line, sp.col)),
            },
            _ => return Err(CompileError::at("internal: closure `__code` is not a pointer".to_string(),
                sp.file.clone(), sp.line, sp.col)),
        };
        // The environment pointer is argument 0; coerce user args to params 1…N.
        let mut all_args = Vec::with_capacity(arg_vals.len() + 1);
        let env_pty = func_ty.params.get(0).cloned().unwrap_or_else(|| self.val_type(&clo));
        all_args.push(self.coerce(clo, &env_pty)?);
        for (i, a) in arg_vals.into_iter().enumerate() {
            match func_ty.params.get(i + 1) {
                Some(pty) if !matches!(pty, Type::Struct(_) | Type::Union(_)) => {
                    let c = self.coerce(a, pty)?; all_args.push(c);
                }
                _ => all_args.push(a),
            }
        }
        let ret_ty = func_ty.ret.clone();
        if super::super::ret_is_sret(&ret_ty, self.ptr_size()) {
            return self.lower_indirect_sret(code, func_ty, all_args);
        }
        let is_void = ret_ty == Type::Void;
        let dest = if !is_void { Some(self.alloc_val()) } else { None };
        self.push_instr(Instr::CallIndirect { dest, fptr: code, args: all_args, ret_ty: ret_ty.clone(), func_ty: Box::new(func_ty) });
        if let Some(d) = dest { self.val_types.insert(d.0, ret_ty); Ok(Val::Local(d)) } else { Ok(Constant::zero()) }
    }

    /// sic generic functions (sic.md §"Generics"): infer the type arguments of a
    /// `name<T,…>` call from its argument types, monomorphize the template, and
    /// re-dispatch as an ordinary call to the concrete instance. Each instantiation
    /// is fully, strongly type-checked by the normal lowerer.
    fn lower_generic_call(&mut self, name: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // The template's type parameters and its declared parameter type patterns.
        let (type_params, param_tys): (Vec<String>, Vec<crate::ast::AstType>) = {
            match self.lowerer.generic_fn_defs.get(name) {
                Some(crate::ast::Decl::Func { type_params, params, .. }) =>
                    (type_params.clone(), params.iter().map(|p| p.ty.ty.clone()).collect()),
                _ => return Err(CompileError::at(
                    format!("`{}` is not a generic function", name),
                    sp.file.clone(), sp.line, sp.col)),
            }
        };
        let params_set: std::collections::HashSet<String> = type_params.iter().cloned().collect();

        // Infer each type parameter from the corresponding argument's type.
        let mut subst: std::collections::HashMap<String, Type> = std::collections::HashMap::new();
        for (i, pat) in param_tys.iter().enumerate() {
            if let Some(arg) = args.get(i) {
                let at = self.infer_expr_type(arg)?;
                super::super::unify_type(pat, &at, &params_set, &mut subst, self.ptr_size())
                    .map_err(|e| CompileError::at(e.to_string(), sp.file.clone(), sp.line, sp.col))?;
            }
        }

        // Every type parameter must be solved (no explicit `name<…>()` form yet).
        let mut ordered = Vec::with_capacity(type_params.len());
        for tp in &type_params {
            match subst.get(tp) {
                Some(t) => ordered.push(t.clone()),
                None => return Err(CompileError::at(format!(
                    "cannot infer type parameter `{}` of generic function `{}` from the arguments",
                    tp, name), sp.file.clone(), sp.line, sp.col)),
            }
        }

        let mangled = self.lowerer.instantiate_generic_fn(name, &ordered)
            .map_err(|e| CompileError::at(e.to_string(), sp.file.clone(), sp.line, sp.col))?;

        // Dispatch as an ordinary direct call to the concrete monomorph.
        let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
        self.lower_call(&callee, args, sp)
    }

    /// sic generic functions (sic.md §"Generics"): a call with explicit type
    /// arguments, `add<int>(1, 2)`. The written types supply the monomorphization
    /// directly (used when a type parameter can't be inferred, e.g. it appears only
    /// in the return type). Arity must match the template's type-parameter list.
    fn lower_generic_call_explicit(
        &mut self, name: &str, type_args: &[crate::ast::QualType], args: &[Expr], sp: &crate::lexer::Span,
    ) -> Result<Val> {
        let n_params = match self.lowerer.generic_fn_defs.get(name) {
            Some(crate::ast::Decl::Func { type_params, .. }) => type_params.len(),
            _ => return Err(CompileError::at(
                format!("`{}` is not a generic function", name), sp.file.clone(), sp.line, sp.col)),
        };
        if type_args.len() != n_params {
            return Err(CompileError::at(format!(
                "generic function `{}` expects {} type argument(s), got {}",
                name, n_params, type_args.len()), sp.file.clone(), sp.line, sp.col));
        }
        let mut ordered = Vec::with_capacity(type_args.len());
        for ta in type_args {
            ordered.push(super::super::lower_type(ta, &self.lowerer.struct_types, self.ptr_size())?);
        }
        let mangled = self.lowerer.instantiate_generic_fn(name, &ordered)
            .map_err(|e| CompileError::at(e.to_string(), sp.file.clone(), sp.line, sp.col))?;
        let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
        self.lower_call(&callee, args, sp)
    }

    /// Lower an indirect call to an aggregate-returning function (sret ABI):
    /// allocate the result slot, pass its pointer as the hidden first argument,
    /// and yield that pointer. `func_ty.params[0]` is the sret pointer parameter.
    fn lower_indirect_sret(&mut self, fptr: Val, func_ty: sic_ir::FunctionType, arg_vals: Vec<Val>) -> Result<Val> {
        let ret_ty = func_ty.ret.clone();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: ret_ty.clone(), align: None });
        let slot = Val::Local(slot);
        // Coerce user args against params[1..] (params[0] is the sret pointer).
        let mut coerced = Vec::with_capacity(arg_vals.len() + 1);
        coerced.push(slot.clone());
        for (i, a) in arg_vals.into_iter().enumerate() {
            match func_ty.params.get(i + 1) {
                Some(pty) if !matches!(pty, Type::Struct(_) | Type::Union(_)) => {
                    coerced.push(self.coerce(a, pty)?);
                }
                _ => coerced.push(a),
            }
        }
        self.push_instr(Instr::CallIndirect {
            dest: None,
            fptr,
            args: coerced,
            ret_ty,
            func_ty: Box::new(func_ty),
        });
        Ok(slot)
    }

    /// Lower `__builtin_{add,mul}_overflow(a, b, *res)`: compute `a op b` in the
    /// result type, store the wrapped value through `*res`, and return an i1
    /// indicating whether the true result overflowed that type.
    fn lower_overflow_builtin(
        &mut self,
        op: BinOp,
        a_expr: &Expr,
        b_expr: &Expr,
        res_expr: &Expr,
    ) -> Result<Val> {
        let a = self.lower_expr(a_expr)?;
        let b = self.lower_expr(b_expr)?;
        let res_ptr = self.lower_expr(res_expr)?;

        // The result type is whatever `*res` points at.
        let ty = match self.val_type(&res_ptr) {
            Type::Pointer(inner) => *inner,
            _ => self.val_type(&a),
        };

        // Coerce operands to the result type so the arithmetic is well-typed.
        let a = self.coerce(a, &ty)?;
        let b = self.coerce(b, &ty)?;

        // result = a op b (wrapping), stored through *res.
        let result = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: result, op, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        let result = Val::Local(result);
        self.push_instr(Instr::Store { val: result.clone(), ptr: res_ptr });

        Ok(self.emit_overflow_flag(op, &a, &b, &result, &ty))
    }

    /// Compute the overflow flag (a `Bool` value) for a wrapping integer
    /// `result = a op b` (op ∈ {Add, Sub, Mul}). Shared by `__builtin_*_overflow`
    /// and sic's `unsafe`/`overflow` trapping arithmetic (sic.md §"Integer
    /// overflow").
    pub(crate) fn emit_overflow_flag(&mut self, op: BinOp, a: &Val, b: &Val, result: &Val, ty: &Type) -> Val {
        let signed = matches!(ty, Type::Int { signed: true, .. });
        let zero = Constant::zero();
        let ovf = self.alloc_val();
        match op {
            BinOp::Add if signed => {
                // Overflow iff a and b share a sign that differs from the sum:
                // ((a ^ sum) & (b ^ sum)) < 0.
                let t1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t1, op: BinOp::Xor, lhs: a.clone(), rhs: result.clone(), ty: ty.clone() });
                let t2 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t2, op: BinOp::Xor, lhs: b.clone(), rhs: result.clone(), ty: ty.clone() });
                let t3 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t3, op: BinOp::And, lhs: Val::Local(t1), rhs: Val::Local(t2), ty: ty.clone() });
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::ISLt, lhs: Val::Local(t3), rhs: zero, ty: ty.clone() });
            }
            BinOp::Add => {
                // Unsigned add overflows iff the sum wrapped below an operand.
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::IULt, lhs: result.clone(), rhs: a.clone(), ty: ty.clone() });
            }
            BinOp::Sub if signed => {
                // Signed sub overflows iff the operands differ in sign and the
                // result's sign differs from the minuend: ((a^b) & (a^diff)) < 0.
                let t1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t1, op: BinOp::Xor, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
                let t2 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t2, op: BinOp::Xor, lhs: a.clone(), rhs: result.clone(), ty: ty.clone() });
                let t3 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t3, op: BinOp::And, lhs: Val::Local(t1), rhs: Val::Local(t2), ty: ty.clone() });
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::ISLt, lhs: Val::Local(t3), rhs: zero, ty: ty.clone() });
            }
            BinOp::Sub => {
                // Unsigned sub overflows (borrows) iff a < b.
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::IULt, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
            }
            _ => {
                // Multiply: overflow iff a != 0 and result / a != b.
                let a_nz = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: a_nz, op: CmpOp::INe, lhs: a.clone(), rhs: zero, ty: ty.clone() });
                let div = if signed { BinOp::SDiv } else { BinOp::UDiv };
                // The divisor must never be zero: integer division by zero traps
                // (Cranelift emits `ud2`; a 128-bit libcall is UB), and that trap
                // fires unconditionally before the `a_nz` select below can mask the
                // result — so `i*i` at `i==0` in an `unsafe` block, or
                // `__builtin_mul_overflow(0, b, &r)`, would crash. Divide by
                // `a_nz ? a : 1` instead; when `a==0` the quotient is unused.
                let safe_div = self.alloc_val();
                self.push_instr(Instr::Select {
                    dest: safe_div,
                    cond: Val::Local(a_nz),
                    on_true: a.clone(),
                    on_false: Constant::int(1),
                    ty: ty.clone(),
                });
                let safe_div = Val::Local(safe_div);
                // 128-bit divide needs a libcall (see emit_div_rem_libcall).
                let quot_val = if let Some(v) = self.emit_div_rem_libcall(div, result.clone(), safe_div.clone(), ty) {
                    v
                } else {
                    let quot = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: quot, op: div, lhs: result.clone(), rhs: safe_div, ty: ty.clone() });
                    Val::Local(quot)
                };
                let mism = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: mism, op: CmpOp::INe, lhs: quot_val, rhs: b.clone(), ty: ty.clone() });
                // ovf = a_nz ? mism : false
                self.push_instr(Instr::Select {
                    dest: ovf,
                    cond: Val::Local(a_nz),
                    on_true: Val::Local(mism),
                    on_false: Val::Const(Constant::Bool(false)),
                    ty: Type::Bool,
                });
            }
        }
        Val::Local(ovf)
    }

    /// Lower an exception-guard block `overflow`/`divide_by_zero`/`exception`
    /// `{ body }` (sic.md §"Integer overflow", §"Errors and exceptions"). The body
    /// runs with the matching exception caught; a caught exception jumps to a fail
    /// block (skipping the rest of the body, committing nothing) and the expression
    /// yields `1`, otherwise `0`.
    pub(crate) fn lower_guard(&mut self, kind: crate::ast::GuardKind, body: &[crate::ast::Stmt]) -> Result<Val> {
        // Result slot defaults to 0 (success).
        let res = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: res, ty: Type::i32(), align: None });
        self.push_instr(Instr::Store { val: Constant::zero(), ptr: Val::Local(res) });

        let fail_bb = self.new_block_after_current();
        let end_bb = self.new_block_after_current();

        self.guard_stack.push(super::super::func::GuardFrame { kind, fail_bb });
        self.enter_scope();
        for s in body {
            if self.is_terminated() { break; }
            self.lower_stmt(s)?;
        }
        self.exit_scope();
        self.guard_stack.pop();

        // Success path: leave result 0, jump to the end.
        if !self.is_terminated() {
            self.set_terminator(Terminator::Jump(end_bb));
        }
        // Fail path: a caught exception lands here — set result to 1.
        self.switch_to_block(fail_bb);
        self.push_instr(Instr::Store { val: Constant::int(1), ptr: Val::Local(res) });
        self.set_terminator(Terminator::Jump(end_bb));

        self.switch_to_block(end_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(res), ty: Type::i32() });
        Ok(Val::Local(dest))
    }

    /// Branch to the exception target when `cond` is true (a caught exception), or
    /// (if there is no active guard) call `__sic_trap`. The offending operation's
    /// commit lives on the fall-through path, so a caught/trapped op is not
    /// committed. Continues on the no-exception path.
    pub(crate) fn branch_on_exception(&mut self, cond: Val, target: Option<super::super::BlockId>) {
        match target {
            Some(fail) => {
                let ok_bb = self.new_block_after_current();
                self.set_terminator(Terminator::CondJump { cond, then_bb: fail, else_bb: ok_bb });
                self.switch_to_block(ok_bb);
            }
            None => {
                let trap_bb = self.new_block_after_current();
                let ok_bb = self.new_block_after_current();
                self.set_terminator(Terminator::CondJump { cond, then_bb: trap_bb, else_bb: ok_bb });
                self.switch_to_block(trap_bb);
                let fref = self.lowerer.ensure_trap_fn();
                self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
                self.set_terminator(Terminator::Jump(ok_bb)); // abort never returns
                self.switch_to_block(ok_bb);
            }
        }
    }

    /// Lower `__builtin_{add,sub}c[l|ll](a, b, carryin, *carryout)`: wide
    /// add/subtract with carry. Returns the wrapped result and stores the
    /// outgoing carry (0/1) through `*carryout`.
    fn lower_carry_builtin(
        &mut self, is_sub: bool,
        a_expr: &Expr, b_expr: &Expr, cin_expr: &Expr, cout_expr: &Expr,
    ) -> Result<Val> {
        let a = self.lower_expr(a_expr)?;
        let b = self.lower_expr(b_expr)?;
        let cin = self.lower_expr(cin_expr)?;
        let cout_ptr = self.lower_expr(cout_expr)?;

        let ty = match self.val_type(&cout_ptr) {
            Type::Pointer(inner) => *inner,
            _ => self.val_type(&a),
        };
        let a = self.coerce(a, &ty)?;
        let b = self.coerce(b, &ty)?;
        let cin = self.coerce(cin, &ty)?;

        let op = if is_sub { BinOp::Sub } else { BinOp::Add };
        // First combine a and b, tracking carry/borrow, then fold in carryin.
        let s1 = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: s1, op, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        let s1 = Val::Local(s1);
        // carry1: add → s1 < a; sub (borrow) → a < b.
        let c1 = self.alloc_val();
        if is_sub {
            self.push_instr(Instr::Cmp { dest: c1, op: CmpOp::IULt, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        } else {
            self.push_instr(Instr::Cmp { dest: c1, op: CmpOp::IULt, lhs: s1.clone(), rhs: a.clone(), ty: ty.clone() });
        }
        let s2 = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: s2, op, lhs: s1.clone(), rhs: cin.clone(), ty: ty.clone() });
        let s2 = Val::Local(s2);
        // carry2: add → s2 < s1; sub (borrow) → s1 < cin.
        let c2 = self.alloc_val();
        if is_sub {
            self.push_instr(Instr::Cmp { dest: c2, op: CmpOp::IULt, lhs: s1.clone(), rhs: cin.clone(), ty: ty.clone() });
        } else {
            self.push_instr(Instr::Cmp { dest: c2, op: CmpOp::IULt, lhs: s2.clone(), rhs: s1.clone(), ty: ty.clone() });
        }
        // carryout = (c1 | c2), extended to the result type.
        let c1i = self.coerce(Val::Local(c1), &ty)?;
        let c2i = self.coerce(Val::Local(c2), &ty)?;
        let cout = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: cout, op: BinOp::Or, lhs: c1i, rhs: c2i, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(cout), ptr: cout_ptr });

        Ok(s2)
    }

    // ─── LValue lowering ─────────────────────────────────────────────────────

    /// Extract a pointer's pointee type, resolving an opaque pointee aggregate
    /// to its full definition. Pointees are stored opaque (see `lower_ast_type`);
    /// dereferencing needs the real layout for loads/stores/copies.
    /// Apply the C default argument promotions to a value passed in the `...`
    /// part of a variadic call: integer types narrower than `int` widen to `int`
    /// (preserving value per the source's signedness), and `float` widens to
    /// `double`. Anything already `int`-width or wider is unchanged.
    fn promote_vararg(&mut self, v: Val) -> Result<Val> {
        match self.val_type(&v) {
            Type::Bool => self.coerce(v, &Type::i32()),
            Type::Int { bits, .. } if bits < 32 => self.coerce(v, &Type::i32()),
            Type::Float32 => self.coerce(v, &Type::Float64),
            _ => Ok(v),
        }
    }

    /// Materialize a `size_t`-typed constant (the result type of `sizeof`,
    /// `_Alignof`, `offsetof`). A bare integer constant defaults to i32 when its
    /// value fits, so `sizeof(long) * n` would compute at 32 bits; forcing the
    /// pointer-width unsigned type keeps such products 64-bit (QEMU's ROUND_UP
    /// masks a 64-bit pointer with `-(sizeof(...)*n)` — a 32-bit result truncated
    /// the TB code buffer address and faulted during code generation).
    pub(crate) fn size_t_val(&mut self, v: u64) -> Val {
        let dest = self.alloc_val();
        let ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        self.push_instr(Instr::Cast { dest, op: CastOp::ZExt, val: Constant::uint(v), to_ty: ty });
        Val::Local(dest)
    }

    pub(crate) fn pointee_of(&self, ptr_ty: &Type) -> Type {
        match ptr_ty {
            Type::Pointer(t) => super::super::types::resolve_aggregate(t, &self.lowerer.struct_types),
            _ => Type::i32(),
        }
    }
}

