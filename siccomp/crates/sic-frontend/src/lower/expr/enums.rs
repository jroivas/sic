use crate::ast::Expr;
use crate::{Result, CompileError};
use super::super::func::FuncCtx;
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    /// sic (sic.md §"Match"/§"Namespace"): the discriminant of a plain (payload-less)
    /// C enum variant named `Enum::VARIANT`. `enum_name` may be scope-qualified
    /// (`N::E`, `mod::E`); the enum is its registry key (alias-resolved).
    pub(crate) fn resolve_plain_enum_const(&self, enum_name: &str, variant: &str) -> Option<i64> {
        let ename = self.lowerer.type_key(enum_name);
        let canon = self.lowerer.c_enum_alias.get(&ename).map(|s| s.as_str()).unwrap_or(&ename);
        let vs = self.lowerer.c_enum_defs.get(canon)?;
        vs.iter().find(|(n, _)| n == variant).map(|(_, v)| *v)
    }

    /// sic (sic.md §"Imports"): reject an UNQUALIFIED use of a name that a plain
    /// `import module;` made namespace-only (an imported enum or generic). A
    /// module-qualified path (`module::name`) is not gated.
    pub(crate) fn gate_qualified(&self, name: &str, sp: &crate::lexer::Span) -> Result<()> {
        if name.contains("::") { return Ok(()); }
        if let Some(m) = self.lowerer.qualified_only.get(name) {
            return Err(CompileError::at(
                format!("`{0}` is only available as `{1}::{0}` (a plain `import {1};` \
                    keeps it namespaced) — write `{1}::{0}`, or `import {1}::{0};` / \
                    `import {1}::*;` to use it unqualified", name, m),
                sp.file.clone(), sp.line, sp.col));
        }
        Ok(())
    }

    /// Construct a sic tagged-enum value (sic.md §"Match"): allocate the
    /// `{ tag; union }` struct on the stack, store the variant's discriminant, and
    /// store the payload (if any). Returns a pointer to the temporary, like a
    /// compound literal, so the surrounding assignment/return copies it.
    /// The error for a `path::name` that resolved to nothing. Such paths parse as
    /// enum variants, so the old message was "'std' is not a tagged enum" even
    /// for a missing module member — and type inference gave it no location.
    pub(crate) fn unresolved_path_error(&self, path: &str, name: &str, sp: &crate::lexer::Span) -> CompileError {
        let (head, rest) = match path.split_once("::") { Some((h, r)) => (h, Some(r)), None => (path, None) };
        let leaf = &self.lowerer.type_key(path);
        let msg = if self.is_sic() && self.lowerer.imported_modules.contains_key(head) {
            let sym = match rest { Some(r) => format!("{}__{}", r.replace("::", "__"), name), None => name.to_string() };
            self.lowerer.module_missing_symbol(head, &sym)
        } else if self.lowerer.enum_defs.contains_key(leaf) || self.lowerer.c_enum_defs.contains_key(leaf) {
            format!("enum '{}' has no variant '{}'", path, name)
        } else if self.lowerer.namespace_members.keys().any(|(scope, _)| scope == path) {
            format!("namespace '{}' has no member '{}'", path, name)
        } else {
            format!("'{}::{}' does not name anything: '{}' is not an imported module, a namespace or an enum",
                path, name, path)
        };
        CompileError::at(msg, sp.file.clone(), sp.line, sp.col)
    }

    pub(crate) fn construct_enum(&mut self, enum_name: &str, variant: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        self.gate_qualified(enum_name, sp)?;
        let path = enum_name;
        // sic plain (payload-less) C enum: `E::VARIANT` — possibly scope-qualified
        // (`N::E::VARIANT`, `mod::E::VARIANT`) — is the variant's discriminant.
        if self.is_sic() && args.is_empty() {
            if let Some(v) = self.resolve_plain_enum_const(enum_name, variant) {
                return Ok(Constant::int(v));
            }
        }
        // A scope-qualified tagged enum `mod::N::Enum` / `N::Enum` resolves to its
        // registry key (sic.md §"Namespace").
        let key;
        let enum_name = if self.is_sic() && !self.lowerer.enum_defs.contains_key(enum_name) {
            key = self.lowerer.type_key(enum_name);
            key.as_str()
        } else { enum_name };
        // A generic constructor (`Option::Some(5)` / `None`) names the template;
        // resolve it to the concrete monomorph via the expected target type.
        let resolved = self.resolve_generic_ctor(enum_name, sp)?;
        let enum_name = resolved.as_deref().unwrap_or(enum_name);
        let info = self.lowerer.enum_defs.get(enum_name).cloned()
            .ok_or_else(|| self.unresolved_path_error(path, variant, sp))?;
        let v = info.variant(variant).cloned().ok_or_else(|| CompileError::at(
            format!("enum '{}' has no variant '{}'", enum_name, variant), sp.file.clone(), sp.line, sp.col))?;

        // A payload arm whose single argument is itself an instance of this enum is
        // an *unwrap* (`Test::CUSTOM(inst)`), not a construction.
        if v.payload.is_some() && args.len() == 1 {
            if let Ok(t) = self.infer_expr_type(&args[0]) {
                if self.is_enum_struct(&t, enum_name) {
                    return self.unwrap_enum(&info, &v, &args[0], sp);
                }
            }
        }

        let struct_ty = info.struct_type.clone();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: struct_ty.clone(), align: None });
        self.val_types.insert(slot.0, struct_ty.clone());
        // Zero the whole value so an unused payload area is deterministic.
        let size = struct_ty.size_of(self.ptr_size());
        self.push_instr(Instr::MemSet {
            dst: Val::Local(slot), val: Constant::zero(), size,
            align: struct_ty.align_of(self.ptr_size()),
        });
        // Store the discriminant into `tag`.
        let tag_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), struct_ty.clone()), "tag", false, sp)?;
        self.store_lvalue(&tag_lv, Constant::int(v.tag))?;

        // Store the payload into the `data` union member (offset 0 of the union).
        match (&v.payload, args.len()) {
            (Some(pty), 1) => {
                let data_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), struct_ty.clone()), "data", false, sp)?;
                let payload_ptr = LValue::plain(data_lv.ptr, pty.clone());
                if self.is_sic() && super::super::types::is_sic_string(pty) {
                    // A `string` payload: wrap a bare `char*`/literal into a
                    // `{data,size,rc}` slice, then copy it in and retain it.
                    // A `string`-typed argument (a variable, field, call…) is used by
                    // address: `lower_expr` would yield the loaded descriptor VALUE,
                    // which retain/memcopy then misused as a pointer (`Some(s)` with
                    // a string local crashed in `__sic_str_retain`).
                    let arg_is_string = self.infer_expr_type(&args[0])
                        .map_or(false, |t| super::super::types::is_sic_string(&t));
                    let src = if arg_is_string {
                        self.lower_aggregate_ptr(&args[0])?
                    } else {
                        let arg = self.lower_expr(&args[0])?;
                        let vt = self.val_type(&arg);
                        let is_str = super::super::types::is_sic_string(&vt)
                            || matches!(&vt, Type::Pointer(inner) if super::super::types::is_sic_string(inner));
                        if is_str { arg } else { self.cstr_to_string(arg)? }
                    };
                    // Escapes like a `return`: a view of a local stack buffer
                    // (`string s = buf; return Some(s);`) gets an owned copy,
                    // anything else shares its refcount.
                    self.emit_string_return_into(&payload_ptr.ptr, &src)?;
                } else if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                    // Other aggregate payload: copy it in.
                    let src = self.lower_aggregate_ptr(&args[0])?;
                    let sz = pty.size_of(self.ptr_size());
                    let al = pty.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: payload_ptr.ptr, src, size: sz, align: al });
                } else if self.is_sic() && super::super::types::is_fixed(pty) {
                    // A `fixed` payload is an exact rational (`__sic_rat*`). Evaluate
                    // the arg into a freshly-owned rational (converting a literal/int,
                    // and taking an independent copy of any source) so the enum owns
                    // its payload — a bare `lower_expr` yields a raw float, and a
                    // shared pointer would dangle when the source's `__sic_rat_free`
                    // cleanup runs.
                    let val = self.eval_fixed_owned(&args[0], 0)?;
                    self.push_instr(Instr::Store { val, ptr: payload_ptr.ptr });
                } else if self.is_sic() && super::super::types::is_bigint(pty) {
                    // A `bigint` payload: same ownership story via `__sic_bi_clone`.
                    let val = self.eval_bigint_owned(&args[0])?;
                    self.push_instr(Instr::Store { val, ptr: payload_ptr.ptr });
                } else if self.is_sic() && (super::super::types::is_list(pty)
                    || super::super::types::is_dict(pty) || super::super::types::is_set(pty)) {
                    // A container payload holds its own reference: the source (a
                    // local released at scope exit, or a call's temporary released
                    // at statement end) would otherwise free it under the enum —
                    // `return Some(l);` handed the caller a freed list.
                    let val = self.lower_expr(&args[0])?;
                    self.container_retain(val.clone(), pty)?;
                    self.store_lvalue(&payload_ptr, val)?;
                } else {
                    let val = self.lower_expr(&args[0])?;
                    self.store_lvalue(&payload_ptr, val)?;
                }
            }
            (Some(_), n) => return Err(CompileError::at(
                format!("variant '{}::{}' takes 1 value, got {}", enum_name, variant, n),
                sp.file.clone(), sp.line, sp.col)),
            (None, 0) => {}
            (None, n) => return Err(CompileError::at(
                format!("variant '{}::{}' takes no value, got {}", enum_name, variant, n),
                sp.file.clone(), sp.line, sp.col)),
        }
        Ok(Val::Local(slot))
    }

    /// Resolve a generic-enum constructor's template name (`Option`) to its
    /// concrete monomorph (`Option<i32>`) using the expected target type
    /// (sic.md §"Match"). Returns `None` for an already-concrete enum name.
    pub(crate) fn resolve_generic_ctor(&self, enum_name: &str, sp: &crate::lexer::Span) -> Result<Option<String>> {
        // Already a concrete (registered) enum — nothing to resolve.
        if self.lowerer.enum_defs.contains_key(enum_name) { return Ok(None); }
        if !self.lowerer.generic_enum_defs.contains_key(enum_name) { return Ok(None); }
        let prefix = format!("{}<", enum_name);
        if let Some(Type::Struct(st)) = &self.expected_ty {
            if let Some(n) = &st.name {
                if n.starts_with(&prefix) && self.lowerer.enum_defs.contains_key(n) {
                    return Ok(Some(n.clone()));
                }
            }
        }
        Err(CompileError::at(format!(
            "cannot infer type arguments for generic enum `{}` here — annotate the \
             target type (e.g. `{}<int> x = …`)", enum_name, enum_name),
            sp.file.clone(), sp.line, sp.col))
    }

    /// True if `t` is the `{tag,union}` struct of the named tagged enum.
    pub(crate) fn is_enum_struct(&self, t: &Type, enum_name: &str) -> bool {
        matches!(t, Type::Struct(st) if st.name.as_deref() == Some(enum_name))
    }

    /// If `pty` is a tagged-enum struct and the arg `pval` is a bare discriminant
    /// (an integer tag), build the enum value into a temporary and repoint `pval`
    /// at it. Returns whether it handled the argument.
    pub(crate) fn build_enum_arg(&mut self, pval: &mut Val, pty: &Type, sp: &crate::lexer::Span) -> Result<bool> {
        if !(self.is_sic() && self.is_tagged_enum_struct(pty)) {
            return Ok(false);
        }
        if !matches!(self.val_type(pval), Type::Int { .. }) {
            // Already a proper enum value (pointer to storage).
            return Ok(false);
        }
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: pty.clone(), align: None });
        self.val_types.insert(slot.0, pty.clone());
        self.build_enum_from_tag(&Val::Local(slot), pty, pval.clone(), sp)?;
        *pval = Val::Local(slot);
        Ok(true)
    }

    /// What a tagged-enum payload of type `pty` owns (sic.md §"Memory safety"):
    /// a refcounted `string`, a `list`/`dict`/`set` handle, or a managed struct
    /// (one with a `~S()`, named by its destructor). `None`: plain data.
    pub(crate) fn payload_ownership(&self, pty: &Type) -> Option<PayloadOwn> {
        if super::super::types::is_sic_string(pty) { return Some(PayloadOwn::Str); }
        if super::super::types::is_list(pty) || super::super::types::is_dict(pty)
            || super::super::types::is_set(pty) {
            return Some(PayloadOwn::Container);
        }
        if let Type::Struct(st) = pty {
            if let Some(d) = st.name.as_deref().and_then(|n| self.lowerer.struct_dtor.get(n)) {
                return Some(PayloadOwn::Managed(d.clone()));
            }
        }
        None
    }

    /// The variants of tagged enum `ety` whose payload owns something, with the
    /// payload type and its ownership kind. Empty: the enum needs no cleanup.
    pub(crate) fn managed_variants(&self, ety: &Type) -> Vec<(i64, Type, PayloadOwn)> {
        let Type::Struct(st) = ety else { return Vec::new() };
        let Some(info) = st.name.as_deref().and_then(|n| self.lowerer.enum_defs.get(n)) else { return Vec::new() };
        info.variants.iter().filter_map(|v| {
            let pty = v.payload.clone()?;
            let own = self.payload_ownership(&pty)?;
            Some((v.tag, pty, own))
        }).collect()
    }

    /// Whether values of `ety` (a tagged enum) own payload resources.
    pub(crate) fn enum_is_managed(&self, ety: &Type) -> bool {
        self.is_sic() && !self.managed_variants(ety).is_empty()
    }

    /// Retain (`retain`) or release the payload of the tagged-enum value at `ptr`,
    /// for whichever variant it currently holds. `structs_only` limits it to a
    /// managed-struct payload (a constructor already retained a string/container).
    pub(crate) fn enum_payload_op(&mut self, ptr: Val, ety: &Type, retain: bool, structs_only: bool) -> Result<()> {
        let vars: Vec<(i64, Type, PayloadOwn)> = self.managed_variants(ety).into_iter()
            .filter(|(_, _, o)| !structs_only || matches!(o, PayloadOwn::Managed(_)))
            .collect();
        if vars.is_empty() { return Ok(()); }
        let sp = crate::lexer::Span::default();
        let tag = self.load_enum_tag(ptr.clone(), ety, &sp)?;
        let data = self.enum_data_ptr(ptr, ety, &sp)?;
        let join = self.new_block_after_current();
        for (vtag, pty, own) in vars {
            let hit = self.new_block_after_current();
            let next = self.new_block_after_current();
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: tag.clone(), rhs: Constant::int(vtag), ty: Type::i32() });
            self.set_terminator(Terminator::CondJump { cond: Val::Local(eq), then_bb: hit, else_bb: next });
            self.switch_to_block(hit);
            match own {
                PayloadOwn::Str => {
                    if retain { self.retain_string_at(&data)?; } else { self.release_string_at(&data)?; }
                }
                PayloadOwn::Container => {
                    let h = self.alloc_val();
                    self.push_instr(Instr::Load { dest: h, ptr: data.clone(), ty: pty.clone() });
                    if retain { self.container_retain(Val::Local(h), &pty)?; }
                    else { self.container_release(Val::Local(h), &pty)?; }
                }
                PayloadOwn::Managed(dtor) => {
                    if retain { self.retain_struct_owned_fields(data.clone(), &pty)?; }
                    else { self.emit_cleanup_call(data.clone(), &dtor); }
                }
            }
            self.set_terminator(Terminator::Jump(join));
            self.switch_to_block(next);
        }
        self.set_terminator(Terminator::Jump(join));
        self.switch_to_block(join);
        Ok(())
    }

    /// True if `t` is any tagged-enum representation struct.
    pub(crate) fn is_tagged_enum_struct(&self, t: &Type) -> bool {
        matches!(t, Type::Struct(st) if st.name.as_deref()
            .map_or(false, |n| self.lowerer.enum_defs.contains_key(n)))
    }

    /// Build a tagged-enum value in place from a bare discriminant (`Test x =
    /// BLACK;`): zero the storage and store the tag. A payload-less variant only.
    pub(crate) fn build_enum_from_tag(&mut self, ptr: &Val, ty: &Type, tag: Val, sp: &crate::lexer::Span) -> Result<()> {
        let size = ty.size_of(self.ptr_size());
        self.push_instr(Instr::MemSet {
            dst: ptr.clone(), val: Constant::zero(), size, align: ty.align_of(self.ptr_size()),
        });
        let tag_lv = self.field_ptr_from(LValue::plain(ptr.clone(), ty.clone()), "tag", false, sp)?;
        self.store_lvalue(&tag_lv, tag)?;
        Ok(())
    }

    /// Load a tagged-enum value's discriminant (`(int)x`). `ptr` addresses the
    /// `{tag,union}` struct.
    pub(crate) fn load_enum_tag(&mut self, ptr: Val, struct_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let tag_lv = self.field_ptr_from(LValue::plain(ptr, struct_ty.clone()), "tag", false, sp)?;
        self.load_lvalue(&tag_lv)
    }

    /// Pointer to a tagged-enum value's payload (`data` union member).
    pub(crate) fn enum_data_ptr(&mut self, ptr: Val, struct_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let data_lv = self.field_ptr_from(LValue::plain(ptr, struct_ty.clone()), "data", false, sp)?;
        Ok(data_lv.ptr)
    }

    /// Materialize a tagged-enum value of type `enum_ty` from `e` and return a
    /// pointer to it: a same-enum expression yields its own storage; a bare
    /// discriminant (`None`, `BLACK`) is built into a fresh temporary. Used where
    /// an enum value is needed by pointer (return, argument passing).
    pub(crate) fn enum_value_ptr(&mut self, e: &Expr, enum_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        // Expose the target enum type so a generic constructor (`return
        // Result::Ok(x)`) resolves its monomorph (sic.md §"Match").
        let prev = self.expected_ty.replace(enum_ty.clone());
        let out = self.enum_value_ptr_impl(e, enum_ty, sp);
        self.expected_ty = prev;
        out
    }

    fn enum_value_ptr_impl(&mut self, e: &Expr, enum_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let same = matches!(self.infer_expr_type(e), Ok(t) if &t == enum_ty);
        if same {
            self.lower_aggregate_ptr(e)
        } else {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: enum_ty.clone(), align: None });
            self.val_types.insert(slot.0, enum_ty.clone());
            let tag = self.lower_expr(e)?;
            self.build_enum_from_tag(&Val::Local(slot), enum_ty, tag, sp)?;
            Ok(Val::Local(slot))
        }
    }

    /// Unwrap a tagged-enum instance to a variant's payload (sic.md §"Match"):
    /// `Enum::VARIANT(inst)`. Aborts at runtime (`__sic_match_fail`) if `inst` is
    /// not that variant. Returns the payload value (or, for an aggregate payload,
    /// a pointer to it).
    fn unwrap_enum(&mut self, info: &super::super::TaggedEnum, v: &super::super::TaggedVariant, inst_expr: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let payload_ty = v.payload.clone().ok_or_else(|| CompileError::at(
            format!("variant '{}::{}' carries no value to unwrap", info.name, v.name),
            sp.file.clone(), sp.line, sp.col))?;
        let inst_ptr = self.lower_aggregate_ptr(inst_expr)?;
        let struct_ty = info.struct_type.clone();

        // Runtime guard: if tag != this variant's, abort.
        let tag_lv = self.field_ptr_from(LValue::plain(inst_ptr.clone(), struct_ty.clone()), "tag", false, sp)?;
        let tag = self.load_lvalue(&tag_lv)?;
        let ne = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: ne, op: CmpOp::INe, lhs: tag, rhs: Constant::int(v.tag), ty: Type::i32() });
        let fail_bb = self.new_block_after_current();
        let ok_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(ne), then_bb: fail_bb, else_bb: ok_bb });
        self.switch_to_block(fail_bb);
        let fref = self.lowerer.ensure_match_fail_fn();
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
        self.set_terminator(Terminator::Jump(ok_bb)); // abort never returns
        self.switch_to_block(ok_bb);

        // Read the payload out of the `data` union member.
        let data_lv = self.field_ptr_from(LValue::plain(inst_ptr, struct_ty), "data", false, sp)?;
        if matches!(payload_ty, Type::Struct(_) | Type::Union(_)) {
            Ok(data_lv.ptr) // aggregate payload decays to a pointer
        } else {
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: data_lv.ptr, ty: payload_ty.clone() });
            self.val_types.insert(d.0, payload_ty);
            Ok(Val::Local(d))
        }
    }
}

/// What a tagged-enum payload owns ([`FuncCtx::payload_ownership`]).
#[derive(Debug, Clone)]
pub(crate) enum PayloadOwn {
    /// A refcounted `string`.
    Str,
    /// A `list`/`dict`/`set` handle.
    Container,
    /// A struct with a destructor (its name).
    Managed(String),
}
