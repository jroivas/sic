use crate::ast::Expr;
use crate::{Result, CompileError};
use sic_ir::*;
use super::super::func::FuncCtx;
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    /// sic (sic.md §"Match"/§"Namespace"): the discriminant of a plain (payload-less)
    /// C enum variant named `Enum::VARIANT`. `enum_name` may be scope-qualified
    /// (`N::E`, `mod::E`); the enum is its last `::` segment (alias-resolved).
    pub(crate) fn resolve_plain_enum_const(&self, enum_name: &str, variant: &str) -> Option<i64> {
        let ename = enum_name.rsplit("::").next().unwrap_or(enum_name);
        let canon = self.lowerer.c_enum_alias.get(ename).map(|s| s.as_str()).unwrap_or(ename);
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
    pub(crate) fn construct_enum(&mut self, enum_name: &str, variant: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        self.gate_qualified(enum_name, sp)?;
        // sic plain (payload-less) C enum: `E::VARIANT` — possibly scope-qualified
        // (`N::E::VARIANT`, `mod::E::VARIANT`) — is the variant's discriminant.
        if self.is_sic() && args.is_empty() {
            if let Some(v) = self.resolve_plain_enum_const(enum_name, variant) {
                return Ok(Constant::int(v));
            }
        }
        // A scope-qualified tagged enum `mod::Enum` / `N::Enum` resolves to its last
        // `::` segment (sic.md §"Namespace").
        let enum_name = if self.is_sic() && !self.lowerer.enum_defs.contains_key(enum_name) {
            enum_name.rsplit("::").next().unwrap_or(enum_name)
        } else { enum_name };
        // A generic constructor (`Option::Some(5)` / `None`) names the template;
        // resolve it to the concrete monomorph via the expected target type.
        let resolved = self.resolve_generic_ctor(enum_name, sp)?;
        let enum_name = resolved.as_deref().unwrap_or(enum_name);
        let info = self.lowerer.enum_defs.get(enum_name).cloned().ok_or_else(|| CompileError::at(
            format!("'{}' is not a tagged enum", enum_name), sp.file.clone(), sp.line, sp.col))?;
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
                    let arg = self.lower_expr(&args[0])?;
                    let vt = self.val_type(&arg);
                    let is_str = super::super::types::is_sic_string(&vt)
                        || matches!(&vt, Type::Pointer(inner) if super::super::types::is_sic_string(inner));
                    let src = if is_str { arg } else { self.cstr_to_string(arg)? };
                    let sz = pty.size_of(self.ptr_size());
                    let al = pty.align_of(self.ptr_size());
                    self.retain_string_at(&src)?;
                    self.push_instr(Instr::MemCopy { dst: payload_ptr.ptr, src, size: sz, align: al });
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
