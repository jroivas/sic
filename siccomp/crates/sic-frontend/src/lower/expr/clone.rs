//! `x.clone()` (sic.md §"Copying: clone"): an independent deep copy.
//!
//! Assignment shares a managed value (the copy holds another reference); a
//! clone owns its own: a `string`'s bytes, a container's elements, a struct's
//! managed fields are all copied, so changing the clone never changes the
//! original. A struct clones field by field unless it says how itself with a
//! `S clone(S *self)` method; one with its own constructor or destructor must
//! (copying its bytes may duplicate a resource it manages, such as a file
//! descriptor).
//!
//! Everything works in place: `clone_at(p, T)` turns the byte copy of a value
//! at `p` into an independent one. Helpers that may recurse (a struct holding
//! a list of itself) are synthesized once per type.

use crate::ast::{Expr, ExprKind};
use crate::{Result, CompileError};
use super::super::func::FuncCtx;
use super::super::Lowerer;
use super::super::types as ty_;
#[allow(unused_imports)]
use super::*;

impl<'m> FuncCtx<'m> {
    pub(crate) fn needs_clone(&self, t: &Type) -> bool { self.lowerer.needs_clone(t) }
    fn clone_method(&self, sname: &str) -> bool { self.lowerer.clone_method(sname) }
    fn has_user_lifecycle(&self, sname: &str) -> bool { self.lowerer.has_user_lifecycle(sname) }
    fn enum_payloads(&self, t: &Type) -> Option<Vec<(i64, Option<Type>)>> { self.lowerer.enum_payloads(t) }

    /// `x.clone()` of a `t` can work: no part of it is a struct that must say
    /// how it is cloned and does not. Containers are checked by element type; an
    /// `any` or a tuple of unknown shape is checked when it is cloned.
    pub(crate) fn check_clonable(&self, t: &Type, sp: &crate::lexer::Span) -> Result<()> {
        self.check_clonable_in(t, sp, &mut Vec::new())
    }

    fn check_clonable_in(&self, t: &Type, sp: &crate::lexer::Span, seen: &mut Vec<String>) -> Result<()> {
        let ps = self.ptr_size();
        let rt = ty_::resolve_aggregate(t, &self.lowerer.struct_types);
        if ty_::is_list(&rt) { return self.check_clonable_in(&ty_::list_elem(&rt, ps), sp, seen); }
        if ty_::is_dict(&rt) || ty_::is_set(&rt) {
            if let Some((_, v)) = ty_::dict_kv(&rt, ps) { return self.check_clonable_in(&v, sp, seen); }
            return Ok(());
        }
        if let Some(layout) = ty_::tuple_layout_of(&rt) {
            if let Type::Struct(st) = &layout {
                for (_, f) in &st.fields { self.check_clonable_in(f, sp, seen)?; }
            }
            return Ok(());
        }
        if ty_::is_sic_string(&rt) || ty_::is_any(&rt) || ty_::is_closure(&rt) || ty_::is_weak_ref(&rt)
            || ty_::is_fixed(&rt) || ty_::is_bigint(&rt) { return Ok(()); }
        if let Some(vs) = self.enum_payloads(&rt) {
            for (_, p) in vs.iter() { if let Some(p) = p { self.check_clonable_in(p, sp, seen)?; } }
            return Ok(());
        }
        match &rt {
            Type::Struct(st) => {
                let Some(n) = st.name.clone() else { return Ok(()) };
                if self.clone_method(&n) || seen.contains(&n) { return Ok(()); }
                if self.has_user_lifecycle(&n) {
                    return Err(CompileError::at(format!(
                        "`{}` has its own constructor or destructor, so it is not cloned field by field; \
                         write `{} clone({} *self)` to say how it is copied", n, n, n),
                        sp.file.clone(), sp.line, sp.col));
                }
                seen.push(n);
                for (_, f) in &st.fields { self.check_clonable_in(f, sp, seen)?; }
                Ok(())
            }
            Type::Array { elem, .. } => self.check_clonable_in(elem, sp, seen),
            _ => Ok(()),
        }
    }

    /// Declare (once) the runtime function `name`.
    fn clone_extern(&mut self, name: &str, params: Vec<Type>, ret: Type) -> FuncRef {
        match self.lowerer.module.func_ref_by_name(name) {
            Some(f) => f,
            None => self.lowerer.module.add_extern(ExternFunc {
                name: name.to_string(),
                sig: FunctionType { params, ret, variadic: false },
            }),
        }
    }

    /// Write `msg` to stderr and abort (a value that cannot be cloned).
    fn emit_clone_fail(&mut self, msg: &str) -> Result<()> {
        let voidp = Type::void_ptr();
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let write = self.clone_extern("write", vec![Type::i32(), voidp.clone(), usize_ty.clone()], Type::i64());
        let abort = self.clone_extern("abort", vec![], Type::Void);
        let text = format!("{}\n", msg);
        let p = self.emit_cstring(&text);
        let p = self.coerce(p, &voidp)?;
        let n = self.coerce(Constant::uint(text.len() as u64), &usize_ty)?;
        let fd = self.coerce(Constant::int(2), &Type::i32())?;
        self.push_instr(Instr::Call { dest: None, func: write, args: vec![fd, p, n], ret_ty: Type::i64() });
        self.push_instr(Instr::Call { dest: None, func: abort, args: vec![], ret_ty: Type::Void });
        Ok(())
    }

    /// Replace the handle/pointer at `ptr` with `f(handle)`.
    fn clone_handle_at(&mut self, ptr: Val, t: &Type, f: FuncRef) {
        let voidp = Type::void_ptr();
        let h = self.alloc_val();
        self.push_instr(Instr::Load { dest: h, ptr: ptr.clone(), ty: voidp.clone() });
        let n = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(n), func: f, args: vec![Val::Local(h)], ret_ty: voidp.clone() });
        let c = self.alloc_val();
        self.push_instr(Instr::Cast { dest: c, op: CastOp::BitCast, val: Val::Local(n), to_ty: t.clone() });
        self.val_types.insert(c.0, t.clone());
        self.push_instr(Instr::Store { val: Val::Local(c), ptr });
    }

    /// Make the byte copy of a `t` at `ptr` an independent value: nothing it
    /// owns is shared with the value it was copied from.
    pub(crate) fn clone_at(&mut self, ptr: Val, t: &Type) -> Result<()> {
        if !self.needs_clone(t) { return Ok(()); }
        let ps = self.ptr_size();
        let voidp = Type::void_ptr();
        let rt = ty_::resolve_aggregate(t, &self.lowerer.struct_types);
        if ty_::is_sic_string(&rt) {
            // New bytes, owned by the copy.
            let sty = ty_::sic_string_type(ps);
            let (dptr, dty, _) = self.member_at(&ptr, &sty, 0).expect("string data");
            let data = self.alloc_val();
            self.push_instr(Instr::Load { dest: data, ptr: dptr, ty: dty });
            let (sptr, sfty, _) = self.member_at(&ptr, &sty, 1).expect("string size");
            let size = self.alloc_val();
            self.push_instr(Instr::Load { dest: size, ptr: sptr, ty: sfty });
            let owned = self.owned_string_from_parts(Val::Local(data), Val::Local(size))?;
            self.push_instr(Instr::MemCopy { dst: ptr, src: owned, size: sty.size_of(ps), align: sty.align_of(ps) as u64 });
            return Ok(());
        }
        if ty_::is_weak_ref(&rt) {
            let inner = ty_::weak_ref_inner(&rt, ps);
            let h = self.alloc_val();
            self.push_instr(Instr::Load { dest: h, ptr, ty: rt.clone() });
            return self.container_weak_op(Val::Local(h), &inner, true);
        }
        // A closure is immutable (its captures are copies or borrows): shared.
        // `fixed`/`bigint` already copy on every copy.
        if ty_::is_closure(&rt) || ty_::is_fixed(&rt) || ty_::is_bigint(&rt) {
            return self.retain_managed_at(ptr, &rt);
        }
        // A container copies each element by the element type (its type-info,
        // which an `any` element carries itself); a tuple by its shape.
        let elem = if ty_::is_list(&rt) { Some(("__sic_list_clone", ty_::list_elem(&rt, ps))) }
            else if ty_::is_dict(&rt) || ty_::is_set(&rt) {
                Some(("__sic_dict_clone", ty_::dict_kv(&rt, ps).map(|(_, v)| v).unwrap_or_else(ty_::any_type)))
            } else { None };
        if let Some((fname, et)) = elem {
            let et = ty_::resolve_aggregate(&et, &self.lowerer.struct_types);
            let ti = self.lower_type_value(&et);
            let ti = self.coerce(ti, &voidp)?;
            let f = self.clone_extern(fname, vec![voidp.clone(), voidp.clone()], voidp.clone());
            let h = self.alloc_val();
            self.push_instr(Instr::Load { dest: h, ptr: ptr.clone(), ty: voidp.clone() });
            let n = self.alloc_val();
            self.push_instr(Instr::Call { dest: Some(n), func: f, args: vec![Val::Local(h), ti], ret_ty: voidp.clone() });
            let c = self.alloc_val();
            self.push_instr(Instr::Cast { dest: c, op: CastOp::BitCast, val: Val::Local(n), to_ty: rt.clone() });
            self.val_types.insert(c.0, rt.clone());
            self.push_instr(Instr::Store { val: Val::Local(c), ptr });
            return Ok(());
        }
        if ty_::is_tuple(&rt) {
            let f = self.lowerer.ensure_tuple_clone()?;
            self.clone_handle_at(ptr, &rt, f);
            return Ok(());
        }
        if ty_::is_any(&rt) {
            let f = self.lowerer.ensure_any_clone_fn()?;
            let any_ty = ty_::any_type();
            let usize_ty = Type::Int { bits: ps * 8, signed: false };
            let sp = crate::lexer::Span::default();
            let ty_lv = self.field_ptr_from(LValue::plain(ptr.clone(), any_ty.clone()), "ty", false, &sp)?;
            let tyv = self.load_lvalue(&ty_lv)?;
            let tyv = self.coerce(tyv, &voidp)?;
            let slot_lv = self.field_ptr_from(LValue::plain(ptr, any_ty), "slot", false, &sp)?;
            let slotv = self.load_lvalue(&slot_lv)?;
            let slotv = self.coerce(slotv, &usize_ty)?;
            let n = self.alloc_val();
            self.push_instr(Instr::Call { dest: Some(n), func: f, args: vec![tyv, slotv], ret_ty: usize_ty.clone() });
            let nv = self.coerce(Val::Local(n), &slot_lv.ty)?;
            self.push_instr(Instr::Store { val: nv, ptr: slot_lv.ptr });
            return Ok(());
        }
        if let Some(vs) = self.enum_payloads(&rt) {
            let sp = crate::lexer::Span::default();
            let vs: Vec<(i64, Type)> = vs.into_iter()
                .filter_map(|(tag, p)| p.filter(|p| self.needs_clone(p)).map(|p| (tag, p))).collect();
            let tag = self.load_enum_tag(ptr.clone(), &rt, &sp)?;
            let data = self.enum_data_ptr(ptr, &rt, &sp)?;
            let join = self.new_block_after_current();
            for (vtag, pty) in vs {
                let hit = self.new_block_after_current();
                let next = self.new_block_after_current();
                let eq = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: tag.clone(), rhs: Constant::int(vtag), ty: Type::i32() });
                self.set_terminator(Terminator::CondJump { cond: Val::Local(eq), then_bb: hit, else_bb: next });
                self.switch_to_block(hit);
                self.clone_at(data.clone(), &pty)?;
                self.set_terminator(Terminator::Jump(join));
                self.switch_to_block(next);
            }
            self.set_terminator(Terminator::Jump(join));
            self.switch_to_block(join);
            return Ok(());
        }
        match &rt {
            Type::Struct(st) => {
                let Some(n) = st.name.clone() else { return Ok(()) };
                self.struct_clone_at(ptr, &rt, &n)
            }
            Type::Array { elem, len } => {
                let esz = elem.size_of(ps);
                for i in 0..*len {
                    let ep = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest: ep, base: ptr.clone(), index: Constant::int(i as i64),
                        elem_size: esz, result_ty: Type::Pointer(elem.clone()) });
                    self.clone_at(Val::Local(ep), elem)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// A struct clones by its own `clone()` method when it has one; one with a
    /// user constructor or destructor and no method cannot be cloned (a dynamic
    /// value — an `any`, an untyped container — reaching here aborts; a typed
    /// one is a compile error at the `.clone()`); any other clones field by
    /// field (a synthesized helper, so a recursive struct works).
    fn struct_clone_at(&mut self, ptr: Val, sty: &Type, sname: &str) -> Result<()> {
        let ps = self.ptr_size();
        if self.clone_method(sname) {
            let pty = Type::Pointer(Box::new(sty.clone()));
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: pty.clone(), align: None });
            let pv = self.coerce(ptr.clone(), &pty)?;
            self.push_instr(Instr::Store { val: pv, ptr: Val::Local(slot) });
            let hidden = format!("__sic_clone_self{}", slot.0);
            self.define_local(hidden.clone(), pty, slot);
            let sp = crate::lexer::Span::default();
            let call = Expr::new(ExprKind::Call {
                func: Box::new(Expr::new(ExprKind::Arrow {
                    base: Box::new(Expr::new(ExprKind::Ident(hidden), sp.clone())),
                    name: "clone".to_string(),
                }, sp.clone())),
                args: vec![],
            }, sp);
            let rp = self.lower_aggregate_ptr(&call)?;
            self.take_struct_temp(&rp);
            self.push_instr(Instr::MemCopy { dst: ptr, src: rp, size: sty.size_of(ps), align: sty.align_of(ps) as u64 });
            return Ok(());
        }
        if self.has_user_lifecycle(sname) {
            return self.emit_clone_fail(&format!(
                "cannot clone a `{}`: it has its own constructor or destructor and no clone() method", sname));
        }
        let f = self.lowerer.ensure_struct_clone(sty)?;
        let voidp = Type::void_ptr();
        let p = self.coerce(ptr, &voidp)?;
        self.push_instr(Instr::Call { dest: None, func: f, args: vec![p], ret_ty: Type::Void });
        Ok(())
    }

    /// The field-by-field clone body of a struct at `ptr`.
    fn struct_fields_clone_at(&mut self, ptr: Val, sty: &Type) -> Result<()> {
        let Type::Struct(st) = sty else { return Ok(()) };
        let weak: Vec<(String, Type)> = st.name.as_ref()
            .and_then(|n| self.lowerer.struct_weak_fields.get(n).cloned()).unwrap_or_default();
        let sp = crate::lexer::Span::default();
        for (fname, fty) in st.fields.clone() {
            if fname.is_empty() { continue; }
            if let Some((_, wty)) = weak.iter().find(|(w, _)| w == &fname) {
                let flv = self.field_ptr_from(LValue::plain(ptr.clone(), sty.clone()), &fname, false, &sp)?;
                let h = self.load_lvalue(&flv)?;
                self.container_weak_op(h, wty, true)?;
                continue;
            }
            if !self.needs_clone(&fty) { continue; }
            let flv = self.field_ptr_from(LValue::plain(ptr.clone(), sty.clone()), &fname, false, &sp)?;
            self.clone_at(flv.ptr, &fty)?;
        }
        Ok(())
    }

    /// `p.clone()` of a pointer from `new`: a new block of the same size (from
    /// its header), the bytes copied and each element cloned. NULL stays NULL.
    fn clone_new_block(&mut self, p: Val, pty: &Type) -> Result<Val> {
        let ps = self.ptr_size() as i64;
        let elem = match pty { Type::Pointer(e) => (**e).clone(), _ => Type::i8() };
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let out = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: out, ty: pty.clone(), align: None });
        let null = self.coerce(Constant::zero(), pty)?;
        self.push_instr(Instr::Store { val: null, ptr: Val::Local(out) });
        let pc = self.coerce(p, &Type::char_ptr())?;
        let is_null = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: pc.clone(), rhs: Constant::zero(), ty: Type::char_ptr() });
        let body = self.new_block_after_current();
        let done = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done, else_bb: body });
        self.switch_to_block(body);
        // [size | count | data…]: copy the header and the `size` data bytes.
        let block = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: block, base: pc, index: Constant::int(-2 * ps), elem_size: 1,
            result_ty: Type::Pointer(Box::new(usize_ty.clone())) });
        let size = self.alloc_val();
        self.push_instr(Instr::Load { dest: size, ptr: Val::Local(block), ty: usize_ty.clone() });
        let total = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: total, op: BinOp::Add, lhs: Val::Local(size), rhs: Constant::int(2 * ps), ty: usize_ty.clone() });
        let total = self.coerce(Val::Local(total), &Type::i64())?;
        let nb = self.emit_malloc(total.clone())?;
        self.emit_memcpy(nb.clone(), Val::Local(block), total)?;
        let cntp = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: cntp, base: nb.clone(), index: Constant::int(ps), elem_size: 1,
            result_ty: Type::Pointer(Box::new(usize_ty.clone())) });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: Val::Local(cntp) });
        let nd = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: nd, base: nb, index: Constant::int(2 * ps), elem_size: 1, result_ty: pty.clone() });
        self.val_types.insert(nd.0, pty.clone());
        if self.needs_clone(&elem) {
            // for (i = 0; i < size / sizeof(elem); i++) clone_at(&nd[i])
            let esz = elem.size_of(self.ptr_size()).max(1);
            let count = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: count, op: BinOp::UDiv, lhs: Val::Local(size), rhs: Constant::uint(esz), ty: usize_ty.clone() });
            let ctr = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: ctr, ty: usize_ty.clone(), align: None });
            let zero = self.coerce(Constant::int(0), &usize_ty)?;
            self.push_instr(Instr::Store { val: zero, ptr: Val::Local(ctr) });
            let head = self.new_block_after_current();
            let lbody = self.new_block_after_current();
            let ldone = self.new_block_after_current();
            self.set_terminator(Terminator::Jump(head));
            self.switch_to_block(head);
            let iv = self.alloc_val();
            self.push_instr(Instr::Load { dest: iv, ptr: Val::Local(ctr), ty: usize_ty.clone() });
            let lt = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: lt, op: CmpOp::IULt, lhs: Val::Local(iv), rhs: Val::Local(count), ty: usize_ty.clone() });
            self.set_terminator(Terminator::CondJump { cond: Val::Local(lt), then_bb: lbody, else_bb: ldone });
            self.switch_to_block(lbody);
            let ep = self.alloc_val();
            self.push_instr(Instr::GetElemPtr { dest: ep, base: Val::Local(nd), index: Val::Local(iv), elem_size: esz,
                result_ty: pty.clone() });
            self.clone_at(Val::Local(ep), &elem)?;
            let nx = self.alloc_val();
            let onei = self.coerce(Constant::int(1), &usize_ty)?;
            self.push_instr(Instr::BinOp { dest: nx, op: BinOp::Add, lhs: Val::Local(iv), rhs: onei, ty: usize_ty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(nx), ptr: Val::Local(ctr) });
            self.set_terminator(Terminator::Jump(head));
            self.switch_to_block(ldone);
        }
        self.push_instr(Instr::Store { val: Val::Local(nd), ptr: Val::Local(out) });
        self.set_terminator(Terminator::Jump(done));
        self.switch_to_block(done);
        let r = self.alloc_val();
        self.push_instr(Instr::Load { dest: r, ptr: Val::Local(out), ty: pty.clone() });
        self.val_types.insert(r.0, pty.clone());
        Ok(Val::Local(r))
    }

    /// The receiver of `base.clone()` and the type cloned: a pointer to a struct
    /// clones the struct (as `p.method()` calls it on the struct).
    fn clone_receiver_type(&self, base: &Expr, arrow: bool) -> Result<Type> {
        let bt = self.infer_expr_type(base)?;
        let rt = ty_::resolve_aggregate(&bt, &self.lowerer.struct_types);
        if let Type::Pointer(inner) = &rt {
            let it = ty_::resolve_aggregate(inner, &self.lowerer.struct_types);
            if arrow || (matches!(it, Type::Struct(_)) && !self.is_builtin_handle(&rt)) { return Ok(it); }
        }
        Ok(bt)
    }

    /// A pointer type that is itself a value — a container, tuple, closure,
    /// weak or bignum handle — rather than a pointer to one.
    fn is_builtin_handle(&self, t: &Type) -> bool {
        ty_::is_list(t) || ty_::is_dict(t) || ty_::is_set(t) || ty_::is_tuple(t) || ty_::is_closure(t)
            || ty_::is_weak_ref(t) || ty_::is_fixed(t) || ty_::is_bigint(t)
    }

    /// `func(args)` is a built-in `.clone()`: no arguments, and the receiver is
    /// no struct with its own `clone` method (that one is an ordinary call).
    /// Gives the receiver and whether it was reached with `->`.
    pub(crate) fn builtin_clone_call<'e>(&self, func: &'e Expr, args: &[Expr]) -> Option<(&'e Expr, bool)> {
        if !self.is_sic() || !args.is_empty() { return None; }
        let (base, arrow) = match &func.kind {
            ExprKind::Field { base, name } if name == "clone" => (base.as_ref(), false),
            ExprKind::Arrow { base, name } if name == "clone" => (base.as_ref(), true),
            _ => return None,
        };
        let t = self.clone_receiver_type(base, arrow).ok()?;
        if let Type::Struct(st) = &t {
            if st.name.as_deref().map_or(false, |n| self.clone_method(n)) { return None; }
        }
        Some((base, arrow))
    }

    /// The type of `base.clone()` (for inference).
    pub(crate) fn infer_clone_type(&self, base: &Expr, arrow: bool) -> Result<Type> {
        self.clone_receiver_type(base, arrow)
    }

    /// Lower `base.clone()` / `base->clone()`: a fresh value, owned the way a
    /// call result is (the caller binds or releases it).
    pub(crate) fn lower_clone(&mut self, base: &Expr, arrow: bool, sp: &crate::lexer::Span) -> Result<Val> {
        let t = self.clone_receiver_type(base, arrow)?;
        let ps = self.ptr_size();
        let rt = ty_::resolve_aggregate(&t, &self.lowerer.struct_types);
        // A pointer that is not a handle: the `new` block it points to.
        if let Type::Pointer(_) = &rt {
            if !self.is_builtin_handle(&rt) {
                let fat = match &base.kind {
                    ExprKind::Ident(n) => self.fat_locals.contains(n),
                    _ => false,
                };
                if !fat {
                    return Err(CompileError::at(
                        "`.clone()` of a pointer needs a `new` allocation (its size is in the block); \
                         this pointer is not known to be one".to_string(),
                        sp.file.clone(), sp.line, sp.col));
                }
                if let Type::Pointer(e) = &rt { self.check_clonable(e, sp)?; }
                let p = self.lower_expr(base)?;
                return self.clone_new_block(p, &rt);
            }
        }
        self.check_clonable(&rt, sp)?;
        let aggregate = matches!(rt, Type::Struct(_) | Type::Union(_) | Type::Array { .. });
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: rt.clone(), align: None });
        let slot = Val::Local(slot);
        if aggregate {
            let src = if arrow || matches!(self.infer_expr_type(base), Ok(Type::Pointer(_))) {
                self.lower_expr(base)?
            } else {
                self.lower_aggregate_ptr(base)?
            };
            self.push_instr(Instr::MemCopy { dst: slot.clone(), src, size: rt.size_of(ps), align: rt.align_of(ps) as u64 });
        } else {
            let v = self.lower_expr(base)?;
            let v = self.coerce(v, &rt)?;
            self.push_instr(Instr::Store { val: v, ptr: slot.clone() });
        }
        self.clone_at(slot.clone(), &rt)?;
        // Own the result as a call's: a string or managed struct is a temporary
        // released at scope exit unless bound; a tuple holds a reference; a
        // bignum is freed at statement end.
        if aggregate {
            if ty_::is_sic_string(&rt) {
                self.register_scope_exit(super::super::func::Cleanup::StringRelease { addr: slot.clone() });
            }
            self.register_struct_temp(&slot, &rt);
            return Ok(slot);
        }
        let v = self.alloc_val();
        self.push_instr(Instr::Load { dest: v, ptr: slot, ty: rt.clone() });
        self.val_types.insert(v.0, rt.clone());
        if ty_::is_tuple(&rt) { self.register_tuple_release(Val::Local(v))?; }
        if ty_::is_bigint(&rt) || ty_::is_fixed(&rt) { self.bigint_temps.push(Val::Local(v)); }
        Ok(Val::Local(v))
    }
}

impl Lowerer {
    /// The struct has a user-written `clone` method.
    pub(crate) fn clone_method(&self, sname: &str) -> bool {
        self.struct_methods.contains_key(&(sname.to_string(), "clone".to_string()))
    }

    /// The struct manages something itself — a user-written constructor or
    /// destructor — so it is never cloned field by field.
    pub(crate) fn has_user_lifecycle(&self, sname: &str) -> bool {
        if self.struct_ctor.contains_key(sname) { return true; }
        match self.struct_dtor.get(sname) {
            Some(d) => !(d.starts_with("__sic_mdtor_") || d.ends_with("__mdtor")),
            None => false,
        }
    }

    /// A tagged enum (`Option<string>`, `Shape`): its variants by tag.
    pub(crate) fn enum_payloads(&self, t: &Type) -> Option<Vec<(i64, Option<Type>)>> {
        let Type::Struct(st) = t else { return None };
        let info = self.enum_defs.get(st.name.as_deref()?)?;
        Some(info.variants.iter().map(|v| (v.tag, v.payload.clone())).collect())
    }

    /// A value of type `t` is not cloned by copying its bytes.
    pub(crate) fn needs_clone(&self, t: &Type) -> bool {
        let rt = ty_::resolve_aggregate(t, &self.struct_types);
        if ty_::is_weak_ref(&rt) || self.managed_value_type(&rt) { return true; }
        if let Some(vs) = self.enum_payloads(&rt) {
            return vs.iter().any(|(_, p)| p.as_ref().map_or(false, |p| self.needs_clone(p)));
        }
        match &rt {
            Type::Struct(st) => st.name.as_deref()
                .map_or(false, |n| self.clone_method(n) || self.has_user_lifecycle(n)),
            Type::Array { elem, len } => *len > 0 && self.needs_clone(elem),
            _ => false,
        }
    }

    /// Synthesize `name` once, reserving it before its body is built so that a
    /// helper reached again while building (a recursive type) calls itself.
    pub(crate) fn synth_fn(&mut self, name: &str, ret: Type, params: Vec<Type>,
        body: impl FnOnce(&mut FuncCtx) -> Result<Option<Val>>) -> Result<FuncRef> {
        if let Some(f) = self.module.func_ref_by_name(name) { return Ok(f); }
        let sig = super::super::build_fn_sig(ret.clone(), params.clone(), false, self.ptr_size);
        let ps: Vec<sic_ir::Param> = params.iter().enumerate()
            .map(|(i, t)| sic_ir::Param { name: format!("a{}", i), ty: t.clone() }).collect();
        let mut placeholder = Function::new(name.to_string(), sig.clone(), ps.clone(), Linkage::Internal);
        let pe = placeholder.alloc_block();
        let mut pb = BasicBlock::new(pe);
        pb.terminator = Terminator::Unreachable;
        placeholder.blocks.push(pb);
        let fref = self.module.add_function(placeholder);
        let mut func = Function::new(name.to_string(), sig, ps, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = FuncCtx::new_with_func(self, &mut func);
            for (i, t) in params.iter().enumerate() { fc.val_types.insert(0x10000 + i as u32, t.clone()); }
            let r = body(&mut fc)?;
            let r = match r { Some(v) => Some(fc.coerce(v, &ret)?), None => None };
            fc.set_terminator(Terminator::Ret(r));
        }
        self.module.functions[fref.index()] = func;
        Ok(fref)
    }

    fn clone_key(t: &Type) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        format!("{:?}", t).hash(&mut h);
        h.finish()
    }

    /// `void __sic_clone_<S>(S *p)`: clone a struct's fields in place.
    pub(crate) fn ensure_struct_clone(&mut self, sty: &Type) -> Result<FuncRef> {
        let n = match sty { Type::Struct(st) => st.name.clone().unwrap_or_default(), _ => String::new() };
        let name = format!("__sic_clone_{}_{:016x}", n, Self::clone_key(sty));
        let sty = sty.clone();
        self.synth_fn(&name, Type::Void, vec![Type::void_ptr()], move |fc| {
            let p = fc.coerce(Val::Local(ValId(0x10000)), &Type::Pointer(Box::new(sty.clone())))?;
            fc.struct_fields_clone_at(p, &sty)?;
            Ok(None)
        })
    }

    /// The type-info clone of `t` (sic.md §"Copying: clone"): `void f(void *p)`
    /// making a byte copy of a `t` at `p` independent, or `None` when the bytes
    /// are the whole value. Every tuple shares the shape-driven one.
    pub(crate) fn ensure_clone_fn(&mut self, t: &Type) -> Result<Option<FuncRef>> {
        let rt = ty_::resolve_aggregate(t, &self.struct_types);
        if !self.needs_clone(&rt) { return Ok(None); }
        if ty_::is_tuple(&rt) { return self.ensure_tuple_clone_at().map(Some); }
        let name = format!("__sic_cloneat_{:016x}", Self::clone_key(&rt));
        self.synth_fn(&name, Type::Void, vec![Type::void_ptr()], move |fc| {
            let p = fc.coerce(Val::Local(ValId(0x10000)), &Type::Pointer(Box::new(rt.clone())))?;
            fc.clone_at(p, &rt)?;
            Ok(None)
        }).map(Some)
    }

    /// `void __sic_tuple_clone_at(void **p)`: the tuple type-info clone.
    fn ensure_tuple_clone_at(&mut self) -> Result<FuncRef> {
        let voidp = Type::void_ptr();
        let f = self.ensure_tuple_clone()?;
        self.synth_fn("__sic_tuple_clone_at", Type::Void, vec![voidp.clone()], move |fc| {
            let p = fc.coerce(Val::Local(ValId(0x10000)), &Type::Pointer(Box::new(voidp.clone())))?;
            let h = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: h, ptr: p.clone(), ty: voidp.clone() });
            let n = fc.alloc_val();
            fc.push_instr(Instr::Call { dest: Some(n), func: f, args: vec![Val::Local(h)], ret_ty: voidp.clone() });
            fc.push_instr(Instr::Store { val: Val::Local(n), ptr: p });
            Ok(None)
        })
    }

    /// `void *__sic_tuple_clone(void *data)`: clone any tuple by its shape
    /// `{ count; { typeinfo *ti; offset }[count] }`. A tuple holding only plain
    /// values is shared (it is immutable); otherwise a new block gets the header
    /// and bytes, refcount 1, and each element is cloned by its type-info.
    pub(crate) fn ensure_tuple_clone(&mut self) -> Result<FuncRef> {
        let voidp = Type::void_ptr();
        let ps = self.ptr_size as i64;
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        self.synth_fn("__sic_tuple_clone", voidp.clone(), vec![voidp.clone()], move |fc| {
            let data = fc.coerce(Val::Local(ValId(0x10000)), &Type::char_ptr())?;
            let word = |fc: &mut FuncCtx, base: Val, off: Val| -> Val {
                let p = fc.alloc_val();
                fc.push_instr(Instr::GetElemPtr { dest: p, base, index: off, elem_size: 1,
                    result_ty: Type::Pointer(Box::new(usize_ty.clone())) });
                let v = fc.alloc_val();
                fc.push_instr(Instr::Load { dest: v, ptr: Val::Local(p), ty: usize_ty.clone() });
                Val::Local(v)
            };
            let to_ptr = |fc: &mut FuncCtx, w: Val| -> Val {
                let p = fc.alloc_val();
                fc.push_instr(Instr::Cast { dest: p, op: CastOp::IntToPtr, val: w, to_ty: Type::char_ptr() });
                Val::Local(p)
            };
            let var = |fc: &mut FuncCtx, ty: &Type, init: Val| -> Val {
                let v = fc.alloc_val();
                fc.push_instr(Instr::Alloca { dest: v, ty: ty.clone(), align: None });
                fc.push_instr(Instr::Store { val: init, ptr: Val::Local(v) });
                Val::Local(v)
            };
            let load = |fc: &mut FuncCtx, p: &Val, ty: &Type| -> Val {
                let v = fc.alloc_val();
                fc.push_instr(Instr::Load { dest: v, ptr: p.clone(), ty: ty.clone() });
                Val::Local(v)
            };
            let bin = |fc: &mut FuncCtx, op: BinOp, a: Val, b: Val| -> Val {
                let v = fc.alloc_val();
                fc.push_instr(Instr::BinOp { dest: v, op, lhs: a, rhs: b, ty: usize_ty.clone() });
                Val::Local(v)
            };
            let cmp = |fc: &mut FuncCtx, op: CmpOp, a: Val, b: Val| -> Val {
                let v = fc.alloc_val();
                fc.push_instr(Instr::Cmp { dest: v, op, lhs: a, rhs: b, ty: usize_ty.clone() });
                Val::Local(v)
            };
            let zero = fc.coerce(Constant::int(0), &usize_ty)?;
            let out = var(fc, &Type::char_ptr(), data.clone());
            let some = fc.new_block_after_current();
            let share = fc.new_block_after_current();
            let done = fc.new_block_after_current();
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: data.clone(), rhs: Constant::zero(), ty: Type::char_ptr() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done, else_bb: some });
            fc.switch_to_block(some);
            let shape = word(fc, data.clone(), Constant::int(-4 * ps));
            let no_shape = cmp(fc, CmpOp::IEq, shape.clone(), zero.clone());
            let has_shape = fc.new_block_after_current();
            fc.set_terminator(Terminator::CondJump { cond: no_shape, then_bb: share, else_bb: has_shape });
            fc.switch_to_block(has_shape);
            let sp = to_ptr(fc, shape);
            let count = word(fc, sp.clone(), Constant::int(0));
            // Element `i`: its type-info's (clone, size) and its offset.
            let elem = |fc: &mut FuncCtx, i: Val| -> (Val, Val, Val) {
                let at = bin(fc, BinOp::Mul, i, Constant::uint(ps as u64 + 8));
                let at = bin(fc, BinOp::Add, at, Constant::uint(8));
                let ti = word(fc, sp.clone(), at.clone());
                let off_at = bin(fc, BinOp::Add, at, Constant::uint(ps as u64));
                let off = word(fc, sp.clone(), off_at);
                let tp = to_ptr(fc, ti);
                let cl = word(fc, tp.clone(), Constant::int(ty_::TYPEINFO_OFF_CLONE as i64));
                let szp = fc.alloc_val();
                fc.push_instr(Instr::GetElemPtr { dest: szp, base: tp, index: Constant::int(ty_::TYPEINFO_OFF_SIZE as i64),
                    elem_size: 1, result_ty: Type::Pointer(Box::new(Type::u32())) });
                let sz = load(fc, &Val::Local(szp), &Type::u32());
                let sz = fc.coerce(sz, &usize_ty).unwrap();
                (cl, sz, off)
            };
            // for (i = 0; i < count; i++) body(i), then continue at the exit block.
            let each = |fc: &mut FuncCtx, body: &mut dyn FnMut(&mut FuncCtx, Val) -> Result<()>| -> Result<()> {
                let iv = var(fc, &usize_ty, zero.clone());
                let head = fc.new_block_after_current();
                let lbody = fc.new_block_after_current();
                let exit = fc.new_block_after_current();
                fc.set_terminator(Terminator::Jump(head));
                fc.switch_to_block(head);
                let i = load(fc, &iv, &usize_ty);
                let lt = cmp(fc, CmpOp::IULt, i.clone(), count.clone());
                fc.set_terminator(Terminator::CondJump { cond: lt, then_bb: lbody, else_bb: exit });
                fc.switch_to_block(lbody);
                body(fc, i.clone())?;
                let nx = bin(fc, BinOp::Add, i, Constant::uint(1));
                fc.push_instr(Instr::Store { val: nx, ptr: iv.clone() });
                fc.set_terminator(Terminator::Jump(head));
                fc.switch_to_block(exit);
                Ok(())
            };
            // Pass 1: the bytes the elements span, and whether any needs a clone.
            let end = var(fc, &usize_ty, zero.clone());
            let deep = var(fc, &usize_ty, zero.clone());
            each(fc, &mut |fc, i| {
                let (cl, sz, off) = elem(fc, i);
                let e = bin(fc, BinOp::Add, off, sz);
                let cur = load(fc, &end, &usize_ty);
                let gt = cmp(fc, CmpOp::IUGt, e.clone(), cur.clone());
                let m = fc.alloc_val();
                fc.push_instr(Instr::Select { dest: m, cond: gt, on_true: e, on_false: cur, ty: usize_ty.clone() });
                fc.push_instr(Instr::Store { val: Val::Local(m), ptr: end.clone() });
                let d = load(fc, &deep, &usize_ty);
                let d = bin(fc, BinOp::Or, d, cl);
                fc.push_instr(Instr::Store { val: d, ptr: deep.clone() });
                Ok(())
            })?;
            let d = load(fc, &deep, &usize_ty);
            let plain = cmp(fc, CmpOp::IEq, d, zero.clone());
            let copy = fc.new_block_after_current();
            fc.set_terminator(Terminator::CondJump { cond: plain, then_bb: share, else_bb: copy });
            fc.switch_to_block(copy);
            let e = load(fc, &end, &usize_ty);
            let total = bin(fc, BinOp::Add, e, Constant::uint(4 * ps as u64));
            let total = fc.coerce(total, &Type::i64())?;
            let block = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: block, base: data.clone(), index: Constant::int(-4 * ps), elem_size: 1,
                result_ty: Type::char_ptr() });
            let nb = fc.emit_malloc(total.clone())?;
            fc.emit_memcpy(nb.clone(), Val::Local(block), total)?;
            let rcp = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: rcp, base: nb.clone(), index: Constant::int(3 * ps), elem_size: 1,
                result_ty: Type::Pointer(Box::new(usize_ty.clone())) });
            let one = fc.coerce(Constant::int(1), &usize_ty)?;
            fc.push_instr(Instr::Store { val: one, ptr: Val::Local(rcp) });
            let nd = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: nd, base: nb, index: Constant::int(4 * ps), elem_size: 1,
                result_ty: Type::char_ptr() });
            fc.push_instr(Instr::Store { val: Val::Local(nd), ptr: out.clone() });
            // Pass 2: clone each element that has a clone, in the new block.
            let fty = FunctionType { params: vec![voidp.clone()], ret: Type::Void, variadic: false };
            each(fc, &mut |fc, i| {
                let (cl, _, off) = elem(fc, i);
                let has = cmp(fc, CmpOp::INe, cl.clone(), zero.clone());
                let call_bb = fc.new_block_after_current();
                let next = fc.new_block_after_current();
                fc.set_terminator(Terminator::CondJump { cond: has, then_bb: call_bb, else_bb: next });
                fc.switch_to_block(call_bb);
                let ep = fc.alloc_val();
                fc.push_instr(Instr::GetElemPtr { dest: ep, base: Val::Local(nd), index: off, elem_size: 1, result_ty: voidp.clone() });
                let fp = fc.alloc_val();
                fc.push_instr(Instr::Cast { dest: fp, op: CastOp::IntToPtr, val: cl,
                    to_ty: Type::Pointer(Box::new(Type::Function(Box::new(fty.clone())))) });
                fc.push_instr(Instr::CallIndirect { dest: None, fptr: Val::Local(fp), args: vec![Val::Local(ep)],
                    ret_ty: Type::Void, func_ty: Box::new(fty.clone()) });
                fc.set_terminator(Terminator::Jump(next));
                fc.switch_to_block(next);
                Ok(())
            })?;
            fc.set_terminator(Terminator::Jump(done));
            fc.switch_to_block(share);
            fc.emit_rc_retain(data)?;
            fc.set_terminator(Terminator::Jump(done));
            fc.switch_to_block(done);
            let r = load(fc, &out, &Type::char_ptr());
            Ok(Some(r))
        })
    }

    /// `u64 __sic_any_clone(void *ty, u64 slot)`: an `any` owns only a wrapped
    /// `string` — give the clone its own (a new string box); any other slot is
    /// a value or a borrow and stays.
    pub(crate) fn ensure_any_clone_fn(&mut self) -> Result<FuncRef> {
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let voidp = Type::void_ptr();
        let u32_ty = Type::Int { bits: 32, signed: false };
        let ps = self.ptr_size;
        self.synth_fn("__sic_any_clone", usize_ty.clone(), vec![voidp.clone(), usize_ty.clone()], move |fc| {
            let tyv = Val::Local(ValId(0x10000));
            let slot = Val::Local(ValId(0x10001));
            let out = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: out, ty: usize_ty.clone(), align: None });
            fc.push_instr(Instr::Store { val: slot.clone(), ptr: Val::Local(out) });
            let kind_bb = fc.new_block_after_current();
            let str_bb = fc.new_block_after_current();
            let done = fc.new_block_after_current();
            let ti = fc.coerce(tyv.clone(), &usize_ty)?;
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: ti, rhs: Constant::int(0), ty: usize_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done, else_bb: kind_bb });
            fc.switch_to_block(kind_bb);
            let kp = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: kp, base: tyv, index: Constant::int(ty_::TYPEINFO_OFF_KIND as i64),
                elem_size: 1, result_ty: Type::Pointer(Box::new(u32_ty.clone())) });
            let k = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: k, ptr: Val::Local(kp), ty: u32_ty.clone() });
            let is_str = fc.alloc_val();
            let sk = ty_::type_kind(&ty_::sic_string_type(ps)) as i64;
            fc.push_instr(Instr::Cmp { dest: is_str, op: CmpOp::IEq, lhs: Val::Local(k), rhs: Constant::int(sk), ty: u32_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_str), then_bb: str_bb, else_bb: done });
            fc.switch_to_block(str_bb);
            // The slot points at a string descriptor: copy its bytes into a new
            // owned box (released by the `any`'s release, like a container's).
            let sty = ty_::sic_string_type(ps);
            let dp = fc.coerce(slot, &Type::Pointer(Box::new(sty.clone())))?;
            let (d0, d0t, _) = fc.member_at(&dp, &sty, 0).expect("string data");
            let data = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: data, ptr: d0, ty: d0t });
            let (d1, d1t, _) = fc.member_at(&dp, &sty, 1).expect("string size");
            let size = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: size, ptr: d1, ty: d1t });
            let boxed = fc.emit_dict_owned_string(Val::Local(data), Val::Local(size))?;
            let bv = fc.coerce(boxed, &usize_ty)?;
            fc.push_instr(Instr::Store { val: bv, ptr: Val::Local(out) });
            fc.set_terminator(Terminator::Jump(done));
            fc.switch_to_block(done);
            let r = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r, ptr: Val::Local(out), ty: usize_ty.clone() });
            Ok(Some(Val::Local(r)))
        })
    }
}
