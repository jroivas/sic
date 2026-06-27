use std::collections::HashMap;
use crate::ast::{self, Decl, Stmt, Expr, ExprKind, ForInit, StorageClass, AstType, QualType, Initializer};
use crate::ast::Param as AstParam;
use crate::{Result, CompileError};
use sic_ir::*;
use super::{Lowerer, lower_type, lower_param_type, eval_const_expr};

/// Per-function lowering context.
pub struct FuncCtx<'m> {
    pub lowerer: &'m mut Lowerer,
    pub func: *mut Function, // raw pointer to avoid lifetime issues during construction
    /// Local variable map: name → (type, alloca ValId)
    pub locals: Vec<HashMap<String, (Type, ValId)>>,
    /// Type of each value produced by instructions: ValId → Type
    pub val_types: HashMap<u32, Type>,
    /// Current basic block id being built
    pub current_bb: BlockId,
    /// Return type of the current function
    pub ret_ty: Type,
    /// Label name → BlockId mapping (for goto)
    pub labels: HashMap<String, BlockId>,
    /// Stack of (break_bb, continue_bb) for loops
    pub loop_stack: Vec<(BlockId, BlockId)>,
    /// Stack of switch default/end blocks
    pub switch_stack: Vec<(BlockId, BlockId)>, // (default_bb, end_bb)
    /// Pending goto stubs: label_name → Vec<(from_bb, stub_term)>
    pub pending_gotos: Vec<(String, BlockId)>,
    /// Last initialized local variable (for implicit return in sic)
    pub last_init_local: Option<(ValId, Type)>,
}

// Safety: we control the lifetime, func pointer is valid as long as FuncCtx exists.
impl<'m> FuncCtx<'m> {
    pub fn new_with_func(lowerer: &'m mut Lowerer, func: &mut Function) -> Self {
        let ret_ty = func.sig.ret.clone();
        let entry_id = if func.blocks.is_empty() {
            let id = func.alloc_block();
            id
        } else {
            func.blocks[0].id
        };
        FuncCtx {
            lowerer,
            func: func as *mut Function,
            locals: vec![HashMap::new()],
            val_types: HashMap::new(),
            current_bb: entry_id,
            ret_ty,
            labels: HashMap::new(),
            loop_stack: Vec::new(),
            switch_stack: Vec::new(),
            pending_gotos: Vec::new(),
            last_init_local: None,
        }
    }

    pub fn func_ref(&self) -> &Function { unsafe { &*self.func } }
    pub fn func_mut(&mut self) -> &mut Function { unsafe { &mut *self.func } }

    pub fn alloc_val(&mut self) -> ValId {
        self.func_mut().alloc_val()
    }

    pub fn alloc_block(&mut self) -> BlockId {
        self.func_mut().alloc_block()
    }

    pub fn current_block_mut(&mut self) -> &mut BasicBlock {
        let id = self.current_bb;
        self.func_mut().block_mut(id)
    }

    pub fn current_block(&self) -> &BasicBlock {
        self.func_ref().block(self.current_bb)
    }

    pub fn push_instr(&mut self, instr: Instr) {
        // Record the result type for any instruction that produces a value.
        if let Some((vid, ty)) = instr_result_type(&instr) {
            self.val_types.insert(vid.0, ty);
        }
        self.current_block_mut().instrs.push(instr);
    }

    pub fn set_terminator(&mut self, t: Terminator) {
        self.current_block_mut().terminator = t;
    }

    pub fn new_block_after_current(&mut self) -> BlockId {
        let id = self.alloc_block();
        let bb = BasicBlock::new(id);
        self.func_mut().blocks.push(bb);
        id
    }

    pub fn switch_to_block(&mut self, id: BlockId) {
        self.current_bb = id;
    }

    pub fn is_terminated(&self) -> bool {
        !matches!(self.current_block().terminator, Terminator::Unreachable)
    }

    pub fn enter_scope(&mut self) { self.locals.push(HashMap::new()); }
    pub fn exit_scope(&mut self)  { self.locals.pop(); }

    pub fn define_local(&mut self, name: String, ty: Type, alloca_id: ValId) {
        self.locals.last_mut().unwrap().insert(name, (ty, alloca_id));
    }

    pub fn lookup(&self, name: &str) -> Option<LookupResult<'_>> {
        for scope in self.locals.iter().rev() {
            if let Some((ty, vid)) = scope.get(name) {
                return Some(LookupResult::Local(ty, *vid));
            }
        }
        if let Some((ty, gref)) = self.lowerer.globals_map.get(name) {
            return Some(LookupResult::Global(ty, *gref));
        }
        if let Some(v) = self.lowerer.enum_consts.get(name) {
            return Some(LookupResult::EnumConst(*v));
        }
        if let Some(fref) = self.lowerer.module.func_ref_by_name(name) {
            return Some(LookupResult::Func(fref));
        }
        None
    }

    pub fn ptr_size(&self) -> u32 { self.lowerer.ptr_size }

    pub fn lower_type(&self, qt: &QualType) -> Result<Type> {
        lower_type(qt, &self.lowerer.struct_types, self.lowerer.ptr_size)
    }

    // ─── Top-level expression lowering (for fake_main) ─────────────────────

    /// Lower a list of expression statements and return the last value.
    pub fn lower_expr_stmts<'a>(
        &mut self, stmts: &[&'a Expr], entry: &mut BasicBlock,
    ) -> Result<Option<Val>> {
        let mut last = None;
        for expr in stmts {
            // We'll generate instructions but for fake_main we need a single block.
            // This is called during synthesis — we'll just generate into the provided block.
            last = Some(self.lower_expr_into_block(expr, entry)?);
        }
        Ok(last)
    }

    fn lower_expr_into_block(&mut self, expr: &Expr, _bb: &mut BasicBlock) -> Result<Val> {
        // In fake_main context, all expressions go into 'entry' block.
        // The entry block is current_bb.
        self.lower_expr(expr)
    }
}

pub enum LookupResult<'a> {
    Local(&'a Type, ValId),   // pointer to alloca
    Global(&'a Type, GlobalRef), // pointer to global
    EnumConst(i64),
    Func(FuncRef),
}

impl<'m> Lowerer {
    pub fn lower_function(
        &mut self,
        name: &str,
        ret_ty: &QualType,
        params: &[AstParam],
        variadic: bool,
        body: &[Stmt],
        storage: &Option<StorageClass>,
    ) -> Result<()> {
        let ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
        let ir_params: Result<Vec<_>> = params.iter().map(|p| {
            lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
        }).collect();
        let ir_params = ir_params?;

        let sig = FunctionType { ret: ir_ret.clone(), params: ir_params.clone(), variadic };

        let linkage = match storage {
            Some(StorageClass::Static) => Linkage::Internal,
            _ => Linkage::External,
        };

        let ir_param_decls: Vec<sic_ir::Param> = params.iter().zip(&ir_params).map(|(p, ty)| {
            sic_ir::Param {
                name: p.name.clone().unwrap_or_default(),
                ty: ty.clone(),
            }
        }).collect();

        let mut func = Function::new(name.to_string(), sig, ir_param_decls, linkage);

        // Create entry block
        let entry_id = func.alloc_block();
        let entry = BasicBlock::new(entry_id);
        func.blocks.push(entry);

        let mut fc = FuncCtx::new_with_func(self, &mut func);

        // Alloca for each parameter and store the param sentinel value.
        // The backend maps ValId(0x10000 + i) → the i-th function parameter.
        fc.enter_scope();
        for (i, p) in params.iter().enumerate() {
            if let Some(pname) = &p.name {
                let pty = ir_params[i].clone();
                let ptr_vid = fc.alloc_val();
                fc.push_instr(Instr::Alloca { dest: ptr_vid, ty: pty.clone() });
                fc.push_instr(Instr::Store {
                    val: Val::Local(ValId(i as u32 + 0x10000)),
                    ptr: Val::Local(ptr_vid),
                });
                fc.define_local(pname.clone(), pty, ptr_vid);
            }
        }

        // Lower body
        for stmt in body {
            if fc.is_terminated() { break; }
            fc.lower_stmt(stmt)?;
        }

        // If function didn't return, add implicit return
        if !fc.is_terminated() {
            let ret_val = if ir_ret == Type::Void {
                None
            } else if let Some((last_vid, last_ty)) = fc.last_init_local.clone() {
                // sic implicit return: last initialized local variable
                let load_dest = fc.alloc_val();
                fc.push_instr(Instr::Load { dest: load_dest, ptr: Val::Local(last_vid), ty: last_ty });
                let coerced = fc.coerce(Val::Local(load_dest), &ir_ret)?;
                Some(coerced)
            } else {
                Some(Constant::zero())
            };
            fc.set_terminator(Terminator::Ret(ret_val));
        }

        fc.exit_scope();

        // Replace the pre-registered placeholder, or add if not pre-registered
        if let Some(idx) = self.module.functions.iter().position(|f| f.name == name) {
            self.module.functions[idx] = func;
        } else {
            self.module.add_function(func);
        }
        Ok(())
    }
}

// ─── Statement lowering ──────────────────────────────────────────────────────

impl<'m> FuncCtx<'m> {
    pub fn lower_stmt(&mut self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Null(_) => {}
            Stmt::Expr(e, _) => { self.lower_expr(e)?; }
            Stmt::Block(stmts, _) => {
                self.enter_scope();
                for s in stmts {
                    if self.is_terminated() { break; }
                    self.lower_stmt(s)?;
                }
                self.exit_scope();
            }
            Stmt::Decl(d) => self.lower_local_decl(d)?,
            Stmt::Return(val, _) => {
                let ret = if let Some(e) = val {
                    let v = self.lower_expr(e)?;
                    let expected = self.ret_ty.clone();
                    Some(self.coerce(v, &expected)?)
                } else {
                    None
                };
                self.set_terminator(Terminator::Ret(ret));
            }
            Stmt::If { cond, then, else_, .. } => self.lower_if(cond, then, else_.as_deref())?,
            Stmt::While { cond, body, .. } => self.lower_while(cond, body)?,
            Stmt::DoWhile { body, cond, .. } => self.lower_do_while(body, cond)?,
            Stmt::For { init, cond, post, body, .. } => self.lower_for(init, cond, post, body)?,
            Stmt::Switch { val, body, .. } => self.lower_switch(val, body)?,
            Stmt::Break(_) => {
                if let Some(&(end, _)) = self.loop_stack.last() {
                    self.set_terminator(Terminator::Jump(end));
                } else if let Some(&(_, end)) = self.switch_stack.last() {
                    self.set_terminator(Terminator::Jump(end));
                } else {
                    return Err(CompileError::new("break outside loop/switch"));
                }
            }
            Stmt::Continue(_) => {
                if let Some(&(_, cont)) = self.loop_stack.last() {
                    self.set_terminator(Terminator::Jump(cont));
                } else {
                    return Err(CompileError::new("continue outside loop"));
                }
            }
            Stmt::Goto(label, _) => {
                if let Some(&target_bb) = self.labels.get(label) {
                    // Backward goto: label already seen
                    self.set_terminator(Terminator::Jump(target_bb));
                    // Switch to a fresh (unreachable) block so we can continue
                    let dead = self.new_block_after_current();
                    self.switch_to_block(dead);
                } else {
                    // Forward goto: create placeholder, patch when label is found
                    let placeholder = self.new_block_after_current();
                    self.pending_gotos.push((label.clone(), self.current_bb));
                    self.set_terminator(Terminator::Jump(placeholder));
                    self.switch_to_block(placeholder);
                }
            }
            Stmt::Label(name, inner, _) => {
                // Create a new block for this label
                let label_bb = self.new_block_after_current();
                if !self.is_terminated() {
                    self.set_terminator(Terminator::Jump(label_bb));
                }
                self.switch_to_block(label_bb);
                self.func_mut().block_mut(label_bb).label = Some(name.clone());
                self.labels.insert(name.clone(), label_bb);
                // Patch pending gotos that target this label
                self.patch_goto(name, label_bb);
                self.lower_stmt(inner)?;
            }
            Stmt::Case(val, body, _) => {
                // Case is handled by the switch lowering
                // When we encounter a case statement in the body of a switch,
                // we emit it as a labeled block
                let case_bb = self.new_block_after_current();
                if !self.is_terminated() {
                    self.set_terminator(Terminator::Jump(case_bb));
                }
                self.switch_to_block(case_bb);
                let const_val = eval_const_expr(val, &self.lowerer.enum_consts).unwrap_or(0);
                self.func_mut().block_mut(case_bb).label = Some(format!("case_{}", const_val));
                self.lower_stmt(body)?;
            }
            Stmt::Default(body, _) => {
                let default_bb = self.new_block_after_current();
                if !self.is_terminated() {
                    self.set_terminator(Terminator::Jump(default_bb));
                }
                self.switch_to_block(default_bb);
                self.func_mut().block_mut(default_bb).label = Some("default".to_string());
                self.lower_stmt(body)?;
            }
        }
        Ok(())
    }

    fn patch_goto(&mut self, label: &str, target: BlockId) {
        let gotos_to_patch: Vec<BlockId> = self.pending_gotos.iter()
            .filter(|(l, _)| l == label)
            .map(|(_, bb)| *bb)
            .collect();
        for from_bb in gotos_to_patch {
            // The block's terminator should be a Jump to some placeholder.
            // Replace it with a jump to the real label block.
            let blk = self.func_mut().block_mut(from_bb);
            if let Terminator::Jump(_) = &blk.terminator {
                blk.terminator = Terminator::Jump(target);
            }
        }
        self.pending_gotos.retain(|(l, _)| l != label);
    }

    fn lower_local_decl(&mut self, decl: &Decl) -> Result<()> {
        match decl {
            Decl::Var { base_ty, declarators, .. } => {
                match &base_ty.ty {
                    AstType::Struct(s) => {
                        self.lowerer.register_struct_type_from_def(s)?;
                    }
                    AstType::Union(u) => {
                        self.lowerer.register_union_type_from_def(u)?;
                    }
                    AstType::Enum(e) => {
                        self.lowerer.register_enum(e)?;
                    }
                    _ => {}
                }
                for d in declarators {
                    let mut ty = self.lower_type(&d.ty)?;
                    // Handle VLA (variable-length array): size was 0 because expr isn't constant
                    // Try to evaluate the size expr at compile time or use a conservative fallback
                    if let (Type::Array { elem: ref elem_ty, len: 0 }, AstType::Array { size: Some(sz_expr), .. }) = (&ty, &d.ty.ty) {
                        let resolved_len = eval_const_expr(sz_expr, &self.lowerer.enum_consts)
                            .unwrap_or(1024) as usize; // fallback: 1024 elements
                        let resolved_len = resolved_len.max(1);
                        ty = Type::Array { elem: elem_ty.clone(), len: resolved_len };
                    }
                    let vid = self.alloc_val();
                    self.push_instr(Instr::Alloca { dest: vid, ty: ty.clone() });

                    if let Some(init) = &d.init {
                        self.lower_initializer(init, Val::Local(vid), &ty)?;
                    } else {
                        // Zero-initialize
                        let size = ty.size_of(self.ptr_size());
                        if size > 0 {
                            self.push_instr(Instr::MemSet {
                                dst: Val::Local(vid), val: Constant::zero(), size, align: ty.align_of(self.ptr_size()),
                            });
                        }
                    }
                    // Track last declared scalar local for implicit return
                    if matches!(ty, Type::Int { .. } | Type::Float32 | Type::Float64 | Type::Pointer(_) | Type::Bool) {
                        self.last_init_local = Some((vid, ty.clone()));
                    }
                    self.define_local(d.name.clone(), ty, vid);
                }
            }
            Decl::TypeDef { names, .. } => {
                for (name, ty) in names {
                    if let Ok(ir_ty) = lower_type(ty, &self.lowerer.struct_types, self.lowerer.ptr_size) {
                        self.lowerer.struct_types.insert(name.clone(), ir_ty);
                    }
                }
            }
            _ => {} // Nested function defs etc. — not supported
        }
        Ok(())
    }

    fn lower_initializer(&mut self, init: &Initializer, ptr: Val, ty: &Type) -> Result<()> {
        match init {
            Initializer::Expr(e) => {
                let val = self.lower_expr(e)?;
                let coerced = self.coerce(val, ty)?;
                self.push_instr(Instr::Store { val: coerced, ptr });
            }
            Initializer::List(items) => {
                match ty {
                    Type::Array { elem, len } => {
                        let elem_size = elem.size_of(self.ptr_size());
                        for (i, item) in items.iter().enumerate() {
                            if i >= *len && *len > 0 { break; }
                            let idx_val = Constant::int(i as i64);
                            let elem_ptr = self.alloc_val();
                            self.push_instr(Instr::GetElemPtr {
                                dest: elem_ptr, base: ptr.clone(), index: idx_val, elem_size,
                            });
                            self.lower_initializer(item, Val::Local(elem_ptr), elem)?;
                        }
                    }
                    Type::Struct(st) => {
                        let st = st.clone();
                        for (i, item) in items.iter().enumerate() {
                            if i >= st.fields.len() { break; }
                            let field_ty = st.fields[i].1.clone();
                            let byte_offset = st.field_offset(i, self.ptr_size());
                            let field_ptr = self.alloc_val();
                            self.push_instr(Instr::GetFieldPtr {
                                dest: field_ptr, base: ptr.clone(), field_idx: i,
                                struct_name: st.name.clone(), byte_offset,
                            });
                            self.lower_initializer(item, Val::Local(field_ptr), &field_ty)?;
                        }
                    }
                    _ => {
                        if let Some(first) = items.first() {
                            self.lower_initializer(first, ptr, ty)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // ─── Control flow ────────────────────────────────────────────────────────

    fn lower_if(&mut self, cond: &Expr, then: &Stmt, else_: Option<&Stmt>) -> Result<()> {
        let cond_val = self.lower_expr(cond)?;
        let cond_bool = self.to_bool(cond_val)?;

        let then_bb = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();
        let else_bb = if else_.is_some() { self.new_block_after_current() } else { merge_bb };

        self.set_terminator(Terminator::CondJump {
            cond: cond_bool,
            then_bb,
            else_bb: if else_.is_some() { else_bb } else { merge_bb },
        });

        self.switch_to_block(then_bb);
        self.lower_stmt(then)?;
        if !self.is_terminated() {
            self.set_terminator(Terminator::Jump(merge_bb));
        }

        if let Some(e) = else_ {
            self.switch_to_block(else_bb);
            self.lower_stmt(e)?;
            if !self.is_terminated() {
                self.set_terminator(Terminator::Jump(merge_bb));
            }
        }

        self.switch_to_block(merge_bb);
        Ok(())
    }

    fn lower_while(&mut self, cond: &Expr, body: &Stmt) -> Result<()> {
        let cond_bb = self.new_block_after_current();
        let body_bb = self.new_block_after_current();
        let end_bb  = self.new_block_after_current();

        if !self.is_terminated() {
            self.set_terminator(Terminator::Jump(cond_bb));
        }
        self.switch_to_block(cond_bb);
        let cv = self.lower_expr(cond)?;
        let cb = self.to_bool(cv)?;
        self.set_terminator(Terminator::CondJump { cond: cb, then_bb: body_bb, else_bb: end_bb });

        self.loop_stack.push((end_bb, cond_bb));
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.loop_stack.pop();

        self.switch_to_block(end_bb);
        Ok(())
    }

    fn lower_do_while(&mut self, body: &Stmt, cond: &Expr) -> Result<()> {
        let body_bb = self.new_block_after_current();
        let cond_bb = self.new_block_after_current();
        let end_bb  = self.new_block_after_current();

        if !self.is_terminated() { self.set_terminator(Terminator::Jump(body_bb)); }
        self.loop_stack.push((end_bb, cond_bb));
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.loop_stack.pop();

        self.switch_to_block(cond_bb);
        let cv = self.lower_expr(cond)?;
        let cb = self.to_bool(cv)?;
        self.set_terminator(Terminator::CondJump { cond: cb, then_bb: body_bb, else_bb: end_bb });

        self.switch_to_block(end_bb);
        Ok(())
    }

    fn lower_for(
        &mut self, init: &Option<ForInit>, cond: &Option<Expr>,
        post: &Option<Expr>, body: &Stmt,
    ) -> Result<()> {
        self.enter_scope();

        if let Some(fi) = init {
            match fi {
                ForInit::Decl(d) => self.lower_local_decl(d)?,
                ForInit::Expr(e) => { self.lower_expr(e)?; }
            }
        }

        let cond_bb = self.new_block_after_current();
        let body_bb = self.new_block_after_current();
        let post_bb = self.new_block_after_current();
        let end_bb  = self.new_block_after_current();

        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.switch_to_block(cond_bb);
        if let Some(c) = cond {
            let cv = self.lower_expr(c)?;
            let cb = self.to_bool(cv)?;
            self.set_terminator(Terminator::CondJump { cond: cb, then_bb: body_bb, else_bb: end_bb });
        } else {
            self.set_terminator(Terminator::Jump(body_bb));
        }

        self.loop_stack.push((end_bb, post_bb));
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(post_bb)); }
        self.loop_stack.pop();

        self.switch_to_block(post_bb);
        if let Some(p) = post { self.lower_expr(p)?; }
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }

        self.switch_to_block(end_bb);
        self.exit_scope();
        Ok(())
    }

    fn lower_switch(&mut self, val: &Expr, body: &Stmt) -> Result<()> {
        let v = self.lower_expr(val)?;
        let v_i32 = self.coerce(v, &Type::i32())?;

        // We'll collect cases as we go (they appear as Case stmts in body).
        // For simplicity: use a two-pass approach where we scan for const case values.
        let end_bb = self.new_block_after_current();
        let body_bb = self.new_block_after_current();
        // Collect case values from the body
        let cases = collect_switch_cases(body, &self.lowerer.enum_consts);
        let default_bb = self.new_block_after_current();

        let mut arms: Vec<(i64, BlockId)> = Vec::new();
        for (case_val, _) in &cases {
            let case_bb = self.new_block_after_current();
            arms.push((*case_val, case_bb));
        }

        self.set_terminator(Terminator::Switch { val: v_i32, default: default_bb, arms: arms.clone() });
        self.switch_stack.push((default_bb, end_bb));
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
        self.switch_stack.pop();

        self.switch_to_block(end_bb);
        Ok(())
    }

    // ─── Type coercion / helpers ─────────────────────────────────────────────

    pub fn coerce(&mut self, val: Val, target: &Type) -> Result<Val> {
        let src_ty = self.val_type(&val);
        if src_ty == *target { return Ok(val); }

        match (src_ty, target) {
            (Type::Void, _) | (_, Type::Void) => return Ok(val),
            _ => {}
        }

        let dest = self.alloc_val();
        let op = cast_op_for(&self.val_type(&val), target);
        self.push_instr(Instr::Cast { dest, op, val, to_ty: target.clone() });
        Ok(Val::Local(dest))
    }

    /// Convert any value to a boolean (i1).
    pub fn to_bool(&mut self, val: Val) -> Result<Val> {
        let ty = self.val_type(&val);
        if ty == Type::Bool { return Ok(val); }

        let dest = self.alloc_val();
        let zero = match &ty {
            Type::Int { .. } | Type::Bool => Constant::zero(),
            Type::Float32 | Type::Float64 => Val::Const(Constant::Float(0.0)),
            Type::Pointer(_) => Constant::null(),
            _ => Constant::zero(),
        };
        let cmp_op = if ty.is_float() { CmpOp::FONe } else { CmpOp::INe };
        self.push_instr(Instr::Cmp { dest, op: cmp_op, lhs: val, rhs: zero });
        Ok(Val::Local(dest))
    }

    /// Get the IR type of a value.
    pub fn val_type(&self, val: &Val) -> Type {
        match val {
            Val::Const(c) => match c {
                Constant::Int(_) => Type::i32(),
                Constant::UInt(_) => Type::u32(),
                Constant::Float(_) => Type::Float64,
                Constant::Bool(_) => Type::Bool,
                Constant::Null => Type::void_ptr(),
                _ => Type::Void,
            },
            Val::Global(gref) => {
                let g = &self.lowerer.module.globals[gref.0 as usize];
                Type::Pointer(Box::new(g.ty.clone()))
            }
            Val::Func(_) => Type::void_ptr(),
            Val::Local(id) => self.val_types.get(&id.0).cloned().unwrap_or(Type::i32()),
        }
    }
}

/// Extract the (dest ValId, result Type) from instructions that produce a value.
fn instr_result_type(instr: &Instr) -> Option<(ValId, Type)> {
    match instr {
        Instr::Alloca { dest, ty } => Some((*dest, Type::Pointer(Box::new(ty.clone())))),
        Instr::Load { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::BinOp { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::UnaryOp { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::Cast { dest, to_ty, .. } => Some((*dest, to_ty.clone())),
        Instr::Cmp { dest, .. } => Some((*dest, Type::Bool)),
        Instr::Call { dest: Some(d), ret_ty, .. } => Some((*d, ret_ty.clone())),
        Instr::CallIndirect { dest: Some(d), ret_ty, .. } => Some((*d, ret_ty.clone())),
        Instr::GetFieldPtr { dest, .. } => Some((*dest, Type::void_ptr())),
        Instr::GetElemPtr { dest, .. } => Some((*dest, Type::void_ptr())),
        Instr::PtrOffset { dest, .. } => Some((*dest, Type::void_ptr())),
        Instr::Select { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::VaArg { dest, ty, .. } => Some((*dest, ty.clone())),
        _ => None,
    }
}

fn cast_op_for(from: &Type, to: &Type) -> CastOp {
    match (from, to) {
        (Type::Int { bits: fb, signed: fs }, Type::Int { bits: tb, .. }) => {
            if fb < tb { if *fs { CastOp::SExt } else { CastOp::ZExt } }
            else if fb > tb { CastOp::Trunc }
            else { CastOp::BitCast }
        }
        (Type::Bool, Type::Int { .. }) => CastOp::ZExt,
        (Type::Int { signed: true, .. }, Type::Float32 | Type::Float64) => CastOp::SIToFP,
        (Type::Int { signed: false, .. }, Type::Float32 | Type::Float64) => CastOp::UIToFP,
        (Type::Float32 | Type::Float64, Type::Int { signed: true, .. }) => CastOp::FPToSI,
        (Type::Float32 | Type::Float64, Type::Int { signed: false, .. }) => CastOp::FPToUI,
        (Type::Float32, Type::Float64) => CastOp::FPExt,
        (Type::Float64, Type::Float32) => CastOp::FPTrunc,
        (Type::Pointer(_), Type::Pointer(_)) => CastOp::BitCast,
        (Type::Pointer(_), Type::Int { .. }) => CastOp::PtrToInt,
        (Type::Int { .. }, Type::Pointer(_)) => CastOp::IntToPtr,
        _ => CastOp::BitCast,
    }
}

/// Collect case values from a switch body (shallow scan).
fn collect_switch_cases(stmt: &Stmt, enum_consts: &HashMap<String, i64>) -> Vec<(i64, usize)> {
    let mut cases = Vec::new();
    collect_cases_in(stmt, enum_consts, &mut cases);
    cases
}

fn collect_cases_in(stmt: &Stmt, enum_consts: &HashMap<String, i64>, out: &mut Vec<(i64, usize)>) {
    match stmt {
        Stmt::Case(val, body, _) => {
            if let Ok(v) = eval_const_expr(val, enum_consts) {
                out.push((v, out.len()));
            }
            collect_cases_in(body, enum_consts, out);
        }
        Stmt::Block(stmts, _) => {
            for s in stmts { collect_cases_in(s, enum_consts, out); }
        }
        Stmt::Label(_, inner, _) => collect_cases_in(inner, enum_consts, out),
        Stmt::Default(inner, _)  => collect_cases_in(inner, enum_consts, out),
        _ => {}
    }
}
