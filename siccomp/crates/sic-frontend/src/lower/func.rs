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
    /// Function-scope `static` locals: name → (type, internal global). These
    /// have static storage duration, so they resolve to a module global rather
    /// than a stack slot.
    pub static_locals: HashMap<String, (Type, GlobalRef)>,
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
    /// Stack of `break` targets for *both* loops and switches, in nesting order.
    /// `break` jumps to the innermost of these (a switch inside a loop breaks the
    /// switch, not the loop); `continue` uses `loop_stack` instead.
    pub break_stack: Vec<BlockId>,
    /// Stack of active switches: (default block, end block, case-value → block).
    /// `case:`/`default:` labels resolve to these pre-created blocks so the
    /// `Switch` terminator's arms and the emitted case bodies share the same
    /// blocks (and C fall-through between cases works).
    pub switch_stack: Vec<(BlockId, BlockId, std::collections::HashMap<i64, BlockId>)>,
    /// Pending goto stubs: label_name → Vec<(from_bb, stub_term)>
    pub pending_gotos: Vec<(String, BlockId)>,
    /// Last initialized local variable (for implicit return in sic)
    pub last_init_local: Option<(ValId, Type)>,
    /// GCC-style signature string for __PRETTY_FUNCTION__
    pub pretty_func: String,
    /// Last source line emitted as a debug marker (avoids redundant markers).
    pub last_line: u32,
    /// When this function returns an aggregate by value (sret ABI), the pointer
    /// to the caller-provided result slot (the hidden first parameter) and the
    /// aggregate type. `return expr` copies into this slot and `ret`s void.
    pub sret: Option<(Val, Type)>,
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
            static_locals: HashMap::new(),
            val_types: HashMap::new(),
            current_bb: entry_id,
            ret_ty,
            labels: HashMap::new(),
            loop_stack: Vec::new(),
            break_stack: Vec::new(),
            switch_stack: Vec::new(),
            pending_gotos: Vec::new(),
            last_init_local: None,
            pretty_func: String::new(),
            last_line: 0,
            sret: None,
        }
    }

    /// Emit a source-line debug marker for `line` if it differs from the last
    /// one, so the DWARF line table can map addresses back to source.
    pub fn mark_line(&mut self, line: u32) {
        if line != 0 && line != self.last_line && !self.is_terminated() {
            self.last_line = line;
            self.push_instr(Instr::SrcLine(line));
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
        if let Some((ty, gref)) = self.static_locals.get(name) {
            return Some(LookupResult::Global(ty, *gref));
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
        self.lower_ast_type_scoped(&qt.ty)
    }

    /// Like the standalone `lower_type`, but resolves `typeof(expr)` against the
    /// current function scope (via `infer_expr_type`) so `typeof(local)` yields
    /// the real type instead of the scope-less fallback. Non-typeof types (and
    /// anything not wrapping a typeof) delegate to the standalone lowerer.
    fn lower_ast_type_scoped(&self, ty: &AstType) -> Result<Type> {
        use crate::ast::AstType as A;
        // Only intercept when a `typeof` actually appears; otherwise defer wholly
        // to the standalone lowerer (its array-size evaluator understands
        // sizeof/offsetof, which the scope-aware path here does not).
        if !contains_typeof(ty) {
            return lower_type(&QualType::new(ty.clone()), &self.lowerer.struct_types, self.lowerer.ptr_size);
        }
        match ty {
            A::Typeof(e) => self.infer_expr_type(e),
            A::Pointer { base, .. } => {
                let inner = self.lower_ast_type_scoped(&base.ty)?;
                Ok(Type::Pointer(Box::new(super::types::opaque_aggregate(inner))))
            }
            A::Array { base, size } => {
                let elem = self.lower_ast_type_scoped(&base.ty)?;
                let len = match size {
                    Some(sz) => crate::lower::eval_const_expr(sz, &self.lowerer.enum_consts)
                        .ok().filter(|&v| v >= 0).map(|v| v as usize).unwrap_or(0),
                    None => 0,
                };
                Ok(Type::Array { elem: Box::new(elem), len })
            }
            _ => lower_type(&QualType::new(ty.clone()), &self.lowerer.struct_types, self.lowerer.ptr_size),
        }
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

        let sig = super::build_fn_sig(ir_ret.clone(), ir_params.clone(), variadic);
        let is_sret = super::ret_is_sret(&ir_ret);

        let linkage = match storage {
            Some(StorageClass::Static) => Linkage::Internal,
            _ => Linkage::External,
        };

        let mut ir_param_decls: Vec<sic_ir::Param> = params.iter().zip(&ir_params).map(|(p, ty)| {
            sic_ir::Param {
                name: p.name.clone().unwrap_or_default(),
                ty: ty.clone(),
            }
        }).collect();
        // sret ABI: prepend the hidden result-pointer parameter so the backend
        // allocates a block param for it (matching the signature).
        if is_sret {
            ir_param_decls.insert(0, sic_ir::Param {
                name: String::new(),
                ty: Type::Pointer(Box::new(ir_ret.clone())),
            });
        }

        let mut func = Function::new(name.to_string(), sig, ir_param_decls, linkage);

        // Create entry block
        let entry_id = func.alloc_block();
        let entry = BasicBlock::new(entry_id);
        func.blocks.push(entry);

        // Build the GCC-style signature used by __PRETTY_FUNCTION__:
        //   "<ret> <name>(<param types>)"
        let pretty = {
            let params_str = params.iter()
                .map(|p| c_type_string(&p.ty))
                .collect::<Vec<_>>()
                .join(", ");
            let params_str = if variadic {
                if params_str.is_empty() { "...".to_string() }
                else { format!("{}, ...", params_str) }
            } else {
                params_str
            };
            format!("{} {}({})", c_type_string(ret_ty), name, params_str)
        };

        let mut fc = FuncCtx::new_with_func(self, &mut func);
        fc.pretty_func = pretty;

        // Alloca for each parameter and store the param sentinel value.
        // The backend maps ValId(0x10000 + i) → the i-th function parameter.
        // With the sret ABI the hidden result pointer occupies sentinel 0, so
        // user parameters are shifted by one.
        fc.enter_scope();
        let param_base = if is_sret { 1 } else { 0 };
        if is_sret {
            fc.sret = Some((Val::Local(ValId(0x10000)), ir_ret.clone()));
        }
        for (i, p) in params.iter().enumerate() {
            if let Some(pname) = &p.name {
                let pty = ir_params[i].clone();
                let sentinel = ValId((i + param_base) as u32 + 0x10000);
                let ptr_vid = fc.alloc_val();
                fc.push_instr(Instr::Alloca { dest: ptr_vid, ty: pty.clone(), align: None });
                if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                    // Struct/union params are passed as pointer; copy into local alloca
                    let ps = fc.ptr_size();
                    let size = pty.size_of(ps);
                    let align = pty.align_of(ps) as u64;
                    fc.push_instr(Instr::MemCopy {
                        dst: Val::Local(ptr_vid),
                        src: Val::Local(sentinel),
                        size,
                        align,
                    });
                } else {
                    fc.push_instr(Instr::Store {
                        val: Val::Local(sentinel),
                        ptr: Val::Local(ptr_vid),
                    });
                }
                fc.push_instr(Instr::DbgVar {
                    name: pname.clone(), ty: pty.clone(), slot: ptr_vid, is_param: true,
                });
                fc.define_local(pname.clone(), pty, ptr_vid);
            }
        }

        // Lower body. Statements after a terminator are dead code, except
        // labels / case / default, which are jump targets that begin new blocks.
        for stmt in body {
            if fc.is_terminated() && !stmt_is_jump_target(stmt) { continue; }
            fc.lower_stmt(stmt)?;
        }

        // If function didn't return, add implicit return
        if !fc.is_terminated() {
            let ret_val = if ir_ret == Type::Void || is_sret {
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
        self.mark_line(stmt_line(stmt));
        match stmt {
            Stmt::Null(_) => {}
            Stmt::Expr(e, _) => { self.lower_expr(e)?; }
            Stmt::Block(stmts, _) => {
                self.enter_scope();
                for s in stmts {
                    if self.is_terminated() && !stmt_is_jump_target(s) { continue; }
                    self.lower_stmt(s)?;
                }
                self.exit_scope();
            }
            Stmt::Decl(d) => self.lower_local_decl(d)?,
            Stmt::Return(val, _) => {
                if let Some((sret_ptr, agg_ty)) = self.sret.clone() {
                    // Aggregate return: copy the value into the caller's slot.
                    if let Some(e) = val {
                        let src = self.lower_aggregate_ptr(e)?;
                        let ps = self.ptr_size();
                        let size = agg_ty.size_of(ps);
                        let align = agg_ty.align_of(ps) as u64;
                        self.push_instr(Instr::MemCopy { dst: sret_ptr, src, size, align });
                    }
                    self.set_terminator(Terminator::Ret(None));
                } else if self.ret_ty == Type::Void {
                    // `return expr;` in a void function (GCC-ism, common in QEMU's
                    // `return qatomic_*()` void wrappers): evaluate the operand for
                    // its side effects but discard the value.
                    if let Some(e) = val {
                        let _ = self.lower_expr(e)?;
                    }
                    self.set_terminator(Terminator::Ret(None));
                } else {
                    let ret = if let Some(e) = val {
                        let v = self.lower_expr(e)?;
                        let expected = self.ret_ty.clone();
                        Some(self.coerce(v, &expected)?)
                    } else {
                        None
                    };
                    self.set_terminator(Terminator::Ret(ret));
                }
            }
            Stmt::If { cond, then, else_, .. } => self.lower_if(cond, then, else_.as_deref())?,
            Stmt::While { cond, body, .. } => self.lower_while(cond, body)?,
            Stmt::DoWhile { body, cond, .. } => self.lower_do_while(body, cond)?,
            Stmt::For { init, cond, post, body, .. } => self.lower_for(init, cond, post, body)?,
            Stmt::Switch { val, body, .. } => self.lower_switch(val, body)?,
            Stmt::Break(_) => {
                // `break` targets the innermost enclosing loop *or* switch,
                // whichever is nested deeper — a switch inside a loop breaks the
                // switch, not the loop.
                if let Some(&end) = self.break_stack.last() {
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
                // Switch to the block the enclosing switch pre-created for this
                // case value; falling through from the previous case jumps here.
                let const_val = eval_const_expr(val, &self.lowerer.enum_consts).unwrap_or(0);
                let case_bb = self.switch_stack.last()
                    .and_then(|(_, _, cases)| cases.get(&const_val).copied())
                    .unwrap_or_else(|| self.new_block_after_current());
                if !self.is_terminated() {
                    self.set_terminator(Terminator::Jump(case_bb));
                }
                self.switch_to_block(case_bb);
                self.func_mut().block_mut(case_bb).label = Some(format!("case_{}", const_val));
                self.lower_stmt(body)?;
            }
            Stmt::CaseRange(lo, _hi, body, _) => {
                // `case LOW ... HIGH:` — every value in the range was pre-created
                // as an arm pointing to a single shared block (see `lower_switch`
                // / `collect_cases_in`). Look it up by the low value and lower the
                // body into it once.
                let low_val = eval_const_expr(lo, &self.lowerer.enum_consts).unwrap_or(0);
                let case_bb = self.switch_stack.last()
                    .and_then(|(_, _, cases)| cases.get(&low_val).copied())
                    .unwrap_or_else(|| self.new_block_after_current());
                if !self.is_terminated() {
                    self.set_terminator(Terminator::Jump(case_bb));
                }
                self.switch_to_block(case_bb);
                self.func_mut().block_mut(case_bb).label = Some(format!("case_{}_range", low_val));
                self.lower_stmt(body)?;
            }
            Stmt::Default(body, _) => {
                // Use the enclosing switch's pre-created default block.
                let default_bb = self.switch_stack.last()
                    .map(|(d, _, _)| *d)
                    .unwrap_or_else(|| self.new_block_after_current());
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
                // `_Alignas(N)` / `alignas(N)` requested alignment, if any.
                let explicit_align = base_ty.qualifiers.iter().find_map(|q| match q {
                    crate::ast::TypeQual::Align(n) => Some(*n),
                    _ => None,
                });
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
                let is_static = matches!(base_ty.storage, Some(StorageClass::Static));
                for d in declarators {
                    // A function-scope `static` local has static storage duration:
                    // back it with an internal global (unique-named to avoid
                    // clashes) and bind the local name to it, rather than a stack
                    // slot re-initialized on every call.
                    if is_static {
                        let fname = self.func_ref().name.clone();
                        let uniq = self.lowerer.module.globals.len();
                        let gname = format!("{}.{}.{}", fname, d.name, uniq);
                        let (gty, gref) = self.lowerer.add_static_local_global(gname, d, base_ty)?;
                        self.static_locals.insert(d.name.clone(), (gty, gref));
                        continue;
                    }
                    let mut ty = self.lower_type(&d.ty)?;
                    // Handle VLA (variable-length array): size was 0 because expr isn't constant
                    // Try to evaluate the size expr at compile time or use a conservative fallback
                    if let (Type::Array { elem: ref elem_ty, len: 0 }, AstType::Array { size: Some(sz_expr), .. }) = (&ty, &d.ty.ty) {
                        let resolved_len = eval_const_expr(sz_expr, &self.lowerer.enum_consts)
                            .unwrap_or(1024) as usize; // fallback: 1024 elements
                        let resolved_len = resolved_len.max(1);
                        ty = Type::Array { elem: elem_ty.clone(), len: resolved_len };
                    }
                    // Array size inferred from its initializer: `T a[] = {...}`
                    // or `char s[] = "..."`. Without this the array would have
                    // length 0, and the element stores would overflow the stack.
                    let inferred = if let Type::Array { elem, len: 0 } = &ty {
                        let n = match &d.init {
                            Some(Initializer::List(items)) => items.len(),
                            Some(Initializer::Expr(e)) => match &e.kind {
                                ExprKind::StringLit(s) => s.len() + 1, // + NUL terminator
                                _ => 0,
                            },
                            None => 0,
                        };
                        if n > 0 { Some((elem.clone(), n)) } else { None }
                    } else {
                        None
                    };
                    if let Some((elem, len)) = inferred {
                        ty = Type::Array { elem, len };
                    }
                    let vid = self.alloc_val();
                    self.push_instr(Instr::Alloca { dest: vid, ty: ty.clone(), align: explicit_align });

                    // Bind the name in scope *before* lowering the initializer:
                    // C makes a declarator visible within its own initializer, so
                    // `T *p = malloc(sizeof(*p))` must see `p` as a `T*` (not
                    // default to `int`, which would size the allocation wrong).
                    self.define_local(d.name.clone(), ty.clone(), vid);

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
                    if matches!(ty, Type::Int { .. } | Type::Float32 | Type::Float64 | Type::Float80 | Type::Pointer(_) | Type::Bool) {
                        self.last_init_local = Some((vid, ty.clone()));
                    }
                    if !d.name.is_empty() {
                        self.push_instr(Instr::DbgVar {
                            name: d.name.clone(), ty: ty.clone(), slot: vid, is_param: false,
                        });
                    }
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

    pub(crate) fn lower_initializer(&mut self, init: &Initializer, ptr: Val, ty: &Type) -> Result<()> {
        match init {
            // `char buf[] = "..."` / `char buf[N] = "..."`: copy the string bytes
            // into the array (not the pointer). Zero-fill any remaining space.
            Initializer::Expr(e)
                if matches!(ty, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }))
                    && matches!(&e.kind, ExprKind::StringLit(_)) =>
            {
                let (elem_len, s) = match (ty, &e.kind) {
                    (Type::Array { len, .. }, ExprKind::StringLit(s)) => (*len, s.clone()),
                    _ => unreachable!(),
                };
                let src = self.emit_cstring(&s);           // pointer to the bytes ("...\0")
                let copy = (s.len() + 1).min(elem_len.max(1)) as u64;
                let total = (elem_len as u64).max(copy);
                // Zero the whole array first so unused tail bytes are 0, then copy.
                self.push_instr(Instr::MemSet { dst: ptr.clone(), val: Constant::zero(), size: total, align: 1 });
                self.push_instr(Instr::MemCopy { dst: ptr, src, size: copy, align: 1 });
            }
            Initializer::Expr(e) => {
                // `T v = <aggregate expr>` (e.g. a compound literal or a struct
                // returned by value) copies the whole object rather than storing
                // a pointer/register-sized scalar.
                if matches!(ty, Type::Struct(_) | Type::Union(_)) {
                    let src = self.lower_aggregate_ptr(e)?;
                    let size = ty.size_of(self.ptr_size());
                    let align = ty.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: ptr, src, size, align });
                } else {
                    let val = self.lower_expr(e)?;
                    let coerced = self.coerce(val, ty)?;
                    self.push_instr(Instr::Store { val: coerced, ptr });
                }
            }
            Initializer::List(items) => {
                // Scalar wrapped in braces: `int x = { 5 };`.
                if !matches!(ty, Type::Struct(_) | Type::Union(_) | Type::Array { .. }) {
                    if let Some(first) = items.first() {
                        self.lower_initializer(&first.init, ptr, ty)?;
                    }
                    return Ok(());
                }
                // Any member not named by the initializer is zero-initialized
                // (C11 6.7.9p19/21). Zero the whole aggregate first, then fill.
                let size = ty.size_of(self.ptr_size());
                if size > 0 {
                    self.push_instr(Instr::MemSet {
                        dst: ptr.clone(), val: Constant::zero(), size,
                        align: ty.align_of(self.ptr_size()),
                    });
                }
                let items = super::expand_init_ranges(items, &self.lowerer.enum_consts);
                let mut cursor = 0usize;
                for item in &items {
                    let (target, next) =
                        self.resolve_init_target(&ptr, ty, &item.designators, cursor)?;
                    if let Some((tptr, tty)) = target {
                        self.lower_initializer(&item.init, tptr, &tty)?;
                    }
                    cursor = next;
                }
            }
        }
        Ok(())
    }

    /// Emit a pointer to `base + byte_offset`, typed as `*pointee`.
    fn gep_offset(&mut self, base: &Val, byte_offset: u64, pointee: &Type) -> Val {
        let dest = self.alloc_val();
        self.push_instr(Instr::GetFieldPtr {
            dest, base: base.clone(), field_idx: 0, struct_name: None,
            byte_offset, result_ty: Type::Pointer(Box::new(pointee.clone())),
        });
        Val::Local(dest)
    }

    /// Resolve where a brace-list element is written: the position named by its
    /// designators, or `cursor` when it has none. Returns the target pointer, its
    /// type, and the next cursor value (top-level index + 1).
    #[allow(clippy::type_complexity)]
    fn resolve_init_target(&mut self, base: &Val, agg: &Type, designators: &[crate::ast::Designator], cursor: usize)
        -> Result<(Option<(Val, Type)>, usize)>
    {
        use crate::ast::Designator;
        // First step: designator[0] if present, else the implicit cursor.
        let (first, top_index) = match designators.first() {
            Some(Designator::Field(name)) => {
                let Some((off, fty, _)) = super::expr::resolve_field_access(agg, name, self.ptr_size(), &self.lowerer.struct_types)
                else { return Ok((None, cursor + 1)); };
                (Some((self.gep_offset(base, off, &fty), fty)), top_field_index(agg, name, &self.lowerer.struct_types))
            }
            Some(Designator::Index(e)) => {
                let i = eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0).max(0) as usize;
                (self.member_at(base, agg, i), i)
            }
            Some(Designator::IndexRange(..)) => unreachable!("ranges expanded before resolution"),
            None => (self.member_at(base, agg, cursor), cursor),
        };
        let Some((mut ptr, mut cur_ty)) = first else {
            // Out-of-range positional/index element (excess initializer): skip it
            // but still advance the cursor past this position.
            return Ok((None, top_index + 1));
        };
        // Navigate any remaining (chained) designators into `cur_ty`.
        let rest = if designators.is_empty() { &designators[..] } else { &designators[1..] };
        for d in rest {
            match d {
                Designator::Field(name) => {
                    let Some((off, fty, _)) = super::expr::resolve_field_access(&cur_ty, name, self.ptr_size(), &self.lowerer.struct_types)
                    else { return Ok((None, top_index + 1)); };
                    ptr = self.gep_offset(&ptr, off, &fty);
                    cur_ty = fty;
                }
                Designator::Index(e) => {
                    let i = eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0).max(0) as usize;
                    let Some((p, ety)) = self.member_at(&ptr, &cur_ty, i) else {
                        return Ok((None, top_index + 1));
                    };
                    ptr = p; cur_ty = ety;
                }
                // A range in a chained (non-leading) position is unsupported;
                // skip the element rather than crash.
                Designator::IndexRange(..) => return Ok((None, top_index + 1)),
            }
        }
        Ok((Some((ptr, cur_ty)), top_index + 1))
    }

    /// Pointer + type of the `idx`-th member of an aggregate (struct field or
    /// array element), by positional index. `None` when `idx` is out of range.
    fn member_at(&mut self, base: &Val, agg: &Type, idx: usize) -> Option<(Val, Type)> {
        let resolved = super::types::resolve_aggregate(agg, &self.lowerer.struct_types);
        match &resolved {
            Type::Struct(st) => {
                let fty = st.fields.get(idx)?.1.clone();
                let off = st.field_offset(idx, self.ptr_size());
                Some((self.gep_offset(base, off, &fty), fty))
            }
            Type::Union(u) => {
                let fty = u.fields.get(idx)?.1.clone();
                Some((self.gep_offset(base, 0, &fty), fty))
            }
            Type::Array { elem, len } => {
                if *len > 0 && idx >= *len { return None; }
                let esz = elem.size_of(self.ptr_size());
                Some((self.gep_offset(base, idx as u64 * esz, elem), (**elem).clone()))
            }
            _ => None,
        }
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
        self.break_stack.push(end_bb);
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.break_stack.pop();
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
        self.break_stack.push(end_bb);
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.break_stack.pop();
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
        self.break_stack.push(end_bb);
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(post_bb)); }
        self.break_stack.pop();
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

        let end_bb = self.new_block_after_current();
        let default_bb = self.new_block_after_current();

        // Pre-create one block per case value; the `Switch` terminator's arms and
        // the emitted case bodies must be the *same* blocks.
        let cases = collect_switch_cases(body, &self.lowerer.enum_consts);
        let mut arms: Vec<(i64, BlockId)> = Vec::new();
        let mut case_blocks: std::collections::HashMap<i64, BlockId> = std::collections::HashMap::new();
        // One block per group, so all values of a `case LOW ... HIGH:` range
        // share a single body block.
        let mut group_blocks: std::collections::HashMap<usize, BlockId> = std::collections::HashMap::new();
        for (case_val, group) in &cases {
            // Duplicate case values shouldn't happen in valid C; keep the first.
            if case_blocks.contains_key(case_val) { continue; }
            let case_bb = match group_blocks.get(group) {
                Some(&bb) => bb,
                None => {
                    let bb = self.new_block_after_current();
                    group_blocks.insert(*group, bb);
                    bb
                }
            };
            arms.push((*case_val, case_bb));
            case_blocks.insert(*case_val, case_bb);
        }

        self.set_terminator(Terminator::Switch { val: v_i32, default: default_bb, arms });
        self.switch_stack.push((default_bb, end_bb, case_blocks));
        self.break_stack.push(end_bb);

        // Statements before the first label are unreachable but may declare
        // locals — lower them into a throwaway block.
        let pre = self.new_block_after_current();
        self.switch_to_block(pre);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
        self.break_stack.pop();
        self.switch_stack.pop();

        // A switch with no `default:` leaves the default block empty — route it
        // straight to the end.
        if matches!(self.func_mut().block_mut(default_bb).terminator, Terminator::Unreachable) {
            self.func_mut().block_mut(default_bb).terminator = Terminator::Jump(end_bb);
        }

        self.switch_to_block(end_bb);
        Ok(())
    }

    // ─── Type coercion / helpers ─────────────────────────────────────────────

    pub fn coerce(&mut self, val: Val, target: &Type) -> Result<Val> {
        let src_ty = self.val_type(&val);
        if src_ty == *target { return Ok(val); }

        match (&src_ty, target) {
            (Type::Void, _) | (_, Type::Void) => return Ok(val),
            _ => {}
        }

        // Integer → pointer: widen the integer to pointer size *first*, with the
        // integer's own signedness. Casting a narrow signed int like `(void*)-1`
        // must sign-extend (0xffff…ffff), not zero-extend (0x0000…ffff); the
        // low-level `IntToPtr` reinterpret can't know the source signedness.
        if let (Type::Int { bits, signed }, Type::Pointer(_)) = (&src_ty, target) {
            let ptr_bits = self.ptr_size() * 8;
            if *bits < ptr_bits {
                let wide = Type::Int { bits: ptr_bits, signed: *signed };
                let ext = self.alloc_val();
                let op = cast_op_for(&src_ty, &wide);
                self.push_instr(Instr::Cast { dest: ext, op, val, to_ty: wide });
                let dest = self.alloc_val();
                self.push_instr(Instr::Cast { dest, op: CastOp::IntToPtr, val: Val::Local(ext), to_ty: target.clone() });
                return Ok(Val::Local(dest));
            }
        }

        let dest = self.alloc_val();
        let op = cast_op_for(&src_ty, target);
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
            Type::Float32 | Type::Float64 | Type::Float80 => Val::Const(Constant::Float(0.0)),
            Type::Pointer(_) => Constant::null(),
            _ => Constant::zero(),
        };
        let cmp_op = if ty.is_float() { CmpOp::FONe } else { CmpOp::INe };
        self.push_instr(Instr::Cmp { dest, op: cmp_op, lhs: val, rhs: zero, ty: ty.clone() });
        Ok(Val::Local(dest))
    }

    /// Get the IR type of a value.
    pub fn val_type(&self, val: &Val) -> Type {
        match val {
            Val::Const(c) => match c {
                // A bare integer constant is 32-bit when its value fits in some
                // 32-bit type ([i32::MIN, u32::MAX]); larger magnitudes force
                // 64-bit. This keeps `0xFFFFFFFF` 32-bit while typing 5000000000
                // as 64-bit. (Suffix-only widths like `1LL` are widened in
                // `lower_expr` via an explicit coercion.)
                Constant::Int(v) => if *v >= i32::MIN as i64 && *v <= u32::MAX as i64 {
                    Type::i32()
                } else {
                    Type::i64()
                },
                Constant::UInt(v) => if *v <= u32::MAX as u64 {
                    Type::u32()
                } else {
                    Type::Int { bits: 64, signed: false }
                },
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
        Instr::Alloca { dest, ty, .. } => Some((*dest, Type::Pointer(Box::new(ty.clone())))),
        Instr::Load { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::BinOp { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::UnaryOp { dest, ty, .. } => Some((*dest, ty.clone())),
        Instr::Cast { dest, to_ty, .. } => Some((*dest, to_ty.clone())),
        Instr::Cmp { dest, .. } => Some((*dest, Type::Bool)),
        Instr::Call { dest: Some(d), ret_ty, .. } => Some((*d, ret_ty.clone())),
        Instr::CallIndirect { dest: Some(d), ret_ty, .. } => Some((*d, ret_ty.clone())),
        Instr::GetFieldPtr { dest, result_ty, .. } => Some((*dest, result_ty.clone())),
        Instr::GetElemPtr { dest, result_ty, .. } => Some((*dest, result_ty.clone())),
        Instr::PtrOffset { dest, .. } => Some((*dest, Type::void_ptr())),
        Instr::BSwap { dest, ty, .. } => Some((*dest, ty.clone())),
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
        (Type::Int { signed: true, .. }, Type::Float32 | Type::Float64 | Type::Float80) => CastOp::SIToFP,
        (Type::Int { signed: false, .. }, Type::Float32 | Type::Float64 | Type::Float80) => CastOp::UIToFP,
        (Type::Float32 | Type::Float64 | Type::Float80, Type::Int { signed: true, .. }) => CastOp::FPToSI,
        (Type::Float32 | Type::Float64 | Type::Float80, Type::Int { signed: false, .. }) => CastOp::FPToUI,
        (Type::Float32, Type::Float64 | Type::Float80) => CastOp::FPExt,
        (Type::Float64 | Type::Float80, Type::Float32) => CastOp::FPTrunc,
        // f64 <-> f80 are both codegen'd as f64: no conversion needed.
        (Type::Float64, Type::Float80) | (Type::Float80, Type::Float64) => CastOp::BitCast,
        (Type::Pointer(_), Type::Pointer(_)) => CastOp::BitCast,
        (Type::Pointer(_), Type::Int { .. }) => CastOp::PtrToInt,
        (Type::Int { .. }, Type::Pointer(_)) => CastOp::IntToPtr,
        _ => CastOp::BitCast,
    }
}

/// Collect case values from a switch body (shallow scan).
/// A statement that begins a new basic block reachable by a jump (a `case:`,
/// `default:`, or `label:`), so it must be lowered even when the preceding code
/// already terminated the current block.
fn stmt_is_jump_target(s: &Stmt) -> bool {
    matches!(s, Stmt::Case(..) | Stmt::CaseRange(..) | Stmt::Default(..) | Stmt::Label(..))
}

/// Source line a statement begins on (for DWARF line markers). 0 = unknown.
fn stmt_line(stmt: &Stmt) -> u32 {
    match stmt {
        Stmt::Decl(d) => decl_line(d),
        Stmt::Expr(_, s) | Stmt::Block(_, s) | Stmt::Return(_, s)
        | Stmt::Break(s) | Stmt::Continue(s) | Stmt::Goto(_, s)
        | Stmt::Null(s) | Stmt::Label(_, _, s) | Stmt::Case(_, _, s)
        | Stmt::CaseRange(_, _, _, s)
        | Stmt::Default(_, s) => s.line,
        Stmt::If { span, .. } | Stmt::While { span, .. } | Stmt::DoWhile { span, .. }
        | Stmt::For { span, .. } | Stmt::Switch { span, .. } => span.line,
    }
}

fn decl_line(d: &Decl) -> u32 {
    match d {
        Decl::Var { span, .. } | Decl::Func { span, .. }
        | Decl::TypeDef { span, .. } | Decl::ExprStmt(_, span) => span.line,
        _ => 0,
    }
}

/// Returns `(case value, group id)` pairs. Values with the same group id share
/// one target block — this is how a `case LOW ... HIGH:` range maps all of its
/// values to a single body. Each plain `case:` gets its own group.
/// Index of the top-level member of `agg` that a designated field name selects
/// (used to advance the positional cursor). A direct member returns its own
/// index; a member reached through an anonymous struct/union returns the
/// anonymous member's index.
/// Whether an AST type mentions `typeof(...)` anywhere reachable through the
/// pointer/array/function spine (so it needs scope-aware resolution).
fn contains_typeof(ty: &AstType) -> bool {
    use crate::ast::AstType as A;
    match ty {
        A::Typeof(_) => true,
        A::Pointer { base, .. } | A::Array { base, .. } => contains_typeof(&base.ty),
        A::Function { ret, params, .. } =>
            contains_typeof(&ret.ty) || params.iter().any(|p| contains_typeof(&p.ty.ty)),
        _ => false,
    }
}

pub(super) fn top_field_index(agg: &Type, name: &str, named: &HashMap<String, Type>) -> usize {
    let resolved = super::types::resolve_aggregate(agg, named);
    if let Type::Struct(st) = &resolved {
        for (i, (fname, _)) in st.fields.iter().enumerate() {
            if fname == name { return i; }
        }
        for (i, (fname, fty)) in st.fields.iter().enumerate() {
            if fname.is_empty()
                && matches!(fty, Type::Struct(_) | Type::Union(_))
                && super::expr::resolve_field_access(fty, name, 8, named).is_some()
            {
                return i;
            }
        }
    }
    0
}

fn collect_switch_cases(stmt: &Stmt, enum_consts: &HashMap<String, i64>) -> Vec<(i64, usize)> {
    let mut cases = Vec::new();
    let mut group = 0usize;
    collect_cases_in(stmt, enum_consts, &mut cases, &mut group);
    cases
}

fn collect_cases_in(stmt: &Stmt, enum_consts: &HashMap<String, i64>, out: &mut Vec<(i64, usize)>, group: &mut usize) {
    match stmt {
        Stmt::Case(val, body, _) => {
            if let Ok(v) = eval_const_expr(val, enum_consts) {
                out.push((v, *group));
            }
            *group += 1;
            collect_cases_in(body, enum_consts, out, group);
        }
        Stmt::CaseRange(lo, hi, body, _) => {
            // Expand the range into one arm per value, all sharing this group so
            // they route to a single body block. Capped to avoid pathological
            // blowups (`case 0 ... INT_MAX:`); real ranges are tiny.
            if let (Ok(l), Ok(h)) = (eval_const_expr(lo, enum_consts), eval_const_expr(hi, enum_consts)) {
                const MAX_RANGE: i64 = 100_000;
                let mut v = l;
                let mut count = 0i64;
                while v <= h && count < MAX_RANGE {
                    out.push((v, *group));
                    if v == i64::MAX { break; }
                    v += 1;
                    count += 1;
                }
            }
            *group += 1;
            collect_cases_in(body, enum_consts, out, group);
        }
        Stmt::Block(stmts, _) => {
            for s in stmts { collect_cases_in(s, enum_consts, out, group); }
        }
        Stmt::Label(_, inner, _) => collect_cases_in(inner, enum_consts, out, group),
        Stmt::Default(inner, _)  => collect_cases_in(inner, enum_consts, out, group),
        _ => {}
    }
}

// ─── C type formatting (for __PRETTY_FUNCTION__) ────────────────────────────────

/// Render a `QualType` as a GCC-style C type string, e.g. "const char *".
fn c_type_string(qt: &QualType) -> String {
    use crate::ast::TypeQual;
    let mut s = String::new();
    if qt.qualifiers.contains(&TypeQual::Const) {
        s.push_str("const ");
    }
    if qt.qualifiers.contains(&TypeQual::Volatile) {
        s.push_str("volatile ");
    }
    s.push_str(&ast_type_string(&qt.ty));
    s
}

fn ast_type_string(t: &AstType) -> String {
    match t {
        AstType::Void => "void".to_string(),
        AstType::Char { signed: None } => "char".to_string(),
        AstType::Char { signed: Some(true) } => "signed char".to_string(),
        AstType::Char { signed: Some(false) } => "unsigned char".to_string(),
        AstType::Short { signed: true } => "short".to_string(),
        AstType::Short { signed: false } => "unsigned short".to_string(),
        AstType::Int { signed: true } => "int".to_string(),
        AstType::Int { signed: false } => "unsigned int".to_string(),
        AstType::Long { signed: true } => "long".to_string(),
        AstType::Long { signed: false } => "unsigned long".to_string(),
        AstType::LongLong { signed: true } => "long long".to_string(),
        AstType::LongLong { signed: false } => "unsigned long long".to_string(),
        AstType::Float => "float".to_string(),
        AstType::Double => "double".to_string(),
        AstType::LongDouble => "long double".to_string(),
        AstType::Bool => "_Bool".to_string(),
        AstType::Complex => "_Complex".to_string(),
        AstType::Pointer { base, .. } => format!("{} *", c_type_string(base)),
        AstType::Array { base, .. } => format!("{} []", c_type_string(base)),
        AstType::Named(n) => n.clone(),
        AstType::Builtin(n) => n.clone(),
        AstType::Struct(s) => format!("struct {}", s.name.clone().unwrap_or_default()),
        AstType::Union(u) => format!("union {}", u.name.clone().unwrap_or_default()),
        AstType::Enum(e) => format!("enum {}", e.name.clone().unwrap_or_default()),
        AstType::Function { ret, .. } => format!("{} ()", c_type_string(ret)),
        AstType::Typeof(_) => "typeof(...)".to_string(),
    }
}
