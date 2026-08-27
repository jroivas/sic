use std::collections::HashMap;
use crate::ast::{self, Decl, Stmt, Expr, ExprKind, ForInit, StorageClass, AstType, QualType, Initializer};
use crate::ast::Param as AstParam;
use crate::{Result, CompileError};
use sic_ir::*;
use super::{Lowerer, lower_type, lower_param_type, eval_const_expr};

/// A scope-exit action, run in LIFO order on every exit path (fall-through,
/// `return`, `break`, `continue`).
#[derive(Clone)]
pub enum Cleanup {
    /// `__attribute__((cleanup(fn)))`: call `fn(&var)`.
    AttrFn { addr: Val, fn_name: String },
    /// sic `defer <stmt>;`: lower the statement at each exit site.
    Defer(Box<Stmt>),
    /// sic refcounted `string` local: release its `rc` on scope exit.
    StringRelease { addr: Val },
    /// sic transient `string.ptr` C-string copy: `free` the pointer held in
    /// `slot` (a `char*` slot, NULL when `.ptr` needed no copy) at scope exit.
    FreePtr { slot: Val },
    /// sic `@` reference: release (decrement + free at 0) the referent pointer
    /// held in `slot` at scope exit (sic.md §"References").
    RefRelease { slot: Val },
    /// sic `bigint`: `__sic_bi_free` the pointer held in `slot` at scope exit
    /// (value semantics — every bigint local/temp owns its heap block).
    BigintFree { slot: Val },
    /// sic `fixed`: `__sic_rat_free` the rational (`__sic_rat*`) held in `slot`
    /// at scope exit (value semantics — every fixed local owns its rational).
    RatFree { slot: Val },
}

/// An active exception-guard (sic.md §"Integer overflow", §"Errors and
/// exceptions"): a caught exception jumps to `fail_bb`, which sets the guard
/// expression's result to 1 without committing the offending operation.
#[derive(Debug, Clone, Copy)]
pub struct GuardFrame {
    pub kind: crate::ast::GuardKind,
    pub fail_bb: BlockId,
}

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
    /// Parallel to the `locals` scope stack: per-scope `(var_address, cleanup_fn)`
    /// pairs from `__attribute__((cleanup(fn)))`. On scope exit / return / break /
    /// continue the cleanup functions are called (`fn(&var)`) in reverse order.
    pub cleanups: Vec<Vec<Cleanup>>,
    /// Scope depth (`cleanups.len()`) recorded per `break_stack` entry (loops and
    /// switches), so `break` runs the cleanups for the scopes it exits.
    pub break_scope_depth: Vec<usize>,
    /// Scope depth recorded per `loop_stack` entry, so `continue` runs cleanups
    /// for the scopes it exits.
    pub continue_scope_depth: Vec<usize>,
    /// sic fat-pointer bounds checking (sic.md §"Scopes and automatic release"):
    /// names of `new`-initialized / `@`-reference locals that are never mutated,
    /// so `name[i]` can be bounds-checked against the header size at
    /// `name - 2*ptr_size`. `moved_names` is the pre-scanned set of locals that
    /// ARE reassigned / incremented (and so cannot be safely checked).
    pub fat_locals: std::collections::HashSet<String>,
    pub moved_names: std::collections::HashSet<String>,
    /// sic deferred tuple locals (`tuple t;` with no initializer, sic.md
    /// §"Tuples"): not yet allocated — the concrete type is fixed by the first
    /// assignment `t = tuple(...)`, which materializes the slot.
    pub deferred_tuples: std::collections::HashSet<String>,
    /// sic `bigint` temporaries created while lowering the current statement
    /// (sic.md §"Integer sizes"): freed at the end of that statement, so a value
    /// re-evaluated each loop iteration doesn't leak. Holds the temp pointers.
    pub bigint_temps: Vec<Val>,
    /// sic `unsafe { }` nesting depth (sic.md §"Integer overflow"): when > 0,
    /// integer overflow and `÷0` trap instead of wrapping / `→0`.
    pub unsafe_depth: u32,
    /// sic exception-guard frames (`overflow`/`divide_by_zero`/`exception` blocks):
    /// an active guard catches the matching exception by jumping to its `fail_bb`
    /// (the offending op is not committed). Innermost last.
    pub guard_stack: Vec<GuardFrame>,
    /// sic generic-enum construction (sic.md §"Match"): the target type of the
    /// value currently being lowered (a binding/return/arg), used to resolve a
    /// generic constructor `Option::Some(5)` / `None` to its concrete monomorph.
    pub expected_ty: Option<Type>,
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
            cleanups: vec![Vec::new()],
            break_scope_depth: Vec::new(),
            continue_scope_depth: Vec::new(),
            fat_locals: std::collections::HashSet::new(),
            moved_names: std::collections::HashSet::new(),
            deferred_tuples: std::collections::HashSet::new(),
            bigint_temps: Vec::new(),
            unsafe_depth: 0,
            guard_stack: Vec::new(),
            expected_ty: None,
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

    /// Whether integer-overflow detection is active here — inside `unsafe`, or an
    /// `overflow`/`exception` guard (sic.md §"Integer overflow").
    pub fn overflow_active(&self) -> bool {
        self.unsafe_depth > 0 || self.overflow_target().is_some()
    }
    /// Whether `÷0` detection is active — inside `unsafe`, or a
    /// `divide_by_zero`/`exception` guard.
    pub fn divzero_active(&self) -> bool {
        self.unsafe_depth > 0 || self.divzero_target().is_some()
    }
    /// The innermost guard catching integer overflow, if any.
    pub fn overflow_target(&self) -> Option<BlockId> {
        use crate::ast::GuardKind::*;
        self.guard_stack.iter().rev()
            .find(|g| matches!(g.kind, Overflow | Exception))
            .map(|g| g.fail_bb)
    }
    /// The innermost guard catching `÷0`, if any.
    pub fn divzero_target(&self) -> Option<BlockId> {
        use crate::ast::GuardKind::*;
        self.guard_stack.iter().rev()
            .find(|g| matches!(g.kind, DivZero | Exception))
            .map(|g| g.fail_bb)
    }

    pub fn enter_scope(&mut self) {
        self.locals.push(HashMap::new());
        self.cleanups.push(Vec::new());
    }
    pub fn exit_scope(&mut self) {
        // Run this scope's cleanups on normal fall-through. A terminated block
        // (ended in return/break/continue/goto) already ran them along that
        // path, so skip to avoid a double call.
        if !self.is_terminated() {
            if let Some(scope) = self.cleanups.last() {
                let calls: Vec<Cleanup> = scope.iter().rev().cloned().collect();
                for c in calls { self.emit_cleanup(c); }
            }
        }
        self.cleanups.pop();
        self.locals.pop();
    }

    /// Register a `__attribute__((cleanup(fn)))` action for a variable in the
    /// current scope. `var_addr` is the variable's storage address (its alloca).
    pub fn register_cleanup(&mut self, var_addr: Val, fn_name: String) {
        if let Some(scope) = self.cleanups.last_mut() {
            scope.push(Cleanup::AttrFn { addr: var_addr, fn_name });
        }
    }

    /// Register an arbitrary scope-exit action in the current scope.
    pub fn register_scope_exit(&mut self, action: Cleanup) {
        if let Some(scope) = self.cleanups.last_mut() {
            scope.push(action);
        }
    }

    /// Emit cleanup calls for every scope down to (and including) `from`,
    /// innermost first — used by `return` (`from` = 0) and `break`/`continue`
    /// (`from` = the loop's recorded scope depth). Does not modify the stack.
    fn emit_cleanups_to(&mut self, from: usize) {
        let n = self.cleanups.len();
        for i in (from..n).rev() {
            let calls: Vec<Cleanup> = self.cleanups[i].iter().rev().cloned().collect();
            for c in calls { self.emit_cleanup(c); }
        }
    }

    /// Dispatch one scope-exit action.
    fn emit_cleanup(&mut self, c: Cleanup) {
        match c {
            Cleanup::AttrFn { addr, fn_name } => self.emit_cleanup_call(addr, &fn_name),
            Cleanup::Defer(stmt) => { let _ = self.lower_stmt(&stmt); }
            Cleanup::StringRelease { addr } => self.emit_string_release_at(addr),
            Cleanup::FreePtr { slot } => self.emit_free_ptr_slot(slot),
            Cleanup::RefRelease { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::char_ptr() });
                let _ = self.emit_rc_release(Val::Local(p));
            }
            Cleanup::BigintFree { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: super::types::bigint_type() });
                let _ = self.emit_bigint_call("__sic_bi_free", vec![Val::Local(p)], Type::Void);
            }
            Cleanup::RatFree { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: super::types::fixed_type(0, 0) });
                let _ = self.emit_bigint_call("__sic_rat_free", vec![Val::Local(p)], Type::Void);
            }
        }
    }

    /// Free the `char*` held in `slot` (a transient `string.ptr` copy). `free`
    /// tolerates NULL, so the no-copy case is a harmless no-op.
    fn emit_free_ptr_slot(&mut self, slot: Val) {
        let p = self.alloc_val();
        self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::char_ptr() });
        let _ = self.emit_free(Val::Local(p));
    }

    /// Release a refcounted `string` local at scope exit: decref its `rc`,
    /// freeing the owned block at 0 (sic.md §"Built-in string").
    fn emit_string_release_at(&mut self, addr: Val) {
        let _ = self.release_string_at(&addr);
    }

    /// Emit `fn(&var)` for a cleanup function. The function takes a pointer to
    /// the variable; declare it as an extern `void(void*)` if not yet known.
    fn emit_cleanup_call(&mut self, var_addr: Val, fn_name: &str) {
        let fref = match self.lowerer.module.func_ref_by_name(fn_name) {
            Some(f) => f,
            None => {
                let sig = sic_ir::FunctionType {
                    params: vec![Type::void_ptr()],
                    ret: Type::Void,
                    variadic: false,
                };
                self.lowerer.module.add_extern(sic_ir::ExternFunc {
                    name: fn_name.to_string(), sig,
                })
            }
        };
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![var_addr], ret_ty: Type::Void });
    }

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
    /// True for SIC-language (`.sic`) sources — gates SIC's defined-behavior
    /// semantics (zero-init, `÷0 → 0`, defined shifts, …).
    pub fn is_sic(&self) -> bool { self.lowerer.sic }

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
    /// Infer the concrete shape of every `tuple` parameter from the call sites in
    /// the whole translation unit (sic.md §"Tuples"). A tuple param is passed by
    /// pointer, so its element types must be known to unpack/index it. For each
    /// call `f(…, tuple-arg, …)`, the tuple argument's type is inferred under a
    /// throwaway FuncCtx that has the *calling* function's params and (linearly
    /// scanned) locals bound. First consistent shape wins.
    pub(crate) fn infer_tuple_params(&mut self, tu: &crate::ast::TranslationUnit) {
        // Which functions have tuple params, and at which positions?
        let mut targets: HashMap<String, Vec<usize>> = HashMap::new();
        for d in &tu.decls {
            if let Decl::Func { name, params, body: Some(_), .. } = d {
                let pos: Vec<usize> = params.iter().enumerate()
                    .filter(|(_, p)| matches!(p.ty.ty, AstType::Tuple))
                    .map(|(i, _)| i).collect();
                if !pos.is_empty() { targets.insert(name.clone(), pos); }
            }
        }
        if targets.is_empty() { return; }

        for d in &tu.decls {
            if let Decl::Func { params, body: Some(body), .. } = d {
                let mut dummy = Function::new("__tparam_infer".to_string(),
                    FunctionType { ret: Type::Void, params: vec![], variadic: false }, vec![], Linkage::Internal);
                let blk = dummy.alloc_block();
                dummy.blocks.push(BasicBlock::new(blk));
                let mut found: Vec<(String, usize, Type)> = Vec::new();
                {
                    let mut fc = FuncCtx::new_with_func(self, &mut dummy);
                    for p in params {
                        if let Some(n) = &p.name {
                            if let Ok(ty) = lower_param_type(&p.ty, &fc.lowerer.struct_types, fc.lowerer.ptr_size) {
                                fc.define_local(n.clone(), ty, ValId(0));
                            }
                        }
                    }
                    infer_calls_in_stmts(&mut fc, &body, &targets, &mut found);
                }
                for (fname, idx, ty) in found {
                    self.tuple_param_types.entry((fname, idx)).or_insert(ty);
                }
            }
        }
    }

    /// Infer the concrete tuple type of a `tuple`-returning function from the
    /// element expressions of its first `return tuple(...)`. Uses a throwaway
    /// FuncCtx with the parameters bound, so full expression inference applies.
    fn infer_tuple_return_type(&mut self, elems: &[Expr], params: &[AstParam], ir_params: &[Type]) -> Type {
        let mut dummy = Function::new("__tuple_infer".to_string(),
            FunctionType { ret: Type::Void, params: vec![], variadic: false }, vec![], Linkage::Internal);
        let blk = dummy.alloc_block();
        dummy.blocks.push(BasicBlock::new(blk));
        let tys: Vec<Type> = {
            let mut fc = FuncCtx::new_with_func(self, &mut dummy);
            for (p, ty) in params.iter().zip(ir_params) {
                if let Some(n) = &p.name { fc.define_local(n.clone(), ty.clone(), ValId(0)); }
            }
            elems.iter().map(|e| fc.infer_expr_type(e).unwrap_or_else(|_| Type::i32())).collect()
        };
        super::types::tuple_type(tys)
    }

    pub fn lower_function(
        &mut self,
        name: &str,
        ret_ty: &QualType,
        params: &[AstParam],
        variadic: bool,
        body: &[Stmt],
        storage: &Option<StorageClass>,
        inline: bool,
        constructor: Option<i32>,
    ) -> Result<()> {
        // sic `@` reference borrow-checking (sic.md §"References").
        if self.sic {
            super::borrowck::check(body)?;
        }
        let ir_params: Result<Vec<_>> = params.iter().enumerate().map(|(i, p)| {
            // sic tuple parameter (sic.md §"Tuples"): a tuple is passed by pointer;
            // its concrete shape was inferred from call sites in a pre-pass.
            if self.sic && matches!(p.ty.ty, AstType::Tuple) {
                if let Some(ty) = self.tuple_param_types.get(&(name.to_string(), i)) {
                    return Ok(ty.clone());
                }
            }
            lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
        }).collect();
        let ir_params = ir_params?;
        // sic `tuple`-returning function (sic.md §"Tuples"): the concrete return
        // type is inferred from the first `return tuple(...)` in the body.
        let ir_ret = if self.sic && matches!(ret_ty.ty, AstType::Tuple) {
            match first_return_tuple(body) {
                Some(elems) => self.infer_tuple_return_type(&elems, params, &ir_params),
                None => lower_type(ret_ty, &self.struct_types, self.ptr_size)?,
            }
        } else {
            lower_type(ret_ty, &self.struct_types, self.ptr_size)?
        };

        let sig = super::build_fn_sig(ir_ret.clone(), ir_params.clone(), variadic, self.ptr_size);
        let is_sret = super::ret_is_sret(&ir_ret, self.ptr_size);

        let linkage = super::fn_linkage(storage, inline, self.static_funcs.contains(name));

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
        func.constructor = constructor;

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
        // sic bounds checking: pre-scan which locals are mutated, so only
        // never-moved `new`/`@` pointers are treated as checkable fat pointers.
        if fc.is_sic() {
            for s in body { scan_mutated_stmt(s, &mut fc.moved_names); }
        }
        let param_base = if is_sret { 1 } else { 0 };
        if is_sret {
            fc.sret = Some((Val::Local(ValId(0x10000)), ir_ret.clone()));
        }
        for (i, p) in params.iter().enumerate() {
            if let Some(pname) = &p.name {
                // A never-moved `@`-reference param is a checkable fat pointer.
                if fc.is_sic()
                    && p.ty.qualifiers.iter().any(|q| matches!(q, crate::ast::TypeQual::Reference { .. }))
                    && !fc.moved_names.contains(pname)
                {
                    fc.fat_locals.insert(pname.clone());
                }
                let pty = ir_params[i].clone();
                let sentinel = ValId((i + param_base) as u32 + 0x10000);
                let ptr_vid = fc.alloc_val();
                fc.push_instr(Instr::Alloca { dest: ptr_vid, ty: pty.clone(), align: None });
                if matches!(pty, Type::Struct(_) | Type::Union(_) | Type::Array { .. }) {
                    // Aggregate params (struct/union/vector) are passed as a
                    // pointer; copy into the local alloca so the callee owns a copy.
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
            // Falling off the end of the function still runs cleanups for any
            // `__attribute__((cleanup))` locals in scope (a function that ends
            // without an explicit `return`).
            fc.emit_cleanups_to(0);
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
            // sic's explicit `fallthrough;` is a no-op: control simply continues
            // into the statements of the next case (sic.md §"Switch - case").
            Stmt::Fallthrough(_) => {}
            // sic `defer <stmt>;` (sic.md §"Defer keyword"): register the statement
            // to be lowered (LIFO) at every exit of the enclosing scope.
            Stmt::Defer(inner, _) => {
                self.register_scope_exit(Cleanup::Defer(inner.clone()));
            }
            // sic `del <expr>;` (sic.md §"Scopes and automatic release").
            Stmt::Delete(e, _) => { self.lower_delete(e)?; }
            Stmt::Expr(e, _) => {
                self.lower_expr(e)?;
                // Free any bigint temporaries this statement created (sic.md
                // §"Integer sizes") — per statement, so loop bodies don't leak.
                if !self.is_terminated() { self.flush_bigint_temps(); }
            }
            Stmt::Block(stmts, _) => {
                self.enter_scope();
                for s in stmts {
                    if self.is_terminated() && !stmt_is_jump_target(s) { continue; }
                    self.lower_stmt(s)?;
                }
                self.exit_scope();
            }
            Stmt::Decl(d) => {
                self.lower_local_decl(d)?;
                if !self.is_terminated() { self.flush_bigint_temps(); }
            }
            Stmt::Return(val, _) => {
                // Evaluate the return value BEFORE running cleanups (the value
                // must be computed while the about-to-be-destroyed locals are
                // still valid), then run every enclosing scope's cleanups.
                if let Some((sret_ptr, agg_ty)) = self.sret.clone() {
                    // Aggregate return: copy the value into the caller's slot.
                    if let Some(e) = val {
                        // sic: `return None;` builds the enum from its discriminant.
                        let src = if self.is_sic() && self.is_tagged_enum_struct(&agg_ty) {
                            self.enum_value_ptr(e, &agg_ty, &e.span)?
                        } else if self.is_sic() && super::types::is_sic_string(&agg_ty)
                            && !self.is_string_operand(e)
                        {
                            // `return "literal";` / `return some_char_ptr;` from a
                            // `string` function: wrap the C string in a (non-owning)
                            // descriptor so the sret copy has a real 24-byte string,
                            // not a 4-byte char* read as a struct.
                            let v = self.lower_expr(e)?;
                            self.cstr_to_string(v)?
                        } else {
                            self.lower_aggregate_ptr(e)?
                        };
                        let ps = self.ptr_size();
                        let size = agg_ty.size_of(ps);
                        let align = agg_ty.align_of(ps) as u64;
                        self.push_instr(Instr::MemCopy { dst: sret_ptr.clone(), src, size, align });
                        // sic: the returned `string` slot acquires a reference —
                        // retain so it outlives this frame's scope-exit releases
                        // (of the local and any temporaries).
                        if self.is_sic() && super::types::is_sic_string(&agg_ty) {
                            self.retain_string_at(&sret_ptr)?;
                        }
                    }
                    self.emit_cleanups_to(0);
                    self.set_terminator(Terminator::Ret(None));
                } else if self.ret_ty == Type::Void {
                    // `return expr;` in a void function (GCC-ism, common in QEMU's
                    // `return qatomic_*()` void wrappers): evaluate the operand for
                    // its side effects but discard the value.
                    if let Some(e) = val {
                        let _ = self.lower_expr(e)?;
                    }
                    self.emit_cleanups_to(0);
                    self.set_terminator(Terminator::Ret(None));
                } else if matches!(self.ret_ty, Type::Struct(_) | Type::Union(_)) {
                    // Small (register-class) aggregate return: `self.sret` is None,
                    // so hand the backend a pointer to the value; it loads the
                    // eightbytes into the return registers.
                    let ret = if let Some(e) = val {
                        if self.is_sic() && self.is_tagged_enum_struct(&self.ret_ty.clone()) {
                            let rty = self.ret_ty.clone();
                            Some(self.enum_value_ptr(e, &rty, &e.span)?)
                        } else {
                            Some(self.lower_aggregate_ptr(e)?)
                        }
                    } else {
                        None
                    };
                    self.emit_cleanups_to(0);
                    self.set_terminator(Terminator::Ret(ret));
                } else {
                    let ret = if let Some(e) = val {
                        let v = self.lower_expr(e)?;
                        let expected = self.ret_ty.clone();
                        let c = self.coerce(v, &expected)?;
                        // sic tuple return (sic.md §"Tuples"): retain the shared
                        // block before scope-exit releases run, so the returned
                        // pointer outlives this frame (the caller releases it).
                        if self.is_sic() && super::types::is_tuple(&expected) {
                            let pc = self.coerce(c.clone(), &Type::char_ptr())?;
                            self.emit_rc_retain(pc)?;
                        }
                        // sic bigint/fixed return: these have value semantics (each
                        // owner frees its own block), so a returned local would be
                        // freed by scope cleanup before the caller reads it. Return
                        // an independent CLONE; the caller owns and frees it.
                        if self.is_sic() && (super::types::is_bigint(&expected) || super::types::is_fixed(&expected)) {
                            // A `fixed` is an exact rational; clone with the matching
                            // runtime so the returned block is a well-formed copy.
                            let (cf, cty) = if super::types::is_fixed(&expected) {
                                ("__sic_rat_clone", super::types::fixed_type(0, 0))
                            } else {
                                ("__sic_bi_clone", super::types::bigint_type())
                            };
                            let cl = self.emit_bigint_call(cf, vec![c], cty)?;
                            self.flush_bigint_temps();  // free the returned expr's temps
                            self.emit_cleanups_to(0);
                            self.set_terminator(Terminator::Ret(Some(cl)));
                            return Ok(());
                        }
                        Some(c)
                    } else {
                        None
                    };
                    self.flush_bigint_temps();  // free any bigint temps in the return expr
                    self.emit_cleanups_to(0);
                    self.set_terminator(Terminator::Ret(ret));
                }
            }
            Stmt::If { cond, then, else_, .. } => self.lower_if(cond, then, else_.as_deref())?,
            Stmt::While { cond, body, .. } => self.lower_while(cond, body)?,
            Stmt::DoWhile { body, cond, .. } => self.lower_do_while(body, cond)?,
            Stmt::For { init, cond, post, body, .. } => self.lower_for(init, cond, post, body)?,
            Stmt::Switch { val, body, .. } => self.lower_switch(val, body)?,
            Stmt::Match { scrutinee, arms, span } => self.lower_match(scrutinee, arms, span)?,
            Stmt::Guard { binding, cond, else_body, span } =>
                self.lower_guard_stmt(binding.as_ref(), cond, else_body, span)?,
            // sic `unsafe { … }` (sic.md §"Integer overflow"): raise the trapping
            // depth for the body so integer overflow / `÷0` become exceptions.
            Stmt::Unsafe(body, _) => {
                self.unsafe_depth += 1;
                self.enter_scope();
                for s in body {
                    if self.is_terminated() && !stmt_is_jump_target(s) { continue; }
                    self.lower_stmt(s)?;
                }
                self.exit_scope();
                self.unsafe_depth -= 1;
            }
            Stmt::Break(_) => {
                // `break` targets the innermost enclosing loop *or* switch,
                // whichever is nested deeper — a switch inside a loop breaks the
                // switch, not the loop.
                if let Some(&end) = self.break_stack.last() {
                    if let Some(&depth) = self.break_scope_depth.last() {
                        self.emit_cleanups_to(depth);
                    }
                    self.set_terminator(Terminator::Jump(end));
                } else {
                    return Err(CompileError::new("break outside loop/switch"));
                }
            }
            Stmt::Continue(_) => {
                if let Some(&(_, cont)) = self.loop_stack.last() {
                    if let Some(&depth) = self.continue_scope_depth.last() {
                        self.emit_cleanups_to(depth);
                    }
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
                // Each case body is its own scope, so a temporary it creates — e.g.
                // the owned string in `case K: return f();` — is released only on
                // this case's exit paths, not leaked into a sibling case's `return`
                // (which runs `emit_cleanups_to(0)`) where its slot is uninitialized.
                self.enter_scope();
                self.lower_stmt(body)?;
                self.exit_scope();
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
                self.enter_scope();
                self.lower_stmt(body)?;
                self.exit_scope();
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
                self.enter_scope();
                self.lower_stmt(body)?;
                self.exit_scope();
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
                let is_extern = matches!(base_ty.storage, Some(StorageClass::Extern));
                for d in declarators {
                    // A block-scope `extern T x;` refers to the file-scope/other-TU
                    // global, NOT a new local: register it as a global (import if
                    // needed) and bind the name to that global, rather than a stack
                    // slot. QEMU accesses `extern const TCGOpDef tcg_op_defs[];` this
                    // way inside functions; a stack slot read pure garbage.
                    if is_extern {
                        self.lowerer.lower_global_var(d, base_ty, false, false)?;
                        if let Some((gty, gref)) = self.lowerer.globals_map.get(&d.name).cloned() {
                            self.static_locals.insert(d.name.clone(), (gty, gref));
                        }
                        continue;
                    }
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
                    // sic tuple local (sic.md §"Tuples"): a tuple value is a pointer
                    // to a refcounted heap block. Bind the pointer, retain the
                    // shared block, and release it at scope exit. A bare `tuple t;`
                    // is deferred until its first assignment.
                    if self.is_sic() && matches!(d.ty.ty, AstType::Tuple) {
                        match &d.init {
                            Some(Initializer::Expr(e)) => {
                                let pty = self.infer_expr_type(e).unwrap_or(ty);
                                let vid = self.alloc_val();
                                self.push_instr(Instr::Alloca { dest: vid, ty: pty.clone(), align: None });
                                self.define_local(d.name.clone(), pty.clone(), vid);
                                let ptr = self.lower_expr(e)?;
                                let pc = self.coerce(ptr.clone(), &Type::char_ptr())?;
                                self.emit_rc_retain(pc)?;
                                self.push_instr(Instr::Store { val: ptr, ptr: Val::Local(vid) });
                                self.register_scope_exit(Cleanup::RefRelease { slot: Val::Local(vid) });
                                if !d.name.is_empty() {
                                    self.push_instr(Instr::DbgVar { name: d.name.clone(), ty: pty, slot: vid, is_param: false });
                                }
                                continue;
                            }
                            _ => {
                                self.deferred_tuples.insert(d.name.clone());
                                continue;
                            }
                        }
                    }
                    // sic fixed-point local (sic.md §"Built-in fixed point"): a
                    // `fixed` value is an EXACT rational (`__sic_rat*`); the declared
                    // `<I,F>` is display-only precision. A bare `fixed` (marked
                    // `(0,0)`) keeps its declared type; the value is stored exactly
                    // and freed at scope exit (value semantics, like bigint).
                    if self.is_sic() && matches!(d.ty.ty, AstType::Fixed { .. }) {
                        if let Some(Initializer::Expr(e)) = &d.init {
                            // Concrete target type: the declared `fixed<I,F>`, or —
                            // for a bare `fixed` — the initializer's fixed type (so
                            // `.str`/`typestr` report the operation's display dims). An
                            // integer/decimal initializer is still a `fixed`, taking
                            // its display dims from the literal.
                            let target = match super::types::fixed_dims(&ty) {
                                Some((0, 0)) | None => match self.infer_expr_type(e) {
                                    Ok(t) if super::types::is_fixed(&t) => t,
                                    _ => {
                                        let (i, f) = self.fixed_expr_dims(e).unwrap_or((0, 0));
                                        super::types::fixed_type(i, f)
                                    }
                                },
                                Some(_) => ty.clone(),
                            };
                            let vid = self.alloc_val();
                            self.push_instr(Instr::Alloca { dest: vid, ty: target.clone(), align: None });
                            self.define_local(d.name.clone(), target.clone(), vid);
                            let m = self.eval_fixed_owned(e, 0)?;
                            self.push_instr(Instr::Store { val: m, ptr: Val::Local(vid) });
                            self.register_scope_exit(Cleanup::RatFree { slot: Val::Local(vid) });
                            if !d.name.is_empty() {
                                self.push_instr(Instr::DbgVar { name: d.name.clone(), ty: target, slot: vid, is_param: false });
                            }
                            self.flush_bigint_temps();
                            continue;
                        }
                    }
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
                        let is_char = matches!(elem.as_ref(), Type::Int { bits: 8, .. });
                        let n = match &d.init {
                            // `char a[] = { "str" }` acts as `char a[] = "str"`.
                            Some(Initializer::List(items))
                                if is_char && super::string_brace_len(items).is_some() =>
                            {
                                super::string_brace_len(items).unwrap()
                            }
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
                    // sic refcounted `string` local: release its `rc` at scope
                    // exit (RAII). Safe for the uninitialized case too — that
                    // zero-inits `rc` to NULL, and releasing NULL is a no-op.
                    if self.is_sic() && super::types::is_sic_string(&ty) {
                        self.register_scope_exit(Cleanup::StringRelease { addr: Val::Local(vid) });
                    }
                    // sic `bigint` local: `__sic_bi_free` its block at scope exit
                    // (value semantics). Uninitialized → NULL slot, freeing which
                    // is a no-op.
                    if self.is_sic() && super::types::is_bigint(&ty) {
                        self.register_scope_exit(Cleanup::BigintFree { slot: Val::Local(vid) });
                    }
                    // sic bounds checking: a never-moved pointer initialized from
                    // `new` (or declared as a `@`-reference) is a checkable fat
                    // pointer — `name[i]` reads the header size at `name-2*ptr`.
                    if self.is_sic() && !d.name.is_empty() && !self.moved_names.contains(&d.name) {
                        let is_new_init = matches!(&d.init,
                            Some(Initializer::Expr(e)) if matches!(&e.kind, ExprKind::New { .. }));
                        let is_ref = d.ty.qualifiers.iter()
                            .any(|q| matches!(q, crate::ast::TypeQual::Reference { .. }));
                        if is_new_init || is_ref {
                            self.fat_locals.insert(d.name.clone());
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
                    // `__attribute__((cleanup(fn)))`: call `fn(&var)` when this
                    // scope exits (glib `g_autoptr`, QEMU `QEMU_LOCK_GUARD`).
                    if let Some(fname) = &d.cleanup {
                        self.register_cleanup(Val::Local(vid), fname.clone());
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
        // Expose the target type so a generic constructor on the RHS
        // (`Option<int> x = Option::Some(5)`) resolves to its monomorph.
        let prev = self.expected_ty.replace(ty.clone());
        let r = self.lower_initializer_inner(init, ptr, ty);
        self.expected_ty = prev;
        r
    }

    fn lower_initializer_inner(&mut self, init: &Initializer, ptr: Val, ty: &Type) -> Result<()> {
        // `char a[] = { "str" }` fills the char array from the string, exactly like
        // `char a[] = "str"` — re-dispatch on the unwrapped string literal.
        if let Type::Array { elem, .. } = ty {
            if matches!(elem.as_ref(), Type::Int { bits: 8, .. }) {
                if let Initializer::List(items) = init {
                    if let Some(e) = super::string_brace_items(items) {
                        return self.lower_initializer(&Initializer::Expr(e.clone()), ptr, ty);
                    }
                }
            }
        }
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
            // sic `string s = "..."`: fill the slice descriptor { data, size }
            // rather than treating the literal as an aggregate to byte-copy.
            Initializer::Expr(e)
                if super::types::is_sic_string(ty) && matches!(&e.kind, ExprKind::StringLit(_)) =>
            {
                let ExprKind::StringLit(s) = &e.kind else { unreachable!() };
                self.store_string_literal(&ptr, ty, s)?;
            }
            // sic `string s = <char*>` (e.g. `string v = argv[1]`): wrap the C
            // string into a non-owning `{data,size,rc=NULL}` descriptor via strlen,
            // rather than byte-copying the pointer as if it were a descriptor. A
            // real `string` source instead copies its descriptor + retains.
            Initializer::Expr(e) if self.is_sic() && super::types::is_sic_string(ty) => {
                let rt = self.infer_expr_type(e).unwrap_or_else(|_| Type::i32());
                let is_str = super::types::is_sic_string(&rt)
                    || matches!(&rt, Type::Pointer(inner) if super::types::is_sic_string(inner));
                let size = ty.size_of(self.ptr_size());
                let align = ty.align_of(self.ptr_size());
                if is_str {
                    let src = self.lower_aggregate_ptr(e)?;
                    self.push_instr(Instr::MemCopy { dst: ptr.clone(), src, size, align });
                    self.retain_string_at(&ptr)?;
                } else {
                    let v = self.lower_expr(e)?;
                    let cp = self.coerce(v, &Type::char_ptr())?;
                    let src = self.cstr_to_string(cp)?; // non-owning {data,size,rc=NULL}
                    self.push_instr(Instr::MemCopy { dst: ptr.clone(), src, size, align });
                }
                return Ok(());
            }
            // sic `bigint x = <expr>` (sic.md §"Integer sizes"): store a
            // freshly-owned bigint. An existing bigint value is CLONED (value
            // semantics — the binding owns its own block); a literal/int builds a
            // new one. The clone/new already registered its scope-exit free.
            Initializer::Expr(e) if self.is_sic() && super::types::is_bigint(ty) => {
                let v = self.eval_bigint_owned(e)?;
                self.push_instr(Instr::Store { val: v, ptr });
                return Ok(());
            }
            // sic `any a = <expr>` (sic.md std): box the value unless the RHS is
            // already an `any` (then it copies below like any aggregate).
            Initializer::Expr(e)
                if self.is_sic() && super::types::is_any(ty)
                    && !matches!(self.infer_expr_type(e), Ok(t) if super::types::is_any(&t)) =>
            {
                let boxed = self.box_any(e)?; // pointer to a fresh `any` struct
                let size = ty.size_of(self.ptr_size());
                let align = ty.align_of(self.ptr_size());
                self.push_instr(Instr::MemCopy { dst: ptr, src: boxed, size, align });
                return Ok(());
            }
            Initializer::Expr(e) => {
                // `T v = <aggregate expr>` (e.g. a compound literal, a struct
                // returned by value, or a `vector_size` array from an element-wise
                // operator/intrinsic) copies the whole object rather than storing
                // a pointer/register-sized scalar. An array-typed target only takes
                // this path for a genuine aggregate RHS (a vector); a scalar RHS is
                // a plain store (the array being an array-decayed element lvalue).
                // sic: `Option b = None;` / `Test x = BLACK;` — a bare
                // (payload-less) variant is the discriminant, so build the
                // `{tag,union}` value from it rather than byte-copying an int as if
                // it were an aggregate. A same-enum RHS still copies.
                // A payload constructor call (`Some(42)`, `Option::Ok(x)`) builds a
                // full enum value and is copied below; only a *bare* variant
                // (`None`, `BLACK`) or enum-constant is the discriminant handled here.
                let is_ctor_call = matches!(&e.kind, ExprKind::Call { .. });
                if self.is_sic() && self.is_tagged_enum_struct(ty) && !is_ctor_call {
                    let same = matches!(self.infer_expr_type(e), Ok(t) if &t == ty);
                    if !same {
                        let tag = self.lower_expr(e)?;
                        return self.build_enum_from_tag(&ptr, ty, tag, &e.span);
                    }
                }
                // sic array init from a differently-sized array RHS (`int c[20] =
                // a + b;`): the target must be at least as large; copy the RHS
                // elements and zero the remainder (sic.md §"Arrays and lists").
                if self.is_sic() {
                    if let (Type::Array { elem: de, len: dn }, Ok(Type::Array { elem: se, len: sn })) =
                        (ty, self.infer_expr_type(e))
                    {
                        if de == &se && *dn != sn {
                            if sn > *dn {
                                return Err(CompileError::at(
                                    format!("array of {} elements does not fit target of {}", sn, dn),
                                    e.span.file.clone(), e.span.line, e.span.col));
                            }
                            let src = self.lower_aggregate_ptr(e)?;
                            let esz = de.size_of(self.ptr_size());
                            let al = de.align_of(self.ptr_size());
                            self.push_instr(Instr::MemSet { dst: ptr.clone(), val: Constant::zero(), size: *dn as u64 * esz, align: al });
                            self.push_instr(Instr::MemCopy { dst: ptr, src, size: sn as u64 * esz, align: al });
                            return Ok(());
                        }
                    }
                }
                let aggregate_init = match ty {
                    Type::Struct(_) | Type::Union(_) => true,
                    Type::Array { .. } => matches!(
                        self.infer_expr_type(e),
                        Ok(Type::Array { .. } | Type::Struct(_) | Type::Union(_))
                    ),
                    _ => false,
                };
                if aggregate_init {
                    let src = self.lower_aggregate_ptr(e)?;
                    let size = ty.size_of(self.ptr_size());
                    let align = ty.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: ptr.clone(), src, size, align });
                    // A `string` binding acquires a reference to the shared
                    // buffer → retain. (Concat/slice temps register their own
                    // release, so uniform retain-on-acquire stays balanced.)
                    if self.is_sic() && super::types::is_sic_string(ty) {
                        self.retain_string_at(&ptr)?;
                    }
                } else {
                    // sic: a float/double target puts the RHS in that numeric
                    // context — bare integer literals adopt it, so `float b = 1/3`
                    // computes 0.333… rather than integer-dividing to 0 (sic.md
                    // §"Built-in fixed point").
                    let promoted;
                    let e = if self.is_sic()
                        && matches!(ty, Type::Float32 | Type::Float64 | Type::Float80)
                    {
                        promoted = Self::promote_numeric_literals(e);
                        &promoted
                    } else {
                        e
                    };
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
                    if let Some((tptr, tty, bf)) = target {
                        if let Some(bf) = bf {
                            // Bit-field member: read-modify-write so it doesn't
                            // clobber neighbours sharing the storage unit.
                            let e = match &item.init {
                                Initializer::Expr(e) => e.clone(),
                                Initializer::List(items) => match items.first() {
                                    Some(crate::ast::InitItem { init: Initializer::Expr(e), .. }) => e.clone(),
                                    _ => continue,
                                },
                            };
                            let v = self.lower_expr(&e)?;
                            self.store_bitfield(&tptr, &tty, bf, v)?;
                        } else {
                            self.lower_initializer(&item.init, tptr, &tty)?;
                        }
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
        -> Result<(Option<(Val, Type, Option<super::expr::BitField>)>, usize)>
    {
        use crate::ast::Designator;
        // First step: designator[0] if present, else the implicit cursor.
        let (first, top_index) = match designators.first() {
            Some(Designator::Field(name)) => {
                let Some((off, fty, bf)) = super::expr::resolve_field_access(agg, name, self.ptr_size(), &self.lowerer.struct_types)
                else { return Ok((None, cursor + 1)); };
                (Some((self.gep_offset(base, off, &fty), fty, bf)), top_field_index(agg, name, &self.lowerer.struct_types))
            }
            Some(Designator::Index(e)) => {
                let i = eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0).max(0) as usize;
                (self.member_at(base, agg, i), i)
            }
            Some(Designator::IndexRange(..)) => unreachable!("ranges expanded before resolution"),
            None => (self.member_at(base, agg, cursor), cursor),
        };
        let Some((mut ptr, mut cur_ty, mut bf)) = first else {
            // Out-of-range positional/index element (excess initializer): skip it
            // but still advance the cursor past this position.
            return Ok((None, top_index + 1));
        };
        // Navigate any remaining (chained) designators into `cur_ty`.
        let rest = if designators.is_empty() { &designators[..] } else { &designators[1..] };
        for d in rest {
            match d {
                Designator::Field(name) => {
                    let Some((off, fty, sub_bf)) = super::expr::resolve_field_access(&cur_ty, name, self.ptr_size(), &self.lowerer.struct_types)
                    else { return Ok((None, top_index + 1)); };
                    ptr = self.gep_offset(&ptr, off, &fty);
                    cur_ty = fty;
                    bf = sub_bf;
                }
                Designator::Index(e) => {
                    let i = eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0).max(0) as usize;
                    let Some((p, ety, sub_bf)) = self.member_at(&ptr, &cur_ty, i) else {
                        return Ok((None, top_index + 1));
                    };
                    ptr = p; cur_ty = ety; bf = sub_bf;
                }
                // A range in a chained (non-leading) position is unsupported;
                // skip the element rather than crash.
                Designator::IndexRange(..) => return Ok((None, top_index + 1)),
            }
        }
        Ok((Some((ptr, cur_ty, bf)), top_index + 1))
    }

    /// Pointer + type of the `idx`-th member of an aggregate (struct field or
    /// array element), by positional index. `None` when `idx` is out of range.
    pub(crate) fn member_at(&mut self, base: &Val, agg: &Type, idx: usize) -> Option<(Val, Type, Option<super::expr::BitField>)> {
        let resolved = super::types::resolve_aggregate(agg, &self.lowerer.struct_types);
        match &resolved {
            Type::Struct(st) => {
                let fty = st.fields.get(idx)?.1.clone();
                // A bit-field member shares its storage unit with neighbours, so
                // the pointer is the unit's byte offset and writes must mask.
                if let Some(Some(width)) = st.bitfields.get(idx).copied() {
                    let (offs, bit_offs, _) = st.layout_full(self.ptr_size());
                    let byte_off = *offs.get(idx).unwrap_or(&0);
                    let bf = super::expr::BitField::new(*bit_offs.get(idx).unwrap_or(&0), width, fty.is_signed());
                    return Some((self.gep_offset(base, byte_off, &fty), fty, Some(bf)));
                }
                let off = st.field_offset(idx, self.ptr_size());
                Some((self.gep_offset(base, off, &fty), fty, None))
            }
            Type::Union(u) => {
                let fty = u.fields.get(idx)?.1.clone();
                Some((self.gep_offset(base, 0, &fty), fty, None))
            }
            Type::Array { elem, len } => {
                if *len > 0 && idx >= *len { return None; }
                let esz = elem.size_of(self.ptr_size());
                Some((self.gep_offset(base, idx as u64 * esz, elem), (**elem).clone(), None))
            }
            _ => None,
        }
    }

    /// Fill a sic `string` slice descriptor at `base` from a string literal:
    /// `data` points at a private NUL-terminated global, `size` is the byte
    /// length (sic.md §"Built-in string").
    pub(crate) fn store_string_literal(&mut self, base: &Val, ty: &Type, s: &str) -> Result<()> {
        let data_src = self.emit_cstring(s);            // char* to "...\0"
        let size_val = Constant::uint(s.len() as u64);  // byte length (excl. NUL)
        if let Some((dptr, dty, _)) = self.member_at(base, ty, 0) {
            let v = self.coerce(data_src, &dty)?;
            self.push_instr(Instr::Store { val: v, ptr: dptr });
        }
        if let Some((sptr, sty, _)) = self.member_at(base, ty, 1) {
            let v = self.coerce(size_val, &sty)?;
            self.push_instr(Instr::Store { val: v, ptr: sptr });
        }
        // rc = NULL — a literal points at static data and owns nothing.
        if let Some((rptr, rfty, _)) = self.member_at(base, ty, 2) {
            let v = self.coerce(Constant::zero(), &rfty)?;
            self.push_instr(Instr::Store { val: v, ptr: rptr });
        }
        Ok(())
    }

    // ─── Control flow ────────────────────────────────────────────────────────

    /// Lower a condition expression to a bool, freeing any bigint/fixed temporaries
    /// it creates in-place (sic.md §"Integer sizes"/"fixed point"). A loop
    /// condition re-executes each iteration, so its temps must be freed there —
    /// not by the statement-end flush, which runs once.
    fn lower_cond(&mut self, cond: &Expr) -> Result<Val> {
        let mark = self.bigint_temps.len();
        let v = self.lower_expr(cond)?;
        let b = self.to_bool(v)?;
        self.flush_bigint_temps_from(mark);
        Ok(b)
    }

    fn lower_if(&mut self, cond: &Expr, then: &Stmt, else_: Option<&Stmt>) -> Result<()> {
        // Fold a compile-time-constant condition to just its taken branch, like
        // gcc/clang. QEMU's feature gates expand to a literal (`whpx_enabled()` →
        // `0` on Linux); lowering the dead branch would emit calls to functions
        // that are never compiled/linked (`whpx_*`/`hvf_*`) → undefined symbols.
        // `eval_const_expr` only succeeds for genuine constant expressions (no
        // calls/side effects), so dropping the other branch is safe.
        if let Ok(v) = crate::lower::eval_const_expr(cond, &self.lowerer.enum_consts) {
            if v != 0 {
                return self.lower_stmt(then);
            } else if let Some(e) = else_ {
                return self.lower_stmt(e);
            }
            return Ok(());
        }
        let cond_bool = self.lower_cond(cond)?;

        let then_bb = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();
        let else_bb = if else_.is_some() { self.new_block_after_current() } else { merge_bb };

        self.set_terminator(Terminator::CondJump {
            cond: cond_bool,
            then_bb,
            else_bb: if else_.is_some() { else_bb } else { merge_bb },
        });

        // Each branch is its own scope, even a non-`{}` statement (C block
        // semantics). This confines any temporaries created evaluating the branch
        // — e.g. the owned string in `if (c) return a + b;` — to that branch, so a
        // sibling branch's `return` (which runs `emit_cleanups_to(0)`) doesn't
        // release a temp that its own path never initialized.
        self.switch_to_block(then_bb);
        self.enter_scope();
        self.lower_stmt(then)?;
        self.exit_scope();
        if !self.is_terminated() {
            self.set_terminator(Terminator::Jump(merge_bb));
        }

        if let Some(e) = else_ {
            self.switch_to_block(else_bb);
            self.enter_scope();
            self.lower_stmt(e)?;
            self.exit_scope();
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
        let cb = self.lower_cond(cond)?;
        self.set_terminator(Terminator::CondJump { cond: cb, then_bb: body_bb, else_bb: end_bb });

        self.loop_stack.push((end_bb, cond_bb));
        self.break_stack.push(end_bb);
        let d = self.cleanups.len();
        self.break_scope_depth.push(d);
        self.continue_scope_depth.push(d);
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.continue_scope_depth.pop();
        self.break_scope_depth.pop();
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
        let d = self.cleanups.len();
        self.break_scope_depth.push(d);
        self.continue_scope_depth.push(d);
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }
        self.continue_scope_depth.pop();
        self.break_scope_depth.pop();
        self.break_stack.pop();
        self.loop_stack.pop();

        self.switch_to_block(cond_bb);
        let cb = self.lower_cond(cond)?;
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
        // `break` exits the whole loop, so it also runs the for-init scope's
        // cleanups (WITH_QEMU_LOCK_GUARD declares its guard there); `continue`
        // jumps to the post-expression with that scope still live.
        self.break_scope_depth.push(self.cleanups.len() - 1);
        self.continue_scope_depth.push(self.cleanups.len());
        self.switch_to_block(body_bb);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(post_bb)); }
        self.continue_scope_depth.pop();
        self.break_scope_depth.pop();
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
        for (case_val, group) in &cases.singles {
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
        // Ranges: bounds checks emitted before the switch dispatch. Each range's
        // low value keys `case_blocks` so the body lowering (`Stmt::CaseRange`)
        // finds its shared block.
        let mut range_arms: Vec<(i64, i64, BlockId)> = Vec::new();
        for (lo, hi, group) in &cases.ranges {
            let bb = match group_blocks.get(group) {
                Some(&b) => b,
                None => { let b = self.new_block_after_current(); group_blocks.insert(*group, b); b }
            };
            case_blocks.entry(*lo).or_insert(bb);
            range_arms.push((*lo, *hi, bb));
        }

        // Dispatch: test each range (`lo <= v <= hi`) in a chain, then fall into
        // the integer `Switch` for the individual case values.
        if range_arms.is_empty() {
            self.set_terminator(Terminator::Switch { val: v_i32.clone(), default: default_bb, arms });
        } else {
            let switch_bb = self.new_block_after_current();
            let n = range_arms.len();
            for (idx, (lo, hi, bb)) in range_arms.iter().enumerate() {
                let next_bb = if idx + 1 < n { self.new_block_after_current() } else { switch_bb };
                let ge = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: ge, op: CmpOp::ISGe, lhs: v_i32.clone(), rhs: Constant::int(*lo), ty: Type::i32() });
                let le = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: le, op: CmpOp::ISLe, lhs: v_i32.clone(), rhs: Constant::int(*hi), ty: Type::i32() });
                let both = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: both, op: BinOp::And, lhs: Val::Local(ge), rhs: Val::Local(le), ty: Type::Bool });
                self.set_terminator(Terminator::CondJump { cond: Val::Local(both), then_bb: *bb, else_bb: next_bb });
                self.switch_to_block(next_bb);
            }
            self.set_terminator(Terminator::Switch { val: v_i32.clone(), default: default_bb, arms });
        }
        self.switch_stack.push((default_bb, end_bb, case_blocks));
        self.break_stack.push(end_bb);
        self.break_scope_depth.push(self.cleanups.len());

        // Statements before the first label are unreachable but may declare
        // locals — lower them into a throwaway block.
        let pre = self.new_block_after_current();
        self.switch_to_block(pre);
        self.lower_stmt(body)?;
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
        self.break_scope_depth.pop();
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

    /// sic guard `… else <stmt>` (sic.md §"Match"): a terse early-exit that avoids
    /// `.unwrap()` and reduces `if` nesting. The boolean form runs `else_body` when
    /// `cond` is false; the bind form binds the present payload (Option/Result) or a
    /// non-null pointer into the CURRENT scope, running `else_body` (which must
    /// diverge) when absent — so the binding is definitely valid afterward.
    fn lower_guard_stmt(&mut self, binding: Option<&(Option<crate::ast::QualType>, String)>,
                   cond: &Expr, else_body: &Stmt, sp: &crate::lexer::Span) -> Result<()> {
        let else_bb = self.new_block_after_current();
        let cont_bb = self.new_block_after_current();

        match binding {
            // Boolean guard: `cond else <stmt>` ≡ `if (!cond) <stmt>`.
            None => {
                let cv = self.lower_expr(cond)?;
                let cb = self.to_bool(cv)?;
                self.set_terminator(Terminator::CondJump { cond: cb, then_bb: cont_bb, else_bb });
                self.switch_to_block(else_bb);
                self.enter_scope();
                self.lower_stmt(else_body)?;
                self.exit_scope();
                // The else may fall through (a plain `if (!cond) x = …;`).
                if !self.is_terminated() { self.set_terminator(Terminator::Jump(cont_bb)); }
                self.switch_to_block(cont_bb);
                return Ok(());
            }
            Some((decl_ty, name)) => {
                let cty = self.infer_expr_type(cond)?;
                // Bind form over an Option/Result: present → bind payload, else exit.
                if self.is_tagged_enum_struct(&cty) {
                    let (_, present) = self.enum_present_variant(&cty).ok_or_else(|| CompileError::at(
                        "guard-bind needs an enum with a payload variant (Some/Ok)".to_string(),
                        sp.file.clone(), sp.line, sp.col))?;
                    let pty = present.payload.clone().unwrap();
                    let ptr = self.lower_aggregate_ptr(cond)?;
                    let tag = self.load_enum_tag(ptr.clone(), &cty, sp)?;
                    let is_present = self.alloc_val();
                    self.push_instr(Instr::Cmp { dest: is_present, op: CmpOp::IEq, lhs: tag, rhs: Constant::int(present.tag), ty: Type::i32() });
                    // Allocate the binding slot up front (dominates `cont`).
                    let slot = self.alloc_val();
                    self.push_instr(Instr::Alloca { dest: slot, ty: pty.clone(), align: None });
                    self.define_local(name.clone(), pty.clone(), slot);
                    let bind_bb = self.new_block_after_current();
                    self.set_terminator(Terminator::CondJump { cond: Val::Local(is_present), then_bb: bind_bb, else_bb });
                    // Absent → the else must diverge.
                    self.switch_to_block(else_bb);
                    self.enter_scope();
                    self.lower_stmt(else_body)?;
                    self.exit_scope();
                    if !self.is_terminated() {
                        return Err(CompileError::at(
                            "guard-bind `else` must exit the scope (return/break/continue)".to_string(),
                            sp.file.clone(), sp.line, sp.col));
                    }
                    // Present → copy the payload into the binding slot.
                    self.switch_to_block(bind_bb);
                    let data = self.enum_data_ptr(ptr, &cty, sp)?;
                    if super::types::is_sic_string(&pty) || matches!(pty, Type::Struct(_) | Type::Union(_)) {
                        let size = pty.size_of(self.ptr_size());
                        let align = pty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: data, size, align });
                    } else {
                        let d = self.alloc_val();
                        self.push_instr(Instr::Load { dest: d, ptr: data, ty: pty.clone() });
                        self.push_instr(Instr::Store { val: Val::Local(d), ptr: Val::Local(slot) });
                    }
                    self.set_terminator(Terminator::Jump(cont_bb));
                    self.switch_to_block(cont_bb);
                    let _ = decl_ty;
                    return Ok(());
                }
                // Bind form over a pointer: non-null → bind, else exit.
                if matches!(cty, Type::Pointer(_)) {
                    let pv = self.lower_expr(cond)?;
                    let nn = self.to_bool(pv.clone())?; // non-null
                    let slot = self.alloc_val();
                    self.push_instr(Instr::Alloca { dest: slot, ty: cty.clone(), align: None });
                    self.define_local(name.clone(), cty.clone(), slot);
                    let bind_bb = self.new_block_after_current();
                    self.set_terminator(Terminator::CondJump { cond: nn, then_bb: bind_bb, else_bb });
                    self.switch_to_block(else_bb);
                    self.enter_scope();
                    self.lower_stmt(else_body)?;
                    self.exit_scope();
                    if !self.is_terminated() {
                        return Err(CompileError::at(
                            "guard-bind `else` must exit the scope (return/break/continue)".to_string(),
                            sp.file.clone(), sp.line, sp.col));
                    }
                    self.switch_to_block(bind_bb);
                    self.push_instr(Instr::Store { val: pv, ptr: Val::Local(slot) });
                    self.set_terminator(Terminator::Jump(cont_bb));
                    self.switch_to_block(cont_bb);
                    let _ = decl_ty;
                    return Ok(());
                }
                Err(CompileError::at(format!(
                    "guard-bind requires an Option/Result or pointer on the right, got a \
                     non-optional value"), sp.file.clone(), sp.line, sp.col))
            }
        }
    }

    /// sic `match` over a tagged enum (sic.md §"Match"). Dispatch on the value's
    /// discriminant; each arm runs in its own scope with the payload bound to the
    /// arm's name (a borrow of the value's storage). A `_` arm is the default; if
    /// no arm and no `_` matches at runtime, abort via `__sic_match_fail`.
    fn lower_match(&mut self, scrutinee: &Expr, arms: &[crate::ast::MatchArm], sp: &crate::lexer::Span) -> Result<()> {
        let sty = self.infer_expr_type(scrutinee)?;
        // sic RTTI (sic.md §"Match"): `match (type(x)) { string: …; int: …; _: … }`
        // dispatches on the value's runtime KIND category — no hand-written kind
        // table needed; the compiler owns the vocabulary.
        if self.is_sic() && super::types::is_type_info(&sty) {
            return self.lower_match_on_type(scrutinee, arms, sp);
        }
        if !self.is_tagged_enum_struct(&sty) {
            return Err(CompileError::at(
                "match requires a tagged enum value".to_string(), sp.file.clone(), sp.line, sp.col));
        }
        let ename = match &sty { Type::Struct(st) => st.name.clone().unwrap(), _ => unreachable!() };
        let info = self.lowerer.enum_defs.get(&ename).cloned().unwrap();
        let ptr = self.lower_aggregate_ptr(scrutinee)?;
        let tag = self.load_enum_tag(ptr.clone(), &sty, sp)?;

        let end_bb = self.new_block_after_current();
        // The wildcard `_` arm (if any) is the fallback.
        let wildcard = arms.iter().find(|a| a.variant.is_none());

        for arm in arms.iter().filter(|a| a.variant.is_some()) {
            let vname = arm.variant.as_ref().unwrap();
            let v = info.variant(vname).cloned().ok_or_else(|| CompileError::at(
                format!("enum '{}' has no variant '{}'", ename, vname), sp.file.clone(), sp.line, sp.col))?;

            let arm_bb = self.new_block_after_current();
            let next_bb = self.new_block_after_current();
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: tag.clone(), rhs: Constant::int(v.tag), ty: Type::i32() });
            self.set_terminator(Terminator::CondJump { cond: Val::Local(eq), then_bb: arm_bb, else_bb: next_bb });

            self.switch_to_block(arm_bb);
            self.enter_scope();
            if let Some(bind) = &arm.binding {
                let pty = v.payload.clone().ok_or_else(|| CompileError::at(
                    format!("variant '{}::{}' has no payload to bind", ename, vname), sp.file.clone(), sp.line, sp.col))?;
                // Bind the payload as a borrow of the value's `data` union member.
                let data_lv = self.enum_data_ptr(ptr.clone(), &sty, sp)?;
                let slot = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: slot, ty: pty.clone(), align: None });
                if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                    let size = pty.size_of(self.ptr_size());
                    let align = pty.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: data_lv, size, align });
                } else {
                    let d = self.alloc_val();
                    self.push_instr(Instr::Load { dest: d, ptr: data_lv, ty: pty.clone() });
                    self.push_instr(Instr::Store { val: Val::Local(d), ptr: Val::Local(slot) });
                }
                self.define_local(bind.clone(), pty, slot);
            }
            self.lower_stmt(&arm.body)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
            self.switch_to_block(next_bb);
        }

        // Fallback: `_` arm, or a runtime abort on an unmatched variant.
        if let Some(w) = wildcard {
            self.enter_scope();
            self.lower_stmt(&w.body)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
        } else {
            let fref = self.lowerer.ensure_match_fail_fn();
            self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
            self.set_terminator(Terminator::Jump(end_bb)); // abort never returns
        }
        self.switch_to_block(end_bb);
        Ok(())
    }

    /// sic `match (type(x)) { <type/category>: … ; _: … }` — dispatch on the value's
    /// runtime kind. An arm pattern is a type name or a kind category (`int`,
    /// `float`, `ptr`, …); it matches when `type(x).kind` is in that category, so
    /// `int` catches every signed-int width and `float` every float. Exact-type
    /// tests remain available with `type(x) == i64`.
    fn lower_match_on_type(&mut self, scrutinee: &Expr, arms: &[crate::ast::MatchArm], sp: &crate::lexer::Span) -> Result<()> {
        let kind = self.emit_type_info_field(scrutinee, "kind")?; // u32
        let end_bb = self.new_block_after_current();
        let wildcard = arms.iter().find(|a| a.variant.is_none());

        for arm in arms.iter().filter(|a| a.variant.is_some()) {
            let name = arm.variant.as_ref().unwrap();
            let kinds = match_type_kinds(name).ok_or_else(|| CompileError::at(
                format!("'{}' is not a type or kind category in a `match` on a type", name),
                sp.file.clone(), sp.line, sp.col))?;
            let arm_bb = self.new_block_after_current();
            let next_bb = self.new_block_after_current();
            // cond = OR over the category's kinds of (kind == k).
            let mut cond: Option<Val> = None;
            for k in kinds {
                let eq = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: kind.clone(), rhs: Constant::int(k as i64), ty: Type::u32() });
                cond = Some(match cond {
                    None => Val::Local(eq),
                    Some(prev) => {
                        let o = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: o, op: BinOp::Or, lhs: prev, rhs: Val::Local(eq), ty: Type::Bool });
                        Val::Local(o)
                    }
                });
            }
            self.set_terminator(Terminator::CondJump { cond: cond.unwrap(), then_bb: arm_bb, else_bb: next_bb });
            self.switch_to_block(arm_bb);
            self.enter_scope();
            self.lower_stmt(&arm.body)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
            self.switch_to_block(next_bb);
        }

        if let Some(w) = wildcard {
            self.enter_scope();
            self.lower_stmt(&w.body)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
        } else {
            let fref = self.lowerer.ensure_match_fail_fn();
            self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
            self.set_terminator(Terminator::Jump(end_bb)); // abort never returns
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

        // Conversion TO `_Bool` is `x != 0`, not a bit-truncation. A wide value
        // whose low bits are zero (e.g. `0x100` from `apic_base & (1<<8)`, the
        // `bool cpu_is_bsp()` return in QEMU) must become `true`, not `false`.
        if *target == Type::Bool && matches!(src_ty, Type::Int { .. } | Type::Pointer(_) | Type::Float32 | Type::Float64 | Type::Float80) {
            return self.to_bool(val);
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
/// The runtime kind(s) a `match (type(x))` arm pattern selects — a type name or a
/// kind category. A category maps to the SET of kinds it covers (`float` = the
/// three float kinds); a concrete type maps to its single kind (all signed-int
/// widths share INT, so `int`/`i64`/`char` all catch any signed int). Mirrors the
/// compiler's `type_kind` numbering, kept in ONE place so nothing hand-copies it.
fn match_type_kinds(name: &str) -> Option<Vec<u32>> {
    Some(match name {
        "void" => vec![0],
        "bool" => vec![1],
        "int" | "char" | "short" | "long" | "signed" | "isize"
        | "i8" | "i16" | "i32" | "i64" | "i128" => vec![2],
        "uint" | "unsigned" | "usize"
        | "u8" | "u16" | "u32" | "u64" | "u128" => vec![3],
        "f32" => vec![4],
        "f64" | "double" => vec![5],
        "f80" | "f128" => vec![6],
        "float" | "real" => vec![4, 5, 6],
        "ptr" | "pointer" => vec![7],
        "cstr" => vec![8],
        "string" | "str" => vec![9],
        "fixed" => vec![10],
        "array" => vec![11],
        "struct" => vec![12],
        "union" => vec![13],
        "enum" => vec![14],
        "tuple" => vec![15],
        "bigint" => vec![16],
        "type" => vec![17],
        _ => return None,
    })
}

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

/// Pre-scan: collect names of locals that are *mutated* somewhere in the body —
/// reassigned (`x = …`, `x += …`), incremented (`x++`, `--x`), swapped (`x <> y`)
/// or address-taken (`&x`). A `new`/`@` pointer in this set can't be safely
/// bounds-checked via its header (it may no longer point at the allocation base),
/// so it is excluded from `fat_locals`.
fn scan_mutated_expr(e: &Expr, out: &mut std::collections::HashSet<String>) {
    use ExprKind::*;
    // Record the mutated name at this node.
    match &e.kind {
        Assign { lhs, .. } => { if let Ident(n) = &lhs.kind { out.insert(n.clone()); } }
        PreInc { expr, .. } | PostInc { expr, .. } => { if let Ident(n) = &expr.kind { out.insert(n.clone()); } }
        Unary { op: crate::ast::UnOpKind::Addr, expr } => { if let Ident(n) = &expr.kind { out.insert(n.clone()); } }
        Swap { lhs, rhs } => {
            if let Ident(n) = &lhs.kind { out.insert(n.clone()); }
            if let Ident(n) = &rhs.kind { out.insert(n.clone()); }
        }
        _ => {}
    }
    // Recurse into children.
    match &e.kind {
        BinOp { lhs, rhs, .. } | Comma(lhs, rhs) | Assign { lhs, rhs, .. } | Swap { lhs, rhs } => {
            scan_mutated_expr(lhs, out); scan_mutated_expr(rhs, out);
        }
        Unary { expr, .. } | PreInc { expr, .. } | PostInc { expr, .. }
        | SizeofExpr(expr) | AlignofExpr(expr) | Cast { expr, .. } | Ref { expr, .. } => scan_mutated_expr(expr, out),
        Ternary { cond, then, else_ } | ChooseExpr { cond, then, else_ } => {
            scan_mutated_expr(cond, out); scan_mutated_expr(then, out); scan_mutated_expr(else_, out);
        }
        Elvis { cond, else_ } => { scan_mutated_expr(cond, out); scan_mutated_expr(else_, out); }
        Call { func, args } => { scan_mutated_expr(func, out); for a in args { scan_mutated_expr(a, out); } }
        Index { base, index } => { scan_mutated_expr(base, out); scan_mutated_expr(index, out); }
        Slice { base, lo, hi } => {
            scan_mutated_expr(base, out);
            if let Some(x) = lo { scan_mutated_expr(x, out); }
            if let Some(x) = hi { scan_mutated_expr(x, out); }
        }
        New { count, .. } => { if let Some(x) = count { scan_mutated_expr(x, out); } }
        Field { base, .. } | Arrow { base, .. } => scan_mutated_expr(base, out),
        Generic { controlling, assocs } => { scan_mutated_expr(controlling, out); for (_, x) in assocs { scan_mutated_expr(x, out); } }
        StmtExpr(stmts) => { for s in stmts { scan_mutated_stmt(s, out); } }
        VaStart { list, last } => { scan_mutated_expr(list, out); scan_mutated_expr(last, out); }
        VaArg { list, .. } | VaEnd { list } => scan_mutated_expr(list, out),
        VaCopy { dst, src } => { scan_mutated_expr(dst, out); scan_mutated_expr(src, out); }
        _ => {}
    }
}

fn scan_mutated_stmt(s: &Stmt, out: &mut std::collections::HashSet<String>) {
    match s {
        Stmt::Decl(Decl::Var { declarators, .. }) => {
            for d in declarators {
                if let Some(Initializer::Expr(e)) = &d.init { scan_mutated_expr(e, out); }
            }
        }
        Stmt::Expr(e, _) | Stmt::Return(Some(e), _) => scan_mutated_expr(e, out),
        Stmt::Block(ss, _) => for s in ss { scan_mutated_stmt(s, out); },
        Stmt::If { cond, then, else_, .. } => {
            scan_mutated_expr(cond, out); scan_mutated_stmt(then, out);
            if let Some(e) = else_ { scan_mutated_stmt(e, out); }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { body, cond, .. } => {
            scan_mutated_expr(cond, out); scan_mutated_stmt(body, out);
        }
        Stmt::For { init, cond, post, body, .. } => {
            if let Some(ForInit::Expr(e)) = init { scan_mutated_expr(e, out); }
            if let Some(ForInit::Decl(Decl::Var { declarators, .. })) = init {
                for d in declarators { if let Some(Initializer::Expr(e)) = &d.init { scan_mutated_expr(e, out); } }
            }
            if let Some(e) = cond { scan_mutated_expr(e, out); }
            if let Some(e) = post { scan_mutated_expr(e, out); }
            scan_mutated_stmt(body, out);
        }
        Stmt::Switch { val, body, .. } => { scan_mutated_expr(val, out); scan_mutated_stmt(body, out); }
        Stmt::Match { scrutinee, arms, .. } => {
            scan_mutated_expr(scrutinee, out);
            for a in arms { scan_mutated_stmt(&a.body, out); }
        }
        Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) | Stmt::Default(body, _)
        | Stmt::Label(_, body, _) | Stmt::Defer(body, _) => scan_mutated_stmt(body, out),
        Stmt::Delete(e, _) => scan_mutated_expr(e, out),
        _ => {}
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
        | Stmt::CaseRange(_, _, _, s) | Stmt::Fallthrough(s)
        | Stmt::Default(_, s) | Stmt::Defer(_, s) | Stmt::Delete(_, s) | Stmt::Unsafe(_, s) => s.line,
        Stmt::If { span, .. } | Stmt::While { span, .. } | Stmt::DoWhile { span, .. }
        | Stmt::For { span, .. } | Stmt::Switch { span, .. } | Stmt::Match { span, .. }
        | Stmt::Guard { span, .. } => span.line,
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

/// Collected switch labels: individual `case V:` values and `case LO ... HI:`
/// ranges, each tagged with a *group* id so all labels sharing one body block
/// map to the same block.
#[derive(Default)]
pub(super) struct SwitchCases {
    pub singles: Vec<(i64, usize)>,        // (value, group)
    pub ranges: Vec<(i64, i64, usize)>,    // (lo, hi, group)
}

fn collect_switch_cases(stmt: &Stmt, enum_consts: &HashMap<String, i64>) -> SwitchCases {
    let mut cases = SwitchCases::default();
    let mut group = 0usize;
    collect_cases_in(stmt, enum_consts, &mut cases, &mut group);
    cases
}

fn collect_cases_in(stmt: &Stmt, enum_consts: &HashMap<String, i64>, out: &mut SwitchCases, group: &mut usize) {
    match stmt {
        Stmt::Case(val, body, _) => {
            if let Ok(v) = eval_const_expr(val, enum_consts) {
                out.singles.push((v, *group));
            }
            *group += 1;
            collect_cases_in(body, enum_consts, out, group);
        }
        Stmt::CaseRange(lo, hi, body, _) => {
            // Record the range as a bounds check — NOT enumerated. QEMU uses huge
            // ranges (`case 0xF0000000 ... 0xFFFFFFFF:`), so enumerating them
            // produces hundreds of millions of switch arms (and hangs codegen).
            if let (Ok(l), Ok(h)) = (eval_const_expr(lo, enum_consts), eval_const_expr(hi, enum_consts)) {
                if l <= h { out.ranges.push((l, h, *group)); }
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

/// Find the element expressions of the first `return tuple(...)` reachable in a
/// function body (used to infer a `tuple`-returning function's concrete type).
fn first_return_tuple(stmts: &[Stmt]) -> Option<Vec<Expr>> {
    fn in_stmt(s: &Stmt) -> Option<Vec<Expr>> {
        match s {
            Stmt::Return(Some(e), _) => match &e.kind {
                ExprKind::TupleExpr(elems) => Some(elems.clone()),
                _ => None,
            },
            Stmt::Block(ss, _) => first_return_tuple(ss),
            Stmt::If { then, else_, .. } =>
                in_stmt(then).or_else(|| else_.as_ref().and_then(|e| in_stmt(e))),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. }
            | Stmt::Label(_, body, _) | Stmt::Default(body, _) | Stmt::Defer(body, _)
            | Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _)
            | Stmt::Switch { body, .. } => in_stmt(body),
            Stmt::Match { arms, .. } => arms.iter().find_map(|a| in_stmt(&a.body)),
            _ => None,
        }
    }
    stmts.iter().find_map(in_stmt)
}

/// Walk statements for the tuple-param inference pre-pass: bind locals as we go
/// (so a call `f(localtuple)` can infer the local's type) and record the tuple
/// types of arguments passed to any function in `targets`.
fn infer_calls_in_stmts(
    fc: &mut FuncCtx<'_>, stmts: &[Stmt],
    targets: &HashMap<String, Vec<usize>>, found: &mut Vec<(String, usize, Type)>,
) {
    for s in stmts { infer_calls_in_stmt(fc, s, targets, found); }
}

fn infer_calls_in_stmt(
    fc: &mut FuncCtx<'_>, s: &Stmt,
    targets: &HashMap<String, Vec<usize>>, found: &mut Vec<(String, usize, Type)>,
) {
    match s {
        Stmt::Decl(Decl::Var { declarators, .. }) => {
            for d in declarators {
                if let Some(Initializer::Expr(e)) = &d.init {
                    find_tuple_calls(fc, e, targets, found);
                }
                // Bind the local's type so later `f(local)` infers it.
                let ty = if matches!(d.ty.ty, AstType::Tuple) {
                    match &d.init {
                        Some(Initializer::Expr(e)) => fc.infer_expr_type(e)
                            .unwrap_or_else(|_| super::types::tuple_type(vec![])),
                        _ => super::types::tuple_type(vec![]),
                    }
                } else {
                    fc.lower_type(&d.ty).unwrap_or_else(|_| Type::i32())
                };
                if !d.name.is_empty() { fc.define_local(d.name.clone(), ty, ValId(0)); }
            }
        }
        Stmt::Decl(_) | Stmt::Null(_) | Stmt::Break(_) | Stmt::Continue(_)
        | Stmt::Goto(_, _) | Stmt::Fallthrough(_) | Stmt::Return(None, _) => {}
        Stmt::Expr(e, _) | Stmt::Return(Some(e), _) | Stmt::Delete(e, _) =>
            find_tuple_calls(fc, e, targets, found),
        Stmt::Block(ss, _) => infer_calls_in_stmts(fc, ss, targets, found),
        Stmt::If { cond, then, else_, .. } => {
            find_tuple_calls(fc, cond, targets, found);
            infer_calls_in_stmt(fc, then, targets, found);
            if let Some(e) = else_ { infer_calls_in_stmt(fc, e, targets, found); }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { body, cond, .. } => {
            find_tuple_calls(fc, cond, targets, found);
            infer_calls_in_stmt(fc, body, targets, found);
        }
        Stmt::For { init, cond, post, body, .. } => {
            match init {
                Some(ForInit::Expr(e)) => find_tuple_calls(fc, e, targets, found),
                Some(ForInit::Decl(d)) => infer_calls_in_stmt(fc, &Stmt::Decl(d.clone()), targets, found),
                None => {}
            }
            if let Some(e) = cond { find_tuple_calls(fc, e, targets, found); }
            if let Some(e) = post { find_tuple_calls(fc, e, targets, found); }
            infer_calls_in_stmt(fc, body, targets, found);
        }
        Stmt::Switch { val, body, .. } => {
            find_tuple_calls(fc, val, targets, found);
            infer_calls_in_stmt(fc, body, targets, found);
        }
        Stmt::Match { scrutinee, arms, .. } => {
            find_tuple_calls(fc, scrutinee, targets, found);
            for a in arms { infer_calls_in_stmt(fc, &a.body, targets, found); }
        }
        Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) | Stmt::Default(body, _)
        | Stmt::Label(_, body, _) | Stmt::Defer(body, _) =>
            infer_calls_in_stmt(fc, body, targets, found),
        Stmt::Unsafe(body, _) => infer_calls_in_stmts(fc, body, targets, found),
        Stmt::Guard { cond, else_body, .. } => {
            find_tuple_calls(fc, cond, targets, found);
            infer_calls_in_stmt(fc, else_body, targets, found);
        }
    }
}

/// Recurse through an expression finding calls to tuple-param functions and
/// recording the tuple argument types (inferred in `fc`'s current scope).
fn find_tuple_calls(
    fc: &mut FuncCtx<'_>, e: &Expr,
    targets: &HashMap<String, Vec<usize>>, found: &mut Vec<(String, usize, Type)>,
) {
    use crate::ast::ExprKind::*;
    match &e.kind {
        Call { func, args } => {
            if let Ident(name) = &func.kind {
                if let Some(positions) = targets.get(name) {
                    for &idx in positions {
                        if let Some(arg) = args.get(idx) {
                            if let Ok(ty) = fc.infer_expr_type(arg) {
                                if super::types::is_tuple(&ty) {
                                    found.push((name.clone(), idx, ty));
                                }
                            }
                        }
                    }
                }
            }
            find_tuple_calls(fc, func, targets, found);
            for a in args { find_tuple_calls(fc, a, targets, found); }
        }
        TupleExpr(xs) => for x in xs { find_tuple_calls(fc, x, targets, found); },
        BinOp { lhs, rhs, .. } | Assign { lhs, rhs, .. } | Comma(lhs, rhs)
        | Swap { lhs, rhs } => { find_tuple_calls(fc, lhs, targets, found); find_tuple_calls(fc, rhs, targets, found); }
        Unary { expr, .. } | PreInc { expr, .. } | PostInc { expr, .. } | Cast { expr, .. }
        | Field { base: expr, .. } | Arrow { base: expr, .. } | Ref { expr, .. } =>
            find_tuple_calls(fc, expr, targets, found),
        Index { base, index } => { find_tuple_calls(fc, base, targets, found); find_tuple_calls(fc, index, targets, found); }
        Ternary { cond, then, else_ } => {
            find_tuple_calls(fc, cond, targets, found);
            find_tuple_calls(fc, then, targets, found);
            find_tuple_calls(fc, else_, targets, found);
        }
        Elvis { cond, else_ } => { find_tuple_calls(fc, cond, targets, found); find_tuple_calls(fc, else_, targets, found); }
        _ => {}
    }
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
        AstType::Tuple => "tuple".to_string(),
        AstType::Fixed { integral, fraction } => format!("fixed<{},{}>", integral, fraction),
        AstType::Generic { name, .. } => name.clone(),
    }
}
