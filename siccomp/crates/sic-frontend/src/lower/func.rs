use std::collections::HashMap;
use crate::ast::{Decl, Stmt, Expr, ExprKind, ForInit, StorageClass, AstType, QualType, Initializer};
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
    /// sic `tuple` (sic.md §"Tuples"): release the tuple held in `slot` at scope
    /// exit — decrement its refcount, run its element destructor (releasing the
    /// refcounted elements it owns) at zero, then free the block.
    TupleRelease { slot: Val },
    /// sic `bigint`: `__sic_bi_free` the pointer held in `slot` at scope exit
    /// (value semantics — every bigint local/temp owns its heap block).
    BigintFree { slot: Val },
    /// sic `fixed`: `__sic_rat_free` the rational (`__sic_rat*`) held in `slot`
    /// at scope exit (value semantics — every fixed local owns its rational).
    RatFree { slot: Val },
    /// sic `dict`: `__sic_dict_free` the handle held in `slot` at scope exit.
    DictFree { slot: Val },
    /// sic `list`: `__sic_list_free` the handle held in `slot` at scope exit.
    ListFree { slot: Val },
    /// sic `any` local: if the `any` at `addr` wraps a refcounted `string` (e.g.
    /// read from a container), release that string's `rc` at scope exit
    /// (`__sic_any_release`). A no-op for any other wrapped type.
    AnyRelease { addr: Val },
    /// sic closure (sic.md §"Lambdas"): release the closure environment held in
    /// `slot` at scope exit — decrement its refcount, run its `__dtor` (freeing
    /// retained captures) at zero, then free the block.
    ClosureRelease { slot: Val },
    /// sic weak reference (sic.md §"Weak"): drop the weak reference held in `slot`
    /// at scope exit (`is_dict` picks the dict vs list runtime). Frees the handle
    /// struct only if it was the last weak ref and the container is already dead.
    WeakRelease { slot: Val, is_dict: bool },
}

/// sic strict enum typing (sic.md §"Enums"): the nominal identity of an
/// expression as seen by the enum type-checker. A C enum collapses to `int` in the
/// IR, so this recovers whether a value is a specific enum, a plain integer, or
/// something we cannot positively classify (treated permissively).
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnumClass {
    Enum(String),
    Int,
    Unknown,
}

/// sic bitfield typing (sic.md §"Bitfields"): the nominal classification of an
/// expression — a specific `bitfield`, a plain integer, or unknown. Mirrors
/// `EnumClass`; used to restrict operators to `& | ^ ~` and enforce strict
/// init/assign / width-checked casts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BitfieldClass {
    Bitfield(String),
    Int,
    Unknown,
}

/// sic shorthand context (sic.md §"Bitfields", §"Enums"): whether a bare
/// member/constant name (`Two`, `BLUE`) may resolve at the point being lowered.
/// `Any` (the default, and what every unhandled expression kind resets to) keeps
/// the old permissive behavior; the determining sites narrow it to `Expect` (a
/// specific enum/bitfield is wanted — only its members resolve bare) or `Forbid`
/// (a determinable plain-integer context — the type is ambiguous, so require the
/// explicit `Type::Member` form).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum BfCtx {
    #[default]
    Any,
    Expect(String),
    Forbid,
}

/// sic type safety (sic.md §"Memory safety"): if `dest` and `src` mismatch across a
/// plain-aggregate pointer/value boundary — a `File` value fed a `File*`, or a
/// `File*` slot fed a `File` value — return a fix-it message. sic's own aggregates
/// (string/tuple/va_array/any/u8char/type) have their own conversions and are exempt.
fn ptr_value_mismatch(dest: &Type, src: &Type) -> Option<String> {
    fn plain_agg(t: &Type) -> bool {
        matches!(t, Type::Struct(_) | Type::Union(_))
            && !super::types::is_sic_string(t) && !super::types::is_tuple(t)
            && !super::types::is_va_array(t) && !super::types::is_any(t)
            && !super::types::is_u8char(t) && !super::types::is_type_info(t)
    }
    fn agg_name(t: &Type) -> String {
        match t {
            Type::Struct(st) => st.name.clone().unwrap_or_else(|| "struct".to_string()),
            Type::Union(u) => u.name.clone().unwrap_or_else(|| "union".to_string()),
            _ => "value".to_string(),
        }
    }
    // A plain aggregate *value* slot fed a pointer: `File f = new File()`.
    if plain_agg(dest) && matches!(src, Type::Pointer(_)) {
        return Some(format!(
            "type mismatch: a pointer where a `{}` value is expected — declare it as `{}*` \
             (`new` returns a pointer)", agg_name(dest), agg_name(dest)));
    }
    // A pointer-to-aggregate slot fed a value: `File *f = a_file_value`, or a `File`
    // value where a `File*` is expected.
    if let Type::Pointer(inner) = dest {
        if plain_agg(inner) && plain_agg(src) {
            return Some(format!(
                "type mismatch: a `{}` value where a `{}*` pointer is expected — take its \
                 address with `&`", agg_name(src), agg_name(inner)));
        }
    }
    None
}

/// An expression-`match` arm's value expression: an `expr;` body, or the trailing
/// expression of a `{ …; expr }` block. `None` for a diverging/valueless arm.
fn arm_value_expr(body: &Stmt) -> Option<&Expr> {
    match body {
        Stmt::Expr(e, _) => Some(e),
        Stmt::Block(ss, _) => ss.last().and_then(|s| match s {
            Stmt::Expr(e, _) => Some(e),
            _ => None,
        }),
        _ => None,
    }
}

/// A short human-readable name for a type, for type-mismatch diagnostics.
pub(crate) fn type_desc(t: &Type) -> String {
    match t {
        Type::Void => "void".into(),
        Type::Bool => "bool".into(),
        Type::Int { bits, signed } => format!("{}{}", if *signed { "i" } else { "u" }, bits),
        Type::Float32 => "float".into(),
        Type::Float64 => "double".into(),
        Type::Float80 => "long double".into(),
        Type::Pointer(_) => "a pointer".into(),
        Type::Array { .. } => "an array".into(),
        Type::Struct(s) => format!("struct {}", s.name.as_deref().unwrap_or("<anon>")),
        Type::Union(u) => format!("union {}", u.name.as_deref().unwrap_or("<anon>")),
        Type::Function(_) => "a function".into(),
    }
}

/// The source symbol for a binary operator, for enum-arithmetic diagnostics.
pub(crate) fn op_symbol(op: crate::ast::BinOpKind) -> &'static str {
    use crate::ast::BinOpKind::*;
    match op {
        Add => "+", Sub => "-", Mul => "*", Div => "/", Rem => "%",
        BitAnd => "&", BitOr => "|", BitXor => "^",
        Shl => "<<", Shr => ">>", RotL => "<<<", RotR => ">>>",
        _ => "op",
    }
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
    /// sic: locals/params declared with a payload-less named enum type
    /// (`enum vals v`) → the enum name, so `v.str` → `"vals::ONE"` can find the
    /// variant table (the enum itself lowers to a plain int, losing its identity).
    pub enum_locals: HashMap<String, String>,
    /// sic bitfields (sic.md §"Bitfields"): locals/params declared with a
    /// `bitfield` type → the bitfield name, so `& | ^ ~` restrictions,
    /// width-checked casts, and `.as_uN` accessors can recover its identity (it
    /// lowers to a plain unsigned int).
    pub bitfield_locals: HashMap<String, String>,
    /// sic weak references (sic.md §"Weak"): locals declared `weak<T>` → the strong
    /// container type `T`, so `.get` upgrades them and the right weak-release runs
    /// at scope exit. A weak local does not keep its container alive.
    pub weak_locals: HashMap<String, Type>,
    /// sic bitfield/enum shorthand context (sic.md §"Bitfields", §"Enums"): the
    /// strict enum-or-bitfield type currently *expected* by the surrounding
    /// expression. A bare member/constant name (`Two`, `BLUE`) resolves ONLY when
    /// it belongs to this type — otherwise its type is ambiguous and the qualified
    /// `Type::Member` form is required. Set at determining sites (init, assign,
    /// return, matching call arg, and comparison/`&|^`/`~` against a typed
    /// operand), propagated through those operators, and reset to `Any` everywhere
    /// else (taken at the top of `lower_expr`).
    pub bf_ctx: BfCtx,
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
    /// sic loop bounds-check elimination (sic.md §"Scopes"): `(array-name,
    /// index-key)` pairs proven in-bounds for the currently-open counting loops, so
    /// `emit_bounds_check` is suppressed for them. A single check on the loop's index
    /// extremes is hoisted before the loop instead. Entries are pushed on loop entry
    /// and truncated back on loop exit (nesting-aware via a saved length).
    pub bce_proven: Vec<(String, String)>,
    /// sic `atomic` locals (sic.md §"Atomics"): names whose declared type is
    /// atomic-qualified at top level, so loads/stores/RMW use the atomic IR ops.
    pub atomic_locals: std::collections::HashSet<String>,
    pub moved_names: std::collections::HashSet<String>,
    /// sic deferred tuple locals (`tuple t;` with no initializer, sic.md
    /// §"Tuples"): not yet allocated — the concrete type is fixed by the first
    /// assignment `t = tuple(...)`, which materializes the slot.
    pub deferred_tuples: std::collections::HashSet<String>,
    /// sic `bigint` temporaries created while lowering the current statement
    /// (sic.md §"Integer sizes"): freed at the end of that statement, so a value
    /// re-evaluated each loop iteration doesn't leak. Holds the temp pointers.
    pub bigint_temps: Vec<Val>,
    /// sic `async` (sic.md §"Async"): `Some(elem)` when the current function is
    /// async — its `return v` wraps `v` into a `Task<elem>`.
    pub async_elem: Option<Type>,
    /// sic `va_dict` (sic.md §"Named parameters"): dict handles packed for a call's
    /// named arguments, freed at the end of the statement (the callee consumes the
    /// va_dict during the call and never keeps it).
    pub va_dict_temps: Vec<Val>,
    /// sic `.keys`/`.values` (sic.md §"Iterators"): freshly-materialized `list`
    /// handles, freed (`__sic_list_free`) at the end of the statement unless the
    /// value flows into a binding that takes ownership (`take_list_temp`).
    pub list_temps: Vec<Val>,
    /// sic freshly-produced `list`/`dict`/`set` handles (sic.md §"List"/§"Dict"):
    /// a `new` container or a call to a container-returning function owns one
    /// reference (the call convention return-retains). Recorded here and released
    /// (`container_release`, type-aware) at the end of the statement — unless a
    /// binding transfers ownership out via `take_container_temp`. This balances the
    /// producer's `+1` for a value that is otherwise dropped (`mk();`), borrowed
    /// (`f(mk())`), or shared into a container (`l.add(mk())` retains its own ref),
    /// closing the leaks those cases would otherwise cause. Paired with the type so
    /// a list and a dict each free with the right runtime.
    pub container_temps: Vec<(Val, Type)>,
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
    /// sic strict enum typing (sic.md §"Enums"): the current function's payload-less
    /// enum return type, so `return <wrong>;` is rejected. `None` if it returns a
    /// non-enum type.
    pub ret_enum: Option<String>,
    /// sic bitfield return type (sic.md §"Bitfields"): the bitfield a function
    /// returns, so a bare flag in `return Two;` resolves against it.
    pub ret_bitfield: Option<String>,
    /// Monotonic counter for synthesized names (e.g. range-`for` temporaries).
    pub gensym: u32,
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
            enum_locals: HashMap::new(),
            bitfield_locals: HashMap::new(),
            weak_locals: HashMap::new(),
            bf_ctx: BfCtx::Any,
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
            bce_proven: Vec::new(),
            atomic_locals: std::collections::HashSet::new(),
            moved_names: std::collections::HashSet::new(),
            deferred_tuples: std::collections::HashSet::new(),
            bigint_temps: Vec::new(),
            list_temps: Vec::new(),
            container_temps: Vec::new(),
            async_elem: None,
            va_dict_temps: Vec::new(),
            unsafe_depth: 0,
            guard_stack: Vec::new(),
            expected_ty: None,
            ret_enum: None,
            ret_bitfield: None,
            gensym: 0,
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
            Cleanup::TupleRelease { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::char_ptr() });
                let _ = self.emit_tuple_release(Val::Local(p));
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
            Cleanup::DictFree { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::void_ptr() });
                let _ = self.emit_bigint_call("__sic_dict_free", vec![Val::Local(p)], Type::Void);
            }
            Cleanup::ListFree { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::void_ptr() });
                let _ = self.emit_bigint_call("__sic_list_free", vec![Val::Local(p)], Type::Void);
            }
            Cleanup::AnyRelease { addr } => { let _ = self.any_refcount_at(addr, false); }
            Cleanup::ClosureRelease { slot } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::void_ptr() });
                let _ = self.emit_closure_release(Val::Local(p));
            }
            Cleanup::WeakRelease { slot, is_dict } => {
                let p = self.alloc_val();
                self.push_instr(Instr::Load { dest: p, ptr: slot, ty: Type::void_ptr() });
                let name = if is_dict { "__sic_dict_weak_release" } else { "__sic_list_weak_release" };
                let f = if is_dict { self.dict_runtime_fn(name) } else { self.list_runtime_fn(name) };
                self.push_instr(Instr::Call { dest: None, func: f, args: vec![Val::Local(p)], ret_ty: Type::Void });
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
    pub(crate) fn emit_string_release_at(&mut self, addr: Val) {
        let _ = self.release_string_at(&addr);
    }

    /// Emit `fn(&var)` for a cleanup function. The function takes a pointer to
    /// the variable; declare it as an extern `void(void*)` if not yet known.
    pub(crate) fn emit_cleanup_call(&mut self, var_addr: Val, fn_name: &str) {
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

    /// Update an existing local's recorded type in place, keeping its slot — used to
    /// refine an empty `tuple t;` to the element types of an assigned tuple value
    /// (sic.md §"Tuples") so a subsequent `t[i]` is typed. Searches innermost-out.
    pub(crate) fn refine_local_type(&mut self, name: &str, ty: Type) {
        for scope in self.locals.iter_mut().rev() {
            if let Some(entry) = scope.get_mut(name) {
                entry.0 = ty;
                return;
            }
        }
    }

    /// If AST type `ty` names a payload-less enum registered for `.str`, the enum
    /// name (`enum vals v` → `"vals"`).
    pub(crate) fn c_enum_name_of(&self, ty: &crate::ast::AstType) -> Option<String> {
        use crate::ast::AstType;
        match ty {
            AstType::Enum(e) => e.name.as_ref()
                .filter(|n| self.lowerer.c_enum_defs.contains_key(*n)).cloned(),
            AstType::Named(n) | AstType::Builtin(n) => {
                if let Some(canon) = self.lowerer.c_enum_alias.get(n) { return Some(canon.clone()); }
                if self.lowerer.c_enum_defs.contains_key(n) { return Some(n.clone()); }
                None
            }
            _ => None,
        }
    }

    /// sic strict enum typing (sic.md §"Enums"): classify an expression as a
    /// specific payload-less enum, a plain integer, or unknown. A C enum collapses
    /// to `int` in the IR, so this recovers the *nominal* identity from the AST and
    /// the enum side-tables — enough to reject an `int`/other-enum flowing into an
    /// `enum E` slot, or an enum operand used in arithmetic, without a cast.
    fn classify_enum(&self, e: &Expr) -> EnumClass {
        use crate::ast::ExprKind;
        match &e.kind {
            // Bare numeric constants are plainly `int`.
            ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::CharLit(..)
            | ExprKind::BoolLit(..) => EnumClass::Int,
            ExprKind::Ident(id) => {
                if let Some(en) = self.enum_locals.get(id) { return EnumClass::Enum(en.clone()); }
                if let Some(en) = self.lowerer.c_enum_variant.get(id) { return EnumClass::Enum(en.clone()); }
                match self.lookup(id) {
                    Some(LookupResult::Local(ty, _))
                        if matches!(ty, Type::Int { .. } | Type::Bool) => EnumClass::Int,
                    _ => EnumClass::Unknown,
                }
            }
            // `E::A` (namespaced enum constant).
            ExprKind::EnumVariant { enum_name, .. }
                if self.lowerer.c_enum_defs.contains_key(enum_name) =>
                EnumClass::Enum(enum_name.clone()),
            // A cast is the explicit escape hatch: `(enum E)x` is enum E; `(int)e`
            // (or any other non-enum cast) is a plain integer.
            ExprKind::Cast { ty, .. } => match self.c_enum_name_of(&ty.ty) {
                Some(en) => EnumClass::Enum(en),
                None => EnumClass::Int,
            },
            // Any binary op yields an int/bool, never an enum.
            ExprKind::BinOp { .. } => EnumClass::Int,
            ExprKind::Unary { op, .. }
                if matches!(op, crate::ast::UnOpKind::Neg | crate::ast::UnOpKind::Not
                    | crate::ast::UnOpKind::BitNot) => EnumClass::Int,
            // A ternary is an enum only when both arms agree on the same enum.
            ExprKind::Ternary { then, else_, .. } => {
                match (self.classify_enum(then), self.classify_enum(else_)) {
                    (EnumClass::Enum(a), EnumClass::Enum(b)) if a == b => EnumClass::Enum(a),
                    (EnumClass::Int, EnumClass::Int) => EnumClass::Int,
                    _ => EnumClass::Unknown,
                }
            }
            // A call classifies by its (tracked) enum return type, else stays
            // unknown — we do not reject results we cannot positively type.
            ExprKind::Call { func, .. } => match &func.kind {
                ExprKind::Ident(fname) => match self.lowerer.c_enum_ret.get(fname) {
                    Some(en) => EnumClass::Enum(en.clone()),
                    None => EnumClass::Unknown,
                },
                _ => EnumClass::Unknown,
            },
            _ => EnumClass::Unknown,
        }
    }

    /// sic type safety (sic.md §"Memory safety"): reject a pointer/value mismatch
    /// between a plain aggregate and a pointer to it — `File f = new File()` (a
    /// `File*` into a `File` value) or `read(f)` passing a `File` value where a
    /// `File*` is wanted. Both silently corrupt at runtime. sic's own aggregates
    /// (string/tuple/va_array/any/u8char/type) have their own conversions and are
    /// exempt. An unresolved source type is left alone (no false positives).
    pub(crate) fn check_ptr_value_mismatch(&mut self, dest: &Type, e: &Expr) -> Result<()> {
        if !self.is_sic() { return Ok(()); }
        let src = match self.infer_expr_type(e) { Ok(t) => t, Err(_) => return Ok(()) };
        if let Some(msg) = ptr_value_mismatch(dest, &src) {
            let sp = &e.span;
            return Err(CompileError::at(msg, sp.file.clone(), sp.line, sp.col));
        }
        Ok(())
    }

    /// sic type safety: reject `return v;` when `v`'s type has no implicit conversion
    /// to the declared return type — an aggregate returned as an unrelated type, or a
    /// pointer/integer mismatch. Numeric↔numeric and pointer↔pointer stay implicit,
    /// and sic's own aggregates (string/bigint/fixed/tuple/…) keep their conversions.
    pub(crate) fn check_return_convertible(&mut self, ret_ty: &Type, e: &Expr) -> Result<()> {
        if !self.is_sic() { return Ok(()); }
        let from = match self.infer_expr_type(e) { Ok(t) => t, Err(_) => return Ok(()) };
        let to = ret_ty;
        if from == *to || matches!(from, Type::Void) || matches!(to, Type::Void) { return Ok(()); }
        fn special(t: &Type) -> bool {
            super::types::is_sic_string(t) || super::types::is_tuple(t) || super::types::is_va_array(t)
                || super::types::is_any(t) || super::types::is_type_info(t) || super::types::is_u8char(t)
                || super::types::is_u8char_arr(t) || super::types::is_bigint(t) || super::types::is_fixed(t)
        }
        // sic-native aggregates convert on their own terms — leave them alone.
        if special(&from) || special(to) { return Ok(()); }
        // Tagged enums are built from variant constructors (`return None;`,
        // `return Ok(5);`), which don't infer as the enum type — exempt them.
        if self.is_tagged_enum_struct(&from) || self.is_tagged_enum_struct(to) { return Ok(()); }
        let plain_agg = |t: &Type| matches!(t, Type::Struct(_) | Type::Union(_));
        let numeric = |t: &Type| matches!(t, Type::Int { .. } | Type::Bool
            | Type::Float32 | Type::Float64 | Type::Float80);
        let is_ptr = |t: &Type| matches!(t, Type::Pointer(_) | Type::Array { .. });
        let sp = &e.span;
        let mismatch = || CompileError::at(
            format!("cannot return `{}` as `{}` — no implicit conversion",
                type_desc(&from), type_desc(to)),
            sp.file.clone(), sp.line, sp.col);
        // A plain aggregate can only become the same aggregate (== handled above).
        // Pointer↔aggregate is `check_ptr_value_mismatch`'s job — skip it here.
        if (plain_agg(&from) || plain_agg(to)) && !is_ptr(&from) && !is_ptr(to) {
            return Err(mismatch());
        }
        // pointer ↔ integer is not implicit (except a literal `0`/`NULL` → pointer).
        if numeric(&from) && !matches!(from, Type::Bool) && matches!(to, Type::Pointer(_)) {
            let zero = matches!(&e.kind, ExprKind::IntLit(0, _)) || matches!(&e.kind, ExprKind::Nullptr);
            if !zero { return Err(mismatch()); }
        }
        if matches!(from, Type::Pointer(_)) && numeric(to) && !matches!(to, Type::Bool) {
            return Err(mismatch());
        }
        Ok(())
    }

    /// sic strict enum typing (sic.md §"Enums"): reject a value flowing into an
    /// `enum <dest>` slot whose nominal type is a plain `int` or a *different* enum.
    /// An unknown source is allowed (no false positives). `site` names the context
    /// (e.g. "assigned to", "passed to") for the diagnostic.
    pub(crate) fn check_enum_dest(&self, dest: &str, src: &Expr, site: &str) -> Result<()> {
        if !self.is_sic() { return Ok(()); }
        let sp = &src.span;
        match self.classify_enum(src) {
            EnumClass::Enum(e) if e == dest => Ok(()),
            EnumClass::Enum(other) => Err(CompileError::at(
                format!("enum type mismatch: `enum {}` {} `enum {}` — use an explicit `(enum {})` cast",
                    other, site, dest, dest), sp.file.clone(), sp.line, sp.col)),
            EnumClass::Int => Err(CompileError::at(
                format!("`int` {} `enum {}` without a cast — use `(enum {})expr`", site, dest, dest),
                sp.file.clone(), sp.line, sp.col)),
            EnumClass::Unknown => Ok(()),
        }
    }

    /// sic strict enum typing (sic.md §"Enums"): a payload-less enum has no
    /// arithmetic — `e + 1` must be written `(int)e + 1`. Rejects an enum operand of
    /// `+ - * / % & | ^ << >> <<< >>>`; comparisons and logical ops are allowed
    /// (an enum's numeric value is fine to compare).
    pub(crate) fn check_enum_arith(&self, op: crate::ast::BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<()> {
        use crate::ast::BinOpKind::*;
        if !self.is_sic() { return Ok(()); }
        if !matches!(op, Add | Sub | Mul | Div | Rem | BitAnd | BitOr | BitXor | Shl | Shr | RotL | RotR) {
            return Ok(());
        }
        for e in [lhs, rhs] {
            if let EnumClass::Enum(en) = self.classify_enum(e) {
                return Err(CompileError::at(
                    format!("enum `{}` has no arithmetic — cast to int first, e.g. `(int)expr {} …`",
                        en, op_symbol(op)),
                    e.span.file.clone(), e.span.line, e.span.col));
            }
        }
        Ok(())
    }

    /// If AST type `ty` names a `bitfield`, its name.
    pub(crate) fn bitfield_name_of(&self, ty: &crate::ast::AstType) -> Option<String> {
        use crate::ast::AstType;
        match ty {
            AstType::Bitfield(b) => Some(b.name.clone()),
            AstType::Named(n) | AstType::Builtin(n)
                if self.lowerer.bitfield_defs.contains_key(n) => Some(n.clone()),
            _ => None,
        }
    }

    /// sic shorthand gating (sic.md §"Bitfields", §"Enums"): if `name` is a bare
    /// member/constant of a *named* strict enum or a bitfield, the owning type's
    /// name. Anonymous-enum constants (`enum { MAX }`) and loose constants return
    /// `None` — they stay freely usable, only named-type members are gated.
    pub(crate) fn strict_const_owner(&self, name: &str) -> Option<String> {
        if let Some(bf) = self.lowerer.bitfield_variant.get(name) { return Some(bf.clone()); }
        if let Some(en) = self.lowerer.c_enum_variant.get(name) { return Some(en.clone()); }
        None
    }

    /// sic shorthand gating: the strict enum/bitfield type an expression *definitely*
    /// has — enough to determine the type of a bare member on the other side of an
    /// operator. A bare member name itself is deliberately NOT definite (it is the
    /// very thing whose type must be resolved), so it returns `None`.
    pub(crate) fn definite_nominal(&self, e: &Expr) -> Option<String> {
        use crate::ast::{ExprKind, BinOpKind, UnOpKind};
        match &e.kind {
            ExprKind::Ident(id) => {
                if let Some(bf) = self.bitfield_locals.get(id) { return Some(bf.clone()); }
                if let Some(en) = self.enum_locals.get(id) { return Some(en.clone()); }
                None
            }
            // `Type::Member` is an explicit, unambiguous type anchor.
            ExprKind::EnumVariant { enum_name, .. }
                if self.lowerer.bitfield_defs.contains_key(enum_name)
                    || self.lowerer.c_enum_defs.contains_key(enum_name) => Some(enum_name.clone()),
            // A cast to an enum/bitfield type anchors that type.
            ExprKind::Cast { ty, .. } =>
                self.bitfield_name_of(&ty.ty).or_else(|| self.c_enum_name_of(&ty.ty)),
            // Flag combinators preserve the bitfield type.
            ExprKind::BinOp { op: BinOpKind::BitAnd | BinOpKind::BitOr | BinOpKind::BitXor, lhs, rhs } =>
                self.definite_nominal(lhs).or_else(|| self.definite_nominal(rhs)),
            ExprKind::Unary { op: UnOpKind::BitNot, expr } => self.definite_nominal(expr),
            _ => None,
        }
    }

    /// The shorthand context a value flowing into a slot establishes: an
    /// enum/bitfield `owner` expects that type; otherwise a plain-integer IR type
    /// forbids bare members (their type would be ambiguous) and anything else is
    /// neutral.
    pub(crate) fn dest_ctx(&self, owner: Option<String>, ir: &Type) -> BfCtx {
        match owner {
            Some(b) => BfCtx::Expect(b),
            None if matches!(ir, Type::Int { .. } | Type::Bool
                | Type::Float32 | Type::Float64 | Type::Float80) => BfCtx::Forbid,
            None => BfCtx::Any,
        }
    }

    /// True if `e` is a determinable *plain* scalar (literal, plain-typed local/
    /// global, arithmetic, or a scalar cast) — NOT a strict enum/bitfield. A bare
    /// member compared against such a value is ambiguous and rejected.
    pub(crate) fn is_definite_plain_scalar(&self, e: &Expr) -> bool {
        use crate::ast::{ExprKind, AstType, BinOpKind::*};
        match &e.kind {
            ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::CharLit(..)
            | ExprKind::BoolLit(..) | ExprKind::FloatLit(..) | ExprKind::DecimalLit(..) => true,
            ExprKind::Ident(id) => {
                if self.strict_const_owner(id).is_some() { return false; }
                if self.enum_locals.contains_key(id) || self.bitfield_locals.contains_key(id) { return false; }
                matches!(self.lookup(id),
                    Some(LookupResult::Local(t, _)) | Some(LookupResult::Global(t, _))
                        if matches!(t, Type::Int { .. } | Type::Bool
                            | Type::Float32 | Type::Float64 | Type::Float80))
            }
            ExprKind::BinOp { op, .. } =>
                matches!(op, Add | Sub | Mul | Div | Rem | Shl | Shr | RotL | RotR),
            ExprKind::Cast { ty, .. } =>
                self.bitfield_name_of(&ty.ty).is_none() && self.c_enum_name_of(&ty.ty).is_none()
                && matches!(&ty.ty, AstType::Int { .. } | AstType::Char { .. } | AstType::Short { .. }
                    | AstType::Long { .. } | AstType::LongLong { .. } | AstType::Bool
                    | AstType::Float | AstType::Double | AstType::Named(_) | AstType::Builtin(_)),
            _ => false,
        }
    }

    /// The shorthand context to lower a binary operator's operands under: a
    /// definite enum/bitfield operand pins a bare member on the other side; a flag
    /// combinator lets the surrounding expectation flow; a comparison against a
    /// plain scalar forbids a bare member; otherwise neutral.
    pub(crate) fn binop_operand_ctx(&self, op: crate::ast::BinOpKind,
        lhs: &Expr, rhs: &Expr, incoming: BfCtx) -> BfCtx {
        use crate::ast::BinOpKind::*;
        if let Some(b) = self.definite_nominal(lhs).or_else(|| self.definite_nominal(rhs)) {
            return BfCtx::Expect(b);
        }
        match op {
            BitAnd | BitOr | BitXor => incoming,
            Eq | Ne | Lt | Le | Gt | Ge =>
                if self.is_definite_plain_scalar(lhs) || self.is_definite_plain_scalar(rhs) {
                    BfCtx::Forbid
                } else { BfCtx::Any },
            _ => BfCtx::Any,
        }
    }

    /// sic bitfield typing (sic.md §"Bitfields"): classify an expression as a
    /// specific bitfield, a plain integer, or unknown — recovering the nominal
    /// identity (the storage is a plain unsigned int) from the AST and side tables.
    pub(crate) fn bitfield_class(&self, e: &Expr) -> BitfieldClass {
        use crate::ast::{ExprKind, BinOpKind, UnOpKind};
        match &e.kind {
            ExprKind::IntLit(..) | ExprKind::UIntLit(..) | ExprKind::CharLit(..)
            | ExprKind::BoolLit(..) => BitfieldClass::Int,
            ExprKind::Ident(id) => {
                if let Some(bf) = self.bitfield_locals.get(id) { return BitfieldClass::Bitfield(bf.clone()); }
                if let Some(bf) = self.lowerer.bitfield_variant.get(id) { return BitfieldClass::Bitfield(bf.clone()); }
                match self.lookup(id) {
                    Some(LookupResult::Local(ty, _))
                        if matches!(ty, Type::Int { .. } | Type::Bool) => BitfieldClass::Int,
                    _ => BitfieldClass::Unknown,
                }
            }
            // `Bits::Member`.
            ExprKind::EnumVariant { enum_name, .. }
                if self.lowerer.bitfield_defs.contains_key(enum_name) =>
                BitfieldClass::Bitfield(enum_name.clone()),
            // A cast to a bitfield type re-enters the flag domain; any other cast
            // (e.g. `(u32)a`) leaves it as a plain integer.
            ExprKind::Cast { ty, .. } => match self.bitfield_name_of(&ty.ty) {
                Some(bf) => BitfieldClass::Bitfield(bf),
                None => BitfieldClass::Int,
            },
            // `& | ^` of bitfield operands stays that bitfield.
            ExprKind::BinOp { op: BinOpKind::BitAnd | BinOpKind::BitOr | BinOpKind::BitXor, lhs, rhs } => {
                match (self.bitfield_class(lhs), self.bitfield_class(rhs)) {
                    (BitfieldClass::Bitfield(a), _) => BitfieldClass::Bitfield(a),
                    (_, BitfieldClass::Bitfield(b)) => BitfieldClass::Bitfield(b),
                    _ => BitfieldClass::Int,
                }
            }
            ExprKind::BinOp { .. } => BitfieldClass::Int,
            // `~x` of a bitfield stays that bitfield (masked to the defined bits).
            ExprKind::Unary { op: UnOpKind::BitNot, expr } => self.bitfield_class(expr),
            ExprKind::Unary { .. } => BitfieldClass::Int,
            ExprKind::Ternary { then, else_, .. } => {
                match (self.bitfield_class(then), self.bitfield_class(else_)) {
                    (BitfieldClass::Bitfield(a), BitfieldClass::Bitfield(b)) if a == b => BitfieldClass::Bitfield(a),
                    _ => BitfieldClass::Unknown,
                }
            }
            _ => BitfieldClass::Unknown,
        }
    }

    /// Number of value bits a bitfield needs = (highest defined bit position) + 1
    /// (`_` holes past the last flag don't count). A `(uN)`/`.as_uN` cast is legal
    /// only when `N ≥` this.
    pub(crate) fn bitfield_required_bits(&self, bf: &str) -> u32 {
        let members = match self.lowerer.bitfield_defs.get(bf) { Some(m) => m, None => return 0 };
        members.iter().enumerate()
            .filter(|(_, m)| *m != "_")
            .map(|(i, _)| i as u32 + 1)
            .max().unwrap_or(0)
    }

    /// Mask of the bitfield's *defined* bits (holes excluded) — used to keep `~x`
    /// within the valid flag set.
    pub(crate) fn bitfield_defined_mask(&self, bf: &str) -> u64 {
        let members = match self.lowerer.bitfield_defs.get(bf) { Some(m) => m, None => return 0 };
        let mut mask = 0u64;
        for (i, m) in members.iter().enumerate() {
            if m != "_" { mask |= 1u64 << i; }
        }
        mask
    }

    /// sic bitfield typing (sic.md §"Bitfields"): reject an operator other than
    /// `& | ^` (and `== !=`) on a bitfield operand — no arithmetic, shifts, or
    /// ordering. `~` is handled separately (unary).
    pub(crate) fn check_bitfield_arith(&self, op: crate::ast::BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<()> {
        use crate::ast::BinOpKind::*;
        if !self.is_sic() { return Ok(()); }
        // `& | ^` are the only binary flag ops; equality is allowed to compare sets.
        if matches!(op, BitAnd | BitOr | BitXor | Eq | Ne) { return Ok(()); }
        for e in [lhs, rhs] {
            if let BitfieldClass::Bitfield(bf) = self.bitfield_class(e) {
                return Err(CompileError::at(
                    format!("bitfield `{}` supports only `& | ^ ~` (and `== !=`), not `{}` — cast to an integer first",
                        bf, op_symbol(op)),
                    e.span.file.clone(), e.span.line, e.span.col));
            }
        }
        Ok(())
    }

    /// sic bitfield typing (sic.md §"Bitfields"): reject a value flowing into a
    /// `bitfield <dest>` slot that is a plain `int` or a *different* bitfield. A
    /// literal `0` (the empty set) and an unknown source are allowed.
    pub(crate) fn check_bitfield_dest(&self, dest: &str, src: &Expr, site: &str) -> Result<()> {
        use crate::ast::ExprKind;
        if !self.is_sic() { return Ok(()); }
        // `Data a = 0;` — the empty flag set.
        if matches!(&src.kind, ExprKind::IntLit(0, _)) { return Ok(()); }
        // A disallowed operator directly on flag operands (`a + Two`) gets the
        // clearer "no arithmetic" diagnostic rather than the generic int mismatch.
        if let ExprKind::BinOp { op, lhs, rhs } = &src.kind {
            self.check_bitfield_arith(*op, lhs, rhs)?;
        }
        let sp = &src.span;
        match self.bitfield_class(src) {
            BitfieldClass::Bitfield(b) if b == dest => Ok(()),
            BitfieldClass::Bitfield(other) => Err(CompileError::at(
                format!("bitfield type mismatch: `{}` {} `{}` — use an explicit cast", other, site, dest),
                sp.file.clone(), sp.line, sp.col)),
            BitfieldClass::Int => Err(CompileError::at(
                format!("`int` {} bitfield `{}` without a cast — combine its flags (e.g. `{}::A | {}::B`)",
                    site, dest, dest, dest),
                sp.file.clone(), sp.line, sp.col)),
            BitfieldClass::Unknown => Ok(()),
        }
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

    /// Propagate fat-pointer-ness to the pointer parameters of `static` functions,
    /// so a `new[]`/`@` array passed to a helper stays bounds-checked in the callee
    /// (sic.md §"Scopes"). Only `static` functions qualify (all their call sites are
    /// visible in this unit — an externally-visible function could be called from
    /// elsewhere with a raw pointer). Greatest fixpoint: assume every pointer param
    /// is fat, then REMOVE the assumption for `(fn, i)` whenever some call passes an
    /// argument that is not a fat-pointer *base* — so a self-recursive call that
    /// passes the param through keeps it fat, while a call passing `&x`, a raw
    /// pointer, or `p + k` clears it. Sound: a param is left fat only if every call
    /// definitely passes a fat base.
    pub(crate) fn infer_fat_params(&mut self, tu: &crate::ast::TranslationUnit) {
        use crate::ast::{Decl, StorageClass, AstType};
        let mut fat: HashMap<String, std::collections::HashSet<usize>> = HashMap::new();
        let mut pnames: HashMap<String, Vec<Option<String>>> = HashMap::new();
        for d in &tu.decls {
            if let Decl::Func { name, params, body: Some(_), storage, variadic, .. } = d {
                let is_static = matches!(storage, Some(StorageClass::Static))
                    || self.static_funcs.contains(name);
                if !is_static || *variadic { continue; }
                let idxs: std::collections::HashSet<usize> = params.iter().enumerate()
                    .filter(|(_, p)| matches!(&p.ty.ty, AstType::Pointer { .. }))
                    .map(|(i, _)| i).collect();
                if !idxs.is_empty() {
                    fat.insert(name.clone(), idxs);
                    pnames.insert(name.clone(), params.iter().map(|p| p.name.clone()).collect());
                }
            }
        }
        if fat.is_empty() { return; }
        let cand: std::collections::HashSet<String> = fat.keys().cloned().collect();

        // Per-function scans (bodies are fixed; only `fat` changes in the fixpoint).
        struct Info { moved: std::collections::HashSet<String>, newloc: std::collections::HashSet<String>,
                      calls: Vec<(String, Vec<Expr>)> }
        let mut infos: Vec<(String, Info)> = Vec::new();
        for d in &tu.decls {
            if let Decl::Func { name, body: Some(body), .. } = d {
                let mut info = Info { moved: Default::default(), newloc: Default::default(), calls: Vec::new() };
                let mut escaped: std::collections::HashSet<String> = Default::default();
                for s in body {
                    scan_mutated_stmt(s, &mut info.moved);
                    fat_prepass_stmt(s, &cand, &mut info.newloc, &mut info.calls, &mut escaped);
                }
                // A candidate whose name is used other than as a direct call target
                // (address taken / stored / indirect) may have unseen callers → drop.
                for e in &escaped { fat.remove(e); }
                infos.push((name.clone(), info));
            }
        }

        // Greatest fixpoint: shrink `fat` until stable.
        loop {
            let mut remove: Vec<(String, usize)> = Vec::new();
            for (caller, info) in &infos {
                // The caller's fat-base names: its own fat params + `new`-init locals,
                // minus anything mutated (a reassigned pointer no longer points at the base).
                let mut fat_names: std::collections::HashSet<String> = std::collections::HashSet::new();
                if let (Some(idxs), Some(ps)) = (fat.get(caller), pnames.get(caller)) {
                    for &i in idxs {
                        if let Some(Some(pn)) = ps.get(i) {
                            if !info.moved.contains(pn) { fat_names.insert(pn.clone()); }
                        }
                    }
                }
                for n in &info.newloc { if !info.moved.contains(n) { fat_names.insert(n.clone()); } }
                for (callee, args) in &info.calls {
                    if let Some(idxs) = fat.get(callee) {
                        for &i in idxs {
                            let ok = args.get(i).map_or(false, |a| is_fat_base_arg(a, &fat_names));
                            if !ok { remove.push((callee.clone(), i)); }
                        }
                    }
                }
            }
            if remove.is_empty() { break; }
            for (f, i) in remove {
                if let Some(set) = fat.get_mut(&f) { set.remove(&i); }
            }
        }
        for (k, v) in fat { if !v.is_empty() { self.fat_params.insert(k, v); } }
    }

    /// Infer the concrete tuple type of a `tuple`-returning function from its first
    /// `return <expr>` — a tuple literal (`return tuple(a, b)`) or a tuple-typed
    /// local (`tuple c = tuple(a, b); return c;`). Uses a throwaway FuncCtx with the
    /// parameters AND the preceding local declarations bound, so an element that
    /// references a local (e.g. a `list<int>`) infers its real type rather than the
    /// `i32` fallback — otherwise the return layout is mis-sized and `f()[i]` reads
    /// at the wrong offset. Returns `None` if no return yields a tuple.
    fn infer_tuple_return_type(&mut self, body: &[Stmt], params: &[AstParam], ir_params: &[Type]) -> Option<Type> {
        let ret_expr = first_return_expr(body)?;
        let mut dummy = Function::new("__tuple_infer".to_string(),
            FunctionType { ret: Type::Void, params: vec![], variadic: false }, vec![], Linkage::Internal);
        let blk = dummy.alloc_block();
        dummy.blocks.push(BasicBlock::new(blk));
        let ty = {
            let mut fc = FuncCtx::new_with_func(self, &mut dummy);
            for (p, ty) in params.iter().zip(ir_params) {
                if let Some(n) = &p.name { fc.define_local(n.clone(), ty.clone(), ValId(0)); }
            }
            // Bind local declaration types (a tuple/auto local from its initializer,
            // so `tuple c = tuple(ll, a)` carries the concrete layout). `ValId(0)` is
            // a placeholder slot — never read; only the type binding matters.
            for stmt in body {
                if let Stmt::Decl(Decl::Var { declarators, .. }) = stmt {
                    for d in declarators {
                        let ty = match (&d.ty.ty, &d.init) {
                            (AstType::Auto | AstType::Tuple, Some(Initializer::Expr(e))) => fc.infer_expr_type(e).ok(),
                            _ => fc.lower_type(&d.ty).ok(),
                        };
                        if let Some(ty) = ty { fc.define_local(d.name.clone(), ty, ValId(0)); }
                    }
                }
            }
            fc.infer_expr_type(&ret_expr).ok()
        };
        match ty { Some(t) if super::types::is_tuple(&t) => Some(t), _ => None }
    }

    /// Infer a body's scalar return type (for a lambda with no explicit `-> T`):
    /// the type of the first `return <expr>;`, evaluated with the params in scope.
    /// A body with no value-return is a `void` lambda.
    pub(crate) fn infer_body_return_type(&mut self, body: &[Stmt], params: &[AstParam], ir_params: &[Type]) -> Type {
        self.infer_body_return_type_ext(body, params, ir_params, &[])
    }

    /// The value type of a lambda at file scope (sic.md §"Lambdas"): builds a
    /// throwaway function context so the (`&mut Lowerer`-only) global-init path can
    /// reuse the same lambda typing as inside a function.
    pub(crate) fn lambda_type_global(&mut self, captures: &[crate::ast::LambdaCapture],
        params: &[AstParam], ret: &Option<QualType>, body: &[Stmt], span: &crate::lexer::Span) -> Result<Type> {
        let mut dummy = Function::new("__lambda_ty".to_string(),
            FunctionType { ret: Type::Void, params: vec![], variadic: false }, vec![], Linkage::Internal);
        let blk = dummy.alloc_block();
        dummy.blocks.push(BasicBlock::new(blk));
        let mut fc = FuncCtx::new_with_func(self, &mut dummy);
        fc.lambda_value_type(captures, params, ret, body, span)
    }

    /// As `infer_body_return_type`, but with `extra` names also in scope (a nested
    /// lambda's captures, so `return a + b;` infers when `a` is captured). A lambda
    /// return expression is typed via `lambda_value_type` so a function that returns
    /// a closure (currying) infers the closure type rather than failing.
    pub(crate) fn infer_body_return_type_ext(&mut self, body: &[Stmt], params: &[AstParam],
        ir_params: &[Type], extra: &[(String, Type)]) -> Type {
        let ret_expr = match first_return_expr(body) { Some(e) => e, None => return Type::Void };
        let mut dummy = Function::new("__lambda_infer".to_string(),
            FunctionType { ret: Type::Void, params: vec![], variadic: false }, vec![], Linkage::Internal);
        let blk = dummy.alloc_block();
        dummy.blocks.push(BasicBlock::new(blk));
        let mut fc = FuncCtx::new_with_func(self, &mut dummy);
        for (p, ty) in params.iter().zip(ir_params) {
            if let Some(n) = &p.name { fc.define_local(n.clone(), ty.clone(), ValId(0)); }
        }
        for (n, ty) in extra { fc.define_local(n.clone(), ty.clone(), ValId(0)); }
        if let crate::ast::ExprKind::Lambda { captures, params, ret, body } = &ret_expr.kind {
            fc.lambda_value_type(captures, params, ret, body, &ret_expr.span).unwrap_or(Type::Void)
        } else {
            fc.infer_expr_type(&ret_expr).unwrap_or(Type::Void)
        }
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
        is_async: bool,
    ) -> Result<()> {
        // sic tail-call optimization (sic.md §"Scopes"): rewrite a self-recursive
        // function's tail calls into a jump back to the entry with the parameters
        // reassigned, so deep tail recursion runs as a loop (O(1) stack, no overflow)
        // instead of ~N stack frames. Conservative and sic-only (leaves C-mode
        // codegen — and the SQLite/QEMU bringups — untouched).
        let tco_body;
        let body: &[Stmt] = if self.sic {
            match tco_rewrite(name, params, variadic, body, &crate::lexer::Span::default()) {
                Some(nb) => { tco_body = nb; &tco_body }
                None => body,
            }
        } else { body };

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
            match self.infer_tuple_return_type(body, params, &ir_params) {
                Some(t) => t,
                None => lower_type(ret_ty, &self.struct_types, self.ptr_size)?,
            }
        } else if self.sic && matches!(ret_ty.ty, AstType::Auto) {
            // sic lambda (sic.md §"Lambdas"): infer the return type from the body.
            self.infer_body_return_type(body, params, &ir_params)
        } else {
            lower_type(ret_ty, &self.struct_types, self.ptr_size)?
        };
        // sic `async` (sic.md §"Async"): the function returns a `Task<ret>`; its
        // `return v` wraps `v` into a task (handled during return lowering).
        let (ir_ret, async_elem) = if is_async {
            let elem = ir_ret;
            (super::types::task_type(&elem), Some(elem))
        } else {
            (ir_ret, None)
        };

        let sig = super::build_fn_sig(ir_ret.clone(), ir_params.clone(), variadic, self.ptr_size);
        let is_sret = super::ret_is_sret(&ir_ret, self.ptr_size);

        let mut linkage = super::fn_linkage(storage, inline, self.static_funcs.contains(name));
        // Compiler runtime helpers (`__sic_*`: the bigint / dict / … prepended
        // runtimes, all `__attribute__((weak))`) are emitted weak so the copies that
        // land in several objects — including an imported module's — dedupe at link
        // instead of colliding. (Function `weak` isn't otherwise threaded here.)
        if linkage == Linkage::External && name.starts_with("__sic_") {
            linkage = Linkage::Weak;
        }

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
        fc.async_elem = async_elem;
        // sic strict enum typing (sic.md §"Enums"): a payload-less enum return type
        // makes `return <int/other-enum>;` an error without an explicit cast.
        fc.ret_enum = fc.lowerer.c_enum_name_of_ast(&ret_ty.ty);
        // sic bitfield return type (sic.md §"Bitfields"): lets `return Two;` resolve.
        fc.ret_bitfield = fc.bitfield_name_of(&ret_ty.ty);

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
                // A pointer param proven to always receive a fat-pointer base (from
                // the whole-unit `infer_fat_params` pass over static functions) is a
                // checkable fat pointer too — so `p[i]` in the callee is bounds-checked
                // (sic.md §"Scopes"). Excluded if the param is reassigned in the body.
                let is_fat_param = fc.is_sic() && !fc.moved_names.contains(pname)
                    && fc.lowerer.fat_params.get(name).map_or(false, |s| s.contains(&i));
                if is_fat_param { fc.fat_locals.insert(pname.clone()); }
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
                // sic `string` params are BORROWED (the caller keeps ownership; no
                // retain on entry). But assigning to one releases its old value, which
                // the callee never owned — freeing the caller's string. A string param
                // the body assigns to (or takes the address of) therefore becomes an
                // owned local, exactly like `string s = arg;`: retained on entry and
                // released at scope exit. Untouched params stay zero-cost borrows.
                let owned_string_param = fc.is_sic() && super::types::is_sic_string(&pty)
                    && fc.moved_names.contains(pname);
                fc.define_local(pname.clone(), pty, ptr_vid);
                if owned_string_param {
                    fc.retain_string_at(&Val::Local(ptr_vid))?;
                    fc.register_scope_exit(Cleanup::StringRelease { addr: Val::Local(ptr_vid) });
                }
                if let Some(en) = fc.c_enum_name_of(&p.ty.ty) {
                    fc.enum_locals.insert(pname.clone(), en);
                }
                if let Some(bf) = fc.bitfield_name_of(&p.ty.ty) {
                    fc.bitfield_locals.insert(pname.clone(), bf);
                }
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
            Stmt::Asm(a) => self.lower_asm(a)?,
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
                // sic `async` (sic.md §"Async"): wrap the returned value in a
                // `Task<elem>` (the stub runtime makes it ready) and return that.
                if let Some(elem) = self.async_elem.clone() {
                    let boxed = match val {
                        Some(e) => { let v = self.lower_expr(e)?; self.async_box_u64(v, &elem)? }
                        None => Constant::uint(0),
                    };
                    let task = self.emit_task_new(boxed, &elem)?;
                    self.flush_bigint_temps();
                    self.emit_cleanups_to(0);
                    self.set_terminator(Terminator::Ret(Some(task)));
                    return Ok(());
                }
                // sic strict enum typing (sic.md §"Enums"): reject returning an
                // `int`/other-enum from an `enum`-returning function without a cast.
                if let (Some(dest), Some(e)) = (self.ret_enum.clone(), val.as_ref()) {
                    self.check_enum_dest(&dest, e, "returned as")?;
                }
                // sic type safety: reject returning a value/pointer that mismatches
                // the declared return type (`File*` fn returning a `File` value), or
                // a value with no implicit conversion to the return type at all.
                if let Some(e) = val.as_ref() {
                    let rt = self.ret_ty.clone();
                    self.check_ptr_value_mismatch(&rt, e)?;
                    self.check_return_convertible(&rt, e)?;
                }
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
                            // `return "literal";` / `return some_char_ptr;` / `return
                            // local_char_array;` from a `string` function: wrap the C
                            // string in a descriptor. A LOCAL stack array gets the
                            // copy-on-escape sentinel so the move below materializes an
                            // owned copy (it would otherwise dangle); a static/caller
                            // pointer stays a plain view.
                            let rc = if self.needs_copy_on_escape(e) { Self::RC_LOCAL_SENTINEL } else { 0 };
                            let v = self.lower_expr(e)?;
                            self.cstr_to_string_rc(v, rc)?
                        } else {
                            self.lower_aggregate_ptr(e)?
                        };
                        if self.is_sic() && super::types::is_sic_string(&agg_ty) {
                            // Move the string out: materialize an owned copy iff it is
                            // a copy-on-escape local-buffer view, else move+retain.
                            self.emit_string_return_into(&sret_ptr, &src)?;
                        } else {
                            let ps = self.ptr_size();
                            let size = agg_ty.size_of(ps);
                            let align = agg_ty.align_of(ps) as u64;
                            self.push_instr(Instr::MemCopy { dst: sret_ptr.clone(), src, size, align });
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
                        // sic shorthand context (sic.md §"Bitfields", §"Enums"): an
                        // enum/bitfield return type lets a bare member resolve; a
                        // plain-integer return type forbids one.
                        let owner = self.ret_enum.clone().or_else(|| self.ret_bitfield.clone());
                        let rt = self.ret_ty.clone();
                        self.bf_ctx = self.dest_ctx(owner, &rt);
                        // Expected-type context (sic.md §"Lambdas"): returning a
                        // captureless lambda as `Fn<…>` boxes it into a closure.
                        let prev_exp = self.expected_ty.replace(rt.clone());
                        let v = self.lower_expr(e);
                        self.expected_ty = prev_exp;
                        let v = v?;
                        let expected = self.ret_ty.clone();
                        let c = self.coerce(v, &expected)?;
                        // sic tuple / closure return (sic.md §"Tuples"/§"Lambdas"):
                        // retain the shared block before scope-exit releases run, so
                        // the returned pointer outlives this frame (the caller
                        // releases it). Closures are the same refcounted heap value,
                        // which is what lets a returned closure (currying) survive.
                        if self.is_sic() && (super::types::is_tuple(&expected) || super::types::is_closure(&expected)) {
                            let pc = self.coerce(c.clone(), &Type::char_ptr())?;
                            self.emit_rc_retain(pc)?;
                        }
                        // sic container return (sic.md §"List"/§"Dict"): a returned
                        // `list`/`dict`/`set` is retained so it survives this frame's
                        // scope-exit release; the caller owns the reference.
                        if self.is_sic() && (super::types::is_list(&expected)
                            || super::types::is_dict(&expected) || super::types::is_set(&expected)) {
                            self.container_retain(c.clone(), &expected)?;
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
            Stmt::ForEach { ty, name, iterable, body, span } =>
                self.lower_foreach(ty, name, iterable, body, span)?,
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
            Stmt::Break(sp) => {
                // `break` targets the innermost enclosing loop *or* switch,
                // whichever is nested deeper — a switch inside a loop breaks the
                // switch, not the loop.
                if let Some(&end) = self.break_stack.last() {
                    if let Some(&depth) = self.break_scope_depth.last() {
                        self.emit_cleanups_to(depth);
                    }
                    self.set_terminator(Terminator::Jump(end));
                } else {
                    return Err(CompileError::at("break outside loop/switch".to_string(), sp.file.clone(), sp.line, sp.col));
                }
            }
            Stmt::Continue(sp) => {
                if let Some(&(_, cont)) = self.loop_stack.last() {
                    if let Some(&depth) = self.continue_scope_depth.last() {
                        self.emit_cleanups_to(depth);
                    }
                    self.set_terminator(Terminator::Jump(cont));
                } else {
                    return Err(CompileError::at("continue outside loop".to_string(), sp.file.clone(), sp.line, sp.col));
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
                // sic (sic.md §"Match"): a qualified enum-variant case label that
                // names no real variant (`case FS::Succcess:` — a typo) is an error,
                // not a silently-dropped case that would fall through to `default`.
                if self.is_sic() {
                    if let ExprKind::EnumVariant { enum_name, variant } = &val.kind {
                        if !self.lowerer.enum_consts.contains_key(variant) {
                            let sp = &val.span;
                            return Err(CompileError::at(
                                format!("enum '{}' has no variant '{}'", enum_name, variant),
                                sp.file.clone(), sp.line, sp.col));
                        }
                    }
                }
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

    /// Whether `name` refers to an atomic-qualified local or global.
    pub(crate) fn is_atomic_name(&self, name: &str) -> bool {
        self.atomic_locals.contains(name) || self.lowerer.atomic_globals.contains(name)
    }

    /// An `atomic` object must be a lock-free size: a 1/2/4/8-byte integer, a
    /// bool, or a pointer. Anything else is rejected.
    pub(crate) fn check_atomic_type(ty: &Type, sp: &crate::lexer::Span) -> Result<()> {
        let ok = match ty {
            Type::Pointer(_) | Type::Bool => true,
            Type::Int { bits, .. } => matches!(bits, 8 | 16 | 32 | 64),
            _ => false,
        };
        if ok { Ok(()) } else {
            Err(CompileError::at(
                "`atomic` requires a 1/2/4/8-byte integer, bool, or pointer type",
                sp.file.clone(), sp.line, sp.col,
            ))
        }
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
                    AstType::Bitfield(b) => {
                        self.lowerer.register_bitfield(b)?;
                    }
                    _ => {}
                }
                let is_static = matches!(base_ty.storage, Some(StorageClass::Static));
                let is_extern = matches!(base_ty.storage, Some(StorageClass::Extern));
                for d in declarators {
                    // sic `atomic` (sic.md §"Atomics"): a top-level atomic-qualified
                    // declarator becomes an atomic local. `d.ty.qualifiers` is the
                    // TOP-level type, so `atomic int a` is atomic but `atomic int *p`
                    // (pointer to atomic int) is not — its atomicity is on the pointee.
                    if self.is_sic() && d.ty.qualifiers.contains(&crate::ast::TypeQual::Atomic) {
                        let ity = self.lower_type(&d.ty)?;
                        Self::check_atomic_type(&ity, &d.span)?;
                        self.atomic_locals.insert(d.name.clone());
                    }
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
                    // C23 `auto x = e;` / GNU `__auto_type x = e;` (parsed as
                    // `AstType::Auto`): the type is the initializer's (after the
                    // usual decay, so an array/function initializer gives a pointer).
                    if matches!(d.ty.ty, AstType::Auto) && !self.is_sic() {
                        let Some(Initializer::Expr(e)) = &d.init else {
                            return Err(CompileError::at(
                                format!("`auto` / `__auto_type` variable `{}` needs an initializer", d.name),
                                d.span.file.clone(), d.span.line, d.span.col));
                        };
                        let it = self.infer_expr_type(e)?;
                        let it = match it {
                            Type::Array { elem, .. } => Type::Pointer(elem),
                            Type::Function(_) => Type::Pointer(Box::new(it)),
                            // An inferred aggregate may be the opaque (name-only)
                            // form; bind the full layout so `x.field` resolves.
                            other => super::types::resolve_aggregate(&other, &self.lowerer.struct_types),
                        };
                        let vid = self.alloc_val();
                        self.push_instr(Instr::Alloca { dest: vid, ty: it.clone(), align: None });
                        if matches!(it, Type::Struct(_) | Type::Union(_)) {
                            // Copy the aggregate's bytes from its address.
                            let src = self.lower_aggregate_ptr(e)?;
                            let ps = self.ptr_size();
                            self.push_instr(Instr::MemCopy { dst: Val::Local(vid), src, size: it.size_of(ps), align: it.align_of(ps) as u64 });
                        } else {
                            let v = self.lower_expr(e)?;
                            let v = self.coerce(v, &it)?;
                            self.push_instr(Instr::Store { val: v, ptr: Val::Local(vid) });
                        }
                        // Bound AFTER the initializer, so `auto x = x;` sees the outer x.
                        self.define_local(d.name.clone(), it.clone(), vid);
                        if !d.name.is_empty() {
                            self.push_instr(Instr::DbgVar { name: d.name.clone(), ty: it, slot: vid, is_param: false });
                        }
                        continue;
                    }
                    let mut ty = self.lower_type(&d.ty)?;
                    // sic `auto x = expr;` — infer the variable's type from its
                    // initializer (rather than C's storage-class `auto`, which
                    // defaults the type to `int`). Lets `auto cps = s.utf8;` bind the
                    // real (marker) type so its members/indexing resolve.
                    if self.is_sic() && matches!(base_ty.storage, Some(StorageClass::Auto)) {
                        if let Some(Initializer::Expr(e)) = &d.init {
                            // sic lambda (sic.md §"Lambdas"): infer the precise value
                            // type — a function pointer (captureless) or a closure
                            // environment pointer (capturing). The return/capture
                            // types need the params in scope, so this can't go through
                            // the `&self` inferer.
                            if let ExprKind::Lambda { captures, params, ret, body } = &e.kind {
                                ty = self.lambda_value_type(captures, params, ret, body, &e.span)?;
                            } else if let Ok(it) = self.infer_expr_type(e) {
                                ty = it;
                            }
                        }
                    }
                    // sic tuple local (sic.md §"Tuples"): a tuple value is a pointer
                    // to a refcounted heap block. Bind the pointer, retain the
                    // shared block, and release it at scope exit. A bare `tuple t;`
                    // is deferred until its first assignment.
                    if self.is_sic() && matches!(d.ty.ty, AstType::Tuple) {
                        match &d.init {
                            Some(Initializer::Expr(e)) => {
                                let pty = self.infer_expr_type(e).unwrap_or(ty);
                                // The initializer must BE a tuple. A parenthesized
                                // list `("a", "b")` is a comma expression (its last
                                // operand), not a tuple — treating that string/int as
                                // a tuple block crashed at run time in the retain.
                                if !super::types::is_tuple(&pty) {
                                    let hint = if matches!(e.kind, ExprKind::Comma(..)) {
                                        "; `(a, b)` is a comma expression — build a tuple with `tuple(a, b, …)`"
                                    } else { "" };
                                    return Err(CompileError::at(
                                        format!("cannot initialize tuple `{}` from a non-tuple value{}", d.name, hint),
                                        e.span.file.clone(), e.span.line, e.span.col));
                                }
                                let vid = self.alloc_val();
                                self.push_instr(Instr::Alloca { dest: vid, ty: pty.clone(), align: None });
                                self.define_local(d.name.clone(), pty.clone(), vid);
                                let ptr = self.lower_expr(e)?;
                                let pc = self.coerce(ptr.clone(), &Type::char_ptr())?;
                                self.emit_rc_retain(pc)?;
                                self.push_instr(Instr::Store { val: ptr, ptr: Val::Local(vid) });
                                self.register_scope_exit(Cleanup::TupleRelease { slot: Val::Local(vid) });
                                if !d.name.is_empty() {
                                    self.push_instr(Instr::DbgVar { name: d.name.clone(), ty: pty, slot: vid, is_param: false });
                                }
                                continue;
                            }
                            _ => {
                                // sic `tuple t;` (sic.md §"Tuples"): a real binding
                                // to an EMPTY tuple — `t.length == 0` and any `t[i]`
                                // is out of range — visible in its whole scope (so a
                                // later `t = …` in a loop persists). Reassigning a
                                // concrete tuple refines the element types.
                                let empty = super::types::tuple_type(vec![]);
                                let vid = self.alloc_val();
                                self.push_instr(Instr::Alloca { dest: vid, ty: empty.clone(), align: None });
                                self.define_local(d.name.clone(), empty.clone(), vid);
                                let t = self.build_empty_tuple()?;
                                self.push_instr(Instr::Store { val: t, ptr: Val::Local(vid) });
                                self.register_scope_exit(Cleanup::TupleRelease { slot: Val::Local(vid) });
                                if !d.name.is_empty() {
                                    self.push_instr(Instr::DbgVar { name: d.name.clone(), ty: empty, slot: vid, is_param: false });
                                }
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
                    // Remember a payload-less enum-typed local so `v.str` works, and
                    // enforce strict enum typing on its initializer (sic.md §"Enums").
                    if let Some(en) = self.c_enum_name_of(&d.ty.ty) {
                        if let Some(Initializer::Expr(e)) = &d.init {
                            self.check_enum_dest(&en, e, "assigned to")?;
                        }
                        self.enum_locals.insert(d.name.clone(), en);
                    }
                    // sic bitfield-typed local (sic.md §"Bitfields"): remember it and
                    // enforce strict typing on its initializer.
                    if let Some(bf) = self.bitfield_name_of(&d.ty.ty) {
                        if let Some(Initializer::Expr(e)) = &d.init {
                            self.check_bitfield_dest(&bf, e, "assigned to")?;
                        }
                        self.bitfield_locals.insert(d.name.clone(), bf);
                    }

                    if let Some(Initializer::Expr(e)) = &d.init {
                        self.check_ptr_value_mismatch(&ty, e)?;
                    }
                    // sic `list<T> x = c.keys/c.values;` (sic.md §"Iterators"): the
                    // local OWNS the freshly materialized list — store it, take it out
                    // of the statement temps, and free it at scope exit.
                    let takes_projection = self.is_sic() && super::types::is_list(&ty)
                        && matches!(&d.init, Some(Initializer::Expr(e)) if self.is_container_projection(e));
                    // sic container local from a fresh producer (`list x = new list;` /
                    // `dict d = makeDict();`, sic.md §"List"/§"Dict"): the producer's
                    // owned reference (recorded in `container_temps` by
                    // `record_container_producer`) TRANSFERS to the local. Take it out
                    // of the statement temps so it isn't also released at statement end,
                    // and free it at scope exit. Mirrors exactly what registered a
                    // producer: a `new` container, or a call whose callee is a plain
                    // function (not method syntax — a `c.method()` result may be an
                    // alias, so it stays on the retain path below).
                    let takes_producer = self.is_sic()
                        && (super::types::is_list(&ty) || super::types::is_dict(&ty) || super::types::is_set(&ty))
                        && !matches!(d.ty.ty, AstType::Weak(_))
                        && !takes_projection
                        && matches!(&d.init, Some(Initializer::Expr(e)) if matches!(&e.kind,
                            ExprKind::New { .. })
                            || matches!(&e.kind, ExprKind::Call { func, .. }
                                if !matches!(func.kind, ExprKind::Field { .. } | ExprKind::Arrow { .. })));
                    if takes_projection {
                        if let Some(Initializer::Expr(e)) = &d.init {
                            let h = self.lower_expr(e)?;
                            self.take_list_temp(&h);
                            self.push_instr(Instr::Store { ptr: Val::Local(vid), val: h });
                            self.register_scope_exit(Cleanup::ListFree { slot: Val::Local(vid) });
                        }
                    } else if takes_producer {
                        if let Some(Initializer::Expr(e)) = &d.init {
                            let h = self.lower_expr(e)?;
                            self.take_container_temp(&h);
                            let stored = self.coerce(h, &Type::void_ptr())?;
                            self.push_instr(Instr::Store { ptr: Val::Local(vid), val: stored });
                            if super::types::is_list(&ty) {
                                self.register_scope_exit(Cleanup::ListFree { slot: Val::Local(vid) });
                            } else {
                                self.register_scope_exit(Cleanup::DictFree { slot: Val::Local(vid) });
                            }
                        }
                    } else if let Some(init) = &d.init {
                        // sic shorthand context (sic.md §"Bitfields", §"Enums"): an
                        // enum/bitfield-typed target lets a bare member in the
                        // initializer resolve (`Some val = Two;`); a plain-integer
                        // target forbids one (`int a = Two;` is ambiguous).
                        let owner = self.c_enum_name_of(&d.ty.ty)
                            .or_else(|| self.bitfield_name_of(&d.ty.ty));
                        self.bf_ctx = self.dest_ctx(owner, &ty);
                        // Expected-type context (sic.md §"Lambdas"): a `Fn<…>`-typed
                        // target boxes a captureless lambda into a closure.
                        let prev_exp = self.expected_ty.replace(ty.clone());
                        let r = self.lower_initializer(init, Val::Local(vid), &ty);
                        self.expected_ty = prev_exp;
                        r?;
                    } else {
                        // Zero-initialize. For a SCALAR local emit a `Store` of a
                        // width-correct zero rather than a `MemSet`: a MemSet takes
                        // the slot's ADDRESS, which makes the alloca escape and blocks
                        // mem2reg register promotion — so neither the zero-init nor any
                        // later dead store could ever be eliminated. A `Store` keeps
                        // the slot promotable to an SSA value, and the backend's DCE
                        // then drops the zero-init (and dead reassignments) whenever the
                        // local is written before it is read (`i32 a; a=5; a=10;` →
                        // just the last value). Aggregates stay on MemSet — they are
                        // memory objects that never promote to a register.
                        let size = ty.size_of(self.ptr_size());
                        if size > 0 {
                            let scalar = matches!(&ty,
                                Type::Int { .. } | Type::Float32 | Type::Float64
                                | Type::Float80 | Type::Pointer(_) | Type::Bool);
                            if scalar {
                                let z = self.coerce(Constant::zero(), &ty)?;
                                self.push_instr(Instr::Store { val: z, ptr: Val::Local(vid) });
                            } else {
                                self.push_instr(Instr::MemSet {
                                    dst: Val::Local(vid), val: Constant::zero(), size, align: ty.align_of(self.ptr_size()),
                                });
                            }
                        }
                    }
                    // sic `dict` local (sic.md §"Dict"): a bare `dict d;` is a fresh
                    // empty map, so auto-initialize the handle to `__sic_dict_new()`
                    // (an uninitialized NULL handle would crash on first use).
                    if self.is_sic() && super::types::is_list(&ty) && d.init.is_none() {
                        let handle = self.lower_list_new(&ty)?;
                        self.push_instr(Instr::Store { ptr: Val::Local(vid), val: handle });
                        self.register_scope_exit(Cleanup::ListFree { slot: Val::Local(vid) });
                    }
                    if self.is_sic() && super::types::is_dict(&ty) && d.init.is_none() {
                        let handle = self.lower_dict_new(&ty, &d.span)?;
                        self.push_instr(Instr::Store { ptr: Val::Local(vid), val: handle });
                        // We created this dict, so we own it: free it at scope exit.
                        self.register_scope_exit(Cleanup::DictFree { slot: Val::Local(vid) });
                    }
                    // sic `dict/list/set p = new dict/list/set<…>` (sic.md §"Dict"/
                    // §"List"/§"Set"): the local owns the freshly `new`-allocated
                    // handle, so free it at scope exit (else it leaks — `new` returns
                    // an owned handle, and a bare `dict d;` already frees the same
                    // way). Keyed on the `new`'s produced type, so it works whether
                    // the slot is declared `dict d` or `dict *p` (the handle bits are
                    // stored either way). Aliasing an EXISTING handle (`dict d =
                    // other;`) is not a `new`, so it is left un-freed (no double free).
                    // sic container local ownership (sic.md §"List"/§"Dict"): a
                    // container local owns exactly ONE reference to its handle, released
                    // at scope exit. A fresh producer (`new`, or a call that already
                    // return-retained) transfers its +1; a SHARE — an alias (`c = a`), a
                    // struct-field read (`c = obj.items`), or a tuple/container element
                    // (`c = t[i]`) — is retained so the local's lifetime is independent
                    // of the source (else a later reassignment would release a handle it
                    // never owned). A weak `.get` upgrade and a `.keys`/`.values`
                    // projection register their own release, so they are skipped here.
                    if self.is_sic() && !matches!(d.ty.ty, AstType::Weak(_)) && !takes_producer {
                        let is_container = super::types::is_list(&ty)
                            || super::types::is_dict(&ty) || super::types::is_set(&ty);
                        if is_container {
                            if let Some(Initializer::Expr(e)) = &d.init {
                                let (needs_retain, needs_release) = match &e.kind {
                                    ExprKind::New { .. } | ExprKind::Call { .. } => (false, true),
                                    ExprKind::Field { name, .. } | ExprKind::Arrow { name, .. }
                                        if matches!(name.as_str(), "get" | "keys" | "values") => (false, false),
                                    ExprKind::Ident(_) | ExprKind::Field { .. } | ExprKind::Arrow { .. }
                                    | ExprKind::Index { .. } => (true, true),
                                    // A container ternary/elvis yields an owned reference
                                    // (its arms retain the selected handle) recorded as a
                                    // producer temp; retain it into the local and free it
                                    // at scope exit, so the statement-end release of that
                                    // temp leaves the local its own reference.
                                    ExprKind::Ternary { .. } | ExprKind::Elvis { .. } => (true, true),
                                    _ => (false, false),
                                };
                                if needs_retain {
                                    let h = self.alloc_val();
                                    self.push_instr(Instr::Load { dest: h, ptr: Val::Local(vid), ty: Type::void_ptr() });
                                    let _ = self.container_retain(Val::Local(h), &ty);
                                }
                                if needs_release {
                                    if super::types::is_list(&ty) {
                                        self.register_scope_exit(Cleanup::ListFree { slot: Val::Local(vid) });
                                    } else {
                                        self.register_scope_exit(Cleanup::DictFree { slot: Val::Local(vid) });
                                    }
                                }
                            }
                        }
                    }
                    // sic weak reference local (sic.md §"Weak"): `weak<T> w = c;` takes
                    // a NON-owning reference — weak-retain the handle and weak-release
                    // it at scope exit (it never keeps the container alive).
                    if self.is_sic() {
                        if let AstType::Weak(_) = &d.ty.ty {
                            let is_dict = super::types::is_dict(&ty) || super::types::is_set(&ty);
                            self.weak_locals.insert(d.name.clone(), ty.clone());
                            let h = self.alloc_val();
                            self.push_instr(Instr::Load { dest: h, ptr: Val::Local(vid), ty: Type::void_ptr() });
                            let name = if is_dict { "__sic_dict_weak_retain" } else { "__sic_list_weak_retain" };
                            let rf = if is_dict { self.dict_runtime_fn(name) } else { self.list_runtime_fn(name) };
                            self.push_instr(Instr::Call { dest: None, func: rf, args: vec![Val::Local(h)], ret_ty: Type::Void });
                            self.register_scope_exit(Cleanup::WeakRelease { slot: Val::Local(vid), is_dict });
                        }
                    }
                    // sic struct constructor/destructor (sic.md §"Memory safety"):
                    // for a struct local with a `S()`, call it on `&local` after
                    // zero-init (only when the user gave no explicit initializer);
                    // a `~S()` runs at scope exit via the cleanup list.
                    if self.is_sic() {
                        // Auto-init any `list`/`dict`/`set` fields to fresh empty
                        // containers (a zero handle crashes on first use). Runs
                        // before the ctor so a `S()` can further populate them.
                        if matches!(&ty, Type::Struct(_)) && d.init.is_none() {
                            self.init_struct_container_fields(&Val::Local(vid), &ty)?;
                        }
                        if let Type::Struct(st) = &ty {
                            if let Some(sn) = st.name.clone() {
                                if d.init.is_none() {
                                    if let Some(ctor) = self.lowerer.struct_ctor.get(&sn).cloned() {
                                        self.emit_cleanup_call(Val::Local(vid), &ctor);
                                    }
                                }
                                if let Some(dtor) = self.lowerer.struct_dtor.get(&sn).cloned() {
                                    self.register_scope_exit(Cleanup::AttrFn { addr: Val::Local(vid), fn_name: dtor });
                                }
                            }
                        }
                    }
                    // sic refcounted `string` local: release its `rc` at scope
                    // exit (RAII). Safe for the uninitialized case too — that
                    // zero-inits `rc` to NULL, and releasing NULL is a no-op.
                    if self.is_sic() && super::types::is_sic_string(&ty) {
                        self.register_scope_exit(Cleanup::StringRelease { addr: Val::Local(vid) });
                    }
                    // sic `any` local: if it wraps a refcounted `string` (e.g. read
                    // from a container), share ownership — retain on bind, release at
                    // scope exit. A no-op for any other wrapped type (and for the
                    // uninitialized case, whose zero `ty` short-circuits the check),
                    // so it never touches non-refcounted values.
                    if self.is_sic() && super::types::is_any(&ty) {
                        if d.init.is_some() {
                            self.any_refcount_at(Val::Local(vid), true)?;
                        }
                        self.register_scope_exit(Cleanup::AnyRelease { addr: Val::Local(vid) });
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
                    // A `list`/`dict`/`set` handle is NOT a fat-pointer array (even
                    // though `new list/dict/set` is also a `New`): its `d[i]` is a
                    // runtime hash/index op, not a bounds-checked memory access, and
                    // its handle has no `name-2*ptr` size header — so marking it fat
                    // makes loop-BCE hoist a bogus bounds check that reads garbage and
                    // aborts (`for (i<n) d[i]=…` in a dict-returning fn).
                    let is_container = super::types::is_list(&ty)
                        || super::types::is_dict(&ty) || super::types::is_set(&ty);
                    if self.is_sic() && !d.name.is_empty() && !self.moved_names.contains(&d.name)
                        && !is_container {
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
                // `string s = <any>`: unbox the `any` to the string descriptor and
                // copy it (an `any` wrapping a string converts without a cast).
                if super::types::is_any(&rt) {
                    let anyp = self.lower_aggregate_ptr(e)?;
                    let src = self.unbox_any_val(anyp, ty)?;
                    self.push_instr(Instr::MemCopy { dst: ptr.clone(), src, size, align });
                    self.retain_string_at(&ptr)?;
                    return Ok(());
                }
                if is_str {
                    let src = self.lower_aggregate_ptr(e)?;
                    self.push_instr(Instr::MemCopy { dst: ptr.clone(), src, size, align });
                    self.retain_string_at(&ptr)?;
                } else {
                    // `string s = <char*/char[]>` wraps a view. A local stack array
                    // (`char b[10]`) gets the copy-on-escape sentinel so `return s`
                    // materializes an owned copy instead of dangling; a static/caller
                    // pointer stays a plain (rc=NULL) view.
                    let rc = if self.needs_copy_on_escape(e) { Self::RC_LOCAL_SENTINEL } else { 0 };
                    let v = self.lower_expr(e)?;
                    let cp = self.coerce(v, &Type::char_ptr())?;
                    let src = self.cstr_to_string_rc(cp, rc)?;
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
            // sic `u8char c = <expr>` (sic.md §"Integer sizes"): a code point held
            // in a `{ u32 cp }` struct. Another u8char copies the struct; an integer
            // (or ASCII char literal) is stored into the `cp` field.
            Initializer::Expr(e) if self.is_sic() && super::types::is_u8char(ty) => {
                if matches!(self.infer_expr_type(e), Ok(t) if super::types::is_u8char(&t)) {
                    let src = self.lower_aggregate_ptr(e)?;
                    let size = ty.size_of(self.ptr_size());
                    let align = ty.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: ptr, src, size, align });
                } else {
                    let v = self.lower_expr(e)?;
                    let cp = self.coerce(v, &Type::Int { bits: 32, signed: false })?;
                    let dst = self.coerce(ptr.clone(), &Type::Pointer(Box::new(Type::Int { bits: 32, signed: false })))?;
                    self.push_instr(Instr::Store { val: cp, ptr: dst });
                }
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
                    // sic `struct S x = <any>`: unbox the `any` to the struct pointer
                    // it wraps, then copy (an `any` converts to the assigned aggregate
                    // without a cast). Otherwise the raw `{ty,slot}` bytes get copied.
                    let src = if self.is_sic()
                        && matches!(self.infer_expr_type(e), Ok(t) if super::types::is_any(&t))
                        && !super::types::is_any(ty)
                    {
                        let anyp = self.lower_aggregate_ptr(e)?;
                        self.unbox_any_val(anyp, ty)?
                    } else {
                        self.lower_aggregate_ptr(e)?
                    };
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

    /// sic: a `struct` local whose fields include `list`/`dict`/`set` handles must
    /// have those fields initialized to fresh empty containers — a zero handle
    /// crashes on first use (`b.items.add(x)` dereferences NULL). Walk the resolved
    /// struct's direct fields, install a fresh empty container in each container
    /// field, and register its free at scope exit. Recurses into nested `struct`
    /// fields; skips `union`s (only one member is live, so auto-init is unsound).
    fn init_struct_container_fields(&mut self, base: &Val, sty: &Type) -> Result<()> {
        let resolved = super::types::resolve_aggregate(sty, &self.lowerer.struct_types);
        let Type::Struct(st) = &resolved else { return Ok(()); };
        let st = st.clone();
        let weak = st.name.as_ref()
            .and_then(|n| self.lowerer.struct_weak_fields.get(n).cloned())
            .unwrap_or_default();
        for (i, (name, fty)) in st.fields.iter().enumerate() {
            let off = st.field_offset(i, self.ptr_size());
            // sic `weak<T>` field (sic.md §"Weak"): a non-owning reference — null it
            // (not a fresh container), and weak-release it at scope exit.
            if weak.iter().any(|(wn, _)| wn == name) {
                let is_dict = super::types::is_dict(fty) || super::types::is_set(fty);
                let fp = self.gep_offset(base, off, fty);
                let z = self.coerce(Constant::zero(), &Type::void_ptr())?;
                self.push_instr(Instr::Store { ptr: fp.clone(), val: z });
                self.register_scope_exit(Cleanup::WeakRelease { slot: fp, is_dict });
                continue;
            }
            if super::types::is_list(fty) {
                let fp = self.gep_offset(base, off, fty);
                let handle = self.lower_list_new(fty)?;
                self.push_instr(Instr::Store { ptr: fp.clone(), val: handle });
                self.register_scope_exit(Cleanup::ListFree { slot: fp });
            } else if super::types::is_dict(fty) {
                let fp = self.gep_offset(base, off, fty);
                let handle = self.lower_dict_new(fty, &crate::lexer::Span::default())?;
                self.push_instr(Instr::Store { ptr: fp.clone(), val: handle });
                self.register_scope_exit(Cleanup::DictFree { slot: fp });
            } else if matches!(super::types::resolve_aggregate(fty, &self.lowerer.struct_types), Type::Struct(_)) {
                let fp = self.gep_offset(base, off, fty);
                self.init_struct_container_fields(&fp, fty)?;
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
    /// Error for a designated initializer `.name = …` naming a field the aggregate
    /// does not have.
    fn unknown_field_err(&self, agg: &Type, name: &str) -> CompileError {
        let tn = match &super::types::resolve_aggregate(agg, &self.lowerer.struct_types) {
            Type::Struct(st) => st.name.clone().unwrap_or_else(|| "struct".into()),
            Type::Union(u) => u.name.clone().unwrap_or_else(|| "union".into()),
            _ => "aggregate".into(),
        };
        CompileError::new(format!("'{}' has no field '{}'", tn, name))
    }

    fn resolve_init_target(&mut self, base: &Val, agg: &Type, designators: &[crate::ast::Designator], cursor: usize)
        -> Result<(Option<(Val, Type, Option<super::expr::BitField>)>, usize)>
    {
        use crate::ast::Designator;
        // First step: designator[0] if present, else the implicit cursor.
        let (first, top_index) = match designators.first() {
            Some(Designator::Field(name)) => {
                let Some((off, fty, bf)) = super::expr::resolve_field_access(agg, name, self.ptr_size(), &self.lowerer.struct_types)
                else { return Err(self.unknown_field_err(agg, name)); };
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
                    else { return Err(self.unknown_field_err(&cur_ty, name)); };
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
        let mark = self.temp_mark();
        let v = self.lower_expr(cond)?;
        let b = self.to_bool(v)?;
        self.flush_temps_from(mark);
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
        // A bare body still needs a per-iteration scope (see `lower_for`).
        if matches!(body, Stmt::Block(..)) {
            self.lower_stmt(body)?;
        } else {
            self.enter_scope();
            self.lower_stmt(body)?;
            self.exit_scope();
        }
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
        // A bare body still needs a per-iteration scope (see `lower_for`).
        if matches!(body, Stmt::Block(..)) {
            self.lower_stmt(body)?;
        } else {
            self.enter_scope();
            self.lower_stmt(body)?;
            self.exit_scope();
        }
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

        // Auto-vectorization (see `try_vectorize`): a unit-stride counting loop whose
        // body is one element-wise array assignment is rewritten to process a SIMD
        // vector of elements per step (with a scalar remainder), emitting the vector
        // ops that the back end lowers to real SIMD. Runs for BOTH SIC and C sources
        // (matmul's C build should vectorize too): it is language-neutral and sound
        // (fat pointers keep their hoisted bounds check; a runtime alias guard falls
        // back to the scalar path). Runs inside the loop's scope so it can declare
        // the induction variable there; on success it emits the whole loop.
        if let (Some(fi), Some(c), Some(p)) = (init, cond, post) {
            if self.try_vectorize(fi, c, p, body)? {
                self.exit_scope();
                return Ok(());
            }
        }

        // Vectorized predicate-count reduction (`if (arr[j] CMP K) acc++`): a SIMD
        // compare + movemask + popcnt per lane-chunk (see `try_vectorize_predcount`).
        if let (Some(fi), Some(c), Some(p)) = (init, cond, post) {
            if self.try_vectorize_predcount(fi, c, p, body)? {
                self.exit_scope();
                return Ok(());
            }
        }

        // Dead counted-loop elimination: a counting loop whose body is only trivial
        // scalar-local assignments with no loop-carried dependency computes the same
        // final state as running just its last iteration, so it is replaced by a
        // single guarded iteration (see `try_delete_loop`). Emits the whole loop on
        // success. Runs before `init` lowering so it can own the emission (like
        // `try_vectorize`).
        if let (Some(fi), Some(c), Some(p)) = (init, cond, post) {
            if self.try_delete_loop(fi, c, p, body)? {
                self.exit_scope();
                return Ok(());
            }
        }

        if let Some(fi) = init {
            match fi {
                ForInit::Decl(d) => self.lower_local_decl(d)?,
                ForInit::Expr(e) => { self.lower_expr(e)?; }
            }
        }

        // sic loop bounds-check elimination: prove the fat-pointer accesses in this
        // counting loop safe with one check on the index extremes before the loop,
        // then suppress the per-iteration checks. Runs after `init` (so the induction
        // variable and arrays are lowered) and before the loop blocks (the guards go
        // in the pre-header). `bce_mark` is the point to truncate `bce_proven` back to
        // on loop exit, so proofs don't leak to sibling loops.
        let bce_mark = self.bce_proven.len();
        if self.is_sic() {
            if let (Some(fi), Some(c), Some(p)) = (init, cond, post) {
                self.try_loop_bce(fi, c, p, body)?;
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
        // A bare (non-block) body must still get its own per-iteration scope so
        // that temporaries it creates — a `string` concat, a `.keys`/`.values`
        // projection, etc. — are released each iteration, not accumulated in the
        // loop scope and freed once at loop exit (which leaked every iteration but
        // the last). A `{}` body already scopes itself via `lower_stmt`, and the
        // break/continue depths above are set to bracket exactly this scope.
        if matches!(body, Stmt::Block(..)) {
            self.lower_stmt(body)?;
        } else {
            self.enter_scope();
            self.lower_stmt(body)?;
            self.exit_scope();
        }
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(post_bb)); }
        self.continue_scope_depth.pop();
        self.break_scope_depth.pop();
        self.break_stack.pop();
        self.loop_stack.pop();

        self.switch_to_block(post_bb);
        if let Some(p) = post { self.lower_expr(p)?; }
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cond_bb)); }

        self.switch_to_block(end_bb);
        self.bce_proven.truncate(bce_mark);
        self.exit_scope();
        Ok(())
    }

    /// Dead counted-loop elimination. Recognizes a unit-stride counting loop
    /// `for (i = LO; i <|<= HI; i++)` whose body is *only* trivial scalar-local
    /// assignments `L = <pure arithmetic of i and loop-invariant names>` with no
    /// loop-carried dependency, and replaces the whole loop with a single guarded
    /// iteration at the terminal index:
    ///
    /// ```text
    ///   init;                       // i = LO
    ///   if (i <|<= HI) {            // loop-entry test, evaluated once at i == LO
    ///       i = i_last;             // HI-1 for `<`, HI for `<=`
    ///       body;                   // runs exactly once, seeing the last i
    ///       i = i_post;             // HI for `<`, HI+1 for `<=`
    ///   }
    /// ```
    ///
    /// Soundness. (1) *Termination + no wrap*: we fire only when the loop provably
    /// runs a finite number of `+1` steps and `i`'s final value is representable in
    /// its type — a constant bound is checked against the type's range; a variable
    /// bound is allowed only for `<` with a width-≥32 index no narrower than the
    /// bound (so `i` is compared in its own type and reaches `HI` without wrapping).
    /// So a genuinely infinite loop is never collapsed. (2) *Last-iteration
    /// equivalence*: the body writes only scalar locals, contains no calls, memory
    /// writes, or control flow, and every RHS is pure and references neither a
    /// body-assigned name (no loop-carried value) nor memory (no masked
    /// out-of-range trap) — only `i` and loop-invariant names. Running the body once
    /// with `i` at its last value therefore yields exactly the state the loop would.
    /// (3) *Zero-iteration*: the guard reproduces the loop-entry test at `i == LO`,
    /// so a loop that never ran leaves `i` and every local at its pre-loop value.
    /// Fails closed (`Ok(false)`, keeping the normal loop) on anything unproven.
    fn try_delete_loop(&mut self, init: &ForInit, cond: &Expr, post: &Expr, body: &Stmt) -> Result<bool> {
        use crate::ast::{ExprKind as E, BinOpKind as B};
        use std::collections::HashSet;
        if !self.lowerer.loop_delete { return Ok(false); }

        // -- induction variable `i` (and its declared type for a `for (T i = …)`). --
        let (ivar, decl_ty): (String, Option<Type>) = match init {
            ForInit::Decl(d @ Decl::Var { declarators, .. }) if declarators.len() == 1 => {
                let de = &declarators[0];
                if de.init.is_none() { return Ok(false); }
                let _ = d;
                (de.name.clone(), Some(self.lower_type(&de.ty)?))
            }
            ForInit::Expr(e) => match &e.kind {
                E::Assign { op: None, lhs, .. } => match &lhs.kind {
                    E::Ident(n) => (n.clone(), None),
                    _ => return Ok(false),
                },
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };

        // -- bound `i < HI` / `i <= HI`. --
        let (hi, inclusive) = match &cond.kind {
            E::BinOp { op, lhs, rhs } => match (&lhs.kind, op) {
                (E::Ident(n), B::Lt) if *n == ivar => ((**rhs).clone(), false),
                (E::Ident(n), B::Le) if *n == ivar => ((**rhs).clone(), true),
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        // HI must be pure (re-evaluated for the guard and the terminal index).
        if simple_expr_idents(&hi).is_none() { return Ok(false); }

        // -- step must be exactly `i++` / `++i` / `i += 1` (unit stride). --
        let unit = match &post.kind {
            E::PostInc { inc: true, expr } | E::PreInc { inc: true, expr } =>
                matches!(&expr.kind, E::Ident(n) if *n == ivar),
            E::Assign { op: Some(B::Add), lhs, rhs } =>
                matches!(&lhs.kind, E::Ident(n) if *n == ivar)
                    && matches!(&rhs.kind, E::IntLit(1, _)),
            _ => false,
        };
        if !unit { return Ok(false); }

        // -- body: a flat list of trivial scalar-local assignments only. --
        let stmts: Vec<&Stmt> = match body {
            Stmt::Block(v, _) => v.iter().collect(),
            Stmt::Expr(_, _) => vec![body],
            Stmt::Null(_) => Vec::new(),
            _ => return Ok(false),
        };
        let mut assigned: HashSet<String> = HashSet::new();
        let mut rhs_idsets: Vec<HashSet<String>> = Vec::new();
        for s in &stmts {
            let (lname, rhs) = match s {
                Stmt::Expr(e, _) => match &e.kind {
                    E::Assign { op: None, lhs, rhs } => match &lhs.kind {
                        E::Ident(n) => (n.clone(), rhs),
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                },
                _ => return Ok(false),
            };
            if lname == ivar { return Ok(false); }
            // LHS must be a plain local scalar (a global could be observed
            // elsewhere; an aggregate is not a trivial assign).
            match self.lookup(&lname) {
                Some(LookupResult::Local(ty, _)) if matches!(ty,
                    Type::Int { .. } | Type::Float32 | Type::Float64 | Type::Float80
                    | Type::Pointer(_) | Type::Bool) => {}
                _ => return Ok(false),
            }
            // RHS must be pure arithmetic of names/literals only (no memory reads,
            // calls, or writes) — `simple_expr_idents` enforces exactly that.
            let ids = match simple_expr_idents(rhs) { Some(s) => s, None => return Ok(false) };
            assigned.insert(lname);
            rhs_idsets.push(ids);
        }
        // No loop-carried dependency: no RHS may read a value the body writes.
        // (Referencing `i` or a loop-invariant name is fine.)
        for ids in &rhs_idsets {
            if ids.iter().any(|n| assigned.contains(n)) { return Ok(false); }
        }

        // -- `i`'s integer type (bits/signedness) drives the termination proof. --
        let ity: Type = match &decl_ty {
            Some(t) => t.clone(),
            None => match self.lookup(&ivar) {
                Some(LookupResult::Local(t, _)) => t.clone(),
                _ => return Ok(false),
            },
        };
        let (bits, signed) = match &ity {
            Type::Int { bits, signed } => (*bits, *signed),
            _ => return Ok(false),
        };
        let type_max: u128 = if signed {
            if bits >= 128 { i128::MAX as u128 } else { (1u128 << (bits - 1)) - 1 }
        } else if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };

        // -- termination + no-wrap proof. --
        let proven = match crate::lower::eval_const_expr(&hi, &self.lowerer.enum_consts) {
            // Constant bound: `i` reaches it iff it fits the type (and, for `<=`,
            // with room for the terminating `HI+1` step). A negative bound means the
            // loop is empty; the guard handles that, but bail to keep this simple.
            Ok(v) if v >= 0 => {
                let hv = v as u128;
                if inclusive { hv < type_max } else { hv <= type_max }
            }
            Ok(_) => false,
            // Variable bound: only `<`, and only when `i` is compared in its own
            // (≥32-bit) type against a no-wider bound of the same signedness, so `i`
            // counts up to `HI` without a promotion-induced wrap.
            Err(_) => {
                if inclusive || bits < 32 { false }
                else {
                    matches!(self.infer_expr_type(&hi),
                        Ok(Type::Int { bits: hb, signed: hs }) if hb <= bits && hs == signed)
                }
            }
        };
        if !proven { return Ok(false); }

        // ===== EMIT: init; if (cond) { i = i_last; body; i = i_post; } =====
        match init {
            ForInit::Decl(d) => self.lower_local_decl(d)?,
            ForInit::Expr(e) => { self.lower_expr(e)?; }
        }
        // Loop-entry guard, evaluated with `i == LO` (init just ran).
        let will = self.lower_expr(cond)?;
        let willb = self.to_bool(will)?;
        let body_bb = self.new_block_after_current();
        let end_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: willb, then_bb: body_bb, else_bb: end_bb });
        self.switch_to_block(body_bb);

        // Terminal index: for `<`, last body `i` is HI-1 and post-loop `i` is HI;
        // for `<=`, HI and HI+1. Synthesized as normal assignments so lowering
        // applies the correct type coercion (the proof above guarantees no wrap).
        let sp = cond.span.clone();
        let one = || Expr::new(E::IntLit(1, false), sp.clone());
        let sub1 = |e: &Expr| Expr::new(E::BinOp { op: B::Sub, lhs: Box::new(e.clone()), rhs: Box::new(one()) }, sp.clone());
        let add1 = |e: &Expr| Expr::new(E::BinOp { op: B::Add, lhs: Box::new(e.clone()), rhs: Box::new(one()) }, sp.clone());
        let i_last = if inclusive { hi.clone() } else { sub1(&hi) };
        let i_post = if inclusive { add1(&hi) } else { hi.clone() };
        let assign_i = |rhs: Expr| Expr::new(E::Assign {
            op: None,
            lhs: Box::new(Expr::new(E::Ident(ivar.clone()), sp.clone())),
            rhs: Box::new(rhs),
        }, sp.clone());

        self.lower_expr(&assign_i(i_last))?;
        self.lower_stmt(body)?;
        if !self.is_terminated() {
            self.lower_expr(&assign_i(i_post))?;
            self.set_terminator(Terminator::Jump(end_bb));
        }
        self.switch_to_block(end_bb);
        Ok(true)
    }

    /// sic loop bounds-check elimination (see the TODO at `emit_bounds_check`).
    /// Recognizes a `+step` counting loop `for (i = LO; i <|<= HI; i++/i+=C)` and,
    /// for each fat-pointer access `arr[X + i]` (X invariant in the loop), hoists a
    /// single check on the index extremes (`X+LO` and `X+maxi`) — guarded by the
    /// loop-entry condition so an empty loop never aborts — then records the access
    /// so the per-iteration check is suppressed. CONSERVATIVE: any construct it does
    /// not understand, or any sign that `i`/`HI`/`X`/`arr` could change in the body,
    /// makes it give up (the per-iteration checks stay). It never removes a check
    /// without a hoisted one that covers the same or a wider range.
    fn try_loop_bce(&mut self, init: &ForInit, cond: &Expr, post: &Expr, body: &Stmt) -> Result<()> {
        use crate::ast::{ExprKind as E, BinOpKind as B};
        // -- induction variable + init value LO --
        let (ivar, lo) = match init {
            ForInit::Decl(Decl::Var { declarators, .. }) if declarators.len() == 1 => {
                let d = &declarators[0];
                match &d.init { Some(Initializer::Expr(e)) => (d.name.clone(), e.clone()), _ => return Ok(()) }
            }
            ForInit::Expr(e) => match &e.kind {
                E::Assign { op: None, lhs, rhs } => match &lhs.kind {
                    E::Ident(n) => (n.clone(), (**rhs).clone()), _ => return Ok(()),
                },
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        // -- bound HI and comparison kind from `i < HI` / `i <= HI` --
        let (hi, inclusive) = match &cond.kind {
            E::BinOp { op, lhs, rhs } => match (&lhs.kind, op) {
                (E::Ident(n), B::Lt) if *n == ivar => ((**rhs).clone(), false),
                (E::Ident(n), B::Le) if *n == ivar => ((**rhs).clone(), true),
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        // -- step must be a POSITIVE increment of `i` (so `i` is non-decreasing and
        //    every used value is <= maxi); the exact stride does not matter for
        //    safety, only that it is positive. --
        let pos_step = match &post.kind {
            E::PostInc { inc: true, expr } | E::PreInc { inc: true, expr } =>
                matches!(&expr.kind, E::Ident(n) if *n == ivar),
            E::Assign { op: Some(B::Add), lhs, rhs } =>
                matches!(&lhs.kind, E::Ident(n) if *n == ivar) && positive_int_lit(rhs),
            E::Assign { op: None, lhs, rhs } => matches!(&lhs.kind, E::Ident(n) if *n == ivar)
                && matches!(&rhs.kind, E::BinOp { op: B::Add, lhs: a, rhs: b }
                    if matches!(&a.kind, E::Ident(n) if *n == ivar) && positive_int_lit(b)),
            _ => false,
        };
        if !pos_step { return Ok(()); }
        // LO and HI must be *simple* (pure, side-effect-free, no calls) so they can
        // be re-evaluated for the guard and cannot change under a body call.
        let lo_ids = match simple_expr_idents(&lo) { Some(s) => s, None => return Ok(()) };
        let hi_ids = match simple_expr_idents(&hi) { Some(s) => s, None => return Ok(()) };

        // -- scan the body: collect every name that could be modified/declared, and
        //    every fat-pointer affine access `arr[X + i]`. Bail on any unhandled or
        //    unsafe construct (e.g. a call, which could mutate HI/X globals). --
        let mut mods: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut accesses: Vec<(String, Expr, Option<Expr>)> = Vec::new(); // (arr, index-expr, X)
        if !self.bce_scan(body, &ivar, &mut mods, &mut accesses) { return Ok(()); }
        if accesses.is_empty() { return Ok(()); }

        // -- invariance: the induction var, the bound's vars, and each candidate's X
        //    vars must NOT be modified in the body; the array must not be modified. --
        if mods.contains(&ivar) { return Ok(()); }
        if hi_ids.iter().any(|n| mods.contains(n)) { return Ok(()); }
        let _ = lo_ids; // LO is only evaluated once (init); its vars need not be invariant.
        let mut safe: Vec<(String, Expr, Option<Expr>)> = Vec::new();
        for (arr, idx, x) in accesses {
            if mods.contains(&arr) { continue; }
            let x_ok = match &x {
                None => true,
                Some(xe) => match simple_expr_idents(xe) {
                    Some(xi) => !xi.contains(&ivar) && !xi.iter().any(|n| mods.contains(n)),
                    None => false,
                },
            };
            if x_ok { safe.push((arr, idx, x)); }
        }
        if safe.is_empty() { return Ok(()); }

        // -- emit the hoisted checks, guarded by the loop-entry condition so an
        //    empty loop (LO past HI) never triggers a spurious abort. `i == LO` here
        //    (init just ran), so lowering `cond` computes "will iterate at least
        //    once". `cond` is a simple `i <|<= HI` comparison (side-effect-free). --
        let will = self.lower_expr(cond)?;
        let willb = self.to_bool(will)?;
        let chk_bb = self.new_block_after_current();
        let cont_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: willb, then_bb: chk_bb, else_bb: cont_bb });
        self.switch_to_block(chk_bb);
        let one = Expr::new(E::IntLit(1, false), cond.span.clone());
        let maxi = if inclusive { hi.clone() }
                   else { Expr::new(E::BinOp { op: B::Sub, lhs: Box::new(hi.clone()), rhs: Box::new(one) }, cond.span.clone()) };
        for (arr, idx, x) in &safe {
            // idx extremes: lo_idx = X + LO (or LO), hi_idx = X + maxi (or maxi).
            let (lo_idx, hi_idx) = match x {
                None => (lo.clone(), maxi.clone()),
                Some(xe) => (
                    Expr::new(E::BinOp { op: B::Add, lhs: Box::new(xe.clone()), rhs: Box::new(lo.clone()) }, idx.span.clone()),
                    Expr::new(E::BinOp { op: B::Add, lhs: Box::new(xe.clone()), rhs: Box::new(maxi.clone()) }, idx.span.clone()),
                ),
            };
            self.emit_hoisted_bounds_check(arr, &lo_idx)?;
            self.emit_hoisted_bounds_check(arr, &hi_idx)?;
            self.bce_proven.push((arr.clone(), bce_index_key(idx)));
        }
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(cont_bb)); }
        self.switch_to_block(cont_bb);
        Ok(())
    }

    /// sic auto-vectorization: recognize a unit-stride counting loop whose body is a
    /// single element-wise array assignment, and rewrite it to process a SIMD vector
    /// of `W` elements per step plus a scalar remainder. The emitted vector
    /// load/op/store instructions lower to real SIMD (see `Type::simd128`).
    ///
    /// Shape handled (matmul's inner loop and similar):
    ///   `for (T j = LO; j < HI; j++)  W[a + j] {=|+=|-=|*=|&=|\|=|^=} <expr>;`
    /// where `W` is a fat-pointer array whose element type is a 128-bit SIMD lane,
    /// `a` is loop-invariant, and `<expr>` is a tree of loop-invariant scalars
    /// (broadcast), unit-stride loads `R[b + j]` from same-element-type fat arrays,
    /// and vectorizable arithmetic. Fails closed (returns `Ok(false)`, keeping the
    /// scalar loop) on anything it does not fully understand.
    ///
    /// Soundness: (1) every array is a fat-pointer local; one hoisted bounds check
    /// per array covers the whole `[LO, HI)` range (like loop-BCE), so the vector
    /// and remainder accesses are safe. (2) Each array is accessed at exactly one
    /// affine offset, so a store never feeds a differently-offset load within a
    /// vector window; distinct fat locals are distinct allocations and cannot alias.
    /// (3) The body is pure (no calls / side effects beyond the one store), so the
    /// bound, offsets and broadcast scalars are loop-invariant.
    fn try_vectorize(&mut self, init: &ForInit, cond: &Expr, post: &Expr, body: &Stmt) -> Result<bool> {
        use crate::ast::{ExprKind as E, BinOpKind as B};

        if !self.lowerer.vectorize { return Ok(false); }

        // Cheap structural pre-filter (runs on every loop): only a body that is a
        // single `arr[...] op= …` assignment can vectorize. This bails immediately
        // for multi-statement bodies and nested loops (e.g. matmul's outer loops)
        // before the pricier header/invariance analysis below.
        let single_index_assign = |s: &Stmt| matches!(s,
            Stmt::Expr(e, _) if matches!(&e.kind,
                E::Assign { lhs, .. } if matches!(lhs.kind, E::Index { .. })));
        let body_ok = match body {
            Stmt::Block(stmts, _) if stmts.len() == 1 => single_index_assign(&stmts[0]),
            other => single_index_assign(other),
        };
        if !body_ok { return Ok(false); }

        // -- induction variable + init value LO (must be a fresh `for (T j = LO; …)`) --
        let (ivar, jdecl, lo) = match init {
            ForInit::Decl(Decl::Var { declarators, .. }) if declarators.len() == 1 => {
                let d = &declarators[0];
                match &d.init {
                    Some(Initializer::Expr(e)) => (d.name.clone(), d.clone(), e.clone()),
                    _ => return Ok(false),
                }
            }
            _ => return Ok(false),
        };
        // -- bound `j < HI` / `j <= HI` --
        let (hi, inclusive) = match &cond.kind {
            E::BinOp { op, lhs, rhs } => match (&lhs.kind, op) {
                (E::Ident(n), B::Lt) if *n == ivar => ((**rhs).clone(), false),
                (E::Ident(n), B::Le) if *n == ivar => ((**rhs).clone(), true),
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        // -- step must be exactly `j++` / `++j` / `j += 1` (unit stride) --
        let unit_step = match &post.kind {
            E::PostInc { inc: true, expr } | E::PreInc { inc: true, expr } =>
                matches!(&expr.kind, E::Ident(n) if *n == ivar),
            E::Assign { op: Some(B::Add), lhs, rhs } =>
                matches!(&lhs.kind, E::Ident(n) if *n == ivar)
                    && matches!(&rhs.kind, E::IntLit(1, _)),
            _ => false,
        };
        if !unit_step { return Ok(false); }
        // LO and HI must be pure (re-evaluated for the guard / loop math).
        if simple_expr_idents(&lo).is_none() || simple_expr_idents(&hi).is_none() { return Ok(false); }

        // -- body must be a single assignment `W[Widx] op= RHS` --
        let assign: &Expr = match body {
            Stmt::Block(stmts, _) if stmts.len() == 1 => match &stmts[0] {
                Stmt::Expr(e, _) => e, _ => return Ok(false),
            },
            Stmt::Expr(e, _) => e,
            _ => return Ok(false),
        };
        let (aop, lhs, rhs) = match &assign.kind {
            E::Assign { op, lhs, rhs } => (*op, lhs, rhs),
            _ => return Ok(false),
        };
        // LHS = W[Widx], W a fat array, Widx unit-stride.
        let (warr, woff) = match &lhs.kind {
            E::Index { base, index } => match &base.kind {
                E::Ident(w) if self.is_vec_array(w) => match affine_x(index, &ivar) {
                    Some(off) => (w.clone(), off),
                    None => return Ok(false),
                },
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        // Element type + lane count (must be a 128-bit SIMD lane layout).
        let et = match self.infer_expr_type(lhs) {
            Ok(t) if t.is_int() || t.is_float() => t,
            _ => return Ok(false),
        };
        let bits = match &et {
            Type::Int { bits, .. } => *bits,
            Type::Float32 => 32, Type::Float64 => 64,
            _ => return Ok(false),
        };
        let lanes = match bits { 8 | 16 | 32 | 64 => (128 / bits) as usize, _ => return Ok(false) };
        let vty = Type::Array { elem: Box::new(et.clone()), len: lanes };
        if vty.simd128().is_none() { return Ok(false); }

        // The store op, as a vector IR op (None = plain `=`).
        let store_op = match aop {
            None => None,
            Some(b) => match vec_binop_for(b, &et) { Some(v) => Some(v), None => return Ok(false) },
        };

        // -- analyze the RHS into a vectorizable plan, collecting every array access --
        let mut accesses: Vec<(String, Option<Expr>)> = vec![(warr.clone(), woff.clone())];
        let plan = match self.analyze_vec_expr(rhs, &ivar, &et, &mut accesses) {
            Some(p) => p,
            None => return Ok(false),
        };
        // Aliasing (static): the WRITE array must be accessed at exactly one offset
        // — a store must never feed a differently-offset load of the SAME array (a
        // loop-carried dependence like `a[i] = a[i-1] + …`). A READ-ONLY array (never
        // the write target) may appear at several offsets — a stencil `b[i] =
        // a[i-1]+a[i]+a[i+1]` reads `a` at three offsets but never writes it, so the
        // loads are order-independent; the runtime alias guard below still handles
        // the case where such an array actually aliases the write array.
        let woff_key = woff.as_ref().map(bce_index_key).unwrap_or_else(|| "0".to_string());
        for (arr, off) in &accesses {
            if arr == &warr {
                let key = off.as_ref().map(bce_index_key).unwrap_or_else(|| "0".to_string());
                if key != woff_key { return Ok(false); }
            }
        }

        // ===== EMIT =====
        // Promote the induction variable to i64 for the vector loop so the
        // loop counter lives in a 64-bit register, eliminating movslq per
        // iteration and letting the backend keep it in a GPR.
        let i64_ty = QualType::new(AstType::LongLong { signed: true });
        let mut jdecl_i64 = jdecl.clone();
        jdecl_i64.ty = i64_ty.clone();
        self.lower_local_decl(&Decl::Var {
            base_ty: i64_ty,
            declarators: vec![jdecl_i64],
            weak: false, thread_local: false, span: cond.span.clone(),
        })?;
        let (jty, jslot) = match self.lookup(&ivar) {
            Some(LookupResult::Local(ty, vid)) => (ty.clone(), Val::Local(vid)),
            _ => return Ok(false),
        };
        let i64t = Type::i64();

        // Hoisted bounds checks over [LO, HI), guarded by the loop-entry condition
        // (an empty loop must not abort). `j == LO` here, so `cond` = "will iterate".
        let will = self.lower_expr(cond)?;
        let willb = self.to_bool(will)?;
        let chk_bb = self.new_block_after_current();
        let loops_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: willb, then_bb: chk_bb, else_bb: loops_bb });
        self.switch_to_block(chk_bb);
        let one = Expr::new(E::IntLit(1, false), cond.span.clone());
        let maxi = if inclusive { hi.clone() }
                   else { Expr::new(E::BinOp { op: B::Sub, lhs: Box::new(hi.clone()), rhs: Box::new(one) }, cond.span.clone()) };
        for (arr, off) in &accesses {
            // Only fat pointers (`new[]`/`@`) carry a size header to check; a raw
            // pointer (a `malloc`'d C array, or a plain pointer local) is unchecked
            // in the scalar loop too, so vectorizing it adds no bounds obligation.
            if !self.fat_locals.contains(arr) { continue; }
            let (lo_idx, hi_idx) = match off {
                None => (lo.clone(), maxi.clone()),
                Some(xe) => (
                    Expr::new(E::BinOp { op: B::Add, lhs: Box::new(xe.clone()), rhs: Box::new(lo.clone()) }, lhs.span.clone()),
                    Expr::new(E::BinOp { op: B::Add, lhs: Box::new(xe.clone()), rhs: Box::new(maxi.clone()) }, lhs.span.clone()),
                ),
            };
            self.emit_hoisted_bounds_check(arr, &lo_idx)?;
            self.emit_hoisted_bounds_check(arr, &hi_idx)?;
        }
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(loops_bb)); }
        self.switch_to_block(loops_bb);

        // vend = LO + ((HI - LO) rounded down to a multiple of W), computed in i64.
        let lo_v = { let v = self.lower_expr(&lo)?; self.coerce(v, &i64t)? };
        let hi_v = {
            let v = self.lower_expr(&hi)?; let v = self.coerce(v, &i64t)?;
            if inclusive {
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: BinOp::Add, lhs: v, rhs: Constant::int(1), ty: i64t.clone() });
                Val::Local(d)
            } else { v }
        };
        let count = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: count, op: BinOp::Sub, lhs: hi_v.clone(), rhs: lo_v.clone(), ty: i64t.clone() });
        let vcount = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: vcount, op: BinOp::And, lhs: Val::Local(count), rhs: Constant::int(!((lanes as i64) - 1)), ty: i64t.clone() });
        let vend = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: vend, op: BinOp::Add, lhs: lo_v.clone(), rhs: Val::Local(vcount), ty: i64t.clone() });
        let vend = Val::Local(vend);

        // Runtime alias guard: distinct fat locals are distinct allocations, but two
        // names could alias (`i32* b = c`). If the write region overlaps any read
        // array's region, skip the vector loop and let the scalar remainder (which
        // then covers all of `[LO, HI)`, since `j` is still `LO`) run — preserving
        // the exact scalar semantics. For genuinely distinct arrays this is always
        // false, so the vector path is taken.
        // Every distinct read region (by name AND offset) is checked against the
        // write region — a multi-offset read array (a stencil's `a`) contributes one
        // region per offset. The write array is single-offset (== the write region),
        // so it is excluded.
        let esz = et.size_of(self.ptr_size());
        let mut read_arrays: Vec<(String, Option<Expr>)> = Vec::new();
        for (arr, off) in &accesses {
            if arr == &warr { continue; }
            let k = off.as_ref().map(bce_index_key).unwrap_or_else(|| "0".to_string());
            if !read_arrays.iter().any(|(n, o)| n == arr
                && o.as_ref().map(bce_index_key).unwrap_or_else(|| "0".to_string()) == k) {
                read_arrays.push((arr.clone(), off.clone()));
            }
        }
        let no_alias = self.emit_no_alias(&warr, &woff, &read_arrays, &lo_v, &hi_v, &et, esz)?;

        // Pre-build broadcast (splat) vectors once, before the vector loop.
        let eplan = self.prebuild_splats(plan, &et, lanes)?;

        // ---- vector loop: while (j < vend) { W[woff+j] op= <plan>; j += W } ----
        let vcond = self.new_block_after_current();
        let vbody = self.new_block_after_current();
        let rem = self.new_block_after_current();
        match no_alias {
            Some(na) => self.set_terminator(Terminator::CondJump { cond: na, then_bb: vcond, else_bb: rem }),
            None => self.set_terminator(Terminator::Jump(vcond)),
        }
        self.switch_to_block(vcond);
        let jv = self.emit_load(&jslot, &jty);
        let jv64 = self.coerce(jv, &i64t)?;
        let lt = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: lt, op: CmpOp::ISLt, lhs: jv64.clone(), rhs: vend.clone(), ty: i64t.clone() });
        self.set_terminator(Terminator::CondJump { cond: Val::Local(lt), then_bb: vbody, else_bb: rem });
        self.switch_to_block(vbody);
        {
            let jvb = self.emit_load(&jslot, &jty);
            let jvb = self.coerce(jvb, &i64t)?;
            // value of <plan>
            let rhs_vec = self.emit_vec_node(&eplan, &jvb, &et, &vty, esz)?;
            // W[woff+j]
            let waddr = self.vec_elem_addr(&warr, &woff, &jvb, &et, esz)?;
            let res = match store_op {
                None => rhs_vec,
                Some(op) => {
                    let cur = self.alloc_val();
                    self.push_instr(Instr::Load { dest: cur, ptr: waddr.clone(), ty: vty.clone() });
                    let d = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: d, op, lhs: Val::Local(cur), rhs: rhs_vec, ty: vty.clone() });
                    Val::Local(d)
                }
            };
            self.push_instr(Instr::Store { val: res, ptr: waddr });
            // j += W
            let jn = self.emit_load(&jslot, &jty);
            let inc = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: inc, op: BinOp::Add, lhs: jn, rhs: Constant::int(lanes as i64), ty: jty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(inc), ptr: jslot.clone() });
            self.set_terminator(Terminator::Jump(vcond));
        }

        // ---- scalar remainder: while (j < HI) { <original body>; j++ } ----
        self.switch_to_block(rem);
        let rcond = self.new_block_after_current();
        let rbody = self.new_block_after_current();
        let done = self.new_block_after_current();
        self.set_terminator(Terminator::Jump(rcond));
        self.switch_to_block(rcond);
        let jr = self.emit_load(&jslot, &jty);
        let jr64 = self.coerce(jr, &i64t)?;
        let rlt = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: rlt, op: CmpOp::ISLt, lhs: jr64, rhs: hi_v.clone(), ty: i64t.clone() });
        self.set_terminator(Terminator::CondJump { cond: Val::Local(rlt), then_bb: rbody, else_bb: done });
        self.switch_to_block(rbody);
        self.lower_stmt(body)?;
        if !self.is_terminated() {
            let jn = self.emit_load(&jslot, &jty);
            let inc = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: inc, op: BinOp::Add, lhs: jn, rhs: Constant::int(1), ty: jty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(inc), ptr: jslot.clone() });
            self.set_terminator(Terminator::Jump(rcond));
        }
        self.switch_to_block(done);
        Ok(true)
    }

    /// Vectorize a byte/lane predicate-count reduction:
    ///
    /// ```text
    ///   for (T j = LO; j < HI; j++)  if (arr[j] CMP K) acc++;
    /// ```
    ///
    /// where `arr` is a fat integer array (8/16/32/64-bit lanes), `K` is a
    /// compile-time constant that fits the element type, and `acc` a scalar integer
    /// local incremented by one. Each `W`-lane chunk becomes: load a vector, compare
    /// all lanes to `splat(K)` (one SIMD compare), extract the lane mask
    /// (`pmovmskb`/`vhigh_bits`), `popcnt` it, and add that to `acc` — so `W` bytes
    /// per step instead of `W` branches. A scalar remainder runs the original body
    /// for the tail. This is the `bytecount` kernel (`buf[i] >= 128`), which LLVM
    /// vectorizes and sic previously left as a per-byte branch.
    ///
    /// Soundness: `arr` is only READ and `acc` is a scalar local (cannot alias the
    /// heap array), so no alias guard is needed; the hoisted bounds check covers the
    /// whole `[LO, HI)` range; `K` constant-and-in-range means the `W`-wide lane
    /// compare has the same truth value as the source's integer-promoted compare;
    /// summing per-chunk popcounts plus the scalar remainder is exactly the scalar
    /// count. Fails closed (`Ok(false)`) on anything not matched.
    fn try_vectorize_predcount(&mut self, init: &ForInit, cond: &Expr, post: &Expr, body: &Stmt) -> Result<bool> {
        use crate::ast::{ExprKind as E, BinOpKind as B};
        if !self.lowerer.vectorize { return Ok(false); }

        // -- induction variable + LO (fresh `for (T j = LO; …)`) --
        let (ivar, jdecl, lo) = match init {
            ForInit::Decl(Decl::Var { declarators, .. }) if declarators.len() == 1 => {
                let d = &declarators[0];
                match &d.init { Some(Initializer::Expr(e)) => (d.name.clone(), d.clone(), e.clone()), _ => return Ok(false) }
            }
            _ => return Ok(false),
        };
        // -- bound `j < HI` / `j <= HI` --
        let (hi, inclusive) = match &cond.kind {
            E::BinOp { op, lhs, rhs } => match (&lhs.kind, op) {
                (E::Ident(n), B::Lt) if *n == ivar => ((**rhs).clone(), false),
                (E::Ident(n), B::Le) if *n == ivar => ((**rhs).clone(), true),
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        // -- unit step `j++` / `++j` / `j += 1` --
        let unit = match &post.kind {
            E::PostInc { inc: true, expr } | E::PreInc { inc: true, expr } =>
                matches!(&expr.kind, E::Ident(n) if *n == ivar),
            E::Assign { op: Some(B::Add), lhs, rhs } =>
                matches!(&lhs.kind, E::Ident(n) if *n == ivar) && matches!(&rhs.kind, E::IntLit(1, _)),
            _ => false,
        };
        if !unit { return Ok(false); }
        if simple_expr_idents(&lo).is_none() || simple_expr_idents(&hi).is_none() { return Ok(false); }

        // -- body must be exactly `if (arr[j] CMP K) acc++;` (no else) --
        let ifstmt: &Stmt = match body {
            Stmt::Block(v, _) if v.len() == 1 => &v[0],
            s @ Stmt::If { .. } => s,
            _ => return Ok(false),
        };
        let (pred, then) = match ifstmt {
            Stmt::If { cond: c, then, else_: None, .. } => (c, then.as_ref()),
            _ => return Ok(false),
        };
        // pred = `arr[j] CMP K`
        let (arr, cmp_ast, k) = match &pred.kind {
            E::BinOp { op, lhs, rhs }
                if matches!(op, B::Lt | B::Le | B::Gt | B::Ge | B::Eq | B::Ne) =>
            {
                match &lhs.kind {
                    E::Index { base, index } => match &base.kind {
                        E::Ident(a) if matches!(affine_x(index, &ivar), Some(None)) =>
                            (a.clone(), *op, (**rhs).clone()),
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }
            }
            _ => return Ok(false),
        };
        // then = `acc++` / `++acc` / `acc += 1` (optionally a 1-statement block)
        let then_e: &Expr = match then {
            Stmt::Expr(e, _) => e,
            Stmt::Block(v, _) if v.len() == 1 => match &v[0] { Stmt::Expr(e, _) => e, _ => return Ok(false) },
            _ => return Ok(false),
        };
        let acc = match &then_e.kind {
            E::PostInc { inc: true, expr } | E::PreInc { inc: true, expr } =>
                match &expr.kind { E::Ident(a) => a.clone(), _ => return Ok(false) },
            E::Assign { op: Some(B::Add), lhs, rhs } =>
                match (&lhs.kind, &rhs.kind) { (E::Ident(a), E::IntLit(1, _)) => a.clone(), _ => return Ok(false) },
            _ => return Ok(false),
        };

        // -- arr must be an integer array/pointer; element 8/16/32/64-bit. A fat
        //    `new[]` local carries a size header (bounds-checked, hoisted below); a
        //    raw pointer (`malloc`) is unchecked in the scalar loop too, so it needs
        //    no hoisted check to vectorize. --
        if !self.is_vec_array(&arr) { return Ok(false); }
        let et = match self.infer_expr_type(&Expr::new(E::Ident(arr.clone()), cond.span.clone())) {
            Ok(Type::Pointer(t)) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
            Ok(Type::Array { elem, .. }) => (*elem).clone(),
            _ => return Ok(false),
        };
        let (ebits, esign) = match &et { Type::Int { bits, signed } => (*bits, *signed), _ => return Ok(false) };
        let lanes = match ebits { 8 => 16, 16 => 8, 32 => 4, 64 => 2, _ => return Ok(false) };
        let vty = Type::Array { elem: Box::new(et.clone()), len: lanes };
        if vty.simd128().is_none() { return Ok(false); }

        // -- K must be a compile-time constant that fits the element type (so the
        //    W-wide lane compare has the same truth as the source's promoted compare)
        //    and must not name j or acc. acc a scalar int local, distinct from arr. --
        if acc == arr { return Ok(false); }
        match simple_expr_idents(&k) {
            Some(ids) if !ids.contains(&ivar) && !ids.contains(&acc) => {}
            _ => return Ok(false),
        }
        let kv = match crate::lower::eval_const_expr(&k, &self.lowerer.enum_consts) { Ok(v) => v, Err(_) => return Ok(false) };
        let (emin, emax): (i128, i128) = if esign {
            (-(1i128 << (ebits - 1)), (1i128 << (ebits - 1)) - 1)
        } else { (0, (1i128 << ebits) - 1) };
        if (kv as i128) < emin || (kv as i128) > emax { return Ok(false); }
        let (acc_ty, acc_slot) = match self.lookup(&acc) {
            Some(LookupResult::Local(t, vid)) if t.is_int() => (t.clone(), Val::Local(vid)),
            _ => return Ok(false),
        };
        let cmpop = match (cmp_ast, esign) {
            (B::Lt, true) => CmpOp::ISLt, (B::Lt, false) => CmpOp::IULt,
            (B::Le, true) => CmpOp::ISLe, (B::Le, false) => CmpOp::IULe,
            (B::Gt, true) => CmpOp::ISGt, (B::Gt, false) => CmpOp::IUGt,
            (B::Ge, true) => CmpOp::ISGe, (B::Ge, false) => CmpOp::IUGe,
            (B::Eq, _) => CmpOp::IEq, (B::Ne, _) => CmpOp::INe,
            _ => return Ok(false),
        };

        // ===== EMIT ===== (mirrors `try_vectorize`'s scaffolding)
        let i64_ty = QualType::new(AstType::LongLong { signed: true });
        let mut jdecl_i64 = jdecl.clone();
        jdecl_i64.ty = i64_ty.clone();
        self.lower_local_decl(&Decl::Var {
            base_ty: i64_ty, declarators: vec![jdecl_i64],
            weak: false, thread_local: false, span: cond.span.clone(),
        })?;
        let (jty, jslot) = match self.lookup(&ivar) {
            Some(LookupResult::Local(ty, vid)) => (ty.clone(), Val::Local(vid)),
            _ => return Ok(false),
        };
        let i64t = Type::i64();
        let esz = et.size_of(self.ptr_size());

        // Hoisted bounds check over [LO, HI), guarded by the loop-entry condition.
        let will = self.lower_expr(cond)?;
        let willb = self.to_bool(will)?;
        let chk_bb = self.new_block_after_current();
        let loops_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: willb, then_bb: chk_bb, else_bb: loops_bb });
        self.switch_to_block(chk_bb);
        let one = Expr::new(E::IntLit(1, false), cond.span.clone());
        let maxi = if inclusive { hi.clone() }
                   else { Expr::new(E::BinOp { op: B::Sub, lhs: Box::new(hi.clone()), rhs: Box::new(one) }, cond.span.clone()) };
        // Only a fat pointer carries a size header to check; a raw pointer is
        // unchecked in the scalar loop too, so vectorizing it adds no obligation.
        if self.fat_locals.contains(&arr) {
            self.emit_hoisted_bounds_check(&arr, &lo)?;
            self.emit_hoisted_bounds_check(&arr, &maxi)?;
        }
        if !self.is_terminated() { self.set_terminator(Terminator::Jump(loops_bb)); }
        self.switch_to_block(loops_bb);

        // vend = LO + floor((HI - LO)/W)*W, in i64.
        let lo_v = { let v = self.lower_expr(&lo)?; self.coerce(v, &i64t)? };
        let hi_v = {
            let v = self.lower_expr(&hi)?; let v = self.coerce(v, &i64t)?;
            if inclusive {
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: BinOp::Add, lhs: v, rhs: Constant::int(1), ty: i64t.clone() });
                Val::Local(d)
            } else { v }
        };
        let count = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: count, op: BinOp::Sub, lhs: hi_v.clone(), rhs: lo_v.clone(), ty: i64t.clone() });
        let vcnt = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: vcnt, op: BinOp::And, lhs: Val::Local(count), rhs: Constant::int(!((lanes as i64) - 1)), ty: i64t.clone() });
        let vend = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: vend, op: BinOp::Add, lhs: lo_v.clone(), rhs: Val::Local(vcnt), ty: i64t.clone() });
        let vend = Val::Local(vend);

        // splat(K) built once, before the vector loop.
        let kscalar = self.coerce(Constant::int(kv), &et)?;
        let kvec = self.emit_splat(kscalar, &et, lanes);

        // ---- vector loop: while (j < vend) { acc += popcnt(movemask(load(arr[j]) CMP K)); j += W } ----
        let vcond = self.new_block_after_current();
        let vbody = self.new_block_after_current();
        let rem = self.new_block_after_current();
        self.set_terminator(Terminator::Jump(vcond));
        self.switch_to_block(vcond);
        let jv = self.emit_load(&jslot, &jty);
        let jv64 = self.coerce(jv, &i64t)?;
        let lt = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: lt, op: CmpOp::ISLt, lhs: jv64, rhs: vend.clone(), ty: i64t.clone() });
        self.set_terminator(Terminator::CondJump { cond: Val::Local(lt), then_bb: vbody, else_bb: rem });
        self.switch_to_block(vbody);
        {
            let jvb = self.emit_load(&jslot, &jty);
            let jvb = self.coerce(jvb, &i64t)?;
            let vaddr = self.vec_elem_addr(&arr, &None, &jvb, &et, esz)?;
            let vv = self.alloc_val();
            self.push_instr(Instr::Load { dest: vv, ptr: vaddr, ty: vty.clone() });
            let mask = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: mask, op: cmpop, lhs: Val::Local(vv), rhs: kvec.clone(), ty: vty.clone() });
            let mm = self.alloc_val();
            self.push_instr(Instr::VecMoveMask { dest: mm, val: Val::Local(mask), ty: vty.clone() });
            let pc = self.alloc_val();
            self.push_instr(Instr::UnaryOp { dest: pc, op: UnOp::Popcnt, val: Val::Local(mm), ty: Type::i32() });
            let pc_acc = self.coerce(Val::Local(pc), &acc_ty)?;
            let accv = self.emit_load(&acc_slot, &acc_ty);
            let sum = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: sum, op: BinOp::Add, lhs: accv, rhs: pc_acc, ty: acc_ty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(sum), ptr: acc_slot.clone() });
            // j += W
            let jn = self.emit_load(&jslot, &jty);
            let inc = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: inc, op: BinOp::Add, lhs: jn, rhs: Constant::int(lanes as i64), ty: jty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(inc), ptr: jslot.clone() });
            self.set_terminator(Terminator::Jump(vcond));
        }

        // ---- scalar remainder: while (j < HI) { <original body>; j++ } ----
        self.switch_to_block(rem);
        let rcond = self.new_block_after_current();
        let rbody = self.new_block_after_current();
        let done = self.new_block_after_current();
        self.set_terminator(Terminator::Jump(rcond));
        self.switch_to_block(rcond);
        let jr = self.emit_load(&jslot, &jty);
        let jr64 = self.coerce(jr, &i64t)?;
        let rlt = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: rlt, op: CmpOp::ISLt, lhs: jr64, rhs: hi_v.clone(), ty: i64t.clone() });
        self.set_terminator(Terminator::CondJump { cond: Val::Local(rlt), then_bb: rbody, else_bb: done });
        self.switch_to_block(rbody);
        self.lower_stmt(body)?;
        if !self.is_terminated() {
            let jn = self.emit_load(&jslot, &jty);
            let inc = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: inc, op: BinOp::Add, lhs: jn, rhs: Constant::int(1), ty: jty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(inc), ptr: jslot.clone() });
            self.set_terminator(Terminator::Jump(rcond));
        }
        self.switch_to_block(done);
        Ok(true)
    }

    /// Recognize a vectorizable RHS sub-expression (unit-stride in `ivar`), pushing
    /// every array access it makes into `accesses`. Returns `None` (→ don't
    /// vectorize) on anything not handled.
    fn analyze_vec_expr(&self, e: &Expr, ivar: &str, elem: &Type,
        accesses: &mut Vec<(String, Option<Expr>)>) -> Option<VecNode> {
        use crate::ast::ExprKind as E;
        match &e.kind {
            // unit-stride load `R[b + j]` from a same-element-type fat array
            E::Index { base, index } => {
                let arr = match &base.kind { E::Ident(a) => a.clone(), _ => return None };
                if !self.is_vec_array(&arr) { return None; }
                let at = self.infer_expr_type(base).ok()?;
                let ae = match &at {
                    Type::Pointer(t) => super::types::resolve_aggregate(t, &self.lowerer.struct_types),
                    Type::Array { elem, .. } => (**elem).clone(),  // a file-scope array base
                    _ => return None,
                };
                if &ae != elem { return None; }
                let off = affine_x(index, ivar)?;
                accesses.push((arr.clone(), off.clone()));
                Some(VecNode::Load { arr, offset: off })
            }
            // element-wise binary op
            E::BinOp { op, lhs, rhs } => {
                let vop = vec_binop_for(*op, elem)?;
                let l = self.analyze_vec_expr(lhs, ivar, elem, accesses)?;
                let r = self.analyze_vec_expr(rhs, ivar, elem, accesses)?;
                Some(VecNode::Bin { op: vop, l: Box::new(l), r: Box::new(r) })
            }
            // otherwise: a loop-invariant scalar, broadcast to every lane. It is
            // lowered and coerced to the vector's element type in `prebuild_splats`.
            _ => {
                let ids = simple_expr_idents(e)?;      // pure (no calls / side effects)
                if ids.contains(ivar) { return None; } // depends on j but not a load → bail
                match self.infer_expr_type(e) {
                    Ok(t) if t.is_int() || t.is_float() => {}
                    _ => return None,
                }
                Some(VecNode::Splat(e.clone()))
            }
        }
    }

    /// Lower every `Splat` in the plan to a broadcast vector value ONCE (they are
    /// loop-invariant), returning a plan whose splats are resolved to those values.
    fn prebuild_splats(&mut self, node: VecNode, elem: &Type, lanes: usize) -> Result<VecEmit> {
        Ok(match node {
            VecNode::Splat(e) => {
                let s = self.lower_expr(&e)?;
                let s = self.coerce(s, elem)?;
                VecEmit::Prebuilt(self.emit_splat(s, elem, lanes))
            }
            VecNode::Load { arr, offset } => VecEmit::Load { arr, offset },
            VecNode::Bin { op, l, r } => VecEmit::Bin {
                op,
                l: Box::new(self.prebuild_splats(*l, elem, lanes)?),
                r: Box::new(self.prebuild_splats(*r, elem, lanes)?),
            },
        })
    }

    /// Emit the vector value of a resolved plan node at loop index `j` (i64).
    fn emit_vec_node(&mut self, node: &VecEmit, j: &Val, elem: &Type, vty: &Type, esz: u64) -> Result<Val> {
        Ok(match node {
            VecEmit::Prebuilt(v) => v.clone(),
            VecEmit::Load { arr, offset } => {
                let addr = self.vec_elem_addr(arr, offset, j, elem, esz)?;
                let d = self.alloc_val();
                self.push_instr(Instr::Load { dest: d, ptr: addr, ty: vty.clone() });
                Val::Local(d)
            }
            VecEmit::Bin { op, l, r } => {
                let lv = self.emit_vec_node(l, j, elem, vty, esz)?;
                let rv = self.emit_vec_node(r, j, elem, vty, esz)?;
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: *op, lhs: lv, rhs: rv, ty: vty.clone() });
                Val::Local(d)
            }
        })
    }

    /// Address of `arr[offset + j]` as a `*elem` pointer (offset invariant, j the i64
    /// loop index).
    fn vec_elem_addr(&mut self, arr: &str, offset: &Option<Expr>, j: &Val, elem: &Type, esz: u64) -> Result<Val> {
        let base = self.lower_expr(&Expr::new(crate::ast::ExprKind::Ident(arr.to_string()), crate::lexer::Span::default()))?;
        let idx = match offset {
            None => j.clone(),
            Some(e) => {
                let ov = self.lower_expr(e)?;
                let ov = self.coerce(ov, &Type::i64())?;
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: BinOp::Add, lhs: ov, rhs: j.clone(), ty: Type::i64() });
                Val::Local(d)
            }
        };
        let d = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: d, base, index: idx, elem_size: esz, result_ty: Type::ptr(elem.clone()) });
        Ok(Val::Local(d))
    }

    /// Runtime "no overlap" test for the vectorizer's alias guard: true iff the
    /// write region `W[woff + LO .. woff + HI)` overlaps NO read array's region.
    /// Returns `None` when there are no distinct read arrays (always safe → vectorize
    /// unconditionally). Regions are compared as unsigned addresses.
    fn emit_no_alias(&mut self, warr: &str, woff: &Option<Expr>,
        reads: &[(String, Option<Expr>)], lo: &Val, hi: &Val, elem: &Type, esz: u64) -> Result<Option<Val>> {
        if reads.is_empty() { return Ok(None); }
        let i64t = Type::i64();
        let addr = |s: &mut Self, arr: &str, off: &Option<Expr>, j: &Val| -> Result<Val> {
            let a = s.vec_elem_addr(arr, off, j, elem, esz)?;
            s.coerce(a, &i64t)
        };
        let ws = addr(self, warr, woff, lo)?;
        let we = addr(self, warr, woff, hi)?;
        let mut acc: Option<Val> = None;
        for (r, roff) in reads {
            let rs = addr(self, r, roff, lo)?;
            let re = addr(self, r, roff, hi)?;
            // overlap = (ws < re) && (rs < we)  → no_overlap = !overlap
            let a = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: a, op: CmpOp::IULt, lhs: ws.clone(), rhs: re, ty: i64t.clone() });
            let b = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: b, op: CmpOp::IULt, lhs: rs, rhs: we.clone(), ty: i64t.clone() });
            let ov = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: ov, op: BinOp::And, lhs: Val::Local(a), rhs: Val::Local(b), ty: Type::Bool });
            let no_ov = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: no_ov, op: CmpOp::IEq, lhs: Val::Local(ov), rhs: Constant::int(0), ty: Type::Bool });
            acc = Some(match acc {
                None => Val::Local(no_ov),
                Some(prev) => {
                    let d = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: d, op: BinOp::And, lhs: prev, rhs: Val::Local(no_ov), ty: Type::Bool });
                    Val::Local(d)
                }
            });
        }
        Ok(acc)
    }

    /// True if `name` is a local array base the vectorizer can index directly: a
    /// pointer or array whose element is a plain scalar (int/float). This excludes
    /// SIC's boxed containers (`list`/`dict`/`set`/`string`/…), whose pointee is a
    /// runtime marker struct, not a scalar — so `l[j]` is never treated as a raw
    /// array. Works for both fat `new[]` pointers (bounds-checked) and raw pointers
    /// (`malloc`, C mode — unchecked, like the scalar loop).
    fn is_vec_array(&self, name: &str) -> bool {
        let scalar = |t: &Type| t.is_int() || t.is_float();
        let ok = |t: &Type| match t {
            Type::Pointer(inner) => scalar(inner),
            Type::Array { elem, .. } => scalar(elem),
            _ => false,
        };
        match self.lookup(name) {
            Some(LookupResult::Local(t, _)) => ok(&t),
            // A file-scope array/pointer (`static double a[N]`) is a valid base too;
            // its element type is one indirection in.
            Some(LookupResult::Global(t, _)) => ok(&t),
            _ => false,
        }
    }

    /// Load a value of type `ty` from `ptr` (a small helper for the vectorizer).
    fn emit_load(&mut self, ptr: &Val, ty: &Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: ptr.clone(), ty: ty.clone() });
        Val::Local(d)
    }

    /// Build a vector with every lane equal to `scalar` (a broadcast/splat), via a
    /// stack slot; the caller hoists this out of the hot loop.
    fn emit_splat(&mut self, scalar: Val, elem: &Type, lanes: usize) -> Val {
        let vty = Type::Array { elem: Box::new(elem.clone()), len: lanes };
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: vty.clone(), align: None });
        let esz = elem.size_of(self.ptr_size()) as i64;
        for i in 0..lanes {
            let addr = if i == 0 { Val::Local(slot) } else {
                let a = self.alloc_val();
                self.push_instr(Instr::PtrOffset { dest: a, base: Val::Local(slot), offset: Constant::int(i as i64 * esz) });
                Val::Local(a)
            };
            self.push_instr(Instr::Store { val: scalar.clone(), ptr: addr });
        }
        let v = self.alloc_val();
        self.push_instr(Instr::Load { dest: v, ptr: Val::Local(slot), ty: vty });
        Val::Local(v)
    }

    /// Emit one hoisted fat-pointer bounds check `arr[idx]` (used by loop-BCE).
    fn emit_hoisted_bounds_check(&mut self, arr: &str, idx: &Expr) -> Result<()> {
        let base = self.lower_expr(&Expr::new(crate::ast::ExprKind::Ident(arr.to_string()), idx.span.clone()))?;
        let bt = self.val_type(&base);
        let elem = match &bt {
            Type::Pointer(t) => super::types::resolve_aggregate(t, &self.lowerer.struct_types),
            _ => Type::i32(),
        };
        let esz = elem.size_of(self.ptr_size()).max(1);
        let iv = self.lower_expr(idx)?;
        let iv = self.coerce(iv, &Type::i64())?;
        self.emit_bounds_check(base, iv, esz)
    }

    /// Recursive body scan for loop-BCE. Collects modified/declared names into
    /// `mods` and fat-pointer affine accesses `arr[X + i]` (or `arr[i]`, X = None)
    /// into `out`. Returns `false` (bail) on any construct not explicitly handled or
    /// known-safe — notably any function call, which could mutate a global the bound
    /// or index depends on. Conservative by construction: an unrecognized form fails
    /// closed (keeps the per-iteration checks).
    fn bce_scan(&self, stmt: &Stmt, ivar: &str,
        mods: &mut std::collections::HashSet<String>,
        out: &mut Vec<(String, Expr, Option<Expr>)>) -> bool {
        match stmt {
            Stmt::Expr(e, _) => self.bce_scan_expr(e, ivar, mods, out),
            Stmt::Block(ss, _) => ss.iter().all(|s| self.bce_scan(s, ivar, mods, out)),
            Stmt::Decl(Decl::Var { declarators, .. }) => {
                for d in declarators {
                    mods.insert(d.name.clone());
                    if let Some(Initializer::Expr(e)) = &d.init {
                        if !self.bce_scan_expr(e, ivar, mods, out) { return false; }
                    } else if d.init.is_some() { return false; } // aggregate init — bail
                }
                true
            }
            Stmt::If { cond, then, else_, .. } => {
                self.bce_scan_expr(cond, ivar, mods, out)
                    && self.bce_scan(then, ivar, mods, out)
                    && else_.as_ref().map_or(true, |e| self.bce_scan(e, ivar, mods, out))
            }
            Stmt::For { init, cond, post, body, .. } => {
                if let Some(fi) = init {
                    match fi {
                        ForInit::Decl(Decl::Var { declarators, .. }) => for d in declarators {
                            mods.insert(d.name.clone());
                            if let Some(Initializer::Expr(e)) = &d.init {
                                if !self.bce_scan_expr(e, ivar, mods, out) { return false; }
                            }
                        },
                        ForInit::Expr(e) => if !self.bce_scan_expr(e, ivar, mods, out) { return false; },
                        _ => return false,
                    }
                }
                cond.as_ref().map_or(true, |c| self.bce_scan_expr(c, ivar, mods, out))
                    && post.as_ref().map_or(true, |p| self.bce_scan_expr(p, ivar, mods, out))
                    && self.bce_scan(body, ivar, mods, out)
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } =>
                self.bce_scan_expr(cond, ivar, mods, out) && self.bce_scan(body, ivar, mods, out),
            Stmt::Break(_) | Stmt::Continue(_) => true,
            _ => false, // return/switch/match/goto/defer/... — bail (conservative)
        }
    }

    /// Expr half of [`bce_scan`]: records assignment/address-of targets in `mods`
    /// and affine fat-pointer accesses in `out`. Returns false (bail) on a call or
    /// any unhandled expression form.
    fn bce_scan_expr(&self, e: &Expr, ivar: &str,
        mods: &mut std::collections::HashSet<String>,
        out: &mut Vec<(String, Expr, Option<Expr>)>) -> bool {
        use crate::ast::{ExprKind as E, UnOpKind};
        match &e.kind {
            E::IntLit(..) | E::UIntLit(..) | E::Ident(_) | E::StringLit(..)
            // A SIC decimal literal is `DecimalLit`, not C's `FloatLit` — both are
            // pure leaf constants. Missing `DecimalLit` made `bce_scan` bail on any
            // SIC loop body with a float constant (`(d2 + 1.0) * 0.5` in n-body),
            // so loop-BCE never hoisted its bounds checks and the fat-pointer size
            // loads spilled the hot loop's registers (3x slower than the C frontend).
            | E::CharLit(_) | E::FloatLit(..) | E::DecimalLit(..) | E::BoolLit(_) => true,
            E::BinOp { lhs, rhs, .. } =>
                self.bce_scan_expr(lhs, ivar, mods, out) && self.bce_scan_expr(rhs, ivar, mods, out),
            E::Assign { lhs, rhs, .. } => {
                // record the assigned name; nested lvalues (a[i]=, *p=) don't name a
                // scalar we track, but be safe: collect any ident at the lhs root.
                if let E::Ident(n) = &lhs.kind { mods.insert(n.clone()); }
                self.bce_scan_expr(lhs, ivar, mods, out) && self.bce_scan_expr(rhs, ivar, mods, out)
            }
            E::PreInc { expr, .. } | E::PostInc { expr, .. } => {
                if let E::Ident(n) = &expr.kind { mods.insert(n.clone()); }
                self.bce_scan_expr(expr, ivar, mods, out)
            }
            E::Unary { op, expr } => {
                if *op == UnOpKind::Addr { if let E::Ident(n) = &expr.kind { mods.insert(n.clone()); } }
                self.bce_scan_expr(expr, ivar, mods, out)
            }
            E::Index { base, index } => {
                // Record a fat-pointer affine access; always recurse to catch nested
                // accesses / assignments inside the index or base.
                if let E::Ident(arr) = &base.kind {
                    if self.fat_locals.contains(arr) {
                        if let Some(x) = affine_x(index, ivar) {
                            out.push((arr.clone(), (**index).clone(), x));
                        }
                    }
                }
                self.bce_scan_expr(base, ivar, mods, out) && self.bce_scan_expr(index, ivar, mods, out)
            }
            E::Cast { expr, .. } => self.bce_scan_expr(expr, ivar, mods, out),
            E::Ternary { cond, then, else_ } =>
                self.bce_scan_expr(cond, ivar, mods, out)
                    && self.bce_scan_expr(then, ivar, mods, out)
                    && self.bce_scan_expr(else_, ivar, mods, out),
            E::Field { base, .. } | E::Arrow { base, .. } => self.bce_scan_expr(base, ivar, mods, out),
            E::Comma(lhs, rhs) =>
                self.bce_scan_expr(lhs, ivar, mods, out) && self.bce_scan_expr(rhs, ivar, mods, out),
            _ => false, // Call, New, Lambda, … — bail (conservative)
        }
    }

    /// sic range-`for` (sic.md §"Iterators"): `for (item : iterable) body`. Desugars
    /// to existing constructs and lowers that, so break/continue/scopes/cleanups all
    /// come for free. Dispatches on the iterable:
    ///   - an enum type name → a counted loop over its variant values;
    ///   - an array/slice (incl. `string.utf8`) → a counted loop over `[i]`;
    ///   - a `string` → its code points (`.utf8`, yielding `u8char`);
    ///   - a struct with a `next()` method → the `Iterator<T>` protocol loop.
    fn lower_foreach(&mut self, ty: &QualType, name: &str, iterable: &Expr, body: &Stmt, sp: &crate::lexer::Span) -> Result<()> {
        use crate::ast::BinOpKind;
        let sp = sp.clone();
        let mk = |k: ExprKind| Expr { kind: k, span: sp.clone() };
        let ident = |n: &str| Expr { kind: ExprKind::Ident(n.to_string()), span: sp.clone() };
        let ulong = || QualType { ty: AstType::Long { signed: false }, qualifiers: vec![], storage: None };

        // `for (unsigned long i = 0; i < <len>; ++i) { <item_ty> name = <elem>; body }`
        let counted = |iname: &str, item_ty: QualType, len: Expr, elem: Expr, body: Stmt, sp: &crate::lexer::Span| -> Stmt {
            let zero = Expr { kind: ExprKind::IntLit(0, false), span: sp.clone() };
            let idx = Decl::Var {
                base_ty: ulong(),
                declarators: vec![crate::ast::Declarator { name: iname.to_string(), ty: ulong(), init: Some(Initializer::Expr(zero)), cleanup: None, span: sp.clone() }],
                weak: false, thread_local: false, span: sp.clone(),
            };
            let cond = Expr { kind: ExprKind::BinOp { op: BinOpKind::Lt, lhs: Box::new(Expr { kind: ExprKind::Ident(iname.to_string()), span: sp.clone() }), rhs: Box::new(len) }, span: sp.clone() };
            let post = Expr { kind: ExprKind::PreInc { inc: true, expr: Box::new(Expr { kind: ExprKind::Ident(iname.to_string()), span: sp.clone() }) }, span: sp.clone() };
            let item = Stmt::Decl(Decl::Var {
                base_ty: item_ty.clone(),
                declarators: vec![crate::ast::Declarator { name: name.to_string(), ty: item_ty, init: Some(Initializer::Expr(elem)), cleanup: None, span: sp.clone() }],
                weak: false, thread_local: false, span: sp.clone(),
            });
            let inner = Stmt::Block(vec![item, body], sp.clone());
            Stmt::For { init: Some(ForInit::Decl(idx)), cond: Some(cond), post: Some(post), body: Box::new(inner), span: sp.clone() }
        };

        // `auto <name> = <init>;` — an inferred-type local (used to materialize the
        // `.keys`/`.values` lists a container iteration walks).
        let auto_local = |lname: &str, init: Expr, sp: &crate::lexer::Span| -> Stmt {
            let at = QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) };
            Stmt::Decl(Decl::Var {
                base_ty: at.clone(),
                declarators: vec![crate::ast::Declarator { name: lname.to_string(), ty: at, init: Some(Initializer::Expr(init)), cleanup: None, span: sp.clone() }],
                weak: false, thread_local: false, span: sp.clone(),
            })
        };
        let field = |b: &Expr, n: &str, sp: &crate::lexer::Span| Expr { kind: ExprKind::Field { base: Box::new(b.clone()), name: n.to_string() }, span: sp.clone() };
        let index = |b: Expr, i: Expr, sp: &crate::lexer::Span| Expr { kind: ExprKind::Index { base: Box::new(b), index: Box::new(i) }, span: sp.clone() };

        let uid = self.gensym; self.gensym += 1;
        let iname = format!("__fe_i_{}", uid);

        // (1) Enum type name: iterate the variant values.
        if let ExprKind::Ident(id) = &iterable.kind {
            let canon = if self.lowerer.c_enum_defs.contains_key(id) { Some(id.clone()) }
                        else { self.lowerer.c_enum_alias.get(id).cloned() };
            if let Some(canon) = canon {
                let vals: Vec<i64> = self.lowerer.c_enum_defs.get(&canon).cloned().unwrap_or_default()
                    .iter().map(|(_, v)| *v).collect();
                let vname = format!("__fe_vals_{}", uid);
                let len = vals.len();
                // `int __fe_vals_N[] = { v0, v1, … };`
                let items: Vec<crate::ast::InitItem> = vals.iter().map(|v| crate::ast::InitItem {
                    designators: vec![],
                    init: Initializer::Expr(Expr { kind: ExprKind::IntLit(*v, false), span: sp.clone() }),
                }).collect();
                let arr_ty = QualType { ty: AstType::Array { base: Box::new(QualType::new(AstType::Int { signed: true })), size: Some(Box::new(mk(ExprKind::IntLit(len as i64, false)))) }, qualifiers: vec![], storage: None };
                let arr_decl = Stmt::Decl(Decl::Var {
                    base_ty: QualType::new(AstType::Int { signed: true }),
                    declarators: vec![crate::ast::Declarator { name: vname.clone(), ty: arr_ty, init: Some(Initializer::List(items)), cleanup: None, span: sp.clone() }],
                    weak: false, thread_local: false, span: sp.clone(),
                });
                // item = (enum Canon) __fe_vals_N[i]
                let elem_raw = mk(ExprKind::Index { base: Box::new(ident(&vname)), index: Box::new(ident(&iname)) });
                let enum_ast = AstType::Enum(crate::ast::EnumDef { name: Some(canon.clone()), variants: None, packed: false, type_params: vec![], private: false, span: sp.clone() });
                let item_ty = QualType { ty: enum_ast, qualifiers: vec![], storage: None };
                let elem = mk(ExprKind::Cast { ty: item_ty.clone(), expr: Box::new(elem_raw) });
                let use_ty = if matches!(ty.storage, Some(StorageClass::Auto)) { item_ty } else { ty.clone() };
                let loop_ = counted(&iname, use_ty, mk(ExprKind::IntLit(len as i64, false)), elem, body.clone(), &sp);
                return self.lower_stmt(&Stmt::Block(vec![arr_decl, loop_], sp.clone()));
            }
        }

        // (2a) A `.keys`/`.values` projection (sic.md §"Iterators") iterates the
        // materialized `list` PLAINLY — each key/value directly, not a `tuple`.
        if self.is_container_projection(iterable) {
            let pname = format!("__fe_proj_{}", uid);
            let proj_decl = auto_local(&pname, iterable.clone(), &sp);
            let len = field(&ident(&pname), "length", &sp);
            let elem = index(ident(&pname), ident(&iname), &sp);
            let loop_ = counted(&iname, ty.clone(), len, elem, body.clone(), &sp);
            return self.lower_stmt(&Stmt::Block(vec![proj_decl, loop_], sp.clone()));
        }

        let ity = self.infer_expr_type(iterable)?;
        let is_set = super::types::is_set(&ity)
            || matches!(&ity, Type::Pointer(i) if super::types::is_set(i));
        let is_dict = super::types::is_dict(&ity)
            || matches!(&ity, Type::Pointer(i) if super::types::is_dict(i));
        let is_list = super::types::is_list(&ity)
            || matches!(&ity, Type::Pointer(i) if super::types::is_list(i));

        // (2b) `set<T>` (sic.md §"Set"): iterate its elements (keys) directly.
        if is_set {
            let kname = format!("__fe_k_{}", uid);
            let kdecl = auto_local(&kname, field(iterable, "keys", &sp), &sp);
            let len = field(&ident(&kname), "length", &sp);
            let elem = index(ident(&kname), ident(&iname), &sp);
            let loop_ = counted(&iname, ty.clone(), len, elem, body.clone(), &sp);
            return self.lower_stmt(&Stmt::Block(vec![kdecl, loop_], sp.clone()));
        }

        // (2c) `dict<K,V>` (sic.md §"Dict"): each step yields `tuple(key, value)`.
        if is_dict {
            let kname = format!("__fe_k_{}", uid);
            let vname = format!("__fe_v_{}", uid);
            let kdecl = auto_local(&kname, field(iterable, "keys", &sp), &sp);
            let vdecl = auto_local(&vname, field(iterable, "values", &sp), &sp);
            let len = field(&ident(&kname), "length", &sp);
            let kv = Expr { kind: ExprKind::TupleExpr(vec![
                index(ident(&kname), ident(&iname), &sp),
                index(ident(&vname), ident(&iname), &sp),
            ]), span: sp.clone() };
            let loop_ = counted(&iname, ty.clone(), len, kv, body.clone(), &sp);
            return self.lower_stmt(&Stmt::Block(vec![kdecl, vdecl, loop_], sp.clone()));
        }

        // (2d) `list<T>` (sic.md §"List"): each step yields `tuple(index, value)`.
        if is_list {
            let len = field(iterable, "length", &sp);
            let iv = Expr { kind: ExprKind::TupleExpr(vec![
                ident(&iname),
                index(iterable.clone(), ident(&iname), &sp),
            ]), span: sp.clone() };
            let loop_ = counted(&iname, ty.clone(), len, iv, body.clone(), &sp);
            return self.lower_stmt(&loop_);
        }

        // (3) string → its UTF-8 code points (`u8char`), via `.utf8` (a slice).
        if super::types::is_sic_string(&ity) {
            let sname = format!("__fe_src_{}", uid);
            let src_decl = Stmt::Decl(Decl::Var {
                base_ty: QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) },
                declarators: vec![crate::ast::Declarator { name: sname.clone(), ty: QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) }, init: Some(Initializer::Expr(mk(ExprKind::Field { base: Box::new(iterable.clone()), name: "utf8".to_string() }))), cleanup: None, span: sp.clone() }],
                weak: false, thread_local: false, span: sp.clone(),
            });
            let inner = Stmt::ForEach { ty: ty.clone(), name: name.to_string(), iterable: ident(&sname), body: Box::new(body.clone()), span: sp.clone() };
            return self.lower_stmt(&Stmt::Block(vec![src_decl, inner], sp.clone()));
        }

        // (4) A struct with a `next()` method → the Iterator<T> protocol loop.
        if let Type::Struct(st) = &ity {
            if let Some(sn) = &st.name {
                if self.lowerer.struct_methods.contains_key(&(sn.clone(), "next".to_string())) {
                    let itname = format!("__fe_it_{}", uid);
                    let stepname = format!("__fe_step_{}", uid);
                    // auto __fe_it = <iterable>;   (a mutable copy the loop advances)
                    let it_decl = Stmt::Decl(Decl::Var {
                        base_ty: QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) },
                        declarators: vec![crate::ast::Declarator { name: itname.clone(), ty: QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) }, init: Some(Initializer::Expr(iterable.clone())), cleanup: None, span: sp.clone() }],
                        weak: false, thread_local: false, span: sp.clone(),
                    });
                    // auto __fe_step = __fe_it.next();
                    let call = mk(ExprKind::Call { func: Box::new(mk(ExprKind::Field { base: Box::new(ident(&itname)), name: "next".to_string() })), args: vec![] });
                    let step_decl = Stmt::Decl(Decl::Var {
                        base_ty: QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) },
                        declarators: vec![crate::ast::Declarator { name: stepname.clone(), ty: QualType { ty: AstType::Int { signed: true }, qualifiers: vec![], storage: Some(StorageClass::Auto) }, init: Some(Initializer::Expr(call)), cleanup: None, span: sp.clone() }],
                        weak: false, thread_local: false, span: sp.clone(),
                    });
                    // match (__fe_step) { Next(name): { body }  Stop: break; }
                    let arm_next = crate::ast::MatchArm { variant: Some("Next".to_string()), binding: Some(name.to_string()), body: Box::new(body.clone()), span: sp.clone() };
                    let arm_stop = crate::ast::MatchArm { variant: Some("Stop".to_string()), binding: None, body: Box::new(Stmt::Break(sp.clone())), span: sp.clone() };
                    let match_stmt = Stmt::Match { scrutinee: ident(&stepname), arms: vec![arm_next, arm_stop], span: sp.clone() };
                    let loop_body = Stmt::Block(vec![step_decl, match_stmt], sp.clone());
                    let inf = Stmt::For { init: None, cond: None, post: None, body: Box::new(loop_body), span: sp.clone() };
                    return self.lower_stmt(&Stmt::Block(vec![it_decl, inf], sp.clone()));
                }
            }
        }

        // (2) Array / slice (incl. a `string.utf8` result): counted loop over `[i]`,
        // yielding each element directly. sic arrays and slices both answer
        // `.length` and `[i]`.
        if matches!(&ity, Type::Array { .. }) || super::types::is_u8char_arr(&ity) {
            let len = mk(ExprKind::Field { base: Box::new(iterable.clone()), name: "length".to_string() });
            let elem = mk(ExprKind::Index { base: Box::new(iterable.clone()), index: Box::new(ident(&iname)) });
            let use_ty = ty.clone();
            let loop_ = counted(&iname, use_ty, len, elem, body.clone(), &sp);
            return self.lower_stmt(&loop_);
        }

        Err(CompileError::at(
            "range-`for` needs an array, string, enum, dict, set, list, or a struct with a `next()` method".to_string(),
            sp.file.clone(), sp.line, sp.col))
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
                    // sic type safety: a declared binding type must match the payload's
                    // pointer/value shape — `File f = <Opened(File*)> else …` (a `File`
                    // value bound from a `File*` payload) is an error; use `File *f`.
                    if let Some(dty) = decl_ty {
                        if let Ok(declared) = self.lower_type(dty) {
                            if let Some(msg) = ptr_value_mismatch(&declared, &pty) {
                                return Err(CompileError::at(msg, sp.file.clone(), sp.line, sp.col));
                            }
                        }
                    }
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
        self.lower_match_into(scrutinee, arms, sp, None)
    }

    /// Lower a `match`. `result = Some((slot, ty))` puts it in expression mode: each
    /// arm's value (its trailing expression) is coerced to `ty` and stored into
    /// `slot`; `None` is statement mode (arm bodies are ordinary statements).
    fn lower_match_into(&mut self, scrutinee: &Expr, arms: &[crate::ast::MatchArm], sp: &crate::lexer::Span,
                        result: Option<(Val, Type)>) -> Result<()> {
        let sty = self.infer_expr_type(scrutinee)?;
        // sic RTTI (sic.md §"Match"): `match (type(x)) { string: …; int: …; _: … }`
        // dispatches on the value's runtime KIND category — no hand-written kind
        // table needed; the compiler owns the vocabulary.
        if self.is_sic() && super::types::is_type_info(&sty) {
            return self.lower_match_on_type(scrutinee, arms, sp, result);
        }
        // sic: `match` on a plain (payload-less) C enum dispatches on the value
        // against each variant's discriminant — a `switch` with variant-name labels.
        if self.is_sic() {
            if let EnumClass::Enum(ename) = self.classify_enum(scrutinee) {
                if self.lowerer.c_enum_defs.contains_key(&ename) {
                    return self.lower_match_c_enum(scrutinee, arms, &ename, sp, result);
                }
            }
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

        // sic (sic.md §"Match"): a `match` must be exhaustive — every variant, or a
        // `_`. Missing variants are a compile error (not a runtime abort).
        if wildcard.is_none() {
            let covered: std::collections::HashSet<&str> =
                arms.iter().filter_map(|a| a.variant.as_deref()).collect();
            let missing: Vec<&str> = info.variants.iter()
                .map(|v| v.name.as_str()).filter(|n| !covered.contains(n)).collect();
            if !missing.is_empty() {
                return Err(CompileError::at(
                    format!("non-exhaustive match on `{}`: missing {} — cover {} or add a `_` arm",
                        ename, missing.join(", "),
                        if missing.len() == 1 { "it" } else { "them" }),
                    sp.file.clone(), sp.line, sp.col));
            }
        }

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
            self.lower_match_arm_body(&arm.body, &result)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
            self.switch_to_block(next_bb);
        }

        // Fallback: `_` arm, or a runtime abort on an unmatched variant.
        if let Some(w) = wildcard {
            self.enter_scope();
            self.lower_match_arm_body(&w.body, &result)?;
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

    /// sic `match` on a plain (payload-less) C enum: dispatch the value against each
    /// variant's discriminant. Arms carry no payload binding. A `_` arm is the
    /// fallback; without one an unmatched value aborts (like a tagged `match`).
    fn lower_match_c_enum(&mut self, scrutinee: &Expr, arms: &[crate::ast::MatchArm], ename: &str, sp: &crate::lexer::Span,
                          result: Option<(Val, Type)>) -> Result<()> {
        let v = self.lower_expr(scrutinee)?;
        let val = self.coerce(v, &Type::i32())?;
        let end_bb = self.new_block_after_current();
        let wildcard = arms.iter().find(|a| a.variant.is_none());

        // sic (sic.md §"Match"): exhaustiveness — cover every variant or use `_`.
        if wildcard.is_none() {
            if let Some(variants) = self.lowerer.c_enum_defs.get(ename) {
                let covered: std::collections::HashSet<&str> =
                    arms.iter().filter_map(|a| a.variant.as_deref()).collect();
                let missing: Vec<&str> = variants.iter()
                    .map(|(n, _)| n.as_str()).filter(|n| !covered.contains(n)).collect();
                if !missing.is_empty() {
                    return Err(CompileError::at(
                        format!("non-exhaustive match on `{}`: missing {} — cover {} or add a `_` arm",
                            ename, missing.join(", "),
                            if missing.len() == 1 { "it" } else { "them" }),
                        sp.file.clone(), sp.line, sp.col));
                }
            }
        }

        for arm in arms.iter().filter(|a| a.variant.is_some()) {
            let vname = arm.variant.as_ref().unwrap();
            // Resolve the discriminant within the SCRUTINEE's enum, not the global
            // `enum_consts` map (which is keyed by bare variant name, so a same-named
            // variant of another enum — e.g. a tagged `FileStatus::Read` vs
            // `OpenMode::Read` — would clobber it and make the arm compare against
            // the wrong tag).
            let disc = self.lowerer.c_enum_defs.get(ename)
                .and_then(|vs| vs.iter().find(|(n, _)| n == vname).map(|(_, d)| *d))
                .ok_or_else(|| CompileError::at(
                    format!("enum '{}' has no variant '{}'", ename, vname), sp.file.clone(), sp.line, sp.col))?;
            if arm.binding.is_some() {
                return Err(CompileError::at(
                    format!("variant '{}::{}' carries no payload to bind", ename, vname),
                    sp.file.clone(), sp.line, sp.col));
            }
            let arm_bb = self.new_block_after_current();
            let next_bb = self.new_block_after_current();
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: val.clone(), rhs: Constant::int(disc), ty: Type::i32() });
            self.set_terminator(Terminator::CondJump { cond: Val::Local(eq), then_bb: arm_bb, else_bb: next_bb });
            self.switch_to_block(arm_bb);
            self.enter_scope();
            self.lower_match_arm_body(&arm.body, &result)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
            self.switch_to_block(next_bb);
        }

        if let Some(w) = wildcard {
            self.enter_scope();
            self.lower_match_arm_body(&w.body, &result)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
        } else {
            let fref = self.lowerer.ensure_match_fail_fn();
            self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
            self.set_terminator(Terminator::Jump(end_bb));
        }
        self.switch_to_block(end_bb);
        Ok(())
    }

    /// sic `match (type(x)) { <type/category>: … ; _: … }` — dispatch on the value's
    /// runtime kind. An arm pattern is a type name or a kind category (`int`,
    /// `float`, `ptr`, …); it matches when `type(x).kind` is in that category, so
    /// `int` catches every signed-int width and `float` every float. Exact-type
    /// tests remain available with `type(x) == i64`.
    fn lower_match_on_type(&mut self, scrutinee: &Expr, arms: &[crate::ast::MatchArm], sp: &crate::lexer::Span,
                           result: Option<(Val, Type)>) -> Result<()> {
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
            self.lower_match_arm_body(&arm.body, &result)?;
            self.exit_scope();
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(end_bb)); }
            self.switch_to_block(next_bb);
        }

        if let Some(w) = wildcard {
            self.enter_scope();
            self.lower_match_arm_body(&w.body, &result)?;
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

    /// Lower a match arm body. In statement mode (`result == None`) it is an ordinary
    /// statement. In expression mode it must yield a value: an expression-statement
    /// `expr;`, or a `{ …; expr }` block whose last statement is an expression — that
    /// value is coerced to the result type and stored into the slot. A diverging arm
    /// (`return`/`break`) yields no value and is lowered as-is.
    fn lower_match_arm_body(&mut self, body: &Stmt, result: &Option<(Val, Type)>) -> Result<()> {
        let (slot, rty) = match result {
            None => return self.lower_stmt(body),
            Some((s, t)) => (s.clone(), t.clone()),
        };
        let store_value = |this: &mut Self, e: &Expr| -> Result<()> {
            let v = this.lower_expr(e)?;
            let c = this.coerce(v, &rty)?;
            this.push_instr(Instr::Store { val: c, ptr: slot.clone() });
            Ok(())
        };
        match body {
            Stmt::Expr(e, _) => store_value(self, e)?,
            Stmt::Block(stmts, _) => {
                self.enter_scope();
                let n = stmts.len();
                for (i, s) in stmts.iter().enumerate() {
                    if i + 1 == n {
                        if let Stmt::Expr(e, _) = s { store_value(self, e)?; continue; }
                    }
                    self.lower_stmt(s)?;
                }
                self.exit_scope();
            }
            // A diverging arm (return/break/…): no value to store.
            other => self.lower_stmt(other)?,
        }
        Ok(())
    }

    /// sic `match` as an expression (sic.md §"Match"): allocate a result slot, run
    /// the dispatch in expression mode (each arm stores its value), and yield the
    /// slot's value. The result type is that of the first value-producing arm.
    pub(crate) fn lower_match_expr(&mut self, scrutinee: &Expr, arms: &[crate::ast::MatchArm], sp: &crate::lexer::Span) -> Result<Val> {
        let rty = self.match_result_type(arms);
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: rty.clone(), align: None });
        self.lower_match_into(scrutinee, arms, sp, Some((Val::Local(slot), rty.clone())))?;
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: Val::Local(slot), ty: rty.clone() });
        self.val_types.insert(d.0, rty);
        Ok(Val::Local(d))
    }

    /// The value type of an expression `match`: the first arm whose value expression
    /// infers a concrete type (a `_`/literal arm usually provides it), else `int`.
    pub(crate) fn match_result_type(&self, arms: &[crate::ast::MatchArm]) -> Type {
        for a in arms {
            if let Some(e) = arm_value_expr(&a.body) {
                if let Ok(t) = self.infer_expr_type(e) {
                    if t != Type::Void { return t; }
                }
            }
        }
        Type::i32()
    }

    // ─── Type coercion / helpers ─────────────────────────────────────────────

    pub fn coerce(&mut self, val: Val, target: &Type) -> Result<Val> {
        let src_ty = self.val_type(&val);
        if src_ty == *target {
            // A same-type coercion is normally a no-op, but a bare integer
            // `Val::Const` carries only a heuristic width, so its value can be out
            // of range for that width (e.g. 0x80000000 is called `i32` though it
            // does not fit). Re-fold it into range so a LATER widen sign-extends
            // correctly — `(long long)(int)0x80000000` must be -2^31, not +2^31.
            // The width is unchanged, so the store width is unaffected (unlike
            // narrowing, which must keep flowing through the Cast path below to
            // produce a correctly-typed narrow value).
            if let (Some(iv), Type::Int { .. }) = (const_int_value(&val), target) {
                let folded = super::apply_int_cast(iv, target);
                if folded != iv {
                    let signed = matches!(target, Type::Int { signed: true, .. });
                    return Ok(if signed { Constant::int(folded) } else { Constant::uint(folded as u64) });
                }
            }
            return Ok(val);
        }

        match (&src_ty, target) {
            (Type::Void, _) | (_, Type::Void) => return Ok(val),
            _ => {}
        }

        // A tagged-enum value (a `{tag, payload}` struct, passed as a pointer) has
        // no meaningful conversion to a scalar — its bytes are not the payload. This
        // used to silently reinterpret the struct as an integer (`u64 n = Size(f);`
        // where `Size` returns a `FileStatus`), producing garbage. Require an
        // explicit `match`/unwrap instead. (SIC-only: tagged enums don't exist in C,
        // and a payload-less C enum is an `Int`, not a struct, so `E → int` is
        // unaffected.)
        if self.is_sic() && matches!(target,
            Type::Int { .. } | Type::Float32 | Type::Float64 | Type::Float80 | Type::Bool)
        {
            let tagged = match &src_ty {
                Type::Struct(_) => self.is_tagged_enum_struct(&src_ty),
                Type::Pointer(inner) => self.is_tagged_enum_struct(inner),
                _ => false,
            };
            if tagged {
                let en = match &src_ty {
                    Type::Struct(st) => st.name.clone(),
                    Type::Pointer(inner) => match inner.as_ref() { Type::Struct(st) => st.name.clone(), _ => None },
                    _ => None,
                }.unwrap_or_else(|| "enum".into());
                return Err(CompileError::new(format!(
                    "cannot convert tagged enum '{}' to a scalar — unwrap it with a `match` (or `{}::Variant(x)`) first",
                    en, en)));
            }
        }

        // sic (sic.md std): an `any` implicitly converts to the assigned type — read
        // its boxed slot and reinterpret it as `target`. Applies wherever a value is
        // coerced (init, assignment, return, arguments), so `int y = anyval;` and
        // `for (int v : list<any>.values)` work without an explicit `(int)` cast.
        // (Boxing the other way, `T → any`, is handled at the box sites, not here.)
        if self.is_sic() && super::types::is_any(&src_ty) && !super::types::is_any(target) {
            return self.unbox_any_val(val, target);
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
// ── Tail-call optimization (self-recursion → loop) ────────────────────────────
//
// Rewrite a SELF-recursive function's tail calls `return f(args)` into a jump back
// to the function entry with the parameters reassigned, so deep tail recursion runs
// in O(1) stack as a loop (no stack-overflow crash) and avoids the call overhead.
// Gated to sic and conservative — see `tco_rewrite`.

/// A local of this type can be re-initialized on each loop iteration with no cleanup
/// obligation (so jumping back to the entry never skips a destructor). Scalars and
/// raw pointers only; aggregates / strings / containers / bigint / fixed / weak are
/// excluded (they may own resources).
fn tco_trivial_ty(t: &crate::ast::AstType) -> bool {
    use crate::ast::AstType::*;
    matches!(t, Void | Char { .. } | Short { .. } | Int { .. } | Long { .. }
        | LongLong { .. } | Float | Double | LongDouble | Bool | Pointer { .. })
}

/// True if `e` is exactly `name(args...)` with `arity` arguments — a self-call that,
/// as a whole `return` expression, sits in tail position.
fn is_self_tail_call(e: &Expr, name: &str, arity: usize) -> bool {
    matches!(&e.kind, ExprKind::Call { func, args }
        if args.len() == arity && matches!(&func.kind, ExprKind::Ident(n) if n == name))
}

/// Expression eligibility for TCO: bail (set `ok=false`) on any address-of (`&x` /
/// `@x`) or `new`, which would make the reused param/local storage observably
/// different from fresh per-call storage. Full traversal (mirrors scan_mutated_expr).
fn tco_scan_expr(e: &Expr, ok: &mut bool) {
    use ExprKind::*;
    if !*ok { return; }
    match &e.kind {
        Unary { op: crate::ast::UnOpKind::Addr, .. } | Ref { .. } | New { .. } => { *ok = false; return; }
        _ => {}
    }
    match &e.kind {
        BinOp { lhs, rhs, .. } | Comma(lhs, rhs) | Assign { lhs, rhs, .. } | Swap { lhs, rhs } => {
            tco_scan_expr(lhs, ok); tco_scan_expr(rhs, ok);
        }
        Unary { expr, .. } | PreInc { expr, .. } | PostInc { expr, .. }
        | SizeofExpr(expr) | AlignofExpr(expr) | Cast { expr, .. } => tco_scan_expr(expr, ok),
        Ternary { cond, then, else_ } | ChooseExpr { cond, then, else_ } => {
            tco_scan_expr(cond, ok); tco_scan_expr(then, ok); tco_scan_expr(else_, ok);
        }
        Elvis { cond, else_ } => { tco_scan_expr(cond, ok); tco_scan_expr(else_, ok); }
        Call { func, args } => { tco_scan_expr(func, ok); for a in args { tco_scan_expr(a, ok); } }
        Index { base, index } => { tco_scan_expr(base, ok); tco_scan_expr(index, ok); }
        Slice { base, lo, hi } => {
            tco_scan_expr(base, ok);
            if let Some(x) = lo { tco_scan_expr(x, ok); }
            if let Some(x) = hi { tco_scan_expr(x, ok); }
        }
        Field { base, .. } | Arrow { base, .. } => tco_scan_expr(base, ok),
        Generic { controlling, assocs } => { tco_scan_expr(controlling, ok); for (_, x) in assocs { tco_scan_expr(x, ok); } }
        StmtExpr(stmts) => for s in stmts { tco_scan_stmt(s, "", usize::MAX, ok, &mut false); },
        VaStart { list, last } => { tco_scan_expr(list, ok); tco_scan_expr(last, ok); }
        VaArg { list, .. } | VaEnd { list } => tco_scan_expr(list, ok),
        VaCopy { dst, src } => { tco_scan_expr(dst, ok); tco_scan_expr(src, ok); }
        _ => {}
    }
}

/// Statement eligibility scan for TCO: bail on `defer` / `del` / a non-trivial local
/// declaration (would need cleanup the entry-jump skips), and on any address-of/new
/// (via `tco_scan_expr`). Records `has_tail` when a `return self(args)` is found.
fn tco_scan_stmt(s: &Stmt, name: &str, arity: usize, ok: &mut bool, has_tail: &mut bool) {
    if !*ok { return; }
    match s {
        Stmt::Defer(..) | Stmt::Delete(..) => *ok = false,
        Stmt::Decl(Decl::Var { declarators, .. }) => for d in declarators {
            // A local shadowing the function name would make `name(args)` an indirect
            // call, not self-recursion — don't optimize such a function.
            if d.name == name { *ok = false; return; }
            if !tco_trivial_ty(&d.ty.ty) { *ok = false; return; }
            if let Some(Initializer::Expr(e)) = &d.init { tco_scan_expr(e, ok); }
            else if d.init.is_some() { *ok = false; return; }
        },
        Stmt::Return(Some(e), _) => {
            if is_self_tail_call(e, name, arity) { *has_tail = true; }
            else { tco_scan_expr(e, ok); }
        }
        Stmt::Expr(e, _) => tco_scan_expr(e, ok),
        Stmt::Block(ss, _) => for x in ss { tco_scan_stmt(x, name, arity, ok, has_tail); },
        Stmt::If { cond, then, else_, .. } => {
            tco_scan_expr(cond, ok);
            tco_scan_stmt(then, name, arity, ok, has_tail);
            if let Some(e) = else_ { tco_scan_stmt(e, name, arity, ok, has_tail); }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { body, cond, .. } => {
            tco_scan_expr(cond, ok); tco_scan_stmt(body, name, arity, ok, has_tail);
        }
        Stmt::For { init, cond, post, body, .. } => {
            match init {
                Some(ForInit::Expr(e)) => tco_scan_expr(e, ok),
                Some(ForInit::Decl(Decl::Var { declarators, .. })) => for d in declarators {
                    if !tco_trivial_ty(&d.ty.ty) { *ok = false; return; }
                    if let Some(Initializer::Expr(e)) = &d.init { tco_scan_expr(e, ok); }
                },
                _ => {}
            }
            if let Some(e) = cond { tco_scan_expr(e, ok); }
            if let Some(e) = post { tco_scan_expr(e, ok); }
            tco_scan_stmt(body, name, arity, ok, has_tail);
        }
        Stmt::Switch { val, body, .. } => { tco_scan_expr(val, ok); tco_scan_stmt(body, name, arity, ok, has_tail); }
        Stmt::Match { scrutinee, arms, .. } => {
            tco_scan_expr(scrutinee, ok);
            for a in arms { tco_scan_stmt(&a.body, name, arity, ok, has_tail); }
        }
        Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) | Stmt::Default(body, _)
        | Stmt::Label(_, body, _) => tco_scan_stmt(body, name, arity, ok, has_tail),
        _ => {}
    }
}

/// Replace each `return self(args)` in `s` with `{ Ti __sic_tco_i = args_i; …;
/// p_i = __sic_tco_i; …; goto <label>; }` — evaluate every argument into a fresh
/// temp of the parameter's type first (so an argument reading an as-yet-unreassigned
/// parameter still sees the old value), then reassign the parameters and jump back.
fn tco_replace(s: &mut Stmt, name: &str, params: &[AstParam], label: &str) {
    match s {
        Stmt::Return(opt, sp) => {
            let is_tc = opt.as_ref().map_or(false, |e| is_self_tail_call(e, name, params.len()));
            if is_tc {
                let sp = sp.clone();
                let args = match opt.take() { Some(Expr { kind: ExprKind::Call { args, .. }, .. }) => args, _ => unreachable!() };
                let mut stmts: Vec<Stmt> = Vec::new();
                // temps
                for (i, a) in args.iter().enumerate() {
                    let tn = format!("__sic_tco_{}", i);
                    stmts.push(Stmt::Decl(Decl::Var {
                        base_ty: params[i].ty.clone(),
                        declarators: vec![crate::ast::Declarator {
                            name: tn, ty: params[i].ty.clone(),
                            init: Some(Initializer::Expr(a.clone())), cleanup: None, span: sp.clone(),
                        }],
                        weak: false, thread_local: false, span: sp.clone(),
                    }));
                }
                // reassign params from temps
                for (i, p) in params.iter().enumerate() {
                    let pn = p.name.clone().unwrap();
                    let lhs = Box::new(Expr::new(ExprKind::Ident(pn), sp.clone()));
                    let rhs = Box::new(Expr::new(ExprKind::Ident(format!("__sic_tco_{}", i)), sp.clone()));
                    stmts.push(Stmt::Expr(Expr::new(ExprKind::Assign { op: None, lhs, rhs }, sp.clone()), sp.clone()));
                }
                stmts.push(Stmt::Goto(label.to_string(), sp.clone()));
                *s = Stmt::Block(stmts, sp);
            }
        }
        Stmt::Block(ss, _) => for x in ss { tco_replace(x, name, params, label); },
        Stmt::If { then, else_, .. } => {
            tco_replace(then, name, params, label);
            if let Some(e) = else_ { tco_replace(e, name, params, label); }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. }
        | Stmt::Switch { body, .. } | Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _)
        | Stmt::Default(body, _) | Stmt::Label(_, body, _) => tco_replace(body, name, params, label),
        Stmt::Match { arms, .. } => for a in arms { tco_replace(&mut a.body, name, params, label); },
        _ => {}
    }
}

/// Tail-call optimization entry point (see the section comment). Returns a rewritten
/// body when the function is a self-recursive tail-call candidate, else None.
/// Conservative eligibility (fails closed): non-variadic, all params named, at least
/// one `return self(args)` with matching arity, and — via the scans — no address-of,
/// no `new`/`del`/`defer`, and only trivial (scalar/pointer) locals.
fn tco_rewrite(name: &str, params: &[AstParam], variadic: bool, body: &[Stmt], sp: &crate::lexer::Span) -> Option<Vec<Stmt>> {
    if variadic || params.is_empty() { return None; }
    if params.iter().any(|p| p.name.is_none()) { return None; }
    let mut ok = true;
    let mut has_tail = false;
    for s in body { tco_scan_stmt(s, name, params.len(), &mut ok, &mut has_tail); }
    if !ok || !has_tail { return None; }
    let label = "__sic_tco_start";
    let mut nb = body.to_vec();
    for s in &mut nb { tco_replace(s, name, params, label); }
    Some(vec![Stmt::Label(label.to_string(), Box::new(Stmt::Block(nb, sp.clone())), sp.clone())])
}

// ── Loop bounds-check elimination helpers (see FuncCtx::try_loop_bce) ──────────

/// True if `e` is a positive integer literal (validating a loop's `+C` step).
fn positive_int_lit(e: &Expr) -> bool {
    use crate::ast::ExprKind as E;
    matches!(&e.kind, E::IntLit(n, _) if *n > 0) || matches!(&e.kind, E::UIntLit(n, _) if *n > 0)
}

/// Collect the identifiers of a *simple* expression — literals, idents, and
/// arithmetic/bitwise/shift/neg over them. Returns `None` if `e` contains anything
/// else (a call, index, field, …); the caller then bails, so an un-analyzable loop
/// bound or index offset is never mistaken for a loop-invariant value.
fn simple_expr_idents(e: &Expr) -> Option<std::collections::HashSet<String>> {
    use crate::ast::{ExprKind as E, UnOpKind as U, BinOpKind as B};
    fn go(e: &Expr, out: &mut std::collections::HashSet<String>) -> bool {
        match &e.kind {
            E::IntLit(..) | E::UIntLit(..) | E::CharLit(_) | E::FloatLit(_) | E::DecimalLit(_) => true,
            E::Ident(n) => { out.insert(n.clone()); true }
            E::BinOp { op, lhs, rhs } => matches!(op,
                    B::Add|B::Sub|B::Mul|B::Div|B::Rem|B::BitAnd|B::BitOr|B::BitXor|B::Shl|B::Shr)
                && go(lhs, out) && go(rhs, out),
            E::Unary { op: U::Neg, expr } | E::Unary { op: U::BitNot, expr } => go(expr, out),
            _ => false,
        }
    }
    let mut s = std::collections::HashSet::new();
    if go(e, &mut s) { Some(s) } else { None }
}

/// Classify `idx` as affine in the induction variable `ivar`:
///   `Some(None)`     — exactly `ivar`;
///   `Some(Some(X))`  — `X + ivar` or `ivar + X`, where `X` does not mention `ivar`;
///   `None`           — any other shape (not eligible for hoisting).
/// A recognized element of a vectorizable RHS (see `try_vectorize`).
enum VecNode {
    /// A loop-invariant scalar, broadcast to every lane.
    Splat(Expr),
    /// `arr[offset + j]` (`offset == None` means `arr[j]`), a unit-stride load.
    Load { arr: String, offset: Option<Expr> },
    /// An element-wise binary op over two vectorizable sub-expressions.
    Bin { op: BinOp, l: Box<VecNode>, r: Box<VecNode> },
}

/// A `VecNode` whose broadcasts have been lowered to concrete vector values
/// (hoisted out of the loop).
enum VecEmit {
    Prebuilt(Val),
    Load { arr: String, offset: Option<Expr> },
    Bin { op: BinOp, l: Box<VecEmit>, r: Box<VecEmit> },
}

/// Map a source binary operator to the IR vector op the back end lowers to real
/// SIMD for element type `elem`, or `None` if there is no single packed form (int
/// div/rem, per-lane shifts, comparisons, packed byte multiply). Mirrors the fast
/// path in `lower_vector_binop`.
fn vec_binop_for(op: crate::ast::BinOpKind, elem: &Type) -> Option<BinOp> {
    use crate::ast::BinOpKind as B;
    let is_float = elem.is_float();
    Some(match op {
        B::Add => if is_float { BinOp::FAdd } else { BinOp::Add },
        B::Sub => if is_float { BinOp::FSub } else { BinOp::Sub },
        B::Mul if is_float => BinOp::FMul,
        B::Mul => match elem { Type::Int { bits, .. } if *bits >= 16 => BinOp::Mul, _ => return None },
        B::Div if is_float => BinOp::FDiv,
        B::BitAnd if !is_float => BinOp::And,
        B::BitOr if !is_float => BinOp::Or,
        B::BitXor if !is_float => BinOp::Xor,
        _ => return None,
    })
}

fn affine_x(idx: &Expr, ivar: &str) -> Option<Option<Expr>> {
    use crate::ast::{ExprKind as E, BinOpKind as B};
    // "e is invariant in ivar": simple AND does not name ivar. A non-simple e is
    // treated as mentioning it (conservative → not used as the invariant part).
    let invariant = |e: &Expr| simple_expr_idents(e).map_or(false, |s| !s.contains(ivar));
    match &idx.kind {
        E::Ident(n) if n == ivar => Some(None),
        E::BinOp { op: B::Add, lhs, rhs } => {
            let l_i = matches!(&lhs.kind, E::Ident(n) if n == ivar);
            let r_i = matches!(&rhs.kind, E::Ident(n) if n == ivar);
            if r_i && invariant(lhs) { Some(Some((**lhs).clone())) }
            else if l_i && invariant(rhs) { Some(Some((**rhs).clone())) }
            else { None }
        }
        // `i - C` (C invariant): a unit-stride access at offset `-C`. Needed for
        // stencils like `a[i-1]`. (`C - i` is a negative stride, not handled.)
        E::BinOp { op: B::Sub, lhs, rhs }
            if matches!(&lhs.kind, E::Ident(n) if n == ivar) && invariant(rhs) =>
        {
            Some(Some(Expr::new(
                crate::ast::ExprKind::Unary { op: crate::ast::UnOpKind::Neg, expr: Box::new((**rhs).clone()) },
                rhs.span.clone(),
            )))
        }
        _ => None,
    }
}

/// A stable structural key for an index expression, used to match a
/// loop-BCE-proven access against the same access when the body is lowered.
pub(crate) fn bce_index_key(e: &Expr) -> String {
    use crate::ast::ExprKind as E;
    match &e.kind {
        E::Ident(n) => format!("v:{}", n),
        E::IntLit(n, _) => format!("i:{}", n),
        E::UIntLit(n, _) => format!("u:{}", n),
        E::CharLit(c) => format!("c:{}", c),
        E::BinOp { op, lhs, rhs } => format!("({:?} {} {})", op, bce_index_key(lhs), bce_index_key(rhs)),
        E::Unary { op, expr } => format!("({:?} {})", op, bce_index_key(expr)),
        E::Cast { expr, .. } => format!("cast({})", bce_index_key(expr)),
        other => format!("?{:p}", other as *const _),
    }
}

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
        New { args, .. } => { for x in args { scan_mutated_expr(x, out); } }
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

// ── Fat-parameter propagation helpers (see Lowerer::infer_fat_params) ──────────
use std::collections::HashSet as FpSet;

/// Is `arg` a fat-pointer *base* (allocation start, so its size header sits at
/// `p - 2*ptr`)? True for a `new` expression or an identifier holding a fat base
/// (`fat_names`); casts are transparent. `p + k` / `&x` / a raw pointer → false.
fn is_fat_base_arg(arg: &Expr, fat_names: &FpSet<String>) -> bool {
    use crate::ast::ExprKind as E;
    match &arg.kind {
        E::Cast { expr, .. } => is_fat_base_arg(expr, fat_names),
        E::New { .. } => true,
        E::Ident(n) => fat_names.contains(n),
        _ => false,
    }
}

/// Statement half of the fat-parameter pre-pass: records `new`-initialized local
/// names, direct calls `f(args)`, and candidate function names that escape as a
/// value (used anywhere but as a direct call target → unseen callers possible).
fn fat_prepass_stmt(s: &Stmt, cand: &FpSet<String>, newloc: &mut FpSet<String>,
    calls: &mut Vec<(String, Vec<Expr>)>, esc: &mut FpSet<String>) {
    let decl_var = |declarators: &Vec<crate::ast::Declarator>, newloc: &mut FpSet<String>,
                    calls: &mut Vec<(String, Vec<Expr>)>, esc: &mut FpSet<String>| {
        for d in declarators {
            if let Some(Initializer::Expr(e)) = &d.init {
                if matches!(&e.kind, ExprKind::New { .. }) { newloc.insert(d.name.clone()); }
                fat_prepass_expr(e, cand, newloc, calls, esc);
            }
        }
    };
    match s {
        Stmt::Decl(Decl::Var { declarators, .. }) => decl_var(declarators, newloc, calls, esc),
        Stmt::Expr(e, _) | Stmt::Return(Some(e), _) => fat_prepass_expr(e, cand, newloc, calls, esc),
        Stmt::Block(ss, _) => for s in ss { fat_prepass_stmt(s, cand, newloc, calls, esc); },
        Stmt::If { cond, then, else_, .. } => {
            fat_prepass_expr(cond, cand, newloc, calls, esc);
            fat_prepass_stmt(then, cand, newloc, calls, esc);
            if let Some(e) = else_ { fat_prepass_stmt(e, cand, newloc, calls, esc); }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { body, cond, .. } => {
            fat_prepass_expr(cond, cand, newloc, calls, esc);
            fat_prepass_stmt(body, cand, newloc, calls, esc);
        }
        Stmt::For { init, cond, post, body, .. } => {
            match init {
                Some(ForInit::Expr(e)) => fat_prepass_expr(e, cand, newloc, calls, esc),
                Some(ForInit::Decl(Decl::Var { declarators, .. })) => decl_var(declarators, newloc, calls, esc),
                _ => {}
            }
            if let Some(e) = cond { fat_prepass_expr(e, cand, newloc, calls, esc); }
            if let Some(e) = post { fat_prepass_expr(e, cand, newloc, calls, esc); }
            fat_prepass_stmt(body, cand, newloc, calls, esc);
        }
        Stmt::Switch { val, body, .. } => { fat_prepass_expr(val, cand, newloc, calls, esc); fat_prepass_stmt(body, cand, newloc, calls, esc); }
        Stmt::Match { scrutinee, arms, .. } => {
            fat_prepass_expr(scrutinee, cand, newloc, calls, esc);
            for a in arms { fat_prepass_stmt(&a.body, cand, newloc, calls, esc); }
        }
        Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) | Stmt::Default(body, _)
        | Stmt::Label(_, body, _) | Stmt::Defer(body, _) => fat_prepass_stmt(body, cand, newloc, calls, esc),
        Stmt::Delete(e, _) => fat_prepass_expr(e, cand, newloc, calls, esc),
        _ => {}
    }
}

/// Expression half of the fat-parameter pre-pass (traversal mirrors
/// [`scan_mutated_expr`], so every child is visited).
fn fat_prepass_expr(e: &Expr, cand: &FpSet<String>, newloc: &mut FpSet<String>,
    calls: &mut Vec<(String, Vec<Expr>)>, esc: &mut FpSet<String>) {
    use ExprKind::*;
    match &e.kind {
        Ident(n) => { if cand.contains(n) { esc.insert(n.clone()); } }
        Call { func, args } => {
            match &func.kind {
                Ident(n) => calls.push((n.clone(), args.clone())),
                _ => fat_prepass_expr(func, cand, newloc, calls, esc),
            }
            for a in args { fat_prepass_expr(a, cand, newloc, calls, esc); }
        }
        BinOp { lhs, rhs, .. } | Comma(lhs, rhs) | Assign { lhs, rhs, .. } | Swap { lhs, rhs } => {
            fat_prepass_expr(lhs, cand, newloc, calls, esc); fat_prepass_expr(rhs, cand, newloc, calls, esc);
        }
        Unary { expr, .. } | PreInc { expr, .. } | PostInc { expr, .. }
        | SizeofExpr(expr) | AlignofExpr(expr) | Cast { expr, .. } | Ref { expr, .. } =>
            fat_prepass_expr(expr, cand, newloc, calls, esc),
        Ternary { cond, then, else_ } | ChooseExpr { cond, then, else_ } => {
            fat_prepass_expr(cond, cand, newloc, calls, esc);
            fat_prepass_expr(then, cand, newloc, calls, esc);
            fat_prepass_expr(else_, cand, newloc, calls, esc);
        }
        Elvis { cond, else_ } => { fat_prepass_expr(cond, cand, newloc, calls, esc); fat_prepass_expr(else_, cand, newloc, calls, esc); }
        Index { base, index } => { fat_prepass_expr(base, cand, newloc, calls, esc); fat_prepass_expr(index, cand, newloc, calls, esc); }
        Slice { base, lo, hi } => {
            fat_prepass_expr(base, cand, newloc, calls, esc);
            if let Some(x) = lo { fat_prepass_expr(x, cand, newloc, calls, esc); }
            if let Some(x) = hi { fat_prepass_expr(x, cand, newloc, calls, esc); }
        }
        New { args, .. } => for x in args { fat_prepass_expr(x, cand, newloc, calls, esc); },
        Field { base, .. } | Arrow { base, .. } => fat_prepass_expr(base, cand, newloc, calls, esc),
        Generic { controlling, assocs } => {
            fat_prepass_expr(controlling, cand, newloc, calls, esc);
            for (_, x) in assocs { fat_prepass_expr(x, cand, newloc, calls, esc); }
        }
        StmtExpr(stmts) => for s in stmts { fat_prepass_stmt(s, cand, newloc, calls, esc); },
        VaStart { list, last } => { fat_prepass_expr(list, cand, newloc, calls, esc); fat_prepass_expr(last, cand, newloc, calls, esc); }
        VaArg { list, .. } | VaEnd { list } => fat_prepass_expr(list, cand, newloc, calls, esc),
        VaCopy { dst, src } => { fat_prepass_expr(dst, cand, newloc, calls, esc); fat_prepass_expr(src, cand, newloc, calls, esc); }
        _ => {}
    }
}

/// The i64 payload of an integer/bool constant, or None for a non-integer value.
fn const_int_value(val: &Val) -> Option<i64> {
    match val {
        Val::Const(Constant::Int(v)) => Some(*v),
        Val::Const(Constant::UInt(v)) => Some(*v as i64),
        Val::Const(Constant::Bool(b)) => Some(*b as i64),
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
        | Stmt::CaseRange(_, _, _, s) | Stmt::Fallthrough(s)
        | Stmt::Default(_, s) | Stmt::Defer(_, s) | Stmt::Delete(_, s) | Stmt::Unsafe(_, s) => s.line,
        Stmt::Asm(a) => a.span.line,
        Stmt::If { span, .. } | Stmt::While { span, .. } | Stmt::DoWhile { span, .. }
        | Stmt::For { span, .. } | Stmt::Switch { span, .. } | Stmt::Match { span, .. }
        | Stmt::ForEach { span, .. } | Stmt::Guard { span, .. } => span.line,
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

/// The first `return <expr>;` expression in a body (used to infer a lambda's
/// return type when it has no explicit `-> T`). `return;` and a body with no
/// return yield `None` (a void lambda).
fn first_return_expr(stmts: &[Stmt]) -> Option<Expr> {
    fn in_stmt(s: &Stmt) -> Option<Expr> {
        match s {
            Stmt::Return(Some(e), _) => Some(e.clone()),
            Stmt::Block(ss, _) => first_return_expr(ss),
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
        Stmt::Asm(a) => for o in a.outputs.iter().chain(&a.inputs) { find_tuple_calls(fc, &o.expr, targets, found); },
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
        Stmt::ForEach { iterable, body, .. } => {
            find_tuple_calls(fc, iterable, targets, found);
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
        AstType::Bitfield(b) => b.name.clone(),
        AstType::Auto => "auto".to_string(),
        AstType::Closure { ret, .. } => format!("Fn<{}(...)>", c_type_string(ret)),
        AstType::Weak(inner) => format!("weak<{}>", c_type_string(inner)),
    }
}
