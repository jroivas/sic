use crate::{Type, FunctionType, Val, ValId, BlockId, FuncRef, GlobalRef, Instr, Terminator, Constant, RelocTarget};

/// Linkage for globals and functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    External,    // visible outside the module (default for functions)
    Internal,    // static, not exported
    Private,     // not even named in object
    Import,      // declared here but defined elsewhere (e.g. libc `stdout`)
    Weak,        // `__attribute__((weak))`: definition that merges with others
}

/// A global variable.
#[derive(Debug, Clone)]
pub struct Global {
    pub name: String,
    pub ty: Type,
    pub init: Option<Constant>,
    pub linkage: Linkage,
    pub constant: bool,   // true for const globals
    pub thread_local: bool, // `__thread` / `_Thread_local`: per-thread storage
}

/// A function parameter.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Type,
}

/// A basic block inside a function.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub label: Option<String>,          // named label (for goto targets)
    pub instrs: Vec<Instr>,
    pub terminator: Terminator,
}

impl BasicBlock {
    pub fn new(id: BlockId) -> Self {
        BasicBlock { id, label: None, instrs: Vec::new(), terminator: Terminator::Unreachable }
    }
}

/// A function definition.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub sig: FunctionType,
    pub params: Vec<Param>,
    pub blocks: Vec<BasicBlock>,
    pub linkage: Linkage,
    /// `Some(priority)` if this is an `__attribute__((constructor))` — its address
    /// is placed in `.init_array` so the C runtime calls it before `main`.
    pub constructor: Option<i32>,
    /// Name of the next-id counter for values inside this function.
    next_val_id: u32,
    next_block_id: u32,
}

impl Function {
    pub fn new(name: String, sig: FunctionType, params: Vec<Param>, linkage: Linkage) -> Self {
        Function {
            name, sig, params, blocks: Vec::new(), linkage,
            constructor: None,
            next_val_id: 0, next_block_id: 0,
        }
    }

    pub fn alloc_val(&mut self) -> ValId {
        let id = self.next_val_id;
        self.next_val_id += 1;
        ValId(id)
    }

    pub fn alloc_block(&mut self) -> BlockId {
        let id = self.next_block_id;
        self.next_block_id += 1;
        BlockId(id)
    }

    pub fn add_block(&mut self, block: BasicBlock) -> usize {
        let idx = self.blocks.len();
        self.blocks.push(block);
        idx
    }

    pub fn entry_block(&self) -> BlockId {
        self.blocks.first().expect("function has no blocks").id
    }

    /// Find block by id.
    pub fn block_mut(&mut self, id: BlockId) -> &mut BasicBlock {
        self.blocks.iter_mut().find(|b| b.id == id).expect("block not found")
    }

    pub fn block(&self, id: BlockId) -> &BasicBlock {
        self.blocks.iter().find(|b| b.id == id).expect("block not found")
    }

    pub fn is_variadic(&self) -> bool {
        self.sig.variadic
    }
}

/// A declaration of an external function (no body).
#[derive(Debug, Clone)]
pub struct ExternFunc {
    pub name: String,
    pub sig: FunctionType,
}

/// The top-level compilation unit.
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub globals: Vec<Global>,
    pub functions: Vec<Function>,
    pub externs: Vec<ExternFunc>,
    /// Named struct/union types registered in this module.
    pub type_defs: Vec<(String, Type)>,
    /// Source file path this module was compiled from (for DWARF debug info).
    pub source_file: Option<String>,
    /// sic module system (sic.md §"Imports"): `Some(name)` when this unit declared
    /// `module name;` — the driver emits a `module_<name>.smod` manifest for it.
    pub sic_module: Option<String>,
    /// Link flags gathered from imported modules' manifests, to be folded into the
    /// final link order by the driver.
    pub imported_links: Vec<String>,
    /// Names of variadic extern functions (e.g. `printf`) called with a
    /// floating-point argument. On x86-64 the backend routes these through a tiny
    /// trampoline that sets the SysV `AL` vector-arg count, which Cranelift never
    /// emits for variadic calls (see cg_clif's `adjust_call_for_c_variadic`).
    pub float_vararg_externs: Vec<String>,
    /// sic `import std;`: this unit imported the blessed std library, so the driver
    /// must compile and link the std lib object.
    pub std_imported: bool,
}

impl Module {
    pub fn new(name: String) -> Self {
        Module {
            name,
            globals: Vec::new(),
            functions: Vec::new(),
            externs: Vec::new(),
            type_defs: Vec::new(),
            source_file: None,
            sic_module: None,
            imported_links: Vec::new(),
            float_vararg_externs: Vec::new(),
            std_imported: false,
        }
    }

    pub fn add_global(&mut self, g: Global) -> GlobalRef {
        let idx = self.globals.len();
        self.globals.push(g);
        GlobalRef(idx as u32)
    }

    pub fn add_function(&mut self, f: Function) -> FuncRef {
        let idx = self.functions.len();
        self.functions.push(f);
        FuncRef::defined(idx)
    }

    pub fn add_extern(&mut self, e: ExternFunc) -> FuncRef {
        // Externs live in a separate list and are encoded with EXTERN_BIT so the
        // ref stays stable no matter how many functions are added later.
        let idx = self.externs.len();
        self.externs.push(e);
        FuncRef::extern_(idx)
    }

    /// Look up a function by name — searches functions then externs.
    pub fn func_ref_by_name(&self, name: &str) -> Option<FuncRef> {
        for (i, f) in self.functions.iter().enumerate() {
            if f.name == name { return Some(FuncRef::defined(i)); }
        }
        for (i, e) in self.externs.iter().enumerate() {
            if e.name == name { return Some(FuncRef::extern_(i)); }
        }
        None
    }

    /// Resolve a FuncRef to either a defined function or an extern.
    pub fn resolve_func(&self, r: FuncRef) -> FuncDecl<'_> {
        if r.is_extern() {
            FuncDecl::Extern(&self.externs[r.index()])
        } else {
            FuncDecl::Defined(&self.functions[r.index()])
        }
    }

    pub fn func_sig(&self, r: FuncRef) -> &FunctionType {
        match self.resolve_func(r) {
            FuncDecl::Defined(f) => &f.sig,
            FuncDecl::Extern(e) => &e.sig,
        }
    }

    pub fn func_name(&self, r: FuncRef) -> &str {
        match self.resolve_func(r) {
            FuncDecl::Defined(f) => &f.name,
            FuncDecl::Extern(e) => &e.name,
        }
    }

    /// Indices (into `externs`) of externs actually referenced by some function
    /// — as a call target or as a function-address value. System headers
    /// declare hundreds of prototypes that are never used; emitting an undefined
    /// symbol for each pollutes the object and can leave unresolvable references
    /// (e.g. glibc's internal `__asinhf`), so only referenced externs matter.
    pub fn used_externs(&self) -> std::collections::HashSet<usize> {
        // Only scan functions that will actually be emitted; an extern referenced
        // solely by a dead (unemitted) internal function must not be declared, or
        // it becomes an undefined symbol that pulls archive members.
        let reachable = self.reachable_functions();
        let mut used = std::collections::HashSet::new();
        let note_val = |v: &Val, used: &mut std::collections::HashSet<usize>| {
            if let Val::Func(fr) = v {
                if fr.is_extern() { used.insert(fr.index()); }
            }
        };
        for (i, f) in self.functions.iter().enumerate() {
            if f.linkage == Linkage::Internal && !reachable.contains(&(i as u32)) {
                continue;
            }
            for bb in &f.blocks {
                for instr in &bb.instrs {
                    if let Instr::Call { func, .. } = instr {
                        if func.is_extern() { used.insert(func.index()); }
                    }
                    instr.for_each_val(|v| note_val(v, &mut used));
                }
                bb.terminator.for_each_val(|v| note_val(v, &mut used));
            }
        }
        // Extern functions referenced only via a static aggregate initializer
        // (e.g. a function-pointer table pointing at an extern).
        for g in &self.globals {
            if let Some(Constant::Aggregate { relocs, .. }) = &g.init {
                for (_, target) in relocs {
                    if let RelocTarget::Func(fr) = target {
                        if fr.is_extern() { used.insert(fr.index()); }
                    }
                }
            }
        }
        used
    }

    /// Indices of globals actually referenced somewhere (an instruction operand,
    /// a terminator, or another global's initializer relocation). An `extern`
    /// (Import) global that a header declared but nothing uses must NOT be emitted
    /// as an undefined symbol, or the linker pulls archive members to satisfy it
    /// — dragging real definitions into conflict with a unit test's stubs
    /// (QEMU's error-report.c declares `global_aio_wait` without using it).
    pub fn used_globals(&self) -> std::collections::HashSet<u32> {
        let mut used = std::collections::HashSet::new();
        let note_val = |v: &Val, used: &mut std::collections::HashSet<u32>| {
            if let Val::Global(gr) = v { used.insert(gr.0); }
        };
        for f in &self.functions {
            for bb in &f.blocks {
                for instr in &bb.instrs {
                    instr.for_each_val(|v| note_val(v, &mut used));
                }
                bb.terminator.for_each_val(|v| note_val(v, &mut used));
            }
        }
        for g in &self.globals {
            match &g.init {
                Some(Constant::Aggregate { relocs, .. }) => {
                    for (_, target) in relocs {
                        if let RelocTarget::Global(gr, _) = target { used.insert(gr.0); }
                    }
                }
                Some(Constant::GlobalAddr(gr)) => { used.insert(gr.0); }
                _ => {}
            }
        }
        used
    }

    /// Indices (into `functions`) of *defined* functions reachable from a root —
    /// an externally-visible function, a constructor, or a function whose address
    /// a global initializer stores — following calls and address-of. An `internal`
    /// (`static`) function unreachable from any root is dead: sic may have emitted
    /// it from a header (e.g. an un-selected `_Generic` branch of QEMU's
    /// `qemu_lockable_*`), and its stray references would otherwise pull archive
    /// members into conflict with unit-test stubs. Not removing them keeps the
    /// object correct but bloated; removing them matches what a real compiler +
    /// `--gc-sections` achieve, without the archive-pull side effect.
    pub fn reachable_functions(&self) -> std::collections::HashSet<u32> {
        use std::collections::HashSet;
        let mut reachable: HashSet<u32> = HashSet::new();
        let mut work: Vec<u32> = Vec::new();
        // Roots: anything not purely-internal, plus constructors.
        for (i, f) in self.functions.iter().enumerate() {
            if f.linkage != Linkage::Internal || f.constructor.is_some() {
                if reachable.insert(i as u32) { work.push(i as u32); }
            }
        }
        // Roots: functions whose address a global initializer stores.
        for g in &self.globals {
            if let Some(Constant::Aggregate { relocs, .. }) = &g.init {
                for (_, target) in relocs {
                    if let RelocTarget::Func(fr) = target {
                        if !fr.is_extern() && reachable.insert(fr.index() as u32) {
                            work.push(fr.index() as u32);
                        }
                    }
                }
            }
        }
        // Transitive closure over calls and address-of within reachable functions.
        while let Some(fi) = work.pop() {
            let Some(f) = self.functions.get(fi as usize) else { continue };
            let mut refs: Vec<u32> = Vec::new();
            for bb in &f.blocks {
                for instr in &bb.instrs {
                    if let Instr::Call { func, .. } = instr {
                        if !func.is_extern() { refs.push(func.index() as u32); }
                    }
                    instr.for_each_val(|v| {
                        if let Val::Func(fr) = v {
                            if !fr.is_extern() { refs.push(fr.index() as u32); }
                        }
                    });
                }
                bb.terminator.for_each_val(|v| {
                    if let Val::Func(fr) = v {
                        if !fr.is_extern() { refs.push(fr.index() as u32); }
                    }
                });
            }
            for r in refs {
                if reachable.insert(r) { work.push(r); }
            }
        }
        reachable
    }
}

pub enum FuncDecl<'a> {
    Defined(&'a Function),
    Extern(&'a ExternFunc),
}
