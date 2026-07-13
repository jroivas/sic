use crate::{Type, FunctionType, Val, ValId, BlockId, FuncRef, GlobalRef, Instr, Terminator, Constant};

/// Linkage for globals and functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    External,    // visible outside the module (default for functions)
    Internal,    // static, not exported
    Private,     // not even named in object
    Import,      // declared here but defined elsewhere (e.g. libc `stdout`)
}

/// A global variable.
#[derive(Debug, Clone)]
pub struct Global {
    pub name: String,
    pub ty: Type,
    pub init: Option<Constant>,
    pub linkage: Linkage,
    pub constant: bool,   // true for const globals
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
    /// Name of the next-id counter for values inside this function.
    next_val_id: u32,
    next_block_id: u32,
}

impl Function {
    pub fn new(name: String, sig: FunctionType, params: Vec<Param>, linkage: Linkage) -> Self {
        Function {
            name, sig, params, blocks: Vec::new(), linkage,
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
}

pub enum FuncDecl<'a> {
    Defined(&'a Function),
    Extern(&'a ExternFunc),
}
