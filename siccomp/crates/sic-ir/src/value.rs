/// A unique identifier for a local value (SSA value or alloca).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValId(pub u32);

/// A unique identifier for a basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub u32);

/// A reference to a function by index in the module.
///
/// Defined functions are encoded as their plain index into `Module::functions`.
/// Externs set [`FuncRef::EXTERN_BIT`] with the low bits holding the index into
/// `Module::externs`. This keeps a ref stable regardless of how many functions
/// are added afterwards (the two index spaces never overlap or shift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FuncRef(pub u32);

impl FuncRef {
    /// Set on a `FuncRef` that refers to an extern rather than a defined function.
    pub const EXTERN_BIT: u32 = 0x8000_0000;

    pub fn defined(idx: usize) -> FuncRef { FuncRef(idx as u32) }
    pub fn extern_(idx: usize) -> FuncRef { FuncRef(Self::EXTERN_BIT | idx as u32) }

    pub fn is_extern(self) -> bool { self.0 & Self::EXTERN_BIT != 0 }
    /// Index into the relevant list (`functions` or `externs`).
    pub fn index(self) -> usize { (self.0 & !Self::EXTERN_BIT) as usize }
}

/// A reference to a global variable by index in the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalRef(pub u32);

/// A value operand used in instructions.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Local(ValId),
    Global(GlobalRef),
    Func(FuncRef),
    Const(Constant),
}

/// Compile-time constants.
#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Int(i64),
    UInt(u64),
    Float(f64),
    Bool(bool),
    Null,
    Undef,
    Bytes(Vec<u8>),          // string data (null-terminated)
    Zeroinit,                // zero-initialized aggregate
    GlobalAddr(GlobalRef),   // address of another global (pointer initializer)
    /// Aggregate initializer: raw bytes with embedded pointer relocations, each
    /// patching a pointer-sized slot at `offset` with a symbol's address.
    Aggregate { bytes: Vec<u8>, relocs: Vec<(usize, RelocTarget)> },
}

/// The target of a pointer relocation inside an aggregate initializer.
#[derive(Debug, Clone, PartialEq)]
pub enum RelocTarget {
    /// Address of a global (with a byte addend), e.g. `&arr[2]` or a string.
    Global(GlobalRef, i64),
    /// Address of a function, e.g. `&func` or a bare function name.
    Func(FuncRef),
}

impl Constant {
    pub fn int(v: i64) -> Val { Val::Const(Constant::Int(v)) }
    pub fn uint(v: u64) -> Val { Val::Const(Constant::UInt(v)) }
    pub fn float(v: f64) -> Val { Val::Const(Constant::Float(v)) }
    pub fn null() -> Val { Val::Const(Constant::Null) }
    pub fn bool_val(b: bool) -> Val { Val::Const(Constant::Bool(b)) }
    pub fn zero() -> Val { Val::Const(Constant::Int(0)) }
}

impl From<ValId> for Val {
    fn from(id: ValId) -> Val { Val::Local(id) }
}
