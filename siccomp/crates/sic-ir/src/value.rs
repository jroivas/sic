/// A unique identifier for a local value (SSA value or alloca).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValId(pub u32);

/// A unique identifier for a basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub u32);

/// A reference to a function by index in the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FuncRef(pub u32);

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
