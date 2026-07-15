use crate::{Val, ValId, BlockId, FuncRef, Type};

/// Binary arithmetic/logic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add, Sub, Mul,
    SDiv, UDiv,      // signed / unsigned integer division
    SRem, URem,      // signed / unsigned remainder
    FAdd, FSub, FMul, FDiv, FRem,
    And, Or, Xor,
    Shl, AShr, LShr, // arithmetic / logical shift right
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,   // integer negation
    FNeg,  // float negation
    Not,   // bitwise NOT
    BoolNot, // logical NOT (result is i1)
}

/// Integer / float comparison predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    // Signed integer comparisons
    IEq, INe,
    ISLt, ISLe, ISGt, ISGe,
    // Unsigned integer comparisons
    IULt, IULe, IUGt, IUGe,
    // Float ordered comparisons
    FOEq, FONe, FOLt, FOLe, FOGt, FOGe,
}

/// Type conversion operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastOp {
    SExt,      // sign-extend integer
    ZExt,      // zero-extend integer
    Trunc,     // truncate integer
    IntToPtr,  // integer to pointer
    PtrToInt,  // pointer to integer
    BitCast,   // reinterpret bits (pointer-to-pointer, etc.)
    SIToFP,    // signed int → float
    UIToFP,    // unsigned int → float
    FPToSI,    // float → signed int (truncate toward zero)
    FPToUI,    // float → unsigned int
    FPExt,     // float32 → float64
    FPTrunc,   // float64 → float32
    BoolToInt, // bool (i1) → integer
}

/// A single IR instruction (does not include terminators).
#[derive(Debug, Clone)]
pub enum Instr {
    /// Allocate stack storage; `dest` holds a pointer to the allocation.
    /// `align`, if set, overrides the type's natural alignment (`_Alignas`).
    Alloca { dest: ValId, ty: Type, align: Option<u32> },

    /// Load a value from a pointer.
    Load { dest: ValId, ptr: Val, ty: Type },

    /// Store a value to a pointer.
    Store { val: Val, ptr: Val },

    /// Binary operation.
    BinOp { dest: ValId, op: BinOp, lhs: Val, rhs: Val, ty: Type },

    /// Unary operation.
    UnaryOp { dest: ValId, op: UnOp, val: Val, ty: Type },

    /// Type cast.
    Cast { dest: ValId, op: CastOp, val: Val, to_ty: Type },

    /// Comparison — result is i1 (Bool). `ty` is the (common) type the operands
    /// are compared at, so the backend can materialize constant operands at the
    /// correct width instead of guessing.
    Cmp { dest: ValId, op: CmpOp, lhs: Val, rhs: Val, ty: Type },

    /// Function call.
    Call { dest: Option<ValId>, func: FuncRef, args: Vec<Val>, ret_ty: Type },

    /// Indirect call through a function pointer.
    CallIndirect { dest: Option<ValId>, fptr: Val, args: Vec<Val>, ret_ty: Type, func_ty: Box<crate::FunctionType> },

    /// Get a pointer to a struct field: `base` is a pointer to the struct.
    GetFieldPtr { dest: ValId, base: Val, field_idx: usize, struct_name: Option<String>, byte_offset: u64 },

    /// Get a pointer to an array element.
    GetElemPtr { dest: ValId, base: Val, index: Val, elem_size: u64 },

    /// Pointer offset (byte-level): `dest = base + offset_bytes`.
    PtrOffset { dest: ValId, base: Val, offset: Val },

    /// Select between two values based on a boolean condition.
    Select { dest: ValId, cond: Val, on_true: Val, on_false: Val, ty: Type },

    /// MemCopy (used for struct assignments).
    MemCopy { dst: Val, src: Val, size: u64, align: u64 },

    /// MemSet (used for zeroinit).
    MemSet { dst: Val, val: Val, size: u64, align: u64 },

    /// Byte-swap an integer value.
    BSwap { dest: ValId, val: Val, ty: Type },

    /// Variable-argument: va_start, va_arg, va_end.
    VaStart { list_ptr: Val },
    VaArg   { dest: ValId, list_ptr: Val, ty: Type },
    VaEnd   { list_ptr: Val },

    /// Debug marker: the source line number that the following instructions
    /// correspond to. Emits no machine code; drives the DWARF line table.
    SrcLine(u32),

    /// Debug marker: associate a source variable `name` of type `ty` with the
    /// stack allocation `slot` (an `Alloca`'s dest ValId). Emits no machine
    /// code; drives the DWARF variable/parameter DIEs so debuggers can inspect
    /// locals. `is_param` distinguishes formal parameters from locals.
    DbgVar { name: String, ty: Type, slot: ValId, is_param: bool },
}

/// Every basic block ends with exactly one terminator.
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Return from function, optionally with a value.
    Ret(Option<Val>),
    /// Unconditional jump.
    Jump(BlockId),
    /// Conditional branch: jump to `then_bb` if cond is true, else `else_bb`.
    CondJump { cond: Val, then_bb: BlockId, else_bb: BlockId },
    /// Multi-way branch (switch).
    Switch { val: Val, default: BlockId, arms: Vec<(i64, BlockId)> },
    /// Unreachable — used after noreturn calls.
    Unreachable,
}
