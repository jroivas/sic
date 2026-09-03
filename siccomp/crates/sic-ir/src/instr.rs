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
    Rotl, Rotr,      // bitwise rotate left / right (SIC `<<<` / `>>>`)
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,   // integer negation
    FNeg,  // float negation
    Not,   // bitwise NOT
    BoolNot, // logical NOT (result is i1)
    Clz,   // count leading zeros
    Ctz,   // count trailing zeros
    Popcnt, // population count (set bits)
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

/// Atomic read-modify-write operation (sic `atomic` types). Maps directly to the
/// backend's atomic-rmw ops; all are single lock-free instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOp {
    Add, Sub, And, Or, Xor, Xchg,
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
    /// `result_ty` is the pointer-to-field type, so the field's type survives
    /// taking its address (e.g. `&s.field`) — without it, address-of would
    /// degrade to `void*` and a following `->`/`*` would lose the field type.
    GetFieldPtr { dest: ValId, base: Val, field_idx: usize, struct_name: Option<String>, byte_offset: u64, result_ty: Type },

    /// Get a pointer to an array element. `result_ty` is the pointer-to-element
    /// type so `&arr[i]` keeps the element type (see `GetFieldPtr::result_ty`).
    GetElemPtr { dest: ValId, base: Val, index: Val, elem_size: u64, result_ty: Type },

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

    /// Atomic load of `ty` from `ptr` (sequentially consistent).
    AtomicLoad { dest: ValId, ptr: Val, ty: Type },
    /// Atomic store of `val` (typed `ty`) to `ptr` (sequentially consistent).
    AtomicStore { ptr: Val, val: Val, ty: Type },
    /// Atomic read-modify-write: `dest` = old value at `ptr`; memory becomes
    /// `old <op> val`. `ty` is the value width.
    AtomicRmw { dest: ValId, op: AtomicOp, ptr: Val, val: Val, ty: Type },
    /// Atomic compare-and-swap: if `*ptr == expected`, store `desired`. `dest`
    /// receives the *old* value (success ⇔ dest == expected). `ty` is the width.
    AtomicCas { dest: ValId, ptr: Val, expected: Val, desired: Val, ty: Type },

    /// Variable-argument: va_start, va_arg, va_end.
    VaStart { list_ptr: Val },
    VaArg   { dest: ValId, list_ptr: Val, ty: Type },
    VaEnd   { list_ptr: Val },

    /// `__builtin_return_address(0)`: the current function's return address (a
    /// pointer). Backed by Cranelift's `get_return_address`. QEMU's `GETPC()`
    /// depends on it to restart a faulting TB at the right guest PC.
    ReturnAddress { dest: ValId },

    /// Debug marker: the source line number that the following instructions
    /// correspond to. Emits no machine code; drives the DWARF line table.
    SrcLine(u32),

    /// Debug marker: associate a source variable `name` of type `ty` with the
    /// stack allocation `slot` (an `Alloca`'s dest ValId). Emits no machine
    /// code; drives the DWARF variable/parameter DIEs so debuggers can inspect
    /// locals. `is_param` distinguishes formal parameters from locals.
    DbgVar { name: String, ty: Type, slot: ValId, is_param: bool },
}

impl Instr {
    /// Invoke `f` on every `Val` operand of this instruction.
    pub fn for_each_val<F: FnMut(&Val)>(&self, mut f: F) {
        match self {
            Instr::Alloca { .. } | Instr::SrcLine(_) | Instr::DbgVar { .. }
            | Instr::ReturnAddress { .. } => {}
            Instr::Load { ptr, .. } => f(ptr),
            Instr::Store { val, ptr } => { f(val); f(ptr); }
            Instr::BinOp { lhs, rhs, .. } | Instr::Cmp { lhs, rhs, .. } => { f(lhs); f(rhs); }
            Instr::UnaryOp { val, .. } | Instr::Cast { val, .. } | Instr::BSwap { val, .. } => f(val),
            Instr::Call { args, .. } => { for a in args { f(a); } }
            Instr::CallIndirect { fptr, args, .. } => { f(fptr); for a in args { f(a); } }
            Instr::GetFieldPtr { base, .. } => f(base),
            Instr::GetElemPtr { base, index, .. } => { f(base); f(index); }
            Instr::PtrOffset { base, offset, .. } => { f(base); f(offset); }
            Instr::Select { cond, on_true, on_false, .. } => { f(cond); f(on_true); f(on_false); }
            Instr::MemCopy { dst, src, .. } => { f(dst); f(src); }
            Instr::MemSet { dst, val, .. } => { f(dst); f(val); }
            Instr::VaStart { list_ptr } | Instr::VaEnd { list_ptr } => f(list_ptr),
            Instr::VaArg { list_ptr, .. } => f(list_ptr),
            Instr::AtomicLoad { ptr, .. } => f(ptr),
            Instr::AtomicStore { ptr, val, .. } => { f(ptr); f(val); }
            Instr::AtomicRmw { ptr, val, .. } => { f(ptr); f(val); }
            Instr::AtomicCas { ptr, expected, desired, .. } => { f(ptr); f(expected); f(desired); }
        }
    }

    /// Invoke `f` on every `Val` operand of this instruction, mutably — used by
    /// optimization passes to substitute operands (e.g. a folded constant).
    pub fn for_each_val_mut<F: FnMut(&mut Val)>(&mut self, mut f: F) {
        match self {
            Instr::Alloca { .. } | Instr::SrcLine(_) | Instr::DbgVar { .. }
            | Instr::ReturnAddress { .. } => {}
            Instr::Load { ptr, .. } => f(ptr),
            Instr::Store { val, ptr } => { f(val); f(ptr); }
            Instr::BinOp { lhs, rhs, .. } | Instr::Cmp { lhs, rhs, .. } => { f(lhs); f(rhs); }
            Instr::UnaryOp { val, .. } | Instr::Cast { val, .. } | Instr::BSwap { val, .. } => f(val),
            Instr::Call { args, .. } => { for a in args { f(a); } }
            Instr::CallIndirect { fptr, args, .. } => { f(fptr); for a in args { f(a); } }
            Instr::GetFieldPtr { base, .. } => f(base),
            Instr::GetElemPtr { base, index, .. } => { f(base); f(index); }
            Instr::PtrOffset { base, offset, .. } => { f(base); f(offset); }
            Instr::Select { cond, on_true, on_false, .. } => { f(cond); f(on_true); f(on_false); }
            Instr::MemCopy { dst, src, .. } => { f(dst); f(src); }
            Instr::MemSet { dst, val, .. } => { f(dst); f(val); }
            Instr::VaStart { list_ptr } | Instr::VaEnd { list_ptr } => f(list_ptr),
            Instr::VaArg { list_ptr, .. } => f(list_ptr),
            Instr::AtomicLoad { ptr, .. } => f(ptr),
            Instr::AtomicStore { ptr, val, .. } => { f(ptr); f(val); }
            Instr::AtomicRmw { ptr, val, .. } => { f(ptr); f(val); }
            Instr::AtomicCas { ptr, expected, desired, .. } => { f(ptr); f(expected); f(desired); }
        }
    }

    /// The value id this instruction defines, if any.
    pub fn dest(&self) -> Option<ValId> {
        match self {
            Instr::Alloca { dest, .. } | Instr::Load { dest, .. }
            | Instr::BinOp { dest, .. } | Instr::UnaryOp { dest, .. }
            | Instr::Cast { dest, .. } | Instr::Cmp { dest, .. }
            | Instr::GetFieldPtr { dest, .. } | Instr::GetElemPtr { dest, .. }
            | Instr::PtrOffset { dest, .. } | Instr::Select { dest, .. }
            | Instr::BSwap { dest, .. } | Instr::VaArg { dest, .. }
            | Instr::AtomicLoad { dest, .. } | Instr::AtomicRmw { dest, .. }
            | Instr::AtomicCas { dest, .. }
            | Instr::ReturnAddress { dest } => Some(*dest),
            Instr::Call { dest, .. } | Instr::CallIndirect { dest, .. } => *dest,
            Instr::Store { .. } | Instr::MemCopy { .. } | Instr::MemSet { .. }
            | Instr::AtomicStore { .. }
            | Instr::VaStart { .. } | Instr::VaEnd { .. } | Instr::SrcLine(_)
            | Instr::DbgVar { .. } => None,
        }
    }

    /// Whether removing this instruction (when its result is unused) is safe —
    /// i.e. it has no side effect. Conservative: loads (possibly volatile MMIO),
    /// stores, calls, allocas, and var-args are never removable.
    pub fn is_pure(&self) -> bool {
        matches!(self,
            Instr::BinOp { .. } | Instr::UnaryOp { .. } | Instr::Cmp { .. }
            | Instr::Cast { .. } | Instr::BSwap { .. } | Instr::GetFieldPtr { .. }
            | Instr::GetElemPtr { .. } | Instr::PtrOffset { .. } | Instr::Select { .. })
    }
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

impl Terminator {
    /// Invoke `f` on every `Val` operand of this terminator.
    pub fn for_each_val<F: FnMut(&Val)>(&self, mut f: F) {
        match self {
            Terminator::Ret(Some(v)) => f(v),
            Terminator::CondJump { cond, .. } => f(cond),
            Terminator::Switch { val, .. } => f(val),
            Terminator::Ret(None) | Terminator::Jump(_) | Terminator::Unreachable => {}
        }
    }

    /// Invoke `f` on every `Val` operand of this terminator, mutably.
    pub fn for_each_val_mut<F: FnMut(&mut Val)>(&mut self, mut f: F) {
        match self {
            Terminator::Ret(Some(v)) => f(v),
            Terminator::CondJump { cond, .. } => f(cond),
            Terminator::Switch { val, .. } => f(val),
            Terminator::Ret(None) | Terminator::Jump(_) | Terminator::Unreachable => {}
        }
    }
}
