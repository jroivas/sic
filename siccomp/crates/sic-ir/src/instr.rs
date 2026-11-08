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

/// Float vector comparisons (lanes are all ones when true): ordered (false
/// when either side is NaN) and unordered (true when either is) forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FCmp {
    Eq, Ne, Lt, Le, Gt, Ge, Ord,
    UEq, UNe, ULt, ULe, UGt, UGe, Uno,
}

/// The operations of [`Instr::Simd`]. Lane-wise unless noted; `a`, `b`, `c`
/// are the operands in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimdOp {
    /// Integer lanes: wrapping `a + b`, `a - b`, low half of `a * b`.
    Add, Sub, Mul,
    /// Bitwise; `AndNot` is `a & !b`.
    And, Or, Xor, AndNot,
    /// Saturating add/sub, signed and unsigned.
    SAddSat, UAddSat, SSubSat, USubSat,
    SMin, SMax, UMin, UMax,
    /// Unsigned `(a + b + 1) >> 1`.
    AvgRound,
    /// High half of the full product, signed / unsigned.
    SMulHi, UMulHi,
    /// i16 lanes: `(a * b + 0x4000) >> 15`, saturated.
    MulHrs,
    FAdd, FSub, FMul, FDiv,
    /// x86 `min`/`max`: `a < b ? a : b` / `a > b ? a : b`, so `b` when either
    /// is NaN or both are zero.
    FMin, FMax,
    /// Adjacent pairs summed: `[a0+a1, a2+a3, …, b0+b1, b2+b3, …]`.
    AddPairwise,
    Abs, Neg, Not, Popcnt,
    FSqrt, FAbs, FNeg, FNearest, FFloor, FCeil, FTrunc,
    /// `a` shifted by the scalar `b` (less than the lane width).
    Shl, LShr, AShr,
    /// Lanes all ones where the comparison holds; `ty` is the integer vector
    /// of the same lane width.
    ICmp(CmpOp),
    FCmp(FCmp),
    /// The low / high half of `a`'s lanes widened to twice the width.
    SWidenLow, SWidenHigh, UWidenLow, UWidenHigh,
    /// `a` then `b` narrowed to half the lane width with saturation: signed to
    /// signed / signed to unsigned.
    SNarrow, UNarrow,
    /// Integer lanes to float lanes of the same width.
    SIToFP,
    /// Float lanes to integers of the same width, truncating; NaN and
    /// out-of-range lanes give the minimum integer (x86 `cvttps2dq`).
    FPToSI,
    /// The low two f32 lanes to f64, and f64 lanes to f32 (high lanes zero).
    FPromoteLow, FDemote,
    /// Bytes of `a` (0..16) and `b` (16..32) picked by the constant indices.
    Shuffle(Box<[u8; 16]>),
    /// Bytes of `a` picked by the byte lanes of `b`; an index of 16 or more
    /// gives zero.
    Swizzle,
    /// The scalar `a` in every lane.
    Splat,
    /// Lane `n` of `a` as a scalar of the lane type.
    Extract(u8),
    /// `a` with lane `n` replaced by the scalar `b`.
    Insert(u8),
    /// Bits of `b` where `a` has ones, else bits of `c`.
    Select,
    /// The same 128 bits as `ty`.
    Bitcast,
    /// `a * b + c` with one rounding.
    Fma,
    /// The high bit of each lane of `a`, packed into an i32.
    MoveMask,
    /// The constant 16 bytes, as `ty`.
    Const(Box<[u8; 16]>),
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
    /// The value, of type `to_ty`, which folding keeps: an integer or pointer
    /// passed to `...`, whose width a constant alone does not tell (on i386 every
    /// argument has its own size on the stack).
    Typed,
}

/// An operand of [`Instr::InlineAsm`]: the value, its type, and for an indirect
/// (memory) operand the type of the object it addresses.
#[derive(Debug, Clone)]
pub struct AsmArg { pub val: Val, pub ty: Type, pub elem: Option<Type> }

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

    /// Load from a pointer into memory that never changes after it is written and
    /// never traps (e.g. a `new[]` allocation's immutable size/refcount header). The
    /// back end marks it `readonly` + `notrap` so the mid-end can freely hoist and
    /// CSE it — in particular, lift a loop-invariant bounds-check size load out of a
    /// hot loop. It is genuinely pure (safe for DCE), unlike a plain `Load` which is
    /// conservatively kept (it might be a volatile MMIO access).
    LoadReadonly { dest: ValId, ptr: Val, ty: Type },

    /// Store a value to a pointer.
    Store { val: Val, ptr: Val },

    /// `Load` of a `volatile` object: it happens, once, in order with the other
    /// volatile accesses.
    VolatileLoad { dest: ValId, ptr: Val, ty: Type },

    /// `Store` of a `volatile` object.
    VolatileStore { val: Val, ptr: Val },

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

    /// Extract the high (sign) bit of each lane of a SIMD vector into a scalar
    /// integer bitmask — lane `k` sets bit `k` (x86 `pmovmskb` / Cranelift
    /// `vhigh_bits`). `ty` is the input vector type; `dest` is an i32. Fed a
    /// lane-comparison mask, `popcnt(dest)` counts the matching lanes — the core
    /// of the vectorized byte-predicate count (see `try_vectorize_predcount`).
    VecMoveMask { dest: ValId, val: Val, ty: Type },

    /// A portable operation on 128-bit vectors (`Type::simd128`); see
    /// [`SimdOp`]. `arg_ty` is the type of the vector operands (the lanes the
    /// op reads), `ty` the result's. Scalar operands (shift counts, inserted or
    /// splatted lanes) are typed by their own value. x86 SIMD builtins lower to
    /// sequences of these, a 256-bit one as two halves.
    Simd { dest: ValId, op: SimdOp, args: Vec<Val>, arg_ty: Type, ty: Type },

    /// MemCopy (used for struct assignments).
    MemCopy { dst: Val, src: Val, size: u64, align: u64 },

    /// MemSet (used for zeroinit).
    MemSet { dst: Val, val: Val, size: u64, align: u64 },

    /// A C99 variable-length array: `size` bytes, zeroed and 16-aligned, valid
    /// until the `VlaFree` of `dest`. On the stack where the back end can (LLVM:
    /// an alloca after a stack save, as GCC); Cranelift, which has no dynamic stack
    /// allocation, takes a fixed stack slot when `size` fits it and `calloc` beyond.
    VlaAlloc { dest: ValId, size: Val, calloc: FuncRef },

    /// The end of the scope of the VLA allocated as `alloc` (a `VlaAlloc` dest),
    /// whose pointer is `ptr`: its storage is released.
    VlaFree { alloc: ValId, ptr: Val, free: FuncRef },

    /// `alloca(size)`: storage until the function returns (LLVM: a dynamic alloca;
    /// Cranelift: `malloc`, never freed).
    DynAlloca { dest: ValId, size: Val, malloc: FuncRef },

    /// GNU inline assembly in LLVM's form (`-m32`: the LLVM back end only).
    /// `template` is in LLVM's syntax (`$0`, `${1:k}`), `constraints` its
    /// comma-separated list: the outputs in order, then the inputs, then the
    /// clobbers. Each register output's value is stored through its pointer in
    /// `outputs`; `args` are the other operands in order — an indirect (memory)
    /// one is an address, with the type it points to.
    /// `at` is the statement's `file:line:col`, for an error about it.
    InlineAsm { template: String, constraints: String, outputs: Vec<(Val, Type)>, args: Vec<AsmArg>, at: String },

    /// Byte-swap an integer value.
    BSwap { dest: ValId, val: Val, ty: Type },

    /// Atomic load of `ty` from `ptr` (sequentially consistent).
    AtomicLoad { dest: ValId, ptr: Val, ty: Type },
    /// Atomic store of `val` (typed `ty`) to `ptr` (sequentially consistent).
    AtomicStore { ptr: Val, val: Val, ty: Type },
    /// Sequentially consistent memory fence (`mfence` on x86-64): no memory
    /// access is reordered across it, by the compiler or the CPU. SIC `fence;`,
    /// C `__atomic_thread_fence(__ATOMIC_SEQ_CST)` / `__sync_synchronize()`.
    Fence,
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
    /// `__builtin_frame_address(0)`: the current function's frame pointer.
    FrameAddress { dest: ValId },

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
            | Instr::ReturnAddress { .. } | Instr::FrameAddress { .. } | Instr::Fence => {}
            Instr::Load { ptr, .. } | Instr::LoadReadonly { ptr, .. } | Instr::VolatileLoad { ptr, .. } => f(ptr),
            Instr::Store { val, ptr } | Instr::VolatileStore { val, ptr } => { f(val); f(ptr); }
            Instr::BinOp { lhs, rhs, .. } | Instr::Cmp { lhs, rhs, .. } => { f(lhs); f(rhs); }
            Instr::UnaryOp { val, .. } | Instr::Cast { val, .. } | Instr::BSwap { val, .. }
            | Instr::VecMoveMask { val, .. } => f(val),
            Instr::Simd { args, .. } => { for a in args { f(a); } }
            Instr::Call { args, .. } => { for a in args { f(a); } }
            Instr::CallIndirect { fptr, args, .. } => { f(fptr); for a in args { f(a); } }
            Instr::GetFieldPtr { base, .. } => f(base),
            Instr::GetElemPtr { base, index, .. } => { f(base); f(index); }
            Instr::PtrOffset { base, offset, .. } => { f(base); f(offset); }
            Instr::Select { cond, on_true, on_false, .. } => { f(cond); f(on_true); f(on_false); }
            Instr::MemCopy { dst, src, .. } => { f(dst); f(src); }
            Instr::MemSet { dst, val, .. } => { f(dst); f(val); }
            Instr::VlaAlloc { size, .. } | Instr::DynAlloca { size, .. } => f(size),
            Instr::VlaFree { ptr, .. } => f(ptr),
            Instr::InlineAsm { outputs, args, .. } => {
                for (p, _) in outputs { f(p); }
                for a in args { f(&a.val); }
            }
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
            | Instr::ReturnAddress { .. } | Instr::FrameAddress { .. } | Instr::Fence => {}
            Instr::Load { ptr, .. } | Instr::LoadReadonly { ptr, .. } | Instr::VolatileLoad { ptr, .. } => f(ptr),
            Instr::Store { val, ptr } | Instr::VolatileStore { val, ptr } => { f(val); f(ptr); }
            Instr::BinOp { lhs, rhs, .. } | Instr::Cmp { lhs, rhs, .. } => { f(lhs); f(rhs); }
            Instr::UnaryOp { val, .. } | Instr::Cast { val, .. } | Instr::BSwap { val, .. }
            | Instr::VecMoveMask { val, .. } => f(val),
            Instr::Simd { args, .. } => { for a in args { f(a); } }
            Instr::Call { args, .. } => { for a in args { f(a); } }
            Instr::CallIndirect { fptr, args, .. } => { f(fptr); for a in args { f(a); } }
            Instr::GetFieldPtr { base, .. } => f(base),
            Instr::GetElemPtr { base, index, .. } => { f(base); f(index); }
            Instr::PtrOffset { base, offset, .. } => { f(base); f(offset); }
            Instr::Select { cond, on_true, on_false, .. } => { f(cond); f(on_true); f(on_false); }
            Instr::MemCopy { dst, src, .. } => { f(dst); f(src); }
            Instr::MemSet { dst, val, .. } => { f(dst); f(val); }
            Instr::VlaAlloc { size, .. } | Instr::DynAlloca { size, .. } => f(size),
            Instr::VlaFree { ptr, .. } => f(ptr),
            Instr::InlineAsm { outputs, args, .. } => {
                for (p, _) in outputs { f(p); }
                for a in args { f(&mut a.val); }
            }
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
            Instr::Alloca { dest, .. } | Instr::Load { dest, .. } | Instr::VolatileLoad { dest, .. }
            | Instr::LoadReadonly { dest, .. }
            | Instr::BinOp { dest, .. } | Instr::UnaryOp { dest, .. }
            | Instr::Cast { dest, .. } | Instr::Cmp { dest, .. }
            | Instr::GetFieldPtr { dest, .. } | Instr::GetElemPtr { dest, .. }
            | Instr::PtrOffset { dest, .. } | Instr::Select { dest, .. }
            | Instr::BSwap { dest, .. } | Instr::VecMoveMask { dest, .. } | Instr::VaArg { dest, .. }
            | Instr::Simd { dest, .. }
            | Instr::AtomicLoad { dest, .. } | Instr::AtomicRmw { dest, .. }
            | Instr::AtomicCas { dest, .. }
            | Instr::ReturnAddress { dest } | Instr::FrameAddress { dest }
            | Instr::VlaAlloc { dest, .. } | Instr::DynAlloca { dest, .. } => Some(*dest),
            Instr::Call { dest, .. } | Instr::CallIndirect { dest, .. } => *dest,
            Instr::Store { .. } | Instr::VolatileStore { .. } | Instr::MemCopy { .. } | Instr::MemSet { .. }
            | Instr::AtomicStore { .. } | Instr::Fence
            | Instr::VaStart { .. } | Instr::VaEnd { .. } | Instr::SrcLine(_)
            | Instr::DbgVar { .. } | Instr::VlaFree { .. } | Instr::InlineAsm { .. } => None,
        }
    }

    /// Whether removing this instruction (when its result is unused) is safe —
    /// i.e. it has no side effect. Conservative: loads (possibly volatile MMIO),
    /// stores, calls, allocas, and var-args are never removable.
    pub fn is_pure(&self) -> bool {
        matches!(self,
            Instr::BinOp { .. } | Instr::UnaryOp { .. } | Instr::Cmp { .. }
            | Instr::Cast { .. } | Instr::BSwap { .. } | Instr::GetFieldPtr { .. }
            | Instr::GetElemPtr { .. } | Instr::PtrOffset { .. } | Instr::Select { .. }
            | Instr::VecMoveMask { .. } | Instr::Simd { .. }
            | Instr::LoadReadonly { .. })
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
