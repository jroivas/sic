//! Facts about IR a backend needs and the IR does not state: the type of every
//! value, the width of a store, and the stack objects of a function.

use crate::fast_hash::HashMap;
use crate::{Constant, Function, Instr, Type, Val, ValId};

/// `ValId` of parameter 0: parameters are numbered from here.
pub const PARAM_VAL_BASE: u32 = 0x10000;

/// The type of every value `f` defines, by `ValId`, and of its parameters.
/// An alloca is a pointer to its slot type. `PtrOffset`, whose result the IR
/// does not type, is a `void*`.
pub fn value_types(f: &Function) -> HashMap<u32, Type> {
    let mut m = HashMap::default();
    for (i, p) in f.params.iter().enumerate() { m.insert(PARAM_VAL_BASE + i as u32, p.ty.clone()); }
    for bb in &f.blocks {
        for instr in &bb.instrs {
            let r = match instr {
                Instr::Alloca { dest, ty, .. } => Some((dest, Type::Pointer(Box::new(ty.clone())))),
                Instr::Load { dest, ty, .. } | Instr::LoadReadonly { dest, ty, .. }
                | Instr::BinOp { dest, ty, .. } | Instr::UnaryOp { dest, ty, .. }
                | Instr::Select { dest, ty, .. } | Instr::VaArg { dest, ty, .. }
                | Instr::Simd { dest, ty, .. } | Instr::BSwap { dest, ty, .. }
                | Instr::AtomicLoad { dest, ty, .. } | Instr::AtomicRmw { dest, ty, .. }
                | Instr::AtomicCas { dest, ty, .. } => Some((dest, ty.clone())),
                Instr::Cast { dest, to_ty, .. } => Some((dest, to_ty.clone())),
                Instr::Cmp { dest, .. } => Some((dest, Type::Bool)),
                Instr::VecMoveMask { dest, .. } => Some((dest, Type::i32())),
                Instr::Call { dest: Some(d), ret_ty, .. }
                | Instr::CallIndirect { dest: Some(d), ret_ty, .. } => Some((d, ret_ty.clone())),
                Instr::GetFieldPtr { dest, result_ty, .. }
                | Instr::GetElemPtr { dest, result_ty, .. } => Some((dest, result_ty.clone())),
                Instr::PtrOffset { dest, .. } | Instr::ReturnAddress { dest }
                | Instr::FrameAddress { dest } => Some((dest, Type::void_ptr())),
                _ => None,
            };
            if let Some((d, t)) = r { m.insert(d.0, t); }
        }
    }
    m
}

/// What `Store { val, .. }` writes. The store has no type of its own, and the
/// pointer's does not count (`*(int *)p = v` through a `long *`): it is the
/// value's. A constant is an `int` unless it needs more, as a frontend that
/// means a wider store must make it one.
pub fn store_type(types: &HashMap<u32, Type>, val: &Val) -> Option<Type> {
    let int_fit = |fits: bool| if fits { Type::i32() } else { Type::i64() };
    match val {
        Val::Local(ValId(id)) => types.get(id).cloned(),
        Val::Global(_) | Val::Func(_) => Some(Type::void_ptr()),
        Val::Const(c) => Some(match c {
            Constant::Int(v) => int_fit(*v >= i32::MIN as i64 && *v <= u32::MAX as i64),
            Constant::UInt(v) => int_fit(*v <= u32::MAX as u64),
            Constant::Float(_) => Type::Float64,
            Constant::Bool(_) => Type::Bool,
            Constant::Null | Constant::Undef | Constant::Zeroinit => Type::i32(),
            _ => Type::void_ptr(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FunctionType, Linkage, Param};

    #[test]
    fn store_widths() {
        let none = HashMap::default();
        let t = |c| store_type(&none, &Val::Const(c));
        assert_eq!(t(Constant::Int(0)), Some(Type::i32()));
        assert_eq!(t(Constant::Int(-1)), Some(Type::i32()));
        assert_eq!(t(Constant::Int(1 << 40)), Some(Type::i64()));
        assert_eq!(t(Constant::UInt(u32::MAX as u64)), Some(Type::i32()));
        assert_eq!(t(Constant::UInt(1 << 32)), Some(Type::i64()));
    }

    #[test]
    fn types_of_values() {
        let sig = FunctionType { ret: Type::Void, params: vec![Type::i64()], variadic: false };
        let params = vec![Param { name: "a".to_string(), ty: Type::i64() }];
        let f = Function::new("f".to_string(), sig, params, Linkage::External);
        let m = value_types(&f);
        assert_eq!(m.get(&PARAM_VAL_BASE), Some(&Type::i64()));
        assert_eq!(store_type(&m, &Val::Local(ValId(PARAM_VAL_BASE))), Some(Type::i64()));
    }
}
