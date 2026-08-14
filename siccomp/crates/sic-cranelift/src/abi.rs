//! Cranelift side of the System V aggregate ABI: turn `sic_ir::abi`
//! classifications into Cranelift `AbiParam`s and marshal aggregate values
//! into/out of the register-sized pieces. See `siccomp/ABI.md` and
//! `sic-ir/src/abi.rs`.

use cranelift_codegen::ir::{types as ct, AbiParam, ArgumentPurpose, InstBuilder, MemFlags, Type as ClType, Value};
use cranelift_frontend::FunctionBuilder;
use sic_ir::abi::{classify_struct_union, AggClass, Chunk, RegClass};
use sic_ir::Type;

use crate::types::cl_type;

/// How one IR parameter/argument is passed at the Cranelift level.
pub enum ParamPass {
    /// An ordinary scalar (also `Array`/vector, kept on the pointer path): one
    /// `AbiParam` of this type.
    Scalar(ClType),
    /// A small aggregate passed in registers: one `AbiParam` per eightbyte.
    Direct(Vec<Chunk>),
    /// A MEMORY-class aggregate: one `StructArgument(size)` param (by value on
    /// the stack); the value at the boundary is a pointer.
    ByValStack(u32),
}

/// Classify one IR parameter type for the System V ABI.
pub fn classify_param(ty: &Type, ptr_size: u32) -> ParamPass {
    match ty {
        Type::Struct(_) | Type::Union(_) => match classify_struct_union(ty, ptr_size) {
            AggClass::Regs(chunks) => ParamPass::Direct(chunks),
            AggClass::Memory(size) => ParamPass::ByValStack(size),
        },
        // Scalars, pointers, and `Array` (vectors) keep the single-value mapping.
        other => ParamPass::Scalar(cl_type(other, ptr_size).unwrap_or(ct::I64)),
    }
}

/// The Cranelift value type carrying one eightbyte. INTEGER eightbytes always
/// travel in a full 64-bit GPR (upper bytes are don't-care for partial ones);
/// SSE eightbytes are a single or double float.
pub fn chunk_cl_type(c: &Chunk) -> ClType {
    match c.class {
        RegClass::Int => ct::I64,
        RegClass::Sse => if c.bytes <= 4 { ct::F32 } else { ct::F64 },
    }
}

/// Append the `AbiParam`s for one IR parameter.
pub fn push_param_abi(ty: &Type, ptr_size: u32, ptr_ty: ClType, out: &mut Vec<AbiParam>) {
    match classify_param(ty, ptr_size) {
        ParamPass::Scalar(t) => out.push(AbiParam::new(t)),
        ParamPass::Direct(chunks) => {
            for c in &chunks {
                out.push(AbiParam::new(chunk_cl_type(c)));
            }
        }
        ParamPass::ByValStack(size) => {
            out.push(AbiParam::special(ptr_ty, ArgumentPurpose::StructArgument(size)));
        }
    }
}

/// Load one eightbyte from an aggregate at `base + chunk.offset` into a value of
/// `chunk_cl_type(chunk)`. Reads exactly `chunk.bytes` bytes so it never runs
/// past the aggregate's storage.
pub fn load_chunk(builder: &mut FunctionBuilder, base: Value, chunk: &Chunk) -> Value {
    let flags = MemFlags::new();
    let off = chunk.offset as i32;
    match chunk.class {
        RegClass::Sse => {
            let ty = if chunk.bytes <= 4 { ct::F32 } else { ct::F64 };
            builder.ins().load(ty, flags, base, off)
        }
        RegClass::Int => {
            // Assemble `bytes` bytes (little-endian) into an i64.
            let mut acc: Option<Value> = None;
            let mut pos = 0u32;
            while pos < chunk.bytes {
                let rem = chunk.bytes - pos;
                let (ty, n) = if rem >= 4 { (ct::I32, 4) } else if rem >= 2 { (ct::I16, 2) } else { (ct::I8, 1) };
                let piece = builder.ins().load(ty, flags, base, off + pos as i32);
                let wide = builder.ins().uextend(ct::I64, piece);
                let shifted = if pos == 0 { wide } else { builder.ins().ishl_imm(wide, (pos * 8) as i64) };
                acc = Some(match acc {
                    None => shifted,
                    Some(a) => builder.ins().bor(a, shifted),
                });
                pos += n;
            }
            acc.unwrap_or_else(|| builder.ins().iconst(ct::I64, 0))
        }
    }
}

/// Store one eightbyte `val` (of `chunk_cl_type`) into `dst + chunk.offset`,
/// writing exactly `chunk.bytes` bytes.
pub fn store_chunk(builder: &mut FunctionBuilder, val: Value, dst: Value, chunk: &Chunk) {
    let flags = MemFlags::new();
    let off = chunk.offset as i32;
    match chunk.class {
        RegClass::Sse => {
            builder.ins().store(flags, val, dst, off);
        }
        RegClass::Int => {
            let mut pos = 0u32;
            while pos < chunk.bytes {
                let rem = chunk.bytes - pos;
                let (ty, n) = if rem >= 4 { (ct::I32, 4) } else if rem >= 2 { (ct::I16, 2) } else { (ct::I8, 1) };
                let shifted = if pos == 0 { val } else { builder.ins().ushr_imm(val, (pos * 8) as i64) };
                let narrow = builder.ins().ireduce(ty, shifted);
                builder.ins().store(flags, narrow, dst, off + pos as i32);
                pos += n;
            }
        }
    }
}
