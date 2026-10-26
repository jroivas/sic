//! Wide integer constants are loaded from read-only data, never from code.
//!
//! Cranelift's x64 lowering puts any constant operand that does not fit a
//! sign-extended 32-bit immediate (`put_in_reg_mem`) into a per-function
//! constant pool emitted *inside the function's code*, and its optimizer
//! creates such constants itself (division by a constant becomes a multiply
//! by a 64-bit "magic" number). Data in `.text` is harmless to the CPU, but a
//! tool that decodes code linearly cannot step over it — Linux's objtool
//! stopped at `0x20c49ba5e353f7cf` (÷1000) in init/main.o.
//!
//! So after Cranelift's optimizer has run, every 64-bit `iconst` that is not a
//! sign-extended 32-bit value becomes a load from an 8-byte read-only data
//! object (one per distinct value, shared by the module). The lowering then
//! sees a load, not a constant: the value lives in `.rodata`, reached by an
//! ordinary relocation — as GCC and Clang place the constants they load. A
//! constant used as an operand cost a memory load from the pool already; one
//! that Cranelift would have materialized with `movabs` now costs a load too.

use std::collections::HashMap;
use cranelift_codegen::cursor::{Cursor, FuncCursor};
use cranelift_codegen::ir::{self as cir, types as ct, InstBuilder, InstructionData, MemFlagsData, Opcode};
use cranelift_module::{DataDescription, DataId, Module, ModuleResult};

/// Rewrite `func`'s wide `iconst`s (see the module docs). `table` holds the
/// module's constant data objects by value.
pub(crate) fn wide_constants_to_rodata<M: Module>(
    func: &mut cir::Function,
    module: &mut M,
    table: &mut HashMap<i64, DataId>,
) -> ModuleResult<()> {
    let mut sites = Vec::new();
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            if let InstructionData::UnaryImm { opcode: Opcode::Iconst, imm } = func.dfg.insts[inst] {
                let v = imm.bits();
                if func.dfg.ctrl_typevar(inst) == ct::I64 && i32::try_from(v).is_err() {
                    sites.push((inst, v));
                }
            }
        }
    }
    let mut gvs: HashMap<i64, cir::GlobalValue> = HashMap::new();
    for (inst, v) in sites {
        let did = match table.get(&v) {
            Some(&d) => d,
            None => {
                let d = module.declare_anonymous_data(false, false)?;
                let mut desc = DataDescription::new();
                desc.define(Box::new(v.to_le_bytes()));
                desc.set_align(8);
                module.define_data(d, &desc)?;
                table.insert(v, d);
                d
            }
        };
        let gv = *gvs.entry(v).or_insert_with(|| module.declare_data_in_func(did, func));
        let mut pos = FuncCursor::new(func).at_inst(inst);
        let addr = pos.ins().symbol_value(ct::I64, gv);
        pos.func.replace(inst).load(ct::I64, MemFlagsData::trusted().with_readonly(), addr, 0);
    }
    Ok(())
}
