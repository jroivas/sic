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

/// Opcodes whose operands Cranelift's x64 lowering takes as register-or-
/// memory with no immediate form (`put_in_reg_mem`): a constant operand of
/// any size goes to the constant pool (`cmov` for a `select`, the multiply of
/// a division-by-constant's magic number, a divisor or extended value at -O0).
fn pools_any_constant(op: Opcode) -> bool {
    matches!(op, Opcode::Select | Opcode::SelectSpectreGuard | Opcode::Smin | Opcode::Smax
        | Opcode::Umin | Opcode::Umax | Opcode::Iabs | Opcode::Umulhi | Opcode::Smulhi
        | Opcode::Udiv | Opcode::Sdiv | Opcode::Urem | Opcode::Srem | Opcode::Uextend | Opcode::Sextend
        | Opcode::Clz | Opcode::Ctz | Opcode::Cls | Opcode::Popcnt | Opcode::Bitrev | Opcode::Bswap
        | Opcode::UmulOverflow | Opcode::SmulOverflow)
}

/// Rewrite `func`'s pool-bound integer constants (see the module docs): every
/// 64-bit `iconst` that is not a sign-extended 32-bit value, and any constant
/// operand of an instruction with no immediate form. `table` holds the
/// module's constant data objects by value (8 bytes, little-endian: a narrower
/// load reads the value's low bytes).
pub(crate) fn wide_constants_to_rodata<M: Module>(
    func: &mut cir::Function,
    module: &mut M,
    table: &mut HashMap<i64, DataId>,
) -> ModuleResult<()> {
    let mut wide = Vec::new();
    let mut operands = Vec::new(); // (user, argument index, value, type)
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            if let InstructionData::UnaryImm { opcode: Opcode::Iconst, imm } = func.dfg.insts[inst] {
                let v = imm.bits();
                if func.dfg.ctrl_typevar(inst) == ct::I64 && i32::try_from(v).is_err() {
                    wide.push((inst, v));
                }
                continue;
            }
            let op = func.dfg.insts[inst].opcode();
            // `cmp` takes an immediate only as its second operand; an 8-bit
            // multiply has no immediate form.
            let only_first = op == Opcode::Icmp;
            let byte_mul = op == Opcode::Imul && func.dfg.ctrl_typevar(inst) == ct::I8;
            if !pools_any_constant(op) && !only_first && !byte_mul { continue; }
            for (k, &a) in func.dfg.inst_args(inst).iter().enumerate() {
                if only_first && k > 0 { break; }
                if let cir::ValueDef::Result(d, _) = func.dfg.value_def(a) {
                    if let InstructionData::UnaryImm { opcode: Opcode::Iconst, imm } = func.dfg.insts[d] {
                        operands.push((inst, k, imm.bits(), func.dfg.value_type(a)));
                    }
                }
            }
        }
    }
    let mut gvs: HashMap<i64, cir::GlobalValue> = HashMap::new();
    let mut global = |v: i64, func: &mut cir::Function, module: &mut M| -> ModuleResult<cir::GlobalValue> {
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
        Ok(*gvs.entry(v).or_insert_with(|| module.declare_data_in_func(did, func)))
    };
    let flags = MemFlagsData::trusted().with_readonly();
    for (inst, k, v, ty) in operands {
        let gv = global(v, func, module)?;
        let mut pos = FuncCursor::new(func).at_inst(inst);
        let addr = pos.ins().symbol_value(ct::I64, gv);
        let loaded = pos.ins().load(ty, flags, addr, 0);
        pos.func.dfg.inst_args_mut(inst)[k] = loaded;
    }
    for (inst, v) in wide {
        let gv = global(v, func, module)?;
        let mut pos = FuncCursor::new(func).at_inst(inst);
        let addr = pos.ins().symbol_value(ct::I64, gv);
        pos.func.replace(inst).load(ct::I64, flags, addr, 0);
    }
    Ok(())
}

/// Whether the function Cranelift just compiled (with `want_disasm`) reads a
/// constant pool, which lives inside its code: its disassembly prints such an
/// operand as a bare `(%rip)` (`const(N)` in older Cranelift); a symbol is
/// reached through `load_ext_name`, never printed that way.
#[cfg(test)]
pub(crate) fn uses_constant_pool(ctx: &cranelift_codegen::Context) -> bool {
    pool_instruction(ctx).is_some()
}

/// The first instruction of the compiled function that reads its constant
/// pool (see `uses_constant_pool`).
pub(crate) fn pool_instruction(ctx: &cranelift_codegen::Context) -> Option<String> {
    let text = ctx.compiled_code()?.vcode.as_ref()?;
    text.lines().find(|l| l.contains(" (%rip)") || l.contains(",(%rip)") || l.contains("const("))
        .map(|l| l.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cranelift_codegen::settings::{self, Configurable};
    use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
    use cranelift_module::Linkage;
    use cranelift_object::{ObjectBuilder, ObjectModule};

    /// `x * 0x123456789` and `x / 7`, compiled as non-PIC code at `speed`:
    /// Cranelift alone keeps constants in a pool inside the code (seen by
    /// `uses_constant_pool`); after the optimizer, the rewrite leaves none.
    fn compile(rewrite: bool) -> bool {
        let mut fb = settings::builder();
        fb.set("is_pic", "false").unwrap();
        fb.set("opt_level", "none").unwrap();
        let isa = cranelift_native::builder().unwrap().finish(settings::Flags::new(fb.clone())).unwrap();
        fb.set("opt_level", "speed").unwrap();
        let opt_isa = cranelift_native::builder().unwrap().finish(settings::Flags::new(fb)).unwrap();
        let mut module = ObjectModule::new(ObjectBuilder::new(isa, "t", cranelift_module::default_libcall_names()).unwrap());
        let mut sig = module.make_signature();
        sig.params.push(cir::AbiParam::new(ct::I64));
        sig.returns.push(cir::AbiParam::new(ct::I64));
        let fid = module.declare_function("f", Linkage::Export, &sig).unwrap();
        let tcfg = module.target_config();
        let mut ctx = module.make_context();
        ctx.func.signature = sig;
        let mut fbc = FunctionBuilderContext::new();
        {
            let mut b = FunctionBuilder::new(&mut ctx.func, &mut fbc);
            let blk = b.create_block();
            b.append_block_params_for_function_params(blk);
            b.switch_to_block(blk);
            b.seal_block(blk);
            let x = b.block_params(blk)[0];
            let k = b.ins().iconst(ct::I64, 0x123456789);
            let m = b.ins().imul(x, k);
            let seven = b.ins().iconst(ct::I64, 7);
            let d = b.ins().udiv(m, seven);
            b.ins().return_(&[d]);
            b.finalize(tcfg);
        }
        ctx.optimize(&*opt_isa, &mut Default::default()).unwrap();
        if rewrite {
            let mut table = HashMap::new();
            wide_constants_to_rodata(&mut ctx.func, &mut module, &mut table).unwrap();
        }
        ctx.want_disasm = true;
        module.define_function(fid, &mut ctx).unwrap();
        uses_constant_pool(&ctx)
    }

    #[test]
    fn constants_leave_the_code() {
        let (plain, rewritten) = (compile(false), compile(true));
        assert!(plain, "the check should see Cranelift's own pool");
        assert!(!rewritten, "rewritten constants must not stay in the code");
    }
}
