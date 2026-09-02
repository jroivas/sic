//! Local dead-code elimination: drop pure instructions whose result is never
//! used. Iterated to a fixpoint within each function (removing one dead value
//! can make its operands' definitions dead too).
//!
//! Only `Instr::is_pure()` instructions are ever removed — never a store, call,
//! alloca, var-arg, or **load** (a load may be a volatile MMIO access in code
//! like QEMU, which must not be elided even when its value is unused).

use std::collections::HashSet;
use sic_ir::{Module, Val, ValId};
use crate::ir::pass::IrPass;

#[derive(Default)]
pub struct Dce;

impl Dce {
    pub fn new() -> Self { Dce }
}

impl IrPass for Dce {
    fn name(&self) -> &'static str { "dce" }
    fn run(&mut self, m: &mut Module) -> bool {
        let mut changed = false;
        for func in &mut m.functions {
            loop {
                // Collect every value id used as an operand anywhere.
                let mut used: HashSet<ValId> = HashSet::new();
                for b in &func.blocks {
                    for ins in &b.instrs {
                        ins.for_each_val(|v| if let Val::Local(id) = v { used.insert(*id); });
                    }
                    b.terminator.for_each_val(|v| if let Val::Local(id) = v { used.insert(*id); });
                }
                // Drop pure instructions whose dest is unused.
                let mut removed = false;
                for b in &mut func.blocks {
                    let before = b.instrs.len();
                    b.instrs.retain(|ins| match ins.dest() {
                        Some(d) => !(ins.is_pure() && !used.contains(&d)),
                        None => true,
                    });
                    if b.instrs.len() != before { removed = true; }
                }
                if removed { changed = true; } else { break; }
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sic_ir::{Function, BasicBlock, Instr, Terminator, Constant, Type, BinOp, FuncRef,
                 FunctionType, Linkage, module::Param};

    #[test]
    fn removes_dead_pure_keeps_call() {
        let sig = FunctionType { ret: Type::i32(), params: vec![], variadic: false };
        let mut f = Function::new("f".into(), sig, vec![] as Vec<Param>, Linkage::External);
        let mut bb = BasicBlock::new(f.alloc_block());
        // %0 = 1 + 2  (pure, unused)
        bb.instrs.push(Instr::BinOp { dest: f.alloc_val(), op: BinOp::Add,
            lhs: Constant::int(1), rhs: Constant::int(2), ty: Type::i32() });
        // call g()  (side effect, unused result)
        bb.instrs.push(Instr::Call { dest: Some(f.alloc_val()), func: FuncRef::extern_(0),
            args: vec![], ret_ty: Type::i32() });
        bb.terminator = Terminator::Ret(Some(Constant::int(0)));
        f.blocks.push(bb);
        let mut m = Module::new("m".into());
        m.functions.push(f);

        assert!(Dce::new().run(&mut m));
        let instrs = &m.functions[0].blocks[0].instrs;
        assert_eq!(instrs.len(), 1, "the dead BinOp is dropped, the Call stays");
        assert!(matches!(instrs[0], Instr::Call { .. }));
    }
}
