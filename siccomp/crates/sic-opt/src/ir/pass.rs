//! IR pass trait + fixpoint manager (mirrors the AST-stage `PassManager`).

use sic_ir::Module;

/// An IR→IR optimization pass. `run` rewrites the module in place and returns
/// `true` if it changed anything.
pub trait IrPass {
    fn name(&self) -> &'static str;
    fn run(&mut self, m: &mut Module) -> bool;
}

pub struct IrPassManager {
    passes: Vec<Box<dyn IrPass>>,
    max_iters: usize,
    debug: bool,
}

impl IrPassManager {
    pub fn new(max_iters: usize, debug: bool) -> Self {
        IrPassManager { passes: Vec::new(), max_iters, debug }
    }

    pub fn add(&mut self, pass: Box<dyn IrPass>) { self.passes.push(pass); }

    pub fn run(&mut self, m: &mut Module) {
        if self.passes.is_empty() { return; }
        if self.debug {
            let names: Vec<_> = self.passes.iter().map(|p| p.name()).collect();
            eprintln!("ir passes: {}", names.join(", "));
        }
        for iter in 0..self.max_iters {
            let mut changed = false;
            for p in &mut self.passes {
                changed |= p.run(m);
            }
            if !changed { return; }
            if iter + 1 == self.max_iters && self.debug {
                eprintln!("ir passes: hit fixpoint cap ({} iters)", self.max_iters);
            }
        }
    }
}
