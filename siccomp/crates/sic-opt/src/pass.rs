//! AST optimization pass framework: a pass trait plus a fixpoint-driven manager.

use std::collections::HashSet;
use sic_frontend::ast::TranslationUnit;

/// An AST→AST optimization pass. `run` rewrites the translation unit in place
/// and returns `true` if it changed anything (drives the manager's fixpoint).
pub trait AstPass {
    fn name(&self) -> &'static str;
    fn run(&mut self, tu: &mut TranslationUnit) -> bool;
}

/// Which passes to run and how, computed by the driver from the `-O` level and
/// `-f<pass>` / `-fno-<pass>` overrides. Shared by both the AST and IR stages.
#[derive(Debug, Clone)]
pub struct PassConfig {
    enabled: HashSet<String>,
    pub debug: bool,
    pub max_iters: usize,
    /// Inliner size budget: a called function of at most this many IR instructions
    /// is a candidate for inlining. Higher `-O` raises it; `inline_aggressive`
    /// ignores it entirely (bounded only by the per-caller growth cap).
    pub inline_threshold: usize,
    /// `-O3`+ : inline every eligible (non-recursive, non-variadic, scalar-return)
    /// callee regardless of size, up to the per-caller growth cap.
    pub inline_aggressive: bool,
}

impl PassConfig {
    pub fn new(enabled: HashSet<String>, debug: bool) -> Self {
        PassConfig { enabled, debug, max_iters: 8, inline_threshold: 0, inline_aggressive: false }
    }
    pub fn is_enabled(&self, name: &str) -> bool { self.enabled.contains(name) }
}

/// Runs an ordered list of passes to a fixpoint: repeat the whole pipeline until
/// a full round makes no change, capped at `max_iters` rounds so a
/// mis-behaving pass can never loop forever.
pub struct PassManager {
    passes: Vec<Box<dyn AstPass>>,
    max_iters: usize,
    debug: bool,
}

impl PassManager {
    pub fn new(max_iters: usize, debug: bool) -> Self {
        PassManager { passes: Vec::new(), max_iters, debug }
    }

    pub fn add(&mut self, pass: Box<dyn AstPass>) { self.passes.push(pass); }

    pub fn run(&mut self, tu: &mut TranslationUnit) {
        if self.passes.is_empty() { return; }
        if self.debug {
            let names: Vec<_> = self.passes.iter().map(|p| p.name()).collect();
            eprintln!("ast passes: {}", names.join(", "));
        }
        for iter in 0..self.max_iters {
            let mut changed = false;
            for p in &mut self.passes {
                changed |= p.run(tu);
            }
            if !changed { return; }
            if iter + 1 == self.max_iters && self.debug {
                eprintln!("ast passes: hit fixpoint cap ({} iters)", self.max_iters);
            }
        }
    }
}
