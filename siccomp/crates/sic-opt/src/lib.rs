//! sic optimization passes, in two pluggable stages:
//!   * **AST stage** (untyped, pre-lowering): `const-fold`, `dead-branch`.
//!   * **IR stage** (typed, post-lowering): `ir-fold`, `algebraic`, `dce`.
//!
//! Each stage runs an ordered pass pipeline to a fixpoint. The driver decides
//! which passes are enabled (from the `-O` level and `-f` overrides) and hands a
//! [`PassConfig`] to [`run_ast_passes`] / [`run_ir_passes`].

pub mod visit;
pub mod pass;
pub mod util;
pub mod const_fold;
pub mod dead_branch;
pub mod ir;

pub use const_fold::ConstFold;
pub use pass::{AstPass, PassConfig, PassManager};

use sic_frontend::ast::TranslationUnit;

/// Run the enabled AST-stage passes over `tu` in place.
pub fn run_ast_passes(tu: &mut TranslationUnit, cfg: &PassConfig) {
    let mut pm = PassManager::new(cfg.max_iters, cfg.debug);
    if cfg.is_enabled("const-fold") { pm.add(Box::new(ConstFold::new())); }
    if cfg.is_enabled("dead-branch") { pm.add(Box::new(dead_branch::DeadBranch::new())); }
    pm.run(tu);
}

/// Run the enabled IR-stage passes over `module` in place.
pub fn run_ir_passes(module: &mut sic_ir::Module, cfg: &PassConfig) {
    ir::run_ir_passes(module, cfg);
}
