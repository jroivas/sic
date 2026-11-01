//! The LLVM back end, through inkwell: sic's IR to an object file in process, with
//! no LLVM tool run.

use inkwell::context::Context;
use sic_ir::{Backend, BackendError, BackendOptions, Module};

#[derive(Default)]
pub struct LlvmBackend;

impl LlvmBackend {
    pub fn new() -> Self { LlvmBackend }
}

impl Backend for LlvmBackend {
    fn name(&self) -> &'static str { "llvm" }

    fn compile_module(&mut self, module: &Module, _opts: &BackendOptions) -> Result<Vec<u8>, BackendError> {
        let context = Context::create();
        let _llvm = context.create_module(&module.name);
        Err("the LLVM back end generates no code yet".into())
    }
}
