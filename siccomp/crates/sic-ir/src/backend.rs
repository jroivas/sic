use crate::Module;

/// The abstract code-generation backend. Receives an IR module, emits native object bytes.
pub trait Backend {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Compile the module to a native object file (.o bytes).
    fn compile_module(&mut self, module: &Module) -> Result<Vec<u8>, Self::Error>;
}
