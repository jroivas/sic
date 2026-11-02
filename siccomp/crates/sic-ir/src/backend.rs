use crate::Module;

/// What a backend failed with; its own errors, boxed.
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// How hard to optimize, as far as the backend goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptLevel { None, Speed, Size }

/// The target and code shape a module is compiled for. Nothing here is specific
/// to one backend.
#[derive(Clone, Debug)]
pub struct BackendOptions {
    pub ptr_size: u32,
    pub opt: OptLevel,
    /// Emit DWARF.
    pub debug_info: bool,
    /// Position-independent code.
    pub pic: bool,
    /// One section per function (`-ffunction-sections`, the default, which the
    /// driver links with `--gc-sections`); off, all code is in `.text`.
    pub function_sections: bool,
    /// SSE registers may be used (`-mno-sse` / `-mno-sse2`: not — Linux's
    /// kernel code, which does not preserve the user's FPU state). Off, sic
    /// emits no SSE: small copies use integer moves, a variadic function does
    /// not save the vector argument registers, and a floating-point or vector
    /// value is an error, as with GCC.
    pub sse: bool,
    /// The x87 FPU may be used (`-mno-80387`: not); sic needs it only for
    /// `long double`.
    pub x87: bool,
    /// Code must hold no data (`-mcmodel=kernel`: Linux's objtool decodes all
    /// of it): a backend's constant pool is avoided, and a function that would
    /// still use one is an error. Needs non-PIC code.
    pub no_text_data: bool,
    /// Nothing may be kept below the stack pointer (`-mno-red-zone`: in Linux an
    /// interrupt uses the same stack).
    pub no_red_zone: bool,
    /// The x64 extensions the code may use, from `-march`/`-m…`, by GCC's names
    /// (`sse4.2`, `popcnt`, `avx2`): nothing of the build machine's CPU beyond them.
    pub features: Vec<String>,
}

impl Default for BackendOptions {
    fn default() -> Self {
        BackendOptions { ptr_size: 8, opt: OptLevel::None, debug_info: false, pic: true,
            function_sections: true, sse: true, x87: true, no_text_data: false, no_red_zone: false, features: Vec::new() }
    }
}

impl BackendOptions {
    pub fn has_feature(&self, name: &str) -> bool { self.features.iter().any(|f| f == name) }
}

/// The abstract code-generation backend. Receives an IR module, emits native object bytes.
pub trait Backend {
    /// The name `-fbackend=` selects it by.
    fn name(&self) -> &'static str;

    /// Compile the module to a native object file (.o bytes).
    fn compile_module(&mut self, module: &Module, opts: &BackendOptions) -> Result<Vec<u8>, BackendError>;
}
