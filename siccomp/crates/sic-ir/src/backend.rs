use crate::Module;

/// What a backend failed with; its own errors, boxed.
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// How hard to optimize, as far as the backend goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptLevel {
    None,
    /// `-O1`: light optimization (what a backend without the level does
    /// unoptimized).
    Basic,
    Speed,
    Size,
}

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
    /// The code is for an executable (PIE: `-fpie`, the default, not `-fpic` or
    /// `-shared`): its own definitions cannot be preempted.
    pub pie: bool,
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
    /// Linux's mitigation and hardening options (what [`Backend::mitigations`]
    /// says the back end does).
    pub mitigations: Mitigations,
}

/// Spectre/SLS mitigations and hardening, from the gcc/clang options.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mitigations {
    /// `-mfunction-return=thunk-extern`: a return is `jmp __x86_return_thunk`.
    pub return_thunk: bool,
    /// Indirect calls and jumps through retpolines: `-mretpoline`,
    /// `-mindirect-branch=thunk[-inline]` (the back end's own thunks).
    pub retpoline: bool,
    /// `-mretpoline-external-thunk`, `-mindirect-branch=thunk-extern`: through
    /// `__x86_indirect_thunk_<reg>`, which the program defines.
    pub retpoline_external: bool,
    /// `-mindirect-branch-cs-prefix`: a `cs` prefix on a thunk call through r8–r15,
    /// so the kernel can patch it into an indirect call in place.
    pub indirect_branch_cs_prefix: bool,
    /// `-mharden-sls=all` (`ret` and indirect jumps; `return`, `indirect-jmp`).
    pub harden_sls_ret: bool,
    pub harden_sls_ijmp: bool,
    pub stack_protector: StackProtector,
    /// `-mstack-protector-guard=global|tls`, `-reg=`, `-symbol=`, `-offset=`.
    pub stack_guard: Option<String>,
    pub stack_guard_reg: Option<String>,
    pub stack_guard_symbol: Option<String>,
    pub stack_guard_offset: Option<i64>,
    /// `-fpatchable-function-entry=N[,M]`: N bytes of `nop`, M of them before the
    /// entry.
    pub patchable_entry: Option<(u32, u32)>,
    /// `-fcf-protection=branch|return|full`: `endbr` at indirect-branch targets,
    /// shadow-stack compatible returns.
    pub cf_branch: bool,
    pub cf_return: bool,
    /// `-fzero-call-used-regs=<kind>`.
    pub zero_call_used_regs: Option<String>,
    /// `-mstack-alignment=N` / `-mpreferred-stack-boundary=log2 N`: the stack is
    /// N-aligned at calls (Linux: 8), not 16.
    pub stack_alignment: Option<u32>,
}

/// `-fstack-protector` (functions with a char array), `-strong` (any array or
/// address-taken local), `-all`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StackProtector { #[default] None, On, Strong, All }

impl Default for BackendOptions {
    fn default() -> Self {
        BackendOptions { ptr_size: 8, opt: OptLevel::None, debug_info: false, pic: true, pie: true,
            function_sections: true, sse: true, x87: true, no_text_data: false, no_red_zone: false, features: Vec::new(),
            mitigations: Mitigations::default() }
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

    /// Whether it implements [`Mitigations`] (else the driver warns they are
    /// ignored).
    fn mitigations(&self) -> bool { false }
}
