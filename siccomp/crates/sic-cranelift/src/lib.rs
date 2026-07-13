mod types;
mod func;
mod dwarf;

use std::collections::HashMap;
use cranelift_codegen::ir as cir;
use cranelift_codegen::ir::types as ct;
use cranelift_codegen::isa::CallConv;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_module::{DataDescription, FuncId, Linkage as CLinkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use sic_ir::{Backend, FuncRef, GlobalRef, Linkage, Type};

pub use types::cl_type;

#[derive(Debug, thiserror::Error)]
pub enum CraneliftError {
    #[error("codegen error: {0}")]
    Codegen(#[from] cranelift_codegen::CodegenError),
    #[error("module error: {0}")]
    Module(#[from] cranelift_module::ModuleError),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

pub struct CraneliftBackend {
    pub ptr_size: u32,
    /// Cranelift `opt_level` setting: "none", "speed", or "speed_and_size".
    pub opt_level: String,
    /// Emit DWARF debug info (line table + compile unit) when set (`-g`).
    pub debug_info: bool,
}

impl CraneliftBackend {
    pub fn new() -> Self {
        CraneliftBackend { ptr_size: 8, opt_level: "none".to_string(), debug_info: false }
    }

    /// Set the Cranelift `opt_level` ("none" | "speed" | "speed_and_size").
    pub fn with_opt_level(mut self, opt_level: &str) -> Self {
        self.opt_level = opt_level.to_string();
        self
    }

    /// Enable DWARF debug-info emission.
    pub fn with_debug_info(mut self, debug_info: bool) -> Self {
        self.debug_info = debug_info;
        self
    }
}

impl Backend for CraneliftBackend {
    type Error = CraneliftError;

    fn compile_module(&mut self, module: &sic_ir::Module) -> Result<Vec<u8>, CraneliftError> {
        compile(module, self.ptr_size, &self.opt_level, self.debug_info)
    }
}

fn ir_linkage(l: Linkage) -> CLinkage {
    match l {
        Linkage::External => CLinkage::Export,
        Linkage::Internal => CLinkage::Local,
        Linkage::Private  => CLinkage::Local,
        Linkage::Import   => CLinkage::Import,
    }
}

fn compile(ir_module: &sic_ir::Module, ptr_size: u32, opt_level: &str, debug_info: bool) -> Result<Vec<u8>, CraneliftError> {
    // Build settings
    let mut flag_builder = settings::builder();
    flag_builder.set("use_colocated_libcalls", "false").unwrap();
    flag_builder.set("is_pic", "true").unwrap();
    flag_builder.set("opt_level", opt_level).unwrap();
    let flags = settings::Flags::new(flag_builder);

    // Native ISA
    let isa = cranelift_native::builder()
        .map_err(|e| CraneliftError::Unsupported(e.to_string()))?
        .finish(flags)
        .map_err(|e| CraneliftError::Unsupported(e.to_string()))?;

    let obj_builder = ObjectBuilder::new(
        isa,
        ir_module.name.as_bytes().to_vec(),
        cranelift_module::default_libcall_names(),
    )?;

    let mut obj_module = ObjectModule::new(obj_builder);

    // ── Declare all functions first ──────────────────────────────────────────
    let mut func_ids: HashMap<u32, FuncId> = HashMap::new();

    // Defined functions
    for (i, f) in ir_module.functions.iter().enumerate() {
        let sig = build_cl_sig(&f.sig, ptr_size, obj_module.target_config().default_call_conv);
        let linkage = ir_linkage(f.linkage);
        let fid = obj_module.declare_function(&f.name, linkage, &sig)?;
        func_ids.insert(i as u32, fid);
    }

    // Extern functions — keyed by their EXTERN_BIT-tagged FuncRef encoding.
    for (i, e) in ir_module.externs.iter().enumerate() {
        let sig = build_cl_sig(&e.sig, ptr_size, obj_module.target_config().default_call_conv);
        let fid = obj_module.declare_function(&e.name, CLinkage::Import, &sig)?;
        func_ids.insert(FuncRef::extern_(i).0, fid);
    }

    // ── Declare globals ──────────────────────────────────────────────────────
    let mut global_ids: HashMap<u32, cranelift_module::DataId> = HashMap::new();
    for (i, g) in ir_module.globals.iter().enumerate() {
        let linkage = ir_linkage(g.linkage);
        let writable = !g.constant;
        let did = obj_module.declare_data(&g.name, linkage, writable, false)?;
        global_ids.insert(i as u32, did);
    }

    // ── Define globals ───────────────────────────────────────────────────────
    for (i, g) in ir_module.globals.iter().enumerate() {
        // Imports are defined in another module (libc etc.); only declared here.
        if g.linkage == Linkage::Import {
            continue;
        }
        let did = global_ids[&(i as u32)];
        let mut desc = DataDescription::new();
        let size = g.ty.size_of(ptr_size) as usize;
        match &g.init {
            Some(sic_ir::Constant::Bytes(b)) => {
                // Pad (or use as-is) to the declared object size so a string
                // initializer shorter than the array still reserves full space.
                let mut bytes = b.clone();
                if bytes.len() < size { bytes.resize(size, 0); }
                desc.define(bytes.into_boxed_slice());
            }
            Some(sic_ir::Constant::GlobalAddr(target)) => {
                // Pointer initialized to the address of another global (e.g.
                // `char *p = "..."`): reserve a real (non-zeroinit) pointer slot
                // in .data so it can carry a load-time relocation, then point it
                // at the target global. A zeroinit slot would land in .bss,
                // which cannot hold relocations.
                desc.define(vec![0u8; ptr_size as usize].into_boxed_slice());
                let target_did = global_ids[&target.0];
                let gv = obj_module.declare_data_in_data(target_did, &mut desc);
                desc.write_data_addr(0, gv, 0);
            }
            Some(sic_ir::Constant::Int(v)) => {
                let mut bytes = vec![0u8; size.max(4)];
                let b = v.to_le_bytes();
                for (i, byte) in b.iter().take(bytes.len()).enumerate() {
                    bytes[i] = *byte;
                }
                desc.define(bytes.into_boxed_slice());
            }
            Some(sic_ir::Constant::Float(v)) => {
                let bytes = if size <= 4 {
                    (*v as f32).to_le_bytes().to_vec()
                } else {
                    v.to_le_bytes().to_vec()
                };
                desc.define(bytes.into_boxed_slice());
            }
            _ => {
                // zero-initialize
                desc.define_zeroinit(size.max(1));
            }
        }
        obj_module.define_data(did, &desc)?;
    }

    // ── Compile defined functions ─────────────────────────────────────────────
    // (FuncId, code size, [(offset, line)]) collected for DWARF when -g is set.
    let mut func_line_info: Vec<(FuncId, String, u64, Vec<(u64, u32)>)> = Vec::new();
    let mut ctx = cranelift_codegen::Context::new();
    for (i, f) in ir_module.functions.iter().enumerate() {
        let fid = func_ids[&(i as u32)];
        ctx.func.signature = build_cl_sig_def(&f.sig, ptr_size, obj_module.target_config().default_call_conv);
        ctx.func.name = cir::UserFuncName::user(0, fid.as_u32());

        func::compile_function(
            f, ir_module, &mut obj_module, &func_ids, &global_ids, &mut ctx.func, ptr_size,
        )?;

        if let Err(e) = obj_module.define_function(fid, &mut ctx) {
            // Print the Cranelift IR to stderr for debugging
            eprintln!("Cranelift error in function '{}': {}", f.name, e);
            eprintln!("{}", cranelift_codegen::ir::Function::display(&ctx.func));
            return Err(e.into());
        }

        if debug_info {
            if let Some(cc) = ctx.compiled_code() {
                let size = cc.code_info().total_size as u64;
                let mut rows: Vec<(u64, u32)> = Vec::new();
                for s in cc.buffer.get_srclocs_sorted() {
                    if s.loc.is_default() {
                        continue;
                    }
                    let line = s.loc.bits();
                    // Collapse consecutive rows with the same line.
                    if rows.last().map(|r| r.1) != Some(line) {
                        // Extend the first line entry back to the function start
                        // (offset 0) so the prologue is attributed to a source
                        // line — this lets `break <func>` land on a real line.
                        let offset = if rows.is_empty() { 0 } else { s.start as u64 };
                        rows.push((offset, line));
                    }
                }
                if !rows.is_empty() {
                    func_line_info.push((fid, f.name.clone(), size, rows));
                }
            }
        }
        ctx.clear();
    }

    // ── Emit object (+ DWARF debug info when -g) ───────────────────────────────
    let mut product = obj_module.finish();
    if debug_info {
        if let Some(src) = &ir_module.source_file {
            let funcs: Vec<dwarf::FuncLines> = func_line_info
                .iter()
                .map(|(fid, name, size, rows)| dwarf::FuncLines {
                    sym: product.function_symbol(*fid),
                    size: *size,
                    name: name.clone(),
                    rows: rows.clone(),
                })
                .collect();
            dwarf::emit_dwarf(&mut product.object, src, &funcs, ptr_size as u8)
                .map_err(CraneliftError::Unsupported)?;
        }
    }
    Ok(product.emit().map_err(|e| CraneliftError::Unsupported(e.to_string()))?)
}

pub fn build_cl_sig(
    sig: &sic_ir::FunctionType,
    ptr_size: u32,
    call_conv: CallConv,
) -> cir::Signature {
    let mut cl_sig = cir::Signature::new(call_conv);

    for p in &sig.params {
        if let Some(t) = types::cl_type(p, ptr_size) {
            cl_sig.params.push(cir::AbiParam::new(t));
        }
    }

    if let Some(t) = types::cl_type(&sig.ret, ptr_size) {
        cl_sig.returns.push(cir::AbiParam::new(t));
    }

    cl_sig
}

/// Number of integer-register/stack slots we materialize for the variadic tail
/// of a variadic function *definition*. Cranelift has no native variadic
/// support, so we over-declare trailing integer params to capture the varargs
/// (in registers first, then the stack overflow area) and spill them into a
/// contiguous save area that `va_arg` walks. See `func::compile_function`.
pub const VARARG_SLOTS: usize = 16;

/// Build the signature used to *compile* a function body. Identical to
/// [`build_cl_sig`] except that variadic functions gain `VARARG_SLOTS` extra
/// trailing `i64` params so the callee can read the passed variadic arguments.
/// The module-level declaration keeps the plain (unpadded) signature so calls
/// still append the actual argument types per the platform ABI.
pub fn build_cl_sig_def(
    sig: &sic_ir::FunctionType,
    ptr_size: u32,
    call_conv: CallConv,
) -> cir::Signature {
    let mut cl_sig = build_cl_sig(sig, ptr_size, call_conv);
    if sig.variadic {
        for _ in 0..VARARG_SLOTS {
            cl_sig.params.push(cir::AbiParam::new(cir::types::I64));
        }
    }
    cl_sig
}
