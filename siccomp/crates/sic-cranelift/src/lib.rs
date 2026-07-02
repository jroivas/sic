mod types;
mod func;

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
}

impl CraneliftBackend {
    pub fn new() -> Self {
        CraneliftBackend { ptr_size: 8 }
    }
}

impl Backend for CraneliftBackend {
    type Error = CraneliftError;

    fn compile_module(&mut self, module: &sic_ir::Module) -> Result<Vec<u8>, CraneliftError> {
        compile(module, self.ptr_size)
    }
}

fn ir_linkage(l: Linkage) -> CLinkage {
    match l {
        Linkage::External => CLinkage::Export,
        Linkage::Internal => CLinkage::Local,
        Linkage::Private  => CLinkage::Local,
    }
}

fn compile(ir_module: &sic_ir::Module, ptr_size: u32) -> Result<Vec<u8>, CraneliftError> {
    // Build settings
    let mut flag_builder = settings::builder();
    flag_builder.set("use_colocated_libcalls", "false").unwrap();
    flag_builder.set("is_pic", "true").unwrap();
    flag_builder.set("opt_level", "none").unwrap();
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

    // Extern functions
    for (i, e) in ir_module.externs.iter().enumerate() {
        let sig = build_cl_sig(&e.sig, ptr_size, obj_module.target_config().default_call_conv);
        let fid = obj_module.declare_function(&e.name, CLinkage::Import, &sig)?;
        func_ids.insert((ir_module.functions.len() + i) as u32, fid);
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
        let did = global_ids[&(i as u32)];
        let mut desc = DataDescription::new();
        let size = g.ty.size_of(ptr_size) as usize;
        match &g.init {
            Some(sic_ir::Constant::Bytes(b)) => {
                desc.define(b.clone().into_boxed_slice());
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
        ctx.clear();
    }

    // ── Emit object ──────────────────────────────────────────────────────────
    let product = obj_module.finish();
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
