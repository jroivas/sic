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
    if debug_info {
        // Keep a real frame pointer (RBP) so DWARF can describe variable
        // locations as fixed frame-relative offsets.
        flag_builder.set("preserve_frame_pointers", "true").unwrap();
    }
    let flags = settings::Flags::new(flag_builder);

    // Native ISA
    let isa = cranelift_native::builder()
        .map_err(|e| CraneliftError::Unsupported(e.to_string()))?
        .finish(flags)
        .map_err(|e| CraneliftError::Unsupported(e.to_string()))?;

    let mut obj_builder = ObjectBuilder::new(
        isa,
        ir_module.name.as_bytes().to_vec(),
        cranelift_module::default_libcall_names(),
    )?;
    // Emit each function into its own ELF section (`.text.<name>`), like GCC's
    // `-ffunction-sections`. Combined with the driver's `--gc-sections`, this
    // lets the linker drop functions that are pulled in from an archive member
    // for one symbol but are themselves unreferenced — e.g. QEMU's pci-stub.c
    // bundles `msi_enabled` (needed) with `hmp_pcie_aer_inject_error` (calls the
    // unavailable `monitor_printf`); without per-function GC the whole object,
    // and thus the dangling reference, is retained and the link fails.
    obj_builder.per_function_section(true);

    let mut obj_module = ObjectModule::new(obj_builder);

    // ── Declare all functions first ──────────────────────────────────────────
    let mut func_ids: HashMap<u32, FuncId> = HashMap::new();

    // An `internal` (static) function unreachable from any external entry,
    // constructor, or global function-pointer is dead — don't emit it. sic can
    // over-emit `static inline`s from headers (e.g. an un-selected `_Generic`
    // branch), whose stray symbol references would otherwise pull archive members
    // into conflict with unit-test stubs. Non-internal functions are always kept.
    let reachable_fns = ir_module.reachable_functions();

    // Defined functions
    for (i, f) in ir_module.functions.iter().enumerate() {
        if f.linkage == Linkage::Internal && !reachable_fns.contains(&(i as u32)) {
            continue;
        }
        let sig = build_cl_sig(&f.sig, ptr_size, obj_module.target_config().default_call_conv);
        let linkage = ir_linkage(f.linkage);
        let fid = obj_module.declare_function(&f.name, linkage, &sig)?;
        func_ids.insert(i as u32, fid);
    }

    // Extern functions — keyed by their EXTERN_BIT-tagged FuncRef encoding.
    // Only declare those actually referenced; system headers pull in hundreds
    // of unused prototypes, and declaring each as an import emits an undefined
    // symbol (some of which, like glibc's internal `__asinhf`, don't exist).
    let used_externs = ir_module.used_externs();
    for (i, e) in ir_module.externs.iter().enumerate() {
        if !used_externs.contains(&i) { continue; }
        let sig = build_cl_sig(&e.sig, ptr_size, obj_module.target_config().default_call_conv);
        let fid = obj_module.declare_function(&e.name, CLinkage::Import, &sig)?;
        func_ids.insert(FuncRef::extern_(i).0, fid);
    }

    // ── Declare globals ──────────────────────────────────────────────────────
    // An `extern` (Import) global that nothing references is not emitted as an
    // undefined symbol — otherwise the linker pulls archive members to satisfy a
    // symbol the code never uses (see `used_globals`). Defined globals are always
    // declared (they are this module's definitions).
    let used_globals = ir_module.used_globals();
    let mut global_ids: HashMap<u32, cranelift_module::DataId> = HashMap::new();
    for (i, g) in ir_module.globals.iter().enumerate() {
        if g.linkage == Linkage::Import && !used_globals.contains(&(i as u32)) {
            continue;
        }
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
        // Align the global to its type's natural alignment. Without this the
        // linker packs data byte-aligned, so a struct/array of pointers can land
        // on an odd address and pointer loads read straddled, garbage bytes.
        desc.set_align(g.ty.align_of(ptr_size).max(1));
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
            Some(sic_ir::Constant::Aggregate { bytes, relocs }) => {
                // Aggregate (struct/array) initializer: raw bytes carrying
                // load-time pointer relocations for embedded function/global
                // addresses (e.g. sqlite's function/mutex method tables).
                let mut data = bytes.clone();
                if data.len() < size { data.resize(size, 0); }
                desc.define(data.into_boxed_slice());
                for (off, target) in relocs {
                    match target {
                        sic_ir::RelocTarget::Global(gref, addend) => {
                            let target_did = global_ids[&gref.0];
                            let gv = obj_module.declare_data_in_data(target_did, &mut desc);
                            desc.write_data_addr(*off as u32, gv, *addend);
                        }
                        sic_ir::RelocTarget::Func(fref) => {
                            let fid = func_ids[&fref.0];
                            let fv = obj_module.declare_func_in_data(fid, &mut desc);
                            desc.write_function_addr(*off as u32, fv);
                        }
                    }
                }
            }
            _ => {
                // zero-initialize
                desc.define_zeroinit(size.max(1));
            }
        }
        obj_module.define_data(did, &desc)?;
    }

    // ── `__attribute__((constructor))` → .init_array ─────────────────────────
    // For each constructor function, emit a pointer-sized, private data object
    // holding its address in the `.init_array` section (priority N in
    // `.init_array.NNNNN` so the linker orders them; default runs last). The C
    // runtime invokes every `.init_array` entry before `main` — this is how
    // QEMU's `type_init`/`block_init`/module-registration constructors run.
    for (i, f) in ir_module.functions.iter().enumerate() {
        let Some(prio) = f.constructor else { continue };
        let fid = func_ids[&(i as u32)];
        let sym = format!(".init_array.entry.{}", f.name);
        let did = obj_module.declare_data(&sym, CLinkage::Local, true, false)?;
        let mut desc = DataDescription::new();
        desc.set_align(ptr_size as u64);
        desc.define(vec![0u8; ptr_size as usize].into_boxed_slice());
        let fv = obj_module.declare_func_in_data(fid, &mut desc);
        desc.write_function_addr(0, fv);
        let section = if prio == 65535 {
            ".init_array".to_string()
        } else {
            format!(".init_array.{:05}", prio)
        };
        desc.set_segment_section("", &section);
        obj_module.define_data(did, &desc)?;
    }

    // ── Compile defined functions ─────────────────────────────────────────────
    // Per-function debug info collected for DWARF when -g is set.
    // rows: (code offset, source line, prologue_end).
    let mut func_line_info: Vec<(FuncId, String, u64, Vec<(u64, u32, bool)>, Vec<dwarf::VarInfo>)> =
        Vec::new();
    let mut ctx = cranelift_codegen::Context::new();
    let dbg_timing = std::env::var("SIC_TIMING").is_ok();
    for (i, f) in ir_module.functions.iter().enumerate() {
        // Skip functions that were not declared (dead internal functions).
        let Some(&fid) = func_ids.get(&(i as u32)) else { continue };
        ctx.func.signature = build_cl_sig_def(&f.sig, ptr_size, obj_module.target_config().default_call_conv);
        ctx.func.name = cir::UserFuncName::user(0, fid.as_u32());

        let ft = std::time::Instant::now();
        let mut var_dbg: Vec<func::VarDbg> = Vec::new();
        func::compile_function(
            f, ir_module, &mut obj_module, &func_ids, &global_ids, &mut ctx.func, ptr_size,
            &mut var_dbg,
        )?;
        if dbg_timing {
            let e = ft.elapsed();
            if e.as_millis() > 100 { eprintln!("[timing] compile_function '{}': {:?}", f.name, e); }
        }

        let dt = std::time::Instant::now();
        let define_res = obj_module.define_function(fid, &mut ctx);
        if dbg_timing {
            let e = dt.elapsed();
            if e.as_millis() > 100 { eprintln!("[timing] define_function '{}': {:?}", f.name, e); }
        }
        if let Err(e) = define_res {
            // Print the Cranelift IR to stderr for debugging
            eprintln!("Cranelift error in function '{}': {:?}", f.name, e);
            eprintln!("{}", cranelift_codegen::ir::Function::display(&ctx.func));
            return Err(e.into());
        }

        if debug_info {
            if let Some(cc) = ctx.compiled_code() {
                let size = cc.code_info().total_size as u64;
                let mut raw: Vec<(u64, u32)> = Vec::new();
                for s in cc.buffer.get_srclocs_sorted() {
                    if s.loc.is_default() {
                        continue;
                    }
                    let line = s.loc.bits();
                    // Collapse consecutive rows with the same line.
                    if raw.last().map(|r| r.1) != Some(line) {
                        raw.push((s.start as u64, line));
                    }
                }
                // Emit an entry row at offset 0 covering the prologue, then mark
                // the first *real* statement row `prologue_end` so `break <func>`
                // skips the prologue and lands there (with params already stored).
                let mut rows: Vec<(u64, u32, bool)> = Vec::new();
                if let Some(&(first_off, first_line)) = raw.first() {
                    if first_off > 0 {
                        rows.push((0, first_line, false));
                    }
                    rows.push((first_off, first_line, true));
                    for &(off, line) in &raw[1..] {
                        rows.push((off, line, false));
                    }
                }
                // Resolve each variable's stack slot to a frame-pointer-relative
                // offset. Slots are laid out from the post-prologue SP, and RBP
                // sits `frame_size` bytes above it, so the RBP-relative offset is
                // `slot_offset - frame_size`.
                let frame = cc.frame_size as i64;
                let mut vars: Vec<dwarf::VarInfo> = Vec::new();
                for v in &var_dbg {
                    if let Some(slot_off) = cc.sized_stackslot_offsets.get(v.slot) {
                        vars.push(dwarf::VarInfo {
                            name: v.name.clone(),
                            ty: v.ty.clone(),
                            fp_offset: *slot_off as i64 - frame,
                            is_param: v.is_param,
                        });
                    }
                }
                if !rows.is_empty() {
                    func_line_info.push((fid, f.name.clone(), size, rows, vars));
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
                .map(|(fid, name, size, rows, vars)| dwarf::FuncLines {
                    sym: product.function_symbol(*fid),
                    size: *size,
                    name: name.clone(),
                    rows: rows.clone(),
                    vars: vars.clone(),
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

    // Aggregate returns use the sret ABI: the frontend prepends a hidden pointer
    // parameter (already present in `sig.params`) and the callee copies the
    // result through it, so there is no register return value.
    if !matches!(sig.ret, sic_ir::Type::Struct(_) | sic_ir::Type::Union(_) | sic_ir::Type::Array { .. }) {
        if let Some(t) = types::cl_type(&sig.ret, ptr_size) {
            cl_sig.returns.push(cir::AbiParam::new(t));
        }
    }

    cl_sig
}

/// x86-64 System V register-save-area geometry: 6 general-purpose argument
/// registers (rdi,rsi,rdx,rcx,r8,r9) and 8 vector registers (xmm0–xmm7).
pub const VA_GP_REGS: usize = 6;
pub const VA_FP_REGS: usize = 8;
/// Extra trailing stack slots captured for varargs that overflow the registers.
pub const VA_OVERFLOW_SLOTS: usize = 8;

/// Count how many named parameters occupy general-purpose vs vector argument
/// registers (each capped at the number of such registers).
pub fn va_named_reg_counts(sig: &sic_ir::FunctionType, ptr_size: u32) -> (usize, usize) {
    let mut n_gp = 0usize;
    let mut n_fp = 0usize;
    for p in &sig.params {
        match types::cl_type(p, ptr_size) {
            Some(t) if t.is_float() => n_fp += 1,
            Some(_) => n_gp += 1,
            None => {}
        }
    }
    (n_gp.min(VA_GP_REGS), n_fp.min(VA_FP_REGS))
}

/// Build the signature used to *compile* a variadic function body. Cranelift has
/// no native variadic support, so we over-declare trailing params to capture the
/// incoming argument registers: `i64` params grab the remaining GP registers,
/// `f64` params grab the remaining XMM registers, and extra `i64` params grab
/// the start of the stack overflow area. The prologue spills these into a
/// System-V-layout register save area (see `func::compile_function`) so a
/// `va_list` built here is ABI-compatible with libc's `vfprintf` et al.
pub fn build_cl_sig_def(
    sig: &sic_ir::FunctionType,
    ptr_size: u32,
    call_conv: CallConv,
) -> cir::Signature {
    let mut cl_sig = build_cl_sig(sig, ptr_size, call_conv);
    if sig.variadic {
        let (n_gp, n_fp) = va_named_reg_counts(sig, ptr_size);
        for _ in 0..(VA_GP_REGS - n_gp) {
            cl_sig.params.push(cir::AbiParam::new(cir::types::I64));
        }
        for _ in 0..(VA_FP_REGS - n_fp) {
            cl_sig.params.push(cir::AbiParam::new(cir::types::F64));
        }
        for _ in 0..VA_OVERFLOW_SLOTS {
            cl_sig.params.push(cir::AbiParam::new(cir::types::I64));
        }
    }
    cl_sig
}
