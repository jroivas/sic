mod types;
mod func;
mod simd;
mod dwarf;
mod wide_consts;
pub mod abi;

use sic_ir::fast_hash::HashMap;
use cranelift_codegen::ir as cir;
use cranelift_codegen::isa::CallConv;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_module::{DataDescription, FuncId, Linkage as CLinkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use sic_ir::{Backend, BackendError, BackendOptions, FuncRef, Linkage, OptLevel};

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

#[derive(Default)]
pub struct CraneliftBackend;

impl CraneliftBackend {
    pub fn new() -> Self { CraneliftBackend }
}

impl Backend for CraneliftBackend {
    fn name(&self) -> &'static str { "cranelift" }

    fn compile_module(&mut self, module: &sic_ir::Module, opts: &BackendOptions) -> Result<Vec<u8>, BackendError> {
        Ok(compile(module, opts)?)
    }
}

/// Cranelift's x64 setting for an extension. `None`: only sic's intrinsics use it.
fn isa_setting(feature: &str) -> Option<&'static str> {
    Some(match feature {
        "sse3" => "has_sse3", "ssse3" => "has_ssse3", "sse4.1" => "has_sse41", "sse4.2" => "has_sse42",
        "popcnt" => "has_popcnt", "avx" => "has_avx", "avx2" => "has_avx2", "fma" => "has_fma",
        "cx16" => "has_cmpxchg16b",
        _ => return None,
    })
}

fn ir_linkage(l: Linkage) -> CLinkage {
    match l {
        Linkage::External => CLinkage::Export,
        Linkage::Internal => CLinkage::Local,
        Linkage::Private  => CLinkage::Local,
        Linkage::Import   => CLinkage::Import,
        // Preemptible emits a weak symbol binding, so multiple definitions of a
        // `__attribute__((weak))` symbol merge instead of colliding at link time.
        Linkage::Weak     => CLinkage::Preemptible,
    }
}

fn compile(ir_module: &sic_ir::Module, cfg: &BackendOptions) -> Result<Vec<u8>, CraneliftError> {
    let (ptr_size, debug_info) = (cfg.ptr_size, cfg.debug_info);
    let opt_level = match cfg.opt { OptLevel::None => "none", OptLevel::Speed => "speed", OptLevel::Size => "speed_and_size" };
    // Build settings
    let mut flag_builder = settings::builder();
    let pic = if cfg.pic { "true" } else { "false" };
    flag_builder.set("use_colocated_libcalls", if cfg.pic { "false" } else { "true" }).unwrap();
    flag_builder.set("is_pic", pic).unwrap();
    // The module's ISA lowers with `opt_level = none`: Cranelift's optimizer
    // runs first, by hand, with the requested level (`opt_isa`), so that the
    // wide constants it leaves are moved to read-only data before lowering
    // (`wide_consts`); `opt_level` affects nothing but that optimizer pass.
    flag_builder.set("opt_level", "none").unwrap();
    // Cranelift checks its own IR after every step: for debug builds of sic.
    flag_builder.set("enable_verifier", if cfg!(debug_assertions) { "true" } else { "false" }).unwrap();
    // Allow `i128` in function signatures (args/returns) — the SysV ABI passes a
    // 128-bit integer in a register pair. Needed for C `__int128` (QEMU's Int128).
    flag_builder.set("enable_llvm_abi_extensions", "true").unwrap();
    // ELF general-dynamic TLS model, so `tls_value` lowers to a real TLS access
    // (__tls_get_addr) for `__thread` variables (QEMU's bql_locked/rcu_reader).
    flag_builder.set("tls_model", "elf_gd").unwrap();
    // Keep a real frame pointer (RBP): DWARF describes variable locations as
    // fixed frame-relative offsets, and Cranelift's `get_return_address`
    // (`__builtin_return_address(0)` / QEMU's GETPC()) requires it.
    let _ = debug_info;
    flag_builder.set("preserve_frame_pointers", "true").unwrap();
    let flags = settings::Flags::new(flag_builder.clone());

    // The host's architecture with only the requested extensions.
    let make_isa = |flags: settings::Flags| -> Result<cranelift_codegen::isa::OwnedTargetIsa, CraneliftError> {
        let mut b = cranelift_native::builder_with_options(false)
            .map_err(|e| CraneliftError::Unsupported(e.to_string()))?;
        for f in cfg.features.iter().filter_map(|f| isa_setting(f)) {
            b.enable(f).map_err(|e| CraneliftError::Unsupported(format!("{}: {}", f, e)))?;
        }
        b.finish(flags).map_err(|e| CraneliftError::Unsupported(e.to_string()))
    };
    let isa = make_isa(flags)?;
    let opt_isa = if opt_level == "none" { None } else {
        flag_builder.set("opt_level", opt_level).unwrap();
        Some(make_isa(settings::Flags::new(flag_builder))?)
    };
    let mut wide_consts: HashMap<i64, cranelift_module::DataId> = HashMap::default();

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
    // `section("…")` placements need a section per function to rename (see
    // `finish_code_sections`, which merges them back for -fno-function-sections).
    obj_builder.per_function_section(cfg.function_sections || !ir_module.fn_sections.is_empty());

    let mut obj_module = ObjectModule::new(obj_builder);

    // Without SSSE3 Cranelift lowers a byte shuffle to a call of its
    // `X86Pshufb` libcall, which the embedder provides: define it here, local
    // to the object, when the module computes with vectors.
    if cfg.sse && !cfg.has_feature("ssse3") && module_uses_simd(ir_module) {
        define_pshufb_libcall(&mut obj_module)?;
    }

    // ── Declare all functions first ──────────────────────────────────────────
    let mut func_ids: HashMap<u32, FuncId> = HashMap::default();

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
        // A recognised inline-asm template lowers to a call of a `__sic_asm_*`
        // helper (sic_ir::asm_helpers): emit its x86-64 machine code as a
        // module-local function instead of importing the symbol.
        if let Some(code) = sic_ir::asm_helpers::asm_helper_code(&e.name) {
            if !matches!(obj_module.isa().triple().architecture, target_lexicon::Architecture::X86_64) {
                return Err(CraneliftError::Unsupported(format!("inline assembly (`{}`) is only supported on x86-64", e.name)));
            }
            let fid = obj_module.declare_function(&e.name, CLinkage::Local, &sig)?;
            obj_module.define_function_bytes(fid, 16, code, &[])?;
            func_ids.insert(FuncRef::extern_(i).0, fid);
            continue;
        }
        let linkage = if ir_module.weak_externs.contains(&e.name) { CLinkage::Preemptible } else { CLinkage::Import };
        let fid = obj_module.declare_function(&e.name, linkage, &sig)?;
        func_ids.insert(FuncRef::extern_(i).0, fid);
    }

    // ── x86-64 variadic-float ABI fix ────────────────────────────────────────
    // Cranelift never sets the SysV `AL` register (count of vector/SSE argument
    // registers) for a variadic call, so libc `printf` reads garbage for float
    // args — this completes cg_clif's `adjust_call_for_c_variadic` FIXME ("Set
    // %al to upperbound on float args"). For each variadic extern called with a
    // float, emit a tiny local trampoline `__sic_fva_<name>` — `movb $8,%al ;
    // jmp <name>` — and route the extern's calls through it. `AL=8` is a safe
    // upper bound (glibc then spills all eight `xmm` registers); the tail-`jmp`
    // leaves the register/stack layout identical to a direct call.
    let is_x86_64 = matches!(
        obj_module.isa().triple().architecture,
        target_lexicon::Architecture::X86_64,
    );
    if is_x86_64 {
        for name in &ir_module.float_vararg_externs {
            let Some(ext_idx) = ir_module.externs.iter().position(|e| &e.name == name) else { continue };
            let ext_ref = FuncRef::extern_(ext_idx).0;
            let Some(&import_fid) = func_ids.get(&ext_ref) else { continue };
            let sig = build_cl_sig(&ir_module.externs[ext_idx].sig, ptr_size, obj_module.target_config().default_call_conv);
            let tramp_fid = obj_module.declare_function(&format!("__sic_fva_{}", name), CLinkage::Local, &sig)?;
            // `movb $8, %al` (B0 08) then `jmp <name>` (E9 + PC-relative rel32).
            let bytes = [0xB0u8, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
            // `define_function_bytes` (cranelift-module 0.132) takes module-level
            // relocations directly — the `jmp` target is the imported extern by its
            // user name (namespace 0, the extern's FuncId), resolved at link time.
            let reloc = cranelift_module::ModuleReloc {
                offset: 3,
                kind: cranelift_codegen::binemit::Reloc::X86CallPLTRel4,
                name: cranelift_module::ModuleRelocTarget::user(0, import_fid.as_u32()),
                addend: -4,
            };
            obj_module.define_function_bytes(tramp_fid, 1, &bytes, &[reloc])?;
            // Route all calls to the extern through the trampoline.
            func_ids.insert(ext_ref, tramp_fid);
        }
    }

    // ── `long double` helpers (sic_ir::f80) ─────────────────────────────────
    // Defined as module-local machine code when the module uses `long double`.
    // `long double` is computed with x87 helpers: not without the FPU.
    if !cfg.x87 && module_uses_f80(ir_module) {
        return Err(CraneliftError::Unsupported(
            "`long double` needs the x87 FPU, which is disabled (-mno-80387)".to_string()));
    }
    let f80_fns: Option<func::F80Fns> = if module_uses_f80(ir_module) {
        if !is_x86_64 {
            return Err(CraneliftError::Unsupported("`long double` is only supported on x86-64".into()));
        }
        let cc = obj_module.target_config().default_call_conv;
        let ptr_ty = types::ptr_cl(ptr_size);
        let mut ids = Vec::new();
        for (name, code) in sic_ir::f80::F80_HELPERS {
            let mut sig = cir::Signature::new(cc);
            match *name {
                sic_ir::f80::F80_LOAD => {
                    sig.params.push(cir::AbiParam::new(ptr_ty));
                    sig.returns.push(cir::AbiParam::new(cir::types::F64));
                }
                sic_ir::f80::F80_STORE => {
                    sig.params.push(cir::AbiParam::new(ptr_ty));
                    sig.params.push(cir::AbiParam::new(cir::types::F64));
                }
                sic_ir::f80::F80_ST0 => sig.returns.push(cir::AbiParam::new(cir::types::F64)),
                _ => sig.params.push(cir::AbiParam::new(cir::types::F64)),
            }
            let fid = obj_module.declare_function(name, CLinkage::Local, &sig)?;
            obj_module.define_function_bytes(fid, 16, code, &[])?;
            ids.push(fid);
        }
        Some(func::F80Fns { load: ids[0], store: ids[1], st0: ids[2], ret: ids[3] })
    } else {
        None
    };

    // ── Declare globals ──────────────────────────────────────────────────────
    // An `extern` (Import) global that nothing references is not emitted as an
    // undefined symbol — otherwise the linker pulls archive members to satisfy a
    // symbol the code never uses (see `used_globals`). Defined globals are always
    // declared (they are this module's definitions).
    let used_globals = ir_module.used_globals();
    let mut global_ids: HashMap<u32, cranelift_module::DataId> = HashMap::default();
    for (i, g) in ir_module.globals.iter().enumerate() {
        if matches!(g.linkage, Linkage::Import | Linkage::Internal | Linkage::Private) && !used_globals.contains(&(i as u32)) {
            continue;
        }
        let linkage = match g.linkage {
            Linkage::Import if ir_module.weak_externs.contains(&g.name) => CLinkage::Preemptible,
            l => ir_linkage(l),
        };
        // A `__thread` global is TLS: writable and declared with the tls flag so
        // the backend emits it into .tdata/.tbss and accesses go through the TLS
        // ABI (see `tls_value` in func.rs).
        let writable = !g.constant || g.thread_local;
        let did = obj_module.declare_data(&g.name, linkage, writable, g.thread_local)?;
        global_ids.insert(i as u32, did);
    }

    // ── Define globals ───────────────────────────────────────────────────────
    for (i, g) in ir_module.globals.iter().enumerate() {
        // Imports are defined in another module (libc etc.); only declared here.
        if g.linkage == Linkage::Import || !global_ids.contains_key(&(i as u32)) {
            continue;
        }
        let did = global_ids[&(i as u32)];
        let mut desc = DataDescription::new();
        // `section("…")` (thread-local data stays in .tdata/.tbss). A named
        // section holds file contents, so zero-initialized data in one is
        // written as zero bytes (cranelift-object would append BSS to it).
        let mut in_custom_section = false;
        if !g.thread_local {
            if let Some((_, sec)) = ir_module.data_sections.iter().find(|(n, _)| *n == g.name) {
                desc.set_custom_section(sec);
                in_custom_section = true;
            }
        }
        // Align the global to its type's natural alignment. Without this the
        // linker packs data byte-aligned, so a struct/array of pointers can land
        // on an odd address and pointer loads read straddled, garbage bytes.
        desc.set_align(g.ty.align_of(ptr_size).max(g.align.unwrap_or(0) as u64).max(1));
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
                let bytes = if g.ty == sic_ir::Type::Float80 {
                    sic_ir::f80::f64_to_f80_bytes(*v).to_vec()
                } else if size <= 4 {
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
                if in_custom_section { desc.define(vec![0u8; size.max(1)].into_boxed_slice()); }
                else { desc.define_zeroinit(size.max(1)); }
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
        let Some(run) = f.constructor else { continue };
        let fid = func_ids[&(i as u32)];
        let sym = format!(".ctor_dtor.entry.{}", f.name);
        let did = obj_module.declare_data(&sym, CLinkage::Local, true, false)?;
        let mut desc = DataDescription::new();
        desc.set_align(ptr_size as u64);
        desc.define(vec![0u8; ptr_size as usize].into_boxed_slice());
        let fv = obj_module.declare_func_in_data(fid, &mut desc);
        desc.write_function_addr(0, fv);
        // ELF: `.init_array` runs before `main`, `.fini_array` at exit (other
        // object formats are not targeted by this backend yet).
        let (array, prio) = match run {
            sic_ir::RunAt::Startup(p) => ("init_array", p),
            sic_ir::RunAt::Exit(p) => ("fini_array", p),
        };
        let section = if prio == 65535 {
            format!(".{}", array)
        } else {
            format!(".{}.{:05}", array, prio)
        };
        desc.set_custom_section(&section);
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
        ctx.func.signature = build_cl_sig_def(&f.sig, ptr_size, obj_module.target_config().default_call_conv, cfg.sse);
        ctx.func.name = cir::UserFuncName::user(0, fid.as_u32());

        let ft = dbg_timing.then(std::time::Instant::now);
        let mut var_dbg: Vec<func::VarDbg> = Vec::new();
        func::compile_function(
            f, ir_module, &mut obj_module, &func_ids, &global_ids, &mut ctx.func, ptr_size,
            &mut var_dbg, f80_fns, cfg.sse,
        )?;
        if !cfg.sse { check_no_float(&ctx.func, &f.name)?; }
        if let Some(ft) = ft {
            let e = ft.elapsed();
            if e.as_millis() > 100 { eprintln!("[timing] compile_function '{}': {:?}", f.name, e); }
        }

        let dt = dbg_timing.then(std::time::Instant::now);
        if let Some(oi) = &opt_isa {
            ctx.optimize(&**oi, &mut cranelift_codegen::control::ControlPlane::default())
                .map_err(CraneliftError::Codegen)?;
        }
        if !cfg.pic {
            // Non-PIC: every symbol is near (direct calls, RIP-relative data).
            colocate_symbols(&mut ctx.func);
        }
        if cfg.no_text_data && !cfg.pic {
            // The lowering's own clean-up first (it runs again in
            // `define_function`): a block parameter that only ever receives
            // one constant becomes that constant, which must be rewritten too.
            ctx.compute_cfg();
            ctx.compute_domtree();
            ctx.eliminate_unreachable_code(obj_module.isa())?;
            ctx.remove_constant_phis(obj_module.isa())?;
            ctx.func.dfg.resolve_all_aliases();
            wide_consts::wide_constants_to_rodata(&mut ctx.func, &mut obj_module, &mut wide_consts)?;
            // Verified below from the disassembly: no constant pool in code.
            ctx.want_disasm = true;
            if std::env::var("SIC_DUMP_CLIF").map_or(false, |v| v == f.name) {
                eprintln!("; after the optimizer and the constant rewrite\n{}", ctx.func.display());
            }
        }
        let define_res = obj_module.define_function(fid, &mut ctx);
        if std::env::var("SIC_DUMP_CLIF").map_or(false, |v| v == f.name) {
            if let Some(t) = ctx.compiled_code().and_then(|c| c.vcode.as_ref()) { eprintln!("; machine code\n{}", t); }
        }
        if cfg.no_text_data && !cfg.pic && define_res.is_ok() {
            if let Some(insn) = wide_consts::pool_instruction(&ctx) {
                return Err(CraneliftError::Unsupported(format!(
                    "internal: function '{}' would keep constant data inside its code (non-PIC code must not): `{}`", f.name, insn)));
            }
        }
        if let Some(dt) = dt {
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
                let base = ctx.func.params.base_srcloc();
                for s in cc.buffer.get_srclocs_sorted() {
                    // Absolute, or relative to the function's base location.
                    let loc = if s.loc.is_abs() { s.loc.as_abs() } else { s.loc.relocate(base) };
                    if loc.is_default() {
                        continue;
                    }
                    let line = loc.bits();
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
                // offset. Cranelift 0.132 exposes the frame layout on the finalized
                // buffer: `frame_to_fp_offset` is the FP position measured from the
                // bottom of the frame, and each slot's `offset` is measured the same
                // way, so the RBP-relative offset is `slot.offset - frame_to_fp_offset`.
                let mut vars: Vec<dwarf::VarInfo> = Vec::new();
                if let Some(fl) = cc.buffer.frame_layout() {
                    let fp = fl.frame_to_fp_offset as i64;
                    for v in &var_dbg {
                        vars.push(dwarf::VarInfo {
                            name: v.name.clone(),
                            ty: v.ty.clone(),
                            fp_offset: fl.stackslots[v.slot].offset as i64 - fp,
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
            let producer = ir_module.producer.clone().unwrap_or_else(|| "sic (SIC Compiler)".to_string());
            dwarf::emit_dwarf(&mut product.object, src, &funcs, ptr_size as u8, &producer)
                .map_err(CraneliftError::Unsupported)?;
        }
    }
    // Identification in `.comment` (as gcc/clang do): a NUL-terminated string in
    // a mergeable-strings section, which the linker keeps (merged) in the final
    // executable — `readelf -p .comment a.out` shows which compiler and
    // preprocessor built it.
    if let Some(producer) = &ir_module.producer {
        let id = product.object.add_section(Vec::new(), b".comment".to_vec(), object::SectionKind::OtherString);
        let mut bytes = producer.as_bytes().to_vec();
        bytes.push(0);
        product.object.section_mut(id).set_data(bytes, 1);
    }
    let bytes = product.emit().map_err(|e| CraneliftError::Unsupported(e.to_string()))?;
    // Named sections of only `const` variables are read-only in non-PIC code.
    // Cranelift's object writer makes constants with pointers writable (for
    // the dynamic loader), but nothing patches them here, and in one section
    // with pointer-free constants the flags would clash (Linux's `.init.rodata`).
    let mut ro_sections: Vec<&str> = Vec::new();
    if !cfg.pic {
        for (_, sec) in &ir_module.data_sections {
            let all_const = ir_module.data_sections.iter().filter(|(_, s)| s == sec)
                .all(|(g, _)| ir_module.globals.iter().any(|x| x.name == *g && x.constant));
            if all_const && !ro_sections.contains(&sec.as_str()) { ro_sections.push(sec); }
        }
    }
    // Several variables in one named section: one ELF section, as a tool reading
    // the object expects (Linux's modpost reads one `.modinfo`).
    let named: sic_ir::fast_hash::HashSet<&str> = ir_module.data_sections.iter().map(|(_, s)| s.as_str()).collect();
    let shared_section = named.len() < ir_module.data_sections.len();
    if ir_module.fn_sections.is_empty() && cfg.function_sections && ro_sections.is_empty()
        && !shared_section && !cfg.no_text_data { return Ok(bytes); }
    finish_code_sections(&bytes, &ir_module.fn_sections, !cfg.function_sections, &ro_sections).map_err(CraneliftError::Unsupported)
}

/// The object's code sections, finished: `section("…")` placements (each
/// function is emitted in its own section, renamed here with its relocation
/// section — Cranelift's object writer has no per-function placement); with
/// `one_text` (`-fno-function-sections`) the other functions' sections become
/// `.text`; then sections of one name and flags, code or data, are merged into
/// one (symbols, relocations and section-symbol references rebased), an
/// undefined symbol nothing refers to is dropped (its call was in dead code,
/// and a tool counting undefined symbols takes it as needed), and alignment padding
/// in code is `int3` (0xcc), not zeros: a tool that decodes code linearly
/// (Linux's objtool) read `00 00` as `add %al,(%rax)`, and an odd gap ran
/// into the next function ("can't find starting instruction"). The sections
/// `ro_sections` lose their write flag.
fn finish_code_sections(obj: &[u8], placements: &[(String, String)], one_text: bool, ro_sections: &[&str]) -> Result<Vec<u8>, String> {
    use object::build::elf::{Builder, SectionData};
    use object::build::Id;
    use object::elf;
    let err = |e: object::build::Error| format!("code sections: {}", e);
    let mut b = Builder::read(obj).map_err(err)?;
    let is_code = |s: &object::build::elf::Section| s.sh_flags.0 & elf::SHF_EXECINSTR.0 != 0
        && matches!(s.data, SectionData::Data(_));
    for sec in b.sections.iter_mut() {
        if ro_sections.iter().any(|n| n.as_bytes() == sec.name.as_slice()) {
            sec.sh_flags = elf::SectionFlags(sec.sh_flags.0 & !elf::SHF_WRITE.0);
        }
    }
    // Placements, then the rest of the per-function code into `.text`.
    let mut placed = sic_ir::fast_hash::HashSet::default();
    for (func, sec) in placements {
        let Some(id) = b.symbols.iter().find(|s| s.name.as_slice() == func.as_bytes()).and_then(|s| s.section) else { continue };
        b.sections.get_mut(id).name = sec.as_bytes().to_vec().into();
        placed.insert(id.index());
    }
    if one_text {
        let ids: Vec<_> = b.sections.iter()
            .filter(|s| is_code(s) && !placed.contains(&s.id().index()) && s.name.as_slice().starts_with(b".text."))
            .map(|s| s.id()).collect();
        for id in ids { b.sections.get_mut(id).name = b".text".to_vec().into(); }
    }
    // Merge sections by name, in order: (first, [(other, base offset)]).
    let is_alloc = |s: &object::build::elf::Section| s.sh_flags.0 & elf::SHF_ALLOC.0 != 0
        && matches!(s.data, SectionData::Data(_));
    let mut groups: Vec<((Vec<u8>, u64), object::build::elf::SectionId, Vec<(object::build::elf::SectionId, u64)>)> = Vec::new();
    let mergeable: Vec<_> = b.sections.iter().filter(|s| is_alloc(s)).map(|s| s.id()).collect();
    for id in mergeable {
        let s = b.sections.get(id);
        let name = (s.name.as_slice().to_vec(), s.sh_flags.0);
        let fill = if is_code(s) { 0xcc } else { 0 };
        match groups.iter_mut().find(|(n, _, _)| *n == name) {
            Some((_, first, rest)) => {
                let (first, other) = (*first, id);
                let align = b.sections.get(other).sh_addralign.max(1);
                let tail = match &b.sections.get(other).data { SectionData::Data(d) => d.as_slice().to_vec(), _ => unreachable!() };
                let fs = b.sections.get_mut(first);
                fs.sh_addralign = fs.sh_addralign.max(align);
                let SectionData::Data(d) = &mut fs.data else { unreachable!() };
                let v = d.to_mut();
                let base = v.len().div_ceil(align as usize) as u64 * align;
                v.resize(base as usize, fill);
                v.extend_from_slice(&tail);
                rest.push((other, base));
            }
            None => groups.push((name, id, Vec::new())),
        }
    }
    let mut moved: sic_ir::fast_hash::HashMap<usize, (object::build::elf::SectionId, u64)> = Default::default();
    for (_, first, rest) in &groups { for &(o, base) in rest { moved.insert(o.index(), (*first, base)); } }
    if !moved.is_empty() {
        // The surviving section's own section symbol, for references to a merged one.
        let sec_sym: sic_ir::fast_hash::HashMap<_, _> = b.symbols.iter()
            .filter(|s| s.st_info.st_type() == elf::STT_SECTION && s.section.is_some())
            .map(|s| (s.section.unwrap().index(), s.id())).collect();
        let mut sym_rebase = sic_ir::fast_hash::HashMap::default();
        for sym in b.symbols.iter_mut() {
            let Some(sec) = sym.section else { continue };
            let Some(&(to, base)) = moved.get(&sec.index()) else { continue };
            if sym.st_info.st_type() == elf::STT_SECTION {
                sym.delete = true;
                if let Some(&t) = sec_sym.get(&to.index()) { sym_rebase.insert(sym.id().index(), (t, base)); }
            } else {
                sym.section = Some(to);
                sym.st_value += base;
            }
        }
        // Relocations: those of a merged section move to the survivor's
        // relocation section (or it becomes that), offsets rebased; references
        // to a merged section's symbol go to the survivor's, addend rebased.
        let mut rela_of = sic_ir::fast_hash::HashMap::default();
        for s in b.sections.iter() {
            if let (SectionData::Relocation(_), Some(t)) = (&s.data, s.sh_info_section) { rela_of.insert(t.index(), s.id()); }
        }
        let rela_ids: Vec<_> = rela_of.values().copied().collect();
        for rid in rela_ids {
            let SectionData::Relocation(relocs) = &mut b.sections.get_mut(rid).data else { continue };
            for r in relocs.iter_mut() {
                if let Some(&(t, base)) = r.symbol.and_then(|sy| sym_rebase.get(&sy.index())) {
                    r.symbol = Some(t);
                    r.r_addend += base as i64;
                }
            }
        }
        for (&from, &(to, base)) in &moved {
            let Some(&from_rela) = rela_of.get(&from) else { continue };
            let SectionData::Relocation(relocs) = std::mem::replace(&mut b.sections.get_mut(from_rela).data, SectionData::Relocation(Vec::new())) else { continue };
            let relocs: Vec<_> = relocs.into_iter().map(|mut r| { r.r_offset += base; r }).collect();
            match rela_of.get(&to.index()) {
                Some(&to_rela) => {
                    if let SectionData::Relocation(v) = &mut b.sections.get_mut(to_rela).data { v.extend(relocs); }
                    b.sections.get_mut(from_rela).delete = true;
                }
                None => {
                    let rs = b.sections.get_mut(from_rela);
                    rs.data = SectionData::Relocation(relocs);
                    rs.sh_info_section = Some(to);
                    rela_of.insert(to.index(), from_rela);
                }
            }
        }
        let gone: Vec<_> = b.sections.iter().filter(|s| moved.contains_key(&s.id().index())).map(|s| s.id()).collect();
        for o in gone { b.sections.get_mut(o).delete = true; }
        // Debug info and other non-code sections referring to a merged section's
        // symbol were handled above (all relocation sections were rewritten).
    }
    let referenced: sic_ir::fast_hash::HashSet<usize> = b.sections.iter()
        .filter_map(|s| match &s.data { SectionData::Relocation(r) => Some(r), _ => None })
        .flatten().filter_map(|r| r.symbol.map(|s| s.index())).collect();
    for sym in b.symbols.iter_mut() {
        if sym.section.is_none() && sym.st_shndx == elf::SHN_UNDEF && !sym.name.as_slice().is_empty()
            && !referenced.contains(&sym.id().index()) {
            sym.delete = true;
        }
    }
    // Zero padding between functions in code becomes int3.
    let funcs: Vec<(object::build::elf::SectionId, u64, u64)> = b.symbols.iter()
        .filter(|s| s.st_info.st_type() == elf::STT_FUNC && !s.delete)
        .filter_map(|s| s.section.map(|sec| (sec, s.st_value, s.st_size))).collect();
    for sec in b.sections.iter_mut() {
        if sec.delete || !is_code(sec) { continue; }
        let id = sec.id();
        let SectionData::Data(d) = &mut sec.data else { continue };
        let mut covered = vec![false; d.len()];
        for &(s, v, n) in &funcs {
            if s != id { continue; }
            for k in v..(v + n).min(covered.len() as u64) { covered[k as usize] = true; }
        }
        if covered.iter().all(|c| *c) { continue; }
        let v = d.to_mut();
        for (k, c) in covered.iter().enumerate() { if !c && v[k] == 0 { v[k] = 0xcc; } }
    }
    // Every relocation section takes its target's name.
    let names: Vec<_> = b.sections.iter().filter(|s| !s.delete).map(|s| (s.id(), s.name.as_slice().to_vec())).collect();
    let fix: Vec<_> = b.sections.iter()
        .filter(|s| !s.delete && matches!(s.data, SectionData::Relocation(_)))
        .filter_map(|s| s.sh_info_section.and_then(|t| names.iter().find(|(i, _)| *i == t)).map(|(_, n)| (s.id(), n.clone())))
        .collect();
    for (id, n) in fix {
        let mut name = b".rela".to_vec();
        name.extend_from_slice(&n);
        b.sections.get_mut(id).name = name.into();
    }
    let mut out = Vec::new();
    b.write(&mut out).map_err(err)?;
    Ok(out)
}

/// Whether `ty` is, or reaches through pointers/arrays/function types, a
/// `long double`.
fn mentions_f80(ty: &sic_ir::Type) -> bool {
    match ty {
        sic_ir::Type::Float80 => true,
        sic_ir::Type::Pointer(t) => mentions_f80(t),
        sic_ir::Type::Array { elem, .. } => mentions_f80(elem),
        sic_ir::Type::Function(ft) => mentions_f80(&ft.ret) || ft.params.iter().any(mentions_f80),
        _ => false,
    }
}

/// Whether any function signature or instruction of the module involves
/// `long double` (then the f80 helpers are emitted).
/// Whether any function computes with SIMD vectors (x86 intrinsics).
fn module_uses_simd(m: &sic_ir::Module) -> bool {
    m.functions.iter().any(|f| f.blocks.iter().any(|b| b.instrs.iter().any(|i|
        matches!(i, sic_ir::Instr::Simd { .. } | sic_ir::Instr::VecMoveMask { .. }))))
}

/// `__cranelift_x86_pshufb(src, mask)`: SSSE3's `pshufb` for SSE2-only code
/// (Cranelift's libcall for a byte shuffle without SSSE3). Byte i of the
/// result is 0 when mask byte i has its top bit set, else src byte
/// (mask & 15). Built from byte loads and stores — no shuffle, so it does not
/// call itself — and local to the object (Cranelift resolves the libcall to a
/// symbol of that name in the object).
fn define_pshufb_libcall(m: &mut ObjectModule) -> Result<(), CraneliftError> {
    use cranelift_codegen::ir::{types as ct, InstBuilder};
    use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
    let mut sig = m.make_signature();
    sig.params.push(cir::AbiParam::new(ct::I8X16));
    sig.params.push(cir::AbiParam::new(ct::I8X16));
    sig.returns.push(cir::AbiParam::new(ct::I8X16));
    let name = (cranelift_module::default_libcall_names())(cir::LibCall::X86Pshufb);
    let fid = m.declare_function(&name, CLinkage::Local, &sig)?;
    let tcfg = m.target_config();
    let mut ctx = m.make_context();
    ctx.func.signature = sig;
    let mut fbc = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fbc);
        let blk = b.create_block();
        b.append_block_params_for_function_params(blk);
        b.switch_to_block(blk);
        b.seal_block(blk);
        let (src, mask) = (b.block_params(blk)[0], b.block_params(blk)[1]);
        let slot = b.create_sized_stack_slot(cir::StackSlotData::new(cir::StackSlotKind::ExplicitSlot, 48, 4));
        let base = b.ins().stack_addr(ct::I64, slot, 0);
        let f = cranelift_codegen::ir::MemFlagsData::new();
        b.ins().store(f, src, base, 0);
        b.ins().store(f, mask, base, 16);
        let zero = b.ins().iconst(ct::I8, 0);
        for i in 0..16 {
            let mi = b.ins().load(ct::I8, f, base, 16 + i);
            let idx = b.ins().band_imm_u(mi, 15);
            let idx = b.ins().uextend(ct::I64, idx);
            let at = b.ins().iadd(base, idx);
            let v = b.ins().load(ct::I8, f, at, 0);
            let off = b.ins().icmp_imm_s(cir::condcodes::IntCC::SignedLessThan, mi, 0);
            let r = b.ins().select(off, zero, v);
            b.ins().store(f, r, base, 32 + i);
        }
        let out = b.ins().load(ct::I8X16, f, base, 32);
        b.ins().return_(&[out]);
        b.finalize(tcfg);
    }
    m.define_function(fid, &mut ctx)?;
    Ok(())
}

fn module_uses_f80(m: &sic_ir::Module) -> bool {
    let sig_f80 = |s: &sic_ir::FunctionType| mentions_f80(&s.ret) || s.params.iter().any(mentions_f80);
    // Only externs actually used: headers declare many `long double` functions.
    let used = m.used_externs();
    if m.externs.iter().enumerate().any(|(i, e)| used.contains(&i) && sig_f80(&e.sig))
        || m.functions.iter().any(|f| sig_f80(&f.sig))
    {
        return true;
    }
    m.functions.iter().any(|f| f.blocks.iter().any(|b| b.instrs.iter().any(|i| match i {
        sic_ir::Instr::Alloca { ty, .. } | sic_ir::Instr::Load { ty, .. }
        | sic_ir::Instr::VaArg { ty, .. } | sic_ir::Instr::BinOp { ty, .. }
        | sic_ir::Instr::Select { ty, .. } => mentions_f80(ty),
        sic_ir::Instr::Cast { to_ty, .. } => mentions_f80(to_ty),
        sic_ir::Instr::GetFieldPtr { result_ty, .. } | sic_ir::Instr::GetElemPtr { result_ty, .. } => mentions_f80(result_ty),
        sic_ir::Instr::Call { ret_ty, .. } => mentions_f80(ret_ty),
        sic_ir::Instr::CallIndirect { ret_ty, func_ty, .. } => mentions_f80(ret_ty) || sig_f80(func_ty),
        _ => false,
    })))
}

pub fn build_cl_sig(
    sig: &sic_ir::FunctionType,
    ptr_size: u32,
    call_conv: CallConv,
) -> cir::Signature {
    let mut cl_sig = cir::Signature::new(call_conv);
    let ptr_ty = types::ptr_cl(ptr_size);

    // System V: a small struct/union is passed in registers (one param per
    // eightbyte), a large one by value on the stack (StructArgument); scalars
    // and vectors keep their single-value mapping. See abi.rs / ABI.md.
    cl_sig.params = abi::params_abi(&sig.params, ptr_size, ptr_ty);

    // Returns: a small struct/union comes back in registers (one return value per
    // eightbyte); a MEMORY-class aggregate (and, for now, `Array`/vectors) uses the
    // sret ABI — the frontend prepends a hidden pointer param (already in
    // `sig.params`) so there is no register return value.
    match &sig.ret {
        sic_ir::Type::Struct(_) | sic_ir::Type::Union(_) => {
            if let sic_ir::abi::AggClass::Regs(chunks) =
                sic_ir::abi::classify_struct_union(&sig.ret, ptr_size)
            {
                for c in &chunks {
                    cl_sig.returns.push(cir::AbiParam::new(abi::chunk_cl_type(c)));
                }
            }
        }
        // `long double` returns in x87 `st(0)`, which Cranelift cannot express:
        // no Cranelift return value (see sic_ir::f80, `__sic_f80_st0`/`_ret`).
        sic_ir::Type::Array { .. } | sic_ir::Type::Void | sic_ir::Type::Float80 => {}
        other => {
            if types::cl_type(other, ptr_size).is_some() {
                // Narrow integers are zero/sign-extended to 32 bits on return
                // (SysV/gcc convention) so callers see clean upper bits.
                cl_sig.returns.push(abi::scalar_abi_param(other, ptr_size));
            }
        }
    }

    cl_sig
}

/// x86-64 System V register-save-area geometry: 6 general-purpose argument
/// registers (rdi,rsi,rdx,rcx,r8,r9) and 8 vector registers (xmm0–xmm7).
pub const VA_GP_REGS: usize = 6;
pub const VA_FP_REGS: usize = 8;
/// Count how many named parameters occupy general-purpose vs vector argument
/// registers (each capped at the number of such registers).
pub fn va_named_reg_counts(sig: &sic_ir::FunctionType, ptr_size: u32) -> (usize, usize) {
    let mut n_gp = 0usize;
    let mut n_fp = 0usize;
    for p in &sig.params {
        // A Direct aggregate consumes one register per eightbyte (by class); a
        // ByValStack aggregate is on the stack and consumes none.
        match abi::classify_param(p, ptr_size) {
            abi::ParamPass::Scalar => {
                if cl_type(p, ptr_size).is_some_and(|t| t.is_float()) { n_fp += 1 } else { n_gp += 1 }
            }
            abi::ParamPass::Direct(chunks) => {
                for c in &chunks {
                    if c.class == sic_ir::abi::RegClass::Sse { n_fp += 1 } else { n_gp += 1 }
                }
            }
            abi::ParamPass::ByValStack(..) | abi::ParamPass::X87 => {}
        }
    }
    (n_gp.min(VA_GP_REGS), n_fp.min(VA_FP_REGS))
}

/// Bytes of stack the named parameters occupy (incl. alignment pads): a
/// variadic function's first stack vararg starts there.
pub fn named_stack_bytes(sig: &sic_ir::FunctionType, ptr_size: u32) -> u32 {
    let kinds: Vec<abi::ArgKind> = sig.params.iter()
        .filter(|t| !matches!(t, sic_ir::Type::Void))
        .flat_map(|t| abi::param_kinds(&abi::classify_param(t, ptr_size), t, ptr_size)).collect();
    abi::stack_pads(&kinds).1
}

/// Build the signature used to *compile* a variadic function body. Cranelift has
/// no native variadic support, so we over-declare trailing params to capture the
/// incoming argument registers: `i64` params grab the remaining GP registers,
/// `f64` params grab the remaining XMM registers. The prologue spills these into
/// a System-V-layout register save area (see `func::compile_function`) so a
/// `va_list` built here is ABI-compatible with libc's `vfprintf` et al. The stack
/// varargs stay where the caller put them: `va_list` points at them.
pub fn build_cl_sig_def(
    sig: &sic_ir::FunctionType,
    ptr_size: u32,
    call_conv: CallConv,
    sse: bool,
) -> cir::Signature {
    let mut cl_sig = build_cl_sig(sig, ptr_size, call_conv);
    if sig.variadic {
        let (n_gp, n_fp) = va_named_reg_counts(sig, ptr_size);
        for _ in 0..(VA_GP_REGS - n_gp) {
            cl_sig.params.push(cir::AbiParam::new(cir::types::I64));
        }
        // The vector argument registers only when SSE may be used (GCC with
        // `-mno-sse` saves none either; no floating-point argument exists).
        if sse {
            for _ in 0..(VA_FP_REGS - n_fp) {
                cl_sig.params.push(cir::AbiParam::new(cir::types::F64));
            }
        }
    }
    cl_sig
}

/// Non-PIC code (`-fno-PIE`, `-mcmodel=kernel`): every function and data symbol
/// is within ±2 GB, so calls are direct `call rel32` and data is addressed
/// RIP-relative — as GCC's small and kernel code models assume. (Cranelift
/// otherwise reaches an imported symbol through `movabs` and an indirect call.)
/// A thread-local symbol keeps its TLS access.
fn colocate_symbols(func: &mut cir::Function) {
    for (_, ef) in func.dfg.ext_funcs.iter_mut() { ef.colocated = true; }
    for (_, gv) in func.global_values.iter_mut() {
        if let cir::GlobalValueData::Symbol { colocated, tls: false, .. } = gv { *colocated = true; }
    }
}

/// With SSE disabled (`-mno-sse`), a function must not compute with floating-
/// point or vector values: x86-64 has only SSE registers for them (and the x87
/// FPU for `long double`). As GCC, that is an error rather than SSE code in,
/// say, kernel code that does not save the FPU state.
fn check_no_float(func: &cir::Function, name: &str) -> Result<(), CraneliftError> {
    let bad = func.dfg.values().any(|v| { let t = func.dfg.value_type(v); t.is_float() || t.is_vector() })
        || func.signature.params.iter().chain(&func.signature.returns).any(|p| p.value_type.is_float() || p.value_type.is_vector());
    if bad {
        return Err(CraneliftError::Unsupported(format!(
            "function '{}' uses floating-point or vector values, but SSE is disabled (-mno-sse)", name)));
    }
    Ok(())
}
