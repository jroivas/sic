//! The LLVM back end, through inkwell: sic's IR to an object file in process, with
//! no LLVM tool run. It takes the IR as the Cranelift back end does (aggregates
//! flow as pointers, `bool` is an `i8`, stack objects are fixed) and leaves the
//! rest of the C ABI to LLVM: `long double` is a real `x86_fp80` at memory and call
//! boundaries, a variadic function is a variadic function.

mod debug;
mod func;
mod simd;
mod types;

use inkwell::attributes::{Attribute, AttributeLoc};
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::module::{Linkage as LLinkage, Module as LModule};
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetMachine};
use inkwell::types::BasicTypeEnum;
use inkwell::values::{BasicValueEnum, FunctionValue, GlobalValue, PointerValue};
use inkwell::{AddressSpace, GlobalVisibility, OptimizationLevel};
use sic_ir::fast_hash::HashMap;
use sic_ir::{Backend, BackendError, BackendOptions, Constant, FuncRef, Global, Linkage, Module, OptLevel, RelocTarget, RunAt};

type R<T> = Result<T, BackendError>;

#[derive(Default)]
pub struct LlvmBackend;

impl LlvmBackend {
    pub fn new() -> Self { LlvmBackend }
}

impl Backend for LlvmBackend {
    fn name(&self) -> &'static str { "llvm" }

    fn compile_module(&mut self, module: &Module, opts: &BackendOptions) -> R<Vec<u8>> {
        compile(module, opts)
    }

    fn mitigations(&self) -> bool { true }
}

/// Shared by everything emitted for one module.
pub(crate) struct Cx<'ctx, 'a> {
    pub ctx: &'ctx Context,
    pub module: &'a LModule<'ctx>,
    pub builder: &'a Builder<'ctx>,
    pub ir: &'a Module,
    pub opts: &'a BackendOptions,
    /// By `FuncRef` encoding.
    pub funcs: HashMap<u32, FunctionValue<'ctx>>,
    /// By `GlobalRef`.
    pub globals: HashMap<u32, GlobalValue<'ctx>>,
    /// `-g`.
    pub debug: Option<debug::Debug<'ctx>>,
}

/// Functions that return twice: a caller must not keep state in registers or
/// reuse stack slots across them.
const RETURNS_TWICE: &[&str] = &["setjmp", "_setjmp", "__sigsetjmp", "sigsetjmp", "vfork"];

fn target_features(opts: &BackendOptions) -> String {
    let mut f: Vec<String> = opts.features.iter().map(|n| format!("+{}", n)).collect();
    if !opts.sse { f.extend(["-mmx", "-sse", "-sse2"].map(String::from)); }
    if !opts.x87 { f.push("-x87".to_string()); }
    let m = &opts.mitigations;
    if m.retpoline || m.retpoline_external {
        f.extend(["+retpoline-indirect-calls", "+retpoline-indirect-branches"].map(String::from));
    }
    if m.retpoline_external { f.push("+retpoline-external-thunk".to_string()); }
    if m.harden_sls_ret { f.push("+harden-sls-ret".to_string()); }
    if m.harden_sls_ijmp { f.push("+harden-sls-ijmp".to_string()); }
    f.join(",")
}

/// The module-wide part of the mitigations, as LLVM's module flags (clang's).
fn mitigation_flags(cx: &Cx<'_, '_>) {
    use inkwell::module::FlagBehavior;
    let m = &cx.opts.mitigations;
    let i32t = cx.ctx.i32_type();
    let int = |key: &str, v: u64| cx.module.add_basic_value_flag(key, FlagBehavior::Override, i32t.const_int(v, false));
    let text = |key: &str, v: &str| cx.module.add_metadata_flag(key, FlagBehavior::Error, cx.ctx.metadata_string(v));
    if m.indirect_branch_cs_prefix { int("indirect_branch_cs_prefix", 1); }
    if m.cf_branch { int("cf-protection-branch", 1); }
    if m.cf_return { int("cf-protection-return", 1); }
    if let Some(g) = &m.stack_guard { text("stack-protector-guard", g); }
    if let Some(r) = &m.stack_guard_reg { text("stack-protector-guard-reg", r); }
    if let Some(s) = &m.stack_guard_symbol { text("stack-protector-guard-symbol", s); }
    if let Some(o) = m.stack_guard_offset { int("stack-protector-guard-offset", o as u64); }
    if let Some(a) = m.stack_alignment { int("override-stack-alignment", a as u64); }
}

/// Non-PIC code (`-fno-PIE`, `-mcmodel=kernel`): every symbol is within reach, as in
/// GCC's small and kernel code models. `RelocMode::Static` does not say so: LLVM goes
/// through the GOT unless a symbol is `dso_local` (Linux's link rejects any GOT entry),
/// and its C API has no setter. Giving a symbol non-default visibility sets the flag,
/// which then stays; an external weak one only while it is not weak. A thread-local
/// symbol keeps its TLS access, an intrinsic is no symbol.
fn assume_local(module: &inkwell::module::Module) {
    let mark = |g: GlobalValue| {
        let (visibility, linkage) = (g.get_visibility(), g.get_linkage());
        if matches!(linkage, LLinkage::Internal | LLinkage::Private) { return; }
        if linkage == LLinkage::ExternalWeak { g.set_linkage(LLinkage::External); }
        g.set_visibility(GlobalVisibility::Hidden);
        g.set_visibility(visibility);
        g.set_linkage(linkage);
    };
    for f in module.get_functions() {
        if !f.get_name().to_bytes().starts_with(b"llvm.") { mark(f.as_global_value()); }
    }
    for g in module.get_globals() {
        if !g.is_thread_local() { mark(g); }
    }
}

fn compile(ir: &Module, opts: &BackendOptions) -> R<Vec<u8>> {
    Target::initialize_x86(&InitializationConfig::default());
    // i386 (`-m32`) as clang's: `i386-pc-linux-gnu`, CPU `pentium4` (SSE2).
    let (triple, cpu) = if opts.ptr_size == 4 {
        (inkwell::targets::TargetTriple::create("i386-pc-linux-gnu"), "pentium4")
    } else {
        (TargetMachine::get_default_triple(), "x86-64")
    };
    let target = Target::from_triple(&triple).map_err(|e| e.to_string())?;
    let level = match opts.opt { OptLevel::None => OptimizationLevel::None, OptLevel::Basic => OptimizationLevel::Less, _ => OptimizationLevel::Default };
    let reloc = if opts.pic { RelocMode::PIC } else { RelocMode::Static };
    let model = if opts.no_text_data { CodeModel::Kernel } else { CodeModel::Default };
    let machine = target.create_target_machine(&triple, cpu, &target_features(opts), level, reloc, model)
        .ok_or("LLVM has no target machine for this configuration")?;

    let ctx = Context::create();
    let module = ctx.create_module(&ir.name);
    module.set_triple(&triple);
    module.set_data_layout(&machine.get_target_data().get_data_layout());
    let builder = ctx.create_builder();
    let debug = opts.debug_info.then(|| debug::Debug::new(&ctx, &module, ir, opts.ptr_size, opts.opt != OptLevel::None));
    let mut cx = Cx { ctx: &ctx, module: &module, builder: &builder, ir, opts, funcs: HashMap::default(), globals: HashMap::default(), debug };

    let mut asm = String::new();
    mitigation_flags(&cx);
    declare_functions(&mut cx, &mut asm)?;
    declare_globals(&mut cx);
    resolve_aliases(&mut cx);
    define_globals(&cx)?;
    let mut used = constructors(&cx)?;
    for (i, f) in ir.functions.iter().enumerate() {
        let Some(&lf) = cx.funcs.get(&(i as u32)) else { continue };
        func::emit(&cx, f, lf).map_err(|e| e.to_string())?;
    }
    for name in &ir.used_functions {
        if let Some(f) = module.get_function(name) { used.push(f.as_global_value().as_pointer_value()); }
    }
    keep(&cx, "llvm.used", &used);
    keep(&cx, "llvm.compiler.used", &named_elsewhere(&cx));
    // i386: file-scope `asm(...)` is the module's assembly (on x86-64 the driver
    // adds it, with the inline-asm text helpers).
    if opts.ptr_size == 4 {
        for t in &ir.file_asm { asm.push_str(t); asm.push('\n'); }
    }
    if let Some(p) = &ir.producer {
        asm.push_str(&format!(".pushsection .comment,\"MS\",@progbits,1\n.asciz \"{}\"\n.popsection\n", p.replace('\\', "\\\\").replace('"', "\\\"")));
    }
    if !asm.is_empty() { module.set_inline_assembly(&asm); }
    if !opts.pic { assume_local(&module); }
    if let Some(d) = &cx.debug { d.di.finalize(); }

    module.verify().map_err(|e| format!("LLVM rejected the module: {}", e.to_string()))?;
    // Unoptimized, `always_inline` functions are still inlined, as clang's -O0
    // (an inline-asm `"i"` operand is a constant only then), and a branch on a
    // constant is folded (clang does not emit the arms a constant `switch` rules
    // out: Linux's cmpxchg has an asm per operand size there).
    let pipeline = match opts.opt {
        OptLevel::None => Some("always-inline,function(simplifycfg)"),
        OptLevel::Basic => Some("default<O1>"),
        OptLevel::Speed => Some("default<O2>"),
        OptLevel::Size => Some("default<Os>"),
    };
    if std::env::var("SIC_DUMP_LLVM").is_ok() { eprintln!("{}", module.print_to_string().to_string()); }
    if let Some(p) = pipeline {
        module.run_passes(p, &machine, PassBuilderOptions::create()).map_err(|e| e.to_string())?;
    }
    let buf = machine.write_to_memory_buffer(&module, FileType::Object).map_err(|e| e.to_string())?;
    Ok(buf.as_slice().to_vec())
}

fn fn_linkage(l: Linkage) -> LLinkage {
    match l {
        Linkage::External | Linkage::Import => LLinkage::External,
        Linkage::Internal | Linkage::Private => LLinkage::Internal,
        Linkage::Weak => LLinkage::WeakAny,
    }
}

pub(crate) fn enum_attr(ctx: &Context, name: &str, val: u64) -> Attribute {
    ctx.create_enum_attribute(Attribute::get_named_enum_kind_id(name), val)
}

fn declare_functions<'ctx>(cx: &mut Cx<'ctx, '_>, asm: &mut String) -> R<()> {
    let ir = cx.ir;
    let reachable = ir.reachable_functions();
    for (i, f) in ir.functions.iter().enumerate() {
        if f.linkage == Linkage::Internal && !reachable.contains(&(i as u32)) { continue; }
        let lf = types::declare(cx, &f.name, &f.sig, Some(fn_linkage(f.linkage)));
        let attr = |k| lf.add_attribute(AttributeLoc::Function, k);
        attr(enum_attr(cx.ctx, "nounwind", 0));
        attr(cx.ctx.create_string_attribute("frame-pointer", "all"));
        if cx.opts.no_red_zone { attr(enum_attr(cx.ctx, "noredzone", 0)); }
        if f.noinline { attr(enum_attr(cx.ctx, "noinline", 0)); }
        if f.always_inline { attr(enum_attr(cx.ctx, "alwaysinline", 0)); }
        // The per-function part of the mitigations (clang's attributes).
        let m = &cx.opts.mitigations;
        if m.return_thunk { attr(enum_attr(cx.ctx, "fn_ret_thunk_extern", 0)); }
        if !ir.no_stack_protector.contains(&f.name) {
            match m.stack_protector {
                sic_ir::StackProtector::None => {}
                sic_ir::StackProtector::On => attr(enum_attr(cx.ctx, "ssp", 0)),
                sic_ir::StackProtector::Strong => attr(enum_attr(cx.ctx, "sspstrong", 0)),
                sic_ir::StackProtector::All => attr(enum_attr(cx.ctx, "sspreq", 0)),
            }
        }
        // `patchable_function_entry(N, M)` (Linux's `notrace`: 0, 0) over the option.
        let patch = ir.patchable_entry.iter().find(|p| p.0 == f.name).map(|p| (p.1, p.2)).or(m.patchable_entry);
        if let Some((n, prefix)) = patch.filter(|p| p.0 > 0) {
            attr(cx.ctx.create_string_attribute("patchable-function-entry", &(n - prefix.min(n)).to_string()));
            if prefix > 0 { attr(cx.ctx.create_string_attribute("patchable-function-prefix", &prefix.to_string())); }
        }
        if let Some(z) = &m.zero_call_used_regs { attr(cx.ctx.create_string_attribute("zero-call-used-regs", z)); }
        match ir.fn_sections.iter().find(|(n, _)| *n == f.name) {
            Some((_, sec)) => lf.as_global_value().set_section(Some(sec)),
            None if cx.opts.function_sections => lf.as_global_value().set_section(Some(&format!(".text.{}", f.name))),
            None => {}
        }
        if ir.hidden_symbols.contains(&f.name) && lf.get_linkage() != LLinkage::Internal {
            lf.as_global_value().set_visibility(GlobalVisibility::Hidden);
        }
        cx.funcs.insert(i as u32, lf);
    }
    let used = ir.used_externs();
    for (i, e) in ir.externs.iter().enumerate() {
        if !used.contains(&i) { continue; }
        // A recognised inline-asm template is a call of a helper whose machine
        // code is known (sic_ir::asm_helpers): local to the object.
        if let Some(code) = sic_ir::asm_helpers::asm_helper_code(&e.name) {
            // The helpers are x86-64 machine code.
            if cx.opts.ptr_size == 4 { return Err("inline assembly is not supported with -m32 yet".into()); }
            let bytes: Vec<String> = code.iter().map(|b| b.to_string()).collect();
            asm.push_str(&format!(".pushsection .text.{0},\"ax\",@progbits\n.p2align 4\n.type {0},@function\n{0}:\n.byte {1}\n.popsection\n", e.name, bytes.join(",")));
        }
        let lf = cx.module.get_function(&e.name).unwrap_or_else(|| types::declare(cx, &e.name, &e.sig, None));
        if ir.weak_externs.contains(&e.name) { lf.set_linkage(LLinkage::ExternalWeak); }
        if ir.hidden_symbols.contains(&e.name) && lf.get_linkage() != LLinkage::Internal {
            lf.as_global_value().set_visibility(GlobalVisibility::Hidden);
        }
        if RETURNS_TWICE.contains(&e.name.as_str()) { lf.add_attribute(AttributeLoc::Function, enum_attr(cx.ctx, "returns_twice", 0)); }
        cx.funcs.insert(FuncRef::extern_(i).0, lf);
    }
    Ok(())
}

/// A global's initializer in pieces: bytes, and pointers between them.
enum Piece<'a> { Bytes(&'a [u8]), Reloc(&'a RelocTarget) }

fn pieces<'a>(bytes: &'a [u8], relocs: &'a [(usize, RelocTarget)], ptr_size: usize) -> Vec<Piece<'a>> {
    // The last of several at one offset: `[0 ... 3] = a, [0] = b`.
    let mut last = std::collections::BTreeMap::new();
    for (off, t) in relocs { last.insert(*off, t); }
    let (mut out, mut pos) = (Vec::new(), 0usize);
    for (off, t) in last {
        if off > pos { out.push(Piece::Bytes(&bytes[pos..off])); }
        out.push(Piece::Reloc(t));
        pos = off + ptr_size;
    }
    if pos < bytes.len() { out.push(Piece::Bytes(&bytes[pos..])); }
    out
}

/// The bytes a global's initializer takes, except a pointer or an aggregate.
fn plain_bytes(g: &Global, size: usize) -> Option<Vec<u8>> {
    Some(match &g.init {
        Some(Constant::Bytes(b)) => { let mut v = b.clone(); if v.len() < size { v.resize(size, 0); } v }
        Some(Constant::Int(v)) => {
            let mut bytes = vec![0u8; size.max(4)];
            for (i, b) in v.to_le_bytes().iter().take(bytes.len()).enumerate() { bytes[i] = *b; }
            bytes
        }
        Some(Constant::Float(v)) => {
            if g.ty == sic_ir::Type::Float80 { sic_ir::f80::f64_to_f80_bytes(*v).to_vec() }
            else if size <= 4 { (*v as f32).to_le_bytes().to_vec() }
            else { v.to_le_bytes().to_vec() }
        }
        Some(Constant::GlobalAddr(_)) | Some(Constant::Aggregate { .. }) => return None,
        _ => vec![0u8; size.max(1)],
    })
}

fn padded(bytes: &[u8], size: usize) -> Vec<u8> {
    let mut d = bytes.to_vec();
    if d.len() < size { d.resize(size, 0); }
    d
}

/// The LLVM type of a global's definition: its initializer's, as an initializer
/// can hold pointers in the middle of bytes.
fn global_type<'ctx>(cx: &Cx<'ctx, '_>, g: &Global, size: usize) -> BasicTypeEnum<'ctx> {
    let i8t = cx.ctx.i8_type();
    let ptr = cx.ctx.ptr_type(AddressSpace::default());
    match &g.init {
        Some(Constant::GlobalAddr(_)) => ptr.into(),
        Some(Constant::Aggregate { bytes, relocs }) => {
            let data = padded(bytes, size);
            let fields: Vec<BasicTypeEnum> = pieces(&data, relocs, cx.opts.ptr_size as usize).iter().map(|p| match p {
                Piece::Bytes(b) => i8t.array_type(b.len() as u32).into(),
                Piece::Reloc(_) => ptr.into(),
            }).collect();
            cx.ctx.struct_type(&fields, true).into()
        }
        _ => i8t.array_type(plain_bytes(g, size).map_or(1, |b| b.len()) as u32).into(),
    }
}

fn declare_globals<'ctx>(cx: &mut Cx<'ctx, '_>) {
    let ir = cx.ir;
    let ptr_size = cx.opts.ptr_size;
    let used = ir.used_globals();
    for (i, g) in ir.globals.iter().enumerate() {
        if matches!(g.linkage, Linkage::Import | Linkage::Internal | Linkage::Private) && !used.contains(&(i as u32)) { continue; }
        let size = g.ty.size_of(ptr_size) as usize;
        let imported = g.linkage == Linkage::Import;
        let lg = match cx.module.get_global(&g.name) {
            Some(lg) => lg,
            None => {
                // An import is as large as its type says: LLVM takes that for the
                // object's extent. Of unknown size (`extern T a[]`), it is empty,
                // and may be where another object is: Linux's `__start_x` and
                // `__end_x` are one address when the section is empty.
                let ty = if imported { cx.ctx.i8_type().array_type(size as u32).into() } else { global_type(cx, g, size) };
                cx.module.add_global(ty, None, &g.name)
            }
        };
        if imported {
            lg.set_linkage(if ir.weak_externs.contains(&g.name) { LLinkage::ExternalWeak } else { LLinkage::External });
        } else {
            lg.set_linkage(fn_linkage(g.linkage));
            lg.set_alignment(g.ty.align_of(ptr_size).max(g.align.unwrap_or(0) as u64).max(1) as u32);
            lg.set_constant(g.constant && !g.thread_local);
        }
        if ir.hidden_symbols.contains(&g.name) && lg.get_linkage() != LLinkage::Internal {
            lg.set_visibility(GlobalVisibility::Hidden);
        }
        if g.thread_local { lg.set_thread_local(true); }
        if !g.thread_local {
            if let Some((_, sec)) = ir.data_sections.iter().find(|(n, _)| *n == g.name) { lg.set_section(Some(sec)); }
        }
        cx.globals.insert(i as u32, lg);
    }
}

/// `__attribute__((alias))` is a `.set` in the file's assembly: to LLVM, two names
/// it would take for two objects. In this unit an alias is its target.
fn resolve_aliases(cx: &mut Cx<'_, '_>) {
    let ir = cx.ir;
    let mut aliases = HashMap::default();
    for text in &ir.file_asm {
        let Some((_, rest)) = text.split_once(".set") else { continue };
        if let Some((name, target)) = rest.split_once(',') { aliases.insert(name.trim().to_string(), target.trim().to_string()); }
    }
    for (i, g) in ir.globals.iter().enumerate() {
        if g.linkage != Linkage::Import { continue; }
        let Some(target) = aliases.get(&g.name).and_then(|t| cx.module.get_global(t)) else { continue };
        if cx.globals.contains_key(&(i as u32)) { cx.globals.insert(i as u32, target); }
    }
    for (i, e) in ir.externs.iter().enumerate() {
        let Some(target) = aliases.get(&e.name).and_then(|t| cx.module.get_function(t)) else { continue };
        let key = FuncRef::extern_(i).0;
        if cx.funcs.contains_key(&key) { cx.funcs.insert(key, target); }
    }
}

fn reloc_value<'ctx>(cx: &Cx<'ctx, '_>, t: &RelocTarget) -> BasicValueEnum<'ctx> {
    let null = cx.ctx.ptr_type(AddressSpace::default()).const_null();
    match t {
        RelocTarget::Global(g, addend) => {
            let Some(lg) = cx.globals.get(&g.0) else { return null.into() };
            let base = lg.as_pointer_value();
            if *addend == 0 { return base.into(); }
            let off = cx.ctx.i64_type().const_int(*addend as u64, true);
            unsafe { base.const_gep(cx.ctx.i8_type(), &[off]) }.into()
        }
        RelocTarget::Func(f) => match cx.funcs.get(&f.0) {
            Some(lf) => lf.as_global_value().as_pointer_value().into(),
            None => null.into(),
        },
    }
}

fn define_globals(cx: &Cx<'_, '_>) -> R<()> {
    let ptr_size = cx.opts.ptr_size;
    for (i, g) in cx.ir.globals.iter().enumerate() {
        if g.linkage == Linkage::Import { continue; }
        let Some(lg) = cx.globals.get(&(i as u32)) else { continue };
        let size = g.ty.size_of(ptr_size) as usize;
        match &g.init {
            Some(Constant::GlobalAddr(t)) => {
                let target = cx.globals.get(&t.0).ok_or("a global's initializer names an unknown global")?;
                lg.set_initializer(&target.as_pointer_value());
            }
            Some(Constant::Aggregate { bytes, relocs }) => {
                let data = padded(bytes, size);
                let vals: Vec<BasicValueEnum> = pieces(&data, relocs, cx.opts.ptr_size as usize).iter().map(|p| match p {
                    Piece::Bytes(b) => cx.ctx.const_string(b, false).into(),
                    Piece::Reloc(t) => reloc_value(cx, t),
                }).collect();
                lg.set_initializer(&cx.ctx.const_struct(&vals, true));
            }
            _ => {
                let bytes = plain_bytes(g, size).unwrap_or_default();
                if matches!(g.init, Some(Constant::Bytes(_) | Constant::Int(_) | Constant::Float(_))) {
                    lg.set_initializer(&cx.ctx.const_string(&bytes, false));
                } else {
                    lg.set_initializer(&cx.ctx.i8_type().array_type(bytes.len() as u32).const_zero());
                }
            }
        }
    }
    Ok(())
}

/// `.init_array` / `.fini_array` entries, by priority as the linker orders them.
fn constructors<'ctx>(cx: &Cx<'ctx, '_>) -> R<Vec<PointerValue<'ctx>>> {
    let mut out = Vec::new();
    let ptr = cx.ctx.ptr_type(AddressSpace::default());
    for (i, f) in cx.ir.functions.iter().enumerate() {
        let Some(run) = f.constructor else { continue };
        let Some(lf) = cx.funcs.get(&(i as u32)) else { continue };
        let (array, prio) = match run { RunAt::Startup(p) => ("init_array", p), RunAt::Exit(p) => ("fini_array", p) };
        let section = if prio == 65535 { format!(".{}", array) } else { format!(".{}.{:05}", array, prio) };
        let g = cx.module.add_global(ptr, None, &format!(".ctor_dtor.entry.{}", f.name));
        g.set_linkage(LLinkage::Internal);
        g.set_section(Some(&section));
        g.set_alignment(cx.opts.ptr_size);
        g.set_initializer(&lf.as_global_value().as_pointer_value());
        out.push(g.as_pointer_value());
    }
    Ok(out)
}

/// What the optimizer cannot see a use of, and the object needs: a variable in a
/// named section (found by `__start_`/`__stop_`, or by a tool), and an internal
/// symbol that only inline-asm text names.
fn named_elsewhere<'ctx>(cx: &Cx<'ctx, '_>) -> Vec<PointerValue<'ctx>> {
    let mut words = sic_ir::fast_hash::HashSet::default();
    let texts = cx.ir.asm_text_helpers.iter().map(|(_, t)| t).chain(cx.ir.file_asm.iter());
    for t in texts {
        for w in t.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '$')) { words.insert(w); }
    }
    let mut out = Vec::new();
    for (i, g) in cx.ir.globals.iter().enumerate() {
        let Some(lg) = cx.globals.get(&(i as u32)) else { continue };
        if g.linkage == Linkage::Import { continue; }
        let in_section = cx.ir.data_sections.iter().any(|(n, _)| *n == g.name);
        if in_section || words.contains(g.name.as_str()) { out.push(lg.as_pointer_value()); }
    }
    for (i, f) in cx.ir.functions.iter().enumerate() {
        let Some(lf) = cx.funcs.get(&(i as u32)) else { continue };
        if words.contains(f.name.as_str()) { out.push(lf.as_global_value().as_pointer_value()); }
    }
    out
}

/// What the optimizer must keep: `llvm.used`, for the linker too.
fn keep<'ctx>(cx: &Cx<'ctx, '_>, list: &str, used: &[PointerValue<'ctx>]) {
    if used.is_empty() { return; }
    let ptr = cx.ctx.ptr_type(AddressSpace::default());
    let init = ptr.const_array(used);
    let g = cx.module.add_global(init.get_type(), None, list);
    g.set_linkage(LLinkage::Appending);
    g.set_section(Some("llvm.metadata"));
    g.set_initializer(&init);
}
