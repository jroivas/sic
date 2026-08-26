pub(crate) mod types;
mod expr;
mod func;
mod borrowck;

use std::collections::{HashMap, HashSet};
use crate::ast::*;
use crate::{Result, CompileError};
use sic_ir::*;

pub use types::{lower_type, lower_param_type};

/// State shared across the lowering of one module.
pub struct Lowerer {
    pub module: Module,
    /// Maps name → (type, value pointing to storage)
    pub globals_map: HashMap<String, (Type, GlobalRef)>,
    /// Known enum variant values
    pub enum_consts: HashMap<String, i64>,
    /// Named struct/union types
    pub struct_types: HashMap<String, Type>,
    /// Target pointer size in bytes
    pub ptr_size: u32,
    /// Names of `inline` functions that are reachable and must be emitted.
    /// Unreferenced inline definitions (e.g. the thousands of `extern __inline`
    /// SIMD intrinsics in `<immintrin.h>`) are skipped — see GNU inline rules.
    emit_inline: HashSet<String>,
    /// File-scope variable types (with inferred array lengths), registered in
    /// `collect_declarations` so `sizeof(global_array)` folds even before the
    /// global is lowered — needed for `enum { N = ARRAY_SIZE(global) }`.
    global_types: HashMap<String, Type>,
    /// Whether to synthesize a `main` from bare top-level statements (a sic-lang
    /// REPL convenience). Off for C, where a unit without `main` is a library.
    repl_main: bool,
    /// Functions declared `static` anywhere in the unit. C gives a function
    /// internal linkage if ANY declaration is `static`, even when its definition
    /// omits the keyword — the decodetree pattern `static bool decode_insn(...);`
    /// then `#include` defining `bool decode_insn(...)` (no `static`). Without
    /// this the two TUs including the same .inc collide ("multiple definition").
    static_funcs: HashSet<String>,
    /// Whether this unit is SIC-language source (`.sic`), which turns on SIC's
    /// defined-behavior semantics (guaranteed zero-init, `÷0 → 0`, defined
    /// shifts, …). Off for C, whose semantics must stay unchanged.
    pub sic: bool,
    /// sic module system (sic.md §"Imports"): `Some(name)` when this translation
    /// unit declared `module name;`. Its non-`static` top-level symbols are
    /// exported with the mangled linker name `name_sym`.
    pub current_module: Option<String>,
    /// Selectively/renamed-imported symbols (`import x.f;` / `import x.f as g;`):
    /// bare name usable here → (mangled linker symbol, IR type). A bare call `f()`
    /// or `g()` resolves through this table.
    pub imported_syms: HashMap<String, (String, Type)>,
    /// Whole imported modules (`import x;` or any `import x.*;`): module name →
    /// {export name → (mangled linker symbol, IR type)}. A namespaced use `x.f`
    /// resolves through this table.
    pub imported_modules: HashMap<String, HashMap<String, (String, Type)>>,
    /// Directories searched for `module_<name>.smod` manifests (from `-I`).
    pub include_dirs: Vec<String>,
    /// Default module search dirs (from `$SIC_MODULE_PATH` and the compiler's
    /// exe-relative sysroot `<exe>/../lib/sic`), searched BEFORE `-I` and cwd so a
    /// `import std;` resolves with no flags (sic.md §"Imports").
    pub module_dirs: Vec<String>,
    /// Target triple this unit is being compiled for; a manifest whose `triple`
    /// differs is a hard error (sic.md §"Imports").
    pub target_triple: String,
    /// Link flags gathered from imported modules' manifests, to be folded into the
    /// final link order by the driver.
    pub imported_links: Vec<String>,
    /// sic tagged enums (sic.md §"Match"): enum name → its variant table (tag,
    /// payload type, and the `{tag,union}` struct representation).
    pub enum_defs: HashMap<String, TaggedEnum>,
    /// Reverse index: variant name → owning enum name, for resolving a bare
    /// `Variant(..)` / `Variant` when the target enum type is not otherwise known.
    /// Last definition wins (a later enum may reuse a variant name).
    pub variant_enum: HashMap<String, String>,
    /// sic tuple parameters (sic.md §"Tuples"): `(function, param index)` → the
    /// concrete tuple value type, inferred from call sites in a pre-pass. A tuple
    /// param is passed by pointer, so its shape must be known to unpack/index it.
    pub tuple_param_types: HashMap<(String, usize), Type>,
    /// Variadic extern functions called with a float argument — the backend
    /// routes these through an `AL`-setting trampoline on x86-64 (Cranelift never
    /// sets `AL` for variadic calls). Surfaced on the IR module for the backend.
    pub float_vararg_externs: HashSet<String>,
    /// sic RTTI (sic.md §"RTTI"): canonical type name → the emitted static
    /// `__sic_type_info` record, so repeated `typeid(x)` of the same type share
    /// one record.
    pub type_info_globals: HashMap<String, GlobalRef>,
    /// sic generic enums (sic.md §"Match"): name → the template `EnumDef` (with
    /// `type_params`), instantiated per concrete `Option<int>` monomorphization.
    pub generic_enum_defs: HashMap<String, EnumDef>,
}

/// One variant of a sic tagged enum.
#[derive(Debug, Clone)]
pub struct TaggedVariant {
    pub name: String,
    /// C-sequential discriminant (also stored in `enum_consts`).
    pub tag: i64,
    /// Payload IR type, or `None` for a bare (payload-less) variant.
    pub payload: Option<Type>,
}

/// A sic tagged enum's lowered metadata.
#[derive(Debug, Clone)]
pub struct TaggedEnum {
    pub name: String,
    /// The `{ i32 tag; union{payloads} data }` struct representation.
    pub struct_type: Type,
    pub variants: Vec<TaggedVariant>,
}

impl TaggedEnum {
    pub fn variant(&self, name: &str) -> Option<&TaggedVariant> {
        self.variants.iter().find(|v| v.name == name)
    }
}

impl Lowerer {
    pub fn new(name: String) -> Self {
        Lowerer {
            module: Module::new(name),
            globals_map: HashMap::new(),
            enum_consts: HashMap::new(),
            struct_types: HashMap::new(),
            ptr_size: 8, // assume 64-bit
            emit_inline: HashSet::new(),
            global_types: HashMap::new(),
            repl_main: true,
            static_funcs: HashSet::new(),
            sic: false,
            current_module: None,
            imported_syms: HashMap::new(),
            imported_modules: HashMap::new(),
            include_dirs: Vec::new(),
            module_dirs: Vec::new(),
            target_triple: String::new(),
            imported_links: Vec::new(),
            enum_defs: HashMap::new(),
            variant_enum: HashMap::new(),
            tuple_param_types: HashMap::new(),
            float_vararg_externs: HashSet::new(),
            type_info_globals: HashMap::new(),
            generic_enum_defs: HashMap::new(),
        }
    }

    /// Enable or disable REPL-style `main` synthesis (default on). C sources set
    /// this off — they must define `main` explicitly.
    pub fn set_repl_main(&mut self, on: bool) {
        self.repl_main = on;
    }

    /// Enable SIC-language semantics (`.sic` sources). See [`Lowerer::sic`].
    pub fn set_sic(&mut self, on: bool) {
        self.sic = on;
    }

    /// Directories searched for `module_<name>.smod` manifests when resolving
    /// `import` (from the driver's `-I` include dirs).
    pub fn set_include_dirs(&mut self, dirs: Vec<String>) {
        self.include_dirs = dirs;
    }

    /// Default module search dirs (env `$SIC_MODULE_PATH` + exe-relative sysroot),
    /// consulted before `-I` and cwd (sic.md §"Imports").
    pub fn set_module_dirs(&mut self, dirs: Vec<String>) {
        self.module_dirs = dirs;
    }

    /// The target triple to enforce against imported manifests.
    pub fn set_target_triple(&mut self, triple: String) {
        self.target_triple = triple;
    }

    /// Link flags gathered from imported modules' manifests (for the driver to
    /// fold into the final link order). Empty unless this unit imports modules.
    pub fn imported_link_flags(&self) -> &[String] {
        &self.imported_links
    }

    pub fn lower(mut self, tu: &TranslationUnit) -> Result<Module> {
        let dbg = std::env::var("SIC_TIMING").is_ok();
        let t0 = std::time::Instant::now();
        // Decide which `inline` functions are reachable (and thus emitted).
        self.emit_inline = compute_emitted_inlines(tu);
        if dbg { eprintln!("[timing] compute_emitted_inlines: {:?} ({} inlines)", t0.elapsed(), self.emit_inline.len()); }

        // First pass: collect all function prototypes and global variable names
        // so that forward references work.
        let t1 = std::time::Instant::now();
        self.collect_declarations(tu)?;
        if dbg { eprintln!("[timing] collect_declarations: {:?}", t1.elapsed()); }

        // Build sic's native-string helpers up front (outside any function's
        // lowering) so their FuncRefs are stable and callers never construct
        // them mid-body.
        if self.sic {
            self.ensure_str_length_fn();
            self.ensure_str_retain_fn();
            self.ensure_str_release_fn();
            self.ensure_bounds_fail_fn();
            // Infer the concrete shape of every `tuple` parameter from its call
            // sites, so tuple params can be unpacked/indexed (sic.md §"Tuples").
            self.infer_tuple_params(tu);
        }

        // Second pass: lower function bodies and global initializers
        let t2 = std::time::Instant::now();
        self.lower_translation_unit(tu)?;
        if dbg { eprintln!("[timing] lower_translation_unit: {:?}", t2.elapsed()); }

        // If no main was defined, wrap top-level expression statements in a fake main.
        if self.module.func_ref_by_name("main").is_none() {
            self.synthesize_fake_main(tu)?;
        }

        // sic module export mangling: rename this unit's exported (external,
        // defined) top-level symbols to `<module>_<name>` (sic.md §"Imports").
        // References are by index, so only the emitted object symbol changes.
        if let Some(m) = self.current_module.clone() {
            self.mangle_module_exports(&m);
        }

        // Surface module metadata to the driver: the module name (→ manifest
        // emission) and any link flags pulled in from imported manifests.
        self.module.sic_module = self.current_module.clone();
        self.module.imported_links = std::mem::take(&mut self.imported_links);
        self.module.float_vararg_externs =
            std::mem::take(&mut self.float_vararg_externs).into_iter().collect();

        Ok(self.module)
    }

    /// Rename external, defined top-level functions/globals to `<module>_<name>`.
    /// `static` (Internal/Private) symbols and imports/externs keep their names.
    fn mangle_module_exports(&mut self, module: &str) {
        for f in &mut self.module.functions {
            // `main` is reserved by the C runtime and never mangled.
            if f.linkage == Linkage::External
                && f.name != "main"
                && !f.name.starts_with(&format!("{}_", module))
            {
                f.name = format!("{}_{}", module, f.name);
            }
        }
        for g in &mut self.module.globals {
            if g.linkage == Linkage::External {
                g.name = format!("{}_{}", module, g.name);
            }
        }
    }

    fn collect_declarations(&mut self, tu: &TranslationUnit) -> Result<()> {
        // A function has internal linkage if ANY of its declarations is `static`,
        // even one whose definition omits the keyword. Collect all such names up
        // front so the definition (processed later) gets the right linkage.
        for decl in &tu.decls {
            if let Decl::Func { name, storage: Some(StorageClass::Static), .. } = decl {
                self.static_funcs.insert(name.clone());
            }
        }
        // sic generic enums (sic.md §"Match"): register the templates and
        // monomorphize every `Option<int>` use BEFORE function signatures (which may
        // mention them) are lowered below.
        if self.sic {
            // sic prelude (sic.md §"Match"): bless `Option`/`Result` as built-in
            // generic enums so users need not declare them. A user declaration of
            // the same name overrides (registered from the AST below).
            for t in blessed_enum_templates() {
                let n = t.name.clone().unwrap();
                self.generic_enum_defs.entry(n).or_insert(t);
            }
            // Pre-register the named types (structs/unions/enums/typedefs) a generic
            // argument might use (`Option<Point>`), plus generic-enum templates, so
            // monomorphization below can resolve them. Idempotently re-registered in
            // the main pass; guarded so a failure here doesn't abort a valid unit.
            for decl in &tu.decls {
                let _ = self.register_type_decl_early(decl);
            }
            self.monomorphize_generics(tu)?;
        }
        for decl in &tu.decls {
            // Record file-scope variable types (with array lengths inferred from
            // their initializers) so `sizeof(global_array)` in a later enum value
            // resolves. Processed in source order, matching C's scope rules.
            if let Decl::Var { base_ty: _, declarators, .. } = decl {
                for d in declarators {
                    if let Ok(mut ty) = lower_type(&d.ty, &self.struct_types, self.ptr_size) {
                        if let Type::Array { len, .. } = &mut ty {
                            if *len == 0 {
                                if let Some(Initializer::List(items)) = &d.init {
                                    *len = self.infer_array_len(items);
                                }
                            }
                        }
                        // Prefer a complete array type over an incomplete one: a
                        // header's `extern T a[];` (len 0) may precede the sized
                        // definition `T a[N] = {...}`, and `sizeof(a)` must fold to
                        // the real length (QEMU's keymap
                        // `qemu_input_map_*_len = sizeof(map)/sizeof(map[0])`).
                        let new_complete = matches!(&ty, Type::Array { len, .. } if *len > 0);
                        if new_complete || !self.global_types.contains_key(&d.name) {
                            self.global_types.insert(d.name.clone(), ty);
                        }
                    }
                }
            }
            match decl {
                Decl::Func { name, ret_ty, params, variadic, body: None, .. } => {
                    // Forward declaration / extern. A struct/union/enum *defined*
                    // in the return type or a parameter (`struct S {..} *f(void)`)
                    // must be registered so its fields resolve later.
                    self.register_nested_struct_defs(&ret_ty.ty)?;
                    for p in params { self.register_nested_struct_defs(&p.ty.ty)?; }
                    let ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
                    let ir_params: Result<Vec<_>> = params.iter().map(|p| {
                        lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
                    }).collect();
                    let sig = build_fn_sig(ir_ret, ir_params?, *variadic, self.ptr_size);
                    if self.module.func_ref_by_name(name).is_none() {
                        self.module.add_extern(ExternFunc { name: name.clone(), sig });
                    }
                }
                Decl::Func { name, ret_ty, params, variadic, body: Some(_), storage, inline, .. } => {
                    // Skip unreferenced inline definitions (see `emit_inline`).
                    if *inline && !self.emit_inline.contains(name) { continue; }
                    // Register any struct/union/enum defined in the return type or
                    // parameters before lowering them.
                    self.register_nested_struct_defs(&ret_ty.ty)?;
                    for p in params { self.register_nested_struct_defs(&p.ty.ty)?; }
                    // Function definition — pre-register with empty body for stable FuncRef
                    let ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
                    let ir_params: Result<Vec<_>> = params.iter().map(|p| {
                        lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
                    }).collect();
                    let sig = build_fn_sig(ir_ret, ir_params?, *variadic, self.ptr_size);
                    // Register the DEFINED function even when a prior forward
                    // declaration only produced an extern (e.g. `static void f();`
                    // then `static void f() {...}` in QEMU's qht.c). Otherwise a
                    // caller lowered before the definition resolves to the extern,
                    // and the real (uncalled) definition is dropped as dead → the
                    // extern reference is left undefined.
                    let already_defined = self.module.functions.iter().any(|f| f.name == *name);
                    if !already_defined {
                        let linkage = fn_linkage(storage, *inline, self.static_funcs.contains(name));
                        self.module.add_function(Function::new(name.clone(), sig, vec![], linkage));
                    }
                }
                Decl::TypeDef { names, .. } => {
                    for (name, ty) in names {
                        // Register any enums/tagged structs nested in the type body
                        // (e.g. `typedef struct { enum { A, B } k; } T;`) so their
                        // constants and tags resolve.
                        self.register_nested_struct_defs(&ty.ty)?;
                        if let Ok(ir_ty) = lower_type(ty, &self.struct_types, self.ptr_size) {
                            // Also register named struct/union by their own name
                            match &ty.ty {
                                AstType::Struct(s) if s.name.is_some() && s.fields.is_some() => {
                                    self.struct_types.insert(s.name.clone().unwrap(), ir_ty.clone());
                                }
                                AstType::Union(u) if u.name.is_some() && u.fields.is_some() => {
                                    self.struct_types.insert(u.name.clone().unwrap(), ir_ty.clone());
                                }
                                AstType::Enum(e) => { self.register_enum(e)?; }
                                _ => {}
                            }
                            self.register_type_name(name.clone(), ir_ty);
                        }
                    }
                }
                Decl::StructDecl(s) | Decl::Var { base_ty: QualType { ty: AstType::Struct(s), .. }, .. } => {
                    self.register_struct_type_from_def(s)?;
                }
                Decl::UnionDecl(u) | Decl::Var { base_ty: QualType { ty: AstType::Union(u), .. }, .. } => {
                    self.register_union_type_from_def(u)?;
                }
                Decl::EnumDecl(e)
                | Decl::Var { base_ty: QualType { ty: AstType::Enum(e), .. }, .. } => {
                    self.register_enum(e)?;
                }
                // sic `module x;` — this unit's exports get mangled `x_sym`.
                Decl::Module(name, _) => { self.current_module = Some(name.clone()); }
                // sic `import x;` / `import x.sym [as alias];` — resolve the
                // module's manifest and register its exports.
                Decl::Import { module, sym, alias, span } => {
                    self.resolve_import(module, sym.as_deref(), alias.as_deref(), span)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Resolve one `import` declaration: load the module's `module_<name>.smod`
    /// manifest (once per module), hard-error on a triple/version mismatch, make
    /// every export available namespaced as `module.sym`, and — for a selective
    /// or renamed import — bind the bare name too. Manifest link flags are folded
    /// into `imported_links` for the driver to pass to the linker.
    fn resolve_import(
        &mut self,
        module: &str,
        sym: Option<&str>,
        alias: Option<&str>,
        span: &crate::lexer::Span,
    ) -> Result<()> {
        use crate::module_manifest::ModuleManifest;

        // `std` is now an ordinary module (`module std;`), built with the compiler
        // and resolved through its manifest like any other — no blessed special
        // case. Load the manifest once; later imports of the same module reuse it.
        if !self.imported_modules.contains_key(module) {
            let file = format!("module_{}.smod", module);
            let mut found: Option<String> = None;
            // Search: default module dirs ($SIC_MODULE_PATH + exe-relative sysroot)
            // first, then `-I` dirs, then the current directory.
            let mut dirs: Vec<String> = self.module_dirs.clone();
            dirs.extend(self.include_dirs.iter().cloned());
            dirs.push(".".to_string());
            for dir in &dirs {
                let path = std::path::Path::new(dir).join(&file);
                if path.exists() {
                    found = Some(path.to_string_lossy().into_owned());
                    break;
                }
            }
            let path = found.ok_or_else(|| CompileError::at(
                format!("cannot find module '{}' (looked for '{}' in include dirs)", module, file),
                span.file.clone(), span.line, span.col,
            ))?;
            let text = std::fs::read_to_string(&path).map_err(|e| CompileError::at(
                format!("reading module manifest '{}': {}", path, e),
                span.file.clone(), span.line, span.col,
            ))?;
            let manifest = ModuleManifest::parse(&text, self.ptr_size).map_err(|e| CompileError::at(
                format!("malformed module manifest '{}': {}", path, e),
                span.file.clone(), span.line, span.col,
            ))?;
            // Hard error on version / triple mismatch (no source fallback).
            if manifest.version != crate::module_manifest::MANIFEST_VERSION {
                return Err(CompileError::at(
                    format!("module '{}' manifest version {} != supported {}",
                        module, manifest.version, crate::module_manifest::MANIFEST_VERSION),
                    span.file.clone(), span.line, span.col,
                ));
            }
            if !self.target_triple.is_empty() && manifest.triple != self.target_triple {
                return Err(CompileError::at(
                    format!("module '{}' was built for target '{}', but this compilation targets '{}'",
                        module, manifest.triple, self.target_triple),
                    span.file.clone(), span.line, span.col,
                ));
            }
            let mut exports = HashMap::new();
            for e in &manifest.exports {
                exports.insert(e.name.clone(), (e.symbol.clone(), e.ty.clone()));
            }
            self.imported_modules.insert(module.to_string(), exports);
            for l in &manifest.links {
                if !self.imported_links.contains(l) {
                    self.imported_links.push(l.clone());
                }
            }
        }

        // Selective / renamed import: bind the bare (or aliased) name.
        if let Some(s) = sym {
            let export = self.imported_modules.get(module)
                .and_then(|m| m.get(s))
                .cloned()
                .ok_or_else(|| CompileError::at(
                    format!("module '{}' has no exported symbol '{}'", module, s),
                    span.file.clone(), span.line, span.col,
                ))?;
            let bind = alias.unwrap_or(s);
            self.imported_syms.insert(bind.to_string(), export);
        }
        Ok(())
    }

    /// Register a typedef name → type binding without clobbering a completed
    /// struct/union of the same name with an incomplete alias. C tags and typedef
    /// names live in one map here, so `typedef Fwd Tag;` (where `struct Tag {..}`
    /// is already complete) must not overwrite the real definition with `Fwd`'s
    /// stale empty snapshot (QEMU's `typedef HexagonCPU ArchCPU;` after
    /// `struct ArchCPU {..}`).
    fn register_type_name(&mut self, name: String, ty: Type) {
        let incoming_empty = matches!(&ty, Type::Struct(s) if s.fields.is_empty())
            || matches!(&ty, Type::Union(u) if u.fields.is_empty());
        if incoming_empty {
            if let Some(existing) = self.struct_types.get(&name) {
                let existing_complete = matches!(existing, Type::Struct(s) if !s.fields.is_empty())
                    || matches!(existing, Type::Union(u) if !u.fields.is_empty());
                if existing_complete { return; }
            }
        }
        self.struct_types.insert(name, ty);
    }

    /// Register any tagged struct/union definitions nested inside a type so they
    /// resolve when later referenced standalone by tag — e.g. a `struct _ht {...}
    /// *ht;` member whose `struct _ht` is used elsewhere as a parameter type.
    fn register_nested_struct_defs(&mut self, ty: &AstType) -> Result<()> {
        match ty {
            AstType::Struct(s) => {
                if s.name.is_some() && s.fields.is_some() {
                    self.register_struct_type_from_def(s)?;
                }
                // Recurse into the body so deeper tagged definitions (even inside
                // anonymous structs/unions) are registered too.
                if let Some(fields) = &s.fields {
                    for f in fields { self.register_nested_struct_defs(&f.ty.ty)?; }
                }
            }
            AstType::Union(u) => {
                if u.name.is_some() && u.fields.is_some() {
                    self.register_union_type_from_def(u)?;
                }
                if let Some(fields) = &u.fields {
                    for f in fields { self.register_nested_struct_defs(&f.ty.ty)?; }
                }
            }
            AstType::Pointer { base, .. } | AstType::Array { base, .. } => {
                self.register_nested_struct_defs(&base.ty)?;
            }
            // An enum defined inline (e.g. `enum { LOC_NONE, ... } kind;` as a
            // struct field) contributes its constants to the enclosing scope.
            AstType::Enum(e) if e.variants.is_some() => {
                self.register_enum(e)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn register_struct_type_from_def(&mut self, s: &StructDef) -> Result<()> {
        if let (Some(name), Some(fields)) = (&s.name, &s.fields) {
            let mut ir_fields = Vec::new();
            let mut bitfields = Vec::new();
            let mut field_aligns = Vec::new();
            let mut any_bitfield = false;
            let mut any_align = false;
            for f in fields {
                self.register_nested_struct_defs(&f.ty.ty)?;
                let fname = f.name.clone().unwrap_or_default();
                let fty = lower_type(&f.ty, &self.struct_types, self.ptr_size)?;
                let bw = f.bit_width.as_ref().map(|e| eval_const_expr(e, &self.enum_consts).unwrap_or(0) as u32);
                if bw.is_some() { any_bitfield = true; }
                if f.align.is_some() { any_align = true; }
                ir_fields.push((fname, fty));
                bitfields.push(bw);
                field_aligns.push(f.align);
            }
            // sic struct reordering (sic.md §"Struct reordering"): place fields
            // largest-first (stable) to minimize padding, unless the struct opts
            // out (`packed`/`__order__`) or has bit-fields / member `aligned` /
            // type `aligned` overrides (whose layout we leave exactly as written).
            let layout_order = if self.sic && !s.keep_order && !any_bitfield
                && !any_align && s.align.is_none()
            {
                let ps = self.ptr_size;
                let mut order: Vec<usize> = (0..ir_fields.len()).collect();
                order.sort_by(|&a, &b| ir_fields[b].1.size_of(ps).cmp(&ir_fields[a].1.size_of(ps)));
                // Only bother if it actually changes the order.
                if order.iter().enumerate().any(|(i, &o)| i != o) { Some(order) } else { None }
            } else {
                None
            };
            let ir_ty = Type::Struct(StructType {
                name: Some(name.clone()),
                fields: ir_fields,
                packed: false,
                bitfields: if any_bitfield { bitfields } else { Vec::new() },
                field_aligns: if any_align { field_aligns } else { Vec::new() },
                min_align: s.align,
                layout_order,
            });
            self.register_type_name(name.clone(), ir_ty);
        }
        Ok(())
    }

    fn register_union_type_from_def(&mut self, u: &UnionDef) -> Result<()> {
        if let (Some(name), Some(fields)) = (&u.name, &u.fields) {
            let mut ir_fields = Vec::new();
            let mut field_aligns = Vec::new();
            let mut any_align = false;
            for f in fields {
                self.register_nested_struct_defs(&f.ty.ty)?;
                let fname = f.name.clone().unwrap_or_default();
                let fty = lower_type(&f.ty, &self.struct_types, self.ptr_size)?;
                if f.align.is_some() { any_align = true; }
                ir_fields.push((fname, fty));
                field_aligns.push(f.align);
            }
            let ir_ty = Type::Union(UnionType {
                name: Some(name.clone()),
                fields: ir_fields,
                field_aligns: if any_align { field_aligns } else { Vec::new() },
                min_align: u.align,
            });
            self.register_type_name(name.clone(), ir_ty);
        }
        Ok(())
    }

    /// Emit `bytes` (already NUL-terminated) as a private, constant global and
    /// return a reference to it. Used for string-literal pointer initializers.
    fn add_cstring_global(&mut self, bytes: Vec<u8>) -> GlobalRef {
        let name = format!(".str.{}", self.module.globals.len());
        let len = bytes.len();
        let g = Global {
            name,
            ty: Type::Array { elem: Box::new(Type::i8()), len },
            init: Some(Constant::Bytes(bytes)),
            linkage: Linkage::Private,
            constant: true,
            thread_local: false,
        };
        self.module.add_global(g)
    }

    /// Synthesize (once per module) the native-string length helper
    /// `usize __sic_str_length(char* data, usize size)` — counts UTF-8 code
    /// points in `data[0..size]` (bytes where `(b & 0xC0) != 0x80`), sic.md
    /// §"Built-in string". Kept as its own function so a caller with several
    /// `.length` uses doesn't get multiple loops inlined (miscompiled at -O0).
    pub(crate) fn ensure_str_length_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_str_length") {
            return f;
        }
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let i8p = Type::char_ptr();
        let sig = FunctionType { ret: usize_ty.clone(), params: vec![i8p.clone(), usize_ty.clone()], variadic: false };
        let params = vec![
            sic_ir::Param { name: "data".to_string(), ty: i8p.clone() },
            sic_ir::Param { name: "size".to_string(), ty: usize_ty.clone() },
        ];
        let mut func = Function::new("__sic_str_length".to_string(), sig, params, Linkage::Internal);
        let entry_id = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry_id));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            // Spill the incoming params into stack slots and read them from memory
            // inside the loop — mirroring normal function lowering. Using the raw
            // entry-block param values across the loop back-edge miscompiles.
            let data_slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: data_slot, ty: i8p.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10000)), ptr: Val::Local(data_slot) });
            let size_slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: size_slot, ty: usize_ty.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10001)), ptr: Val::Local(size_slot) });
            // Zero-init i64 slots with a properly-widened zero: a bare
            // `Constant::int(0)` stores only 32 bits (leaving the high half of an
            // i64 slot as stack garbage), so coerce it to i64 first.
            let zero64 = fc.coerce(Constant::int(0), &Type::i64()).unwrap();
            let count = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: count, ty: Type::i64(), align: None });
            fc.push_instr(Instr::Store { val: zero64.clone(), ptr: Val::Local(count) });
            let i = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: i, ty: Type::i64(), align: None });
            fc.push_instr(Instr::Store { val: zero64, ptr: Val::Local(i) });

            let cond_bb = fc.new_block_after_current();
            let body_bb = fc.new_block_after_current();
            let end_bb = fc.new_block_after_current();
            fc.set_terminator(Terminator::Jump(cond_bb));

            // cond: i < size
            fc.switch_to_block(cond_bb);
            let iv = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: iv, ptr: Val::Local(i), ty: Type::i64() });
            let sz = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: sz, ptr: Val::Local(size_slot), ty: usize_ty.clone() });
            let sz = fc.coerce(Val::Local(sz), &Type::i64()).unwrap();
            let lt = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: lt, op: CmpOp::ISLt, lhs: Val::Local(iv), rhs: sz, ty: Type::i64() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(lt), then_bb: body_bb, else_bb: end_bb });

            let incr_bb = fc.new_block_after_current();
            let next_bb = fc.new_block_after_current();

            // body: if (data[i] & 0xC0) != 0x80 → count++ ; then i++
            fc.switch_to_block(body_bb);
            let iv2 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: iv2, ptr: Val::Local(i), ty: Type::i64() });
            let dp = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: dp, ptr: Val::Local(data_slot), ty: i8p.clone() });
            let bptr = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: bptr, base: Val::Local(dp), index: Val::Local(iv2), elem_size: 1, result_ty: i8p.clone() });
            let byte = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: byte, ptr: Val::Local(bptr), ty: Type::u8() });
            let byte_w = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: byte_w, op: CastOp::ZExt, val: Val::Local(byte), to_ty: Type::i32() });
            let masked = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: masked, op: BinOp::And, lhs: Val::Local(byte_w), rhs: Constant::int(0xC0), ty: Type::i32() });
            let is_cp = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_cp, op: CmpOp::INe, lhs: Val::Local(masked), rhs: Constant::int(0x80), ty: Type::i32() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_cp), then_bb: incr_bb, else_bb: next_bb });

            // incr: count += 1
            fc.switch_to_block(incr_bb);
            let cv = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: cv, ptr: Val::Local(count), ty: Type::i64() });
            let nc = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: nc, op: BinOp::Add, lhs: Val::Local(cv), rhs: Constant::int(1), ty: Type::i64() });
            fc.push_instr(Instr::Store { val: Val::Local(nc), ptr: Val::Local(count) });
            fc.set_terminator(Terminator::Jump(next_bb));

            // next: i += 1; loop
            fc.switch_to_block(next_bb);
            let iv3 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: iv3, ptr: Val::Local(i), ty: Type::i64() });
            let ni = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: ni, op: BinOp::Add, lhs: Val::Local(iv3), rhs: Constant::int(1), ty: Type::i64() });
            fc.push_instr(Instr::Store { val: Val::Local(ni), ptr: Val::Local(i) });
            fc.set_terminator(Terminator::Jump(cond_bb));

            // end: return count as usize
            fc.switch_to_block(end_bb);
            let r = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r, ptr: Val::Local(count), ty: Type::i64() });
            let r = fc.coerce(Val::Local(r), &usize_ty).unwrap();
            fc.set_terminator(Terminator::Ret(Some(r)));
        }
        self.module.add_function(func)
    }

    /// Synthesize `void __sic_str_retain(usize* rc)` — `if (rc) (*rc)++;`
    /// (sic.md §"Built-in string" refcounting). NULL rc is a no-op.
    pub(crate) fn ensure_str_retain_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_str_retain") {
            return f;
        }
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let rcp = Type::Pointer(Box::new(usize_ty.clone()));
        let sig = FunctionType { ret: Type::Void, params: vec![rcp.clone()], variadic: false };
        let params = vec![sic_ir::Param { name: "rc".to_string(), ty: rcp.clone() }];
        let mut func = Function::new("__sic_str_retain".to_string(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: slot, ty: rcp.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10000)), ptr: Val::Local(slot) });
            let r = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r, ptr: Val::Local(slot), ty: rcp.clone() });
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: Val::Local(r), rhs: Constant::zero(), ty: rcp.clone() });
            let body = fc.new_block_after_current();
            let done = fc.new_block_after_current();
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done, else_bb: body });
            fc.switch_to_block(body);
            let r2 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r2, ptr: Val::Local(slot), ty: rcp.clone() });
            let v = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: v, ptr: Val::Local(r2), ty: usize_ty.clone() });
            let one = fc.coerce(Constant::int(1), &usize_ty).unwrap();
            let v2 = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: v2, op: BinOp::Add, lhs: Val::Local(v), rhs: one, ty: usize_ty.clone() });
            fc.push_instr(Instr::Store { val: Val::Local(v2), ptr: Val::Local(r2) });
            fc.set_terminator(Terminator::Jump(done));
            fc.switch_to_block(done);
            fc.set_terminator(Terminator::Ret(None));
        }
        self.module.add_function(func)
    }

    /// Synthesize `void __sic_str_release(usize* rc)` —
    /// `if (rc && --(*rc)==0) free(rc);`. NULL rc is a no-op.
    pub(crate) fn ensure_str_release_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_str_release") {
            return f;
        }
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let rcp = Type::Pointer(Box::new(usize_ty.clone()));
        let voidp = Type::void_ptr();
        let free_fref = self.module.func_ref_by_name("free").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "free".to_string(),
                sig: FunctionType { ret: Type::Void, params: vec![voidp.clone()], variadic: false },
            })
        });
        let sig = FunctionType { ret: Type::Void, params: vec![rcp.clone()], variadic: false };
        let params = vec![sic_ir::Param { name: "rc".to_string(), ty: rcp.clone() }];
        let mut func = Function::new("__sic_str_release".to_string(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: slot, ty: rcp.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10000)), ptr: Val::Local(slot) });
            let r = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r, ptr: Val::Local(slot), ty: rcp.clone() });
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: Val::Local(r), rhs: Constant::zero(), ty: rcp.clone() });
            let body = fc.new_block_after_current();
            let free_bb = fc.new_block_after_current();
            let done = fc.new_block_after_current();
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done, else_bb: body });
            // body: n = *rc - 1; *rc = n; if (n==0) free(rc)
            fc.switch_to_block(body);
            let r2 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r2, ptr: Val::Local(slot), ty: rcp.clone() });
            let v = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: v, ptr: Val::Local(r2), ty: usize_ty.clone() });
            let one = fc.coerce(Constant::int(1), &usize_ty).unwrap();
            let n = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: n, op: BinOp::Sub, lhs: Val::Local(v), rhs: one, ty: usize_ty.clone() });
            fc.push_instr(Instr::Store { val: Val::Local(n), ptr: Val::Local(r2) });
            let zero = fc.coerce(Constant::int(0), &usize_ty).unwrap();
            let is_zero = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::IEq, lhs: Val::Local(n), rhs: zero, ty: usize_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_zero), then_bb: free_bb, else_bb: done });
            // free: free(rc)
            fc.switch_to_block(free_bb);
            let r3 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: r3, ptr: Val::Local(slot), ty: rcp.clone() });
            let p = fc.coerce(Val::Local(r3), &voidp).unwrap();
            fc.push_instr(Instr::Call { dest: None, func: free_fref, args: vec![p], ret_ty: Type::Void });
            fc.set_terminator(Terminator::Jump(done));
            fc.switch_to_block(done);
            fc.set_terminator(Terminator::Ret(None));
        }
        self.module.add_function(func)
    }

    /// Synthesize `void __sic_bounds_fail()` — write a message to stderr (fd 2)
    /// and `abort()` on a failed fat-pointer bounds check (sic.md §"Scopes and
    /// automatic release": "runtime exception").
    pub(crate) fn ensure_bounds_fail_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_bounds_fail") {
            return f;
        }
        let voidp = Type::void_ptr();
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let write_fref = self.module.func_ref_by_name("write").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "write".to_string(),
                sig: FunctionType { ret: Type::i64(), params: vec![Type::i32(), voidp.clone(), usize_ty.clone()], variadic: false },
            })
        });
        let abort_fref = self.module.func_ref_by_name("abort").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "abort".to_string(),
                sig: FunctionType { ret: Type::Void, params: vec![], variadic: false },
            })
        });
        let sig = FunctionType { ret: Type::Void, params: vec![], variadic: false };
        let mut func = Function::new("__sic_bounds_fail".to_string(), sig, vec![], Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let msg = "sic: fat-pointer bounds check failed\n";
            let ptr = fc.emit_cstring(msg);
            let ptr = fc.coerce(ptr, &voidp).unwrap();
            let len = fc.coerce(Constant::uint(msg.len() as u64), &usize_ty).unwrap();
            let two = fc.coerce(Constant::int(2), &Type::i32()).unwrap();
            fc.push_instr(Instr::Call { dest: None, func: write_fref, args: vec![two, ptr, len], ret_ty: Type::i64() });
            fc.push_instr(Instr::Call { dest: None, func: abort_fref, args: vec![], ret_ty: Type::Void });
            fc.set_terminator(Terminator::Ret(None)); // unreachable after abort
        }
        self.module.add_function(func)
    }

    /// Synthesize `void __sic_match_fail()` — write a message to stderr and
    /// `abort()` when a tagged-enum unwrap hits the wrong variant, or a `match`
    /// has no arm for the runtime tag (sic.md §"Match").
    pub(crate) fn ensure_match_fail_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_match_fail") {
            return f;
        }
        let voidp = Type::void_ptr();
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let write_fref = self.module.func_ref_by_name("write").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "write".to_string(),
                sig: FunctionType { ret: Type::i64(), params: vec![Type::i32(), voidp.clone(), usize_ty.clone()], variadic: false },
            })
        });
        let abort_fref = self.module.func_ref_by_name("abort").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "abort".to_string(),
                sig: FunctionType { ret: Type::Void, params: vec![], variadic: false },
            })
        });
        let sig = FunctionType { ret: Type::Void, params: vec![], variadic: false };
        let mut func = Function::new("__sic_match_fail".to_string(), sig, vec![], Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let msg = "sic: no match / wrong enum variant\n";
            let ptr = fc.emit_cstring(msg);
            let ptr = fc.coerce(ptr, &voidp).unwrap();
            let len = fc.coerce(Constant::uint(msg.len() as u64), &usize_ty).unwrap();
            let two = fc.coerce(Constant::int(2), &Type::i32()).unwrap();
            fc.push_instr(Instr::Call { dest: None, func: write_fref, args: vec![two, ptr, len], ret_ty: Type::i64() });
            fc.push_instr(Instr::Call { dest: None, func: abort_fref, args: vec![], ret_ty: Type::Void });
            fc.set_terminator(Terminator::Ret(None)); // unreachable after abort
        }
        self.module.add_function(func)
    }

    /// Synthesize `void __sic_trap()` — an uncaught sic exception (integer
    /// overflow or `÷0` inside `unsafe`, sic.md §"Errors and exceptions"): write a
    /// message to stderr and `abort()` (SIGABRT / exit 134).
    pub(crate) fn ensure_trap_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_trap") {
            return f;
        }
        let voidp = Type::void_ptr();
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let write_fref = self.module.func_ref_by_name("write").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "write".to_string(),
                sig: FunctionType { ret: Type::i64(), params: vec![Type::i32(), voidp.clone(), usize_ty.clone()], variadic: false },
            })
        });
        let abort_fref = self.module.func_ref_by_name("abort").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "abort".to_string(),
                sig: FunctionType { ret: Type::Void, params: vec![], variadic: false },
            })
        });
        let sig = FunctionType { ret: Type::Void, params: vec![], variadic: false };
        let mut func = Function::new("__sic_trap".to_string(), sig, vec![], Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let msg = "sic: arithmetic exception (overflow or divide-by-zero) in unsafe block\n";
            let ptr = fc.emit_cstring(msg);
            let ptr = fc.coerce(ptr, &voidp).unwrap();
            let len = fc.coerce(Constant::uint(msg.len() as u64), &usize_ty).unwrap();
            let two = fc.coerce(Constant::int(2), &Type::i32()).unwrap();
            fc.push_instr(Instr::Call { dest: None, func: write_fref, args: vec![two, ptr, len], ret_ty: Type::i64() });
            fc.push_instr(Instr::Call { dest: None, func: abort_fref, args: vec![], ret_ty: Type::Void });
            fc.set_terminator(Terminator::Ret(None)); // unreachable after abort
        }
        self.module.add_function(func)
    }

    /// Register the named type a declaration introduces (struct/union/enum/typedef)
    /// — used in the early pre-pass so generic-enum monomorphization can resolve
    /// user types in its arguments (sic.md §"Match"). Mirrors the main pass.
    fn register_type_decl_early(&mut self, decl: &Decl) -> Result<()> {
        match decl {
            Decl::TypeDef { names, .. } => {
                for (name, ty) in names {
                    self.register_nested_struct_defs(&ty.ty)?;
                    if let Ok(ir_ty) = lower_type(ty, &self.struct_types, self.ptr_size) {
                        match &ty.ty {
                            AstType::Struct(s) if s.name.is_some() && s.fields.is_some() =>
                                { self.struct_types.insert(s.name.clone().unwrap(), ir_ty.clone()); }
                            AstType::Union(u) if u.name.is_some() && u.fields.is_some() =>
                                { self.struct_types.insert(u.name.clone().unwrap(), ir_ty.clone()); }
                            AstType::Enum(e) => { self.register_enum(e)?; }
                            _ => {}
                        }
                        self.register_type_name(name.clone(), ir_ty);
                    }
                }
            }
            Decl::StructDecl(s) | Decl::Var { base_ty: QualType { ty: AstType::Struct(s), .. }, .. } =>
                self.register_struct_type_from_def(s)?,
            Decl::UnionDecl(u) | Decl::Var { base_ty: QualType { ty: AstType::Union(u), .. }, .. } =>
                self.register_union_type_from_def(u)?,
            Decl::EnumDecl(e) | Decl::Var { base_ty: QualType { ty: AstType::Enum(e), .. }, .. } =>
                self.register_enum(e)?,
            _ => {}
        }
        Ok(())
    }

    fn register_enum(&mut self, e: &EnumDef) -> Result<()> {
        // A generic enum (`enum Option<T> {…}`) is a monomorphization template,
        // not a concrete type — store it and instantiate per `Option<int>` use.
        if self.sic && !e.type_params.is_empty() {
            if let Some(name) = &e.name {
                self.generic_enum_defs.insert(name.clone(), e.clone());
            }
            return Ok(());
        }
        if let Some(variants) = &e.variants {
            let mut counter = 0i64;
            for v in variants {
                let val = if let Some(init) = &v.value {
                    // Use the richer size-aware evaluator so enum values built from
                    // `sizeof(T)`, `offsetof(...)` and division (e.g. QEMU's `_IOR`
                    // / register-index enums) fold instead of erroring.
                    crate::lower::types::eval_const_size(init, &self.struct_types, self.ptr_size, &self.enum_consts)
                        // Fall back to the globals-aware evaluator so enum values
                        // built from `ARRAY_SIZE(global_array)` (= sizeof of a
                        // file-scope array) also fold — e.g. e1000e's NREADOPS.
                        .or_else(|| self.eval_const_int(init))
                        .ok_or_else(|| CompileError::new(format!("enum value for '{}' is not a constant", v.name)))?
                } else {
                    counter
                };
                self.enum_consts.insert(v.name.clone(), val);
                counter = val + 1;
            }
            // Publish the updated enum constants so subsequent array dimensions
            // (`T arr[SOME_ENUM_MAX]`) fold via the scope-less `lower_type` path.
            types::set_enum_consts(&self.enum_consts);

            // sic tagged enum (sic.md §"Match"): build its `{tag,union}` struct and
            // record each variant's tag + payload type so construction, match and
            // unwrap can find them. A payload-less enum is left as a plain C enum.
            if self.sic {
                if let Some(res) = types::tagged_enum_type(e, &self.struct_types, self.ptr_size) {
                    let struct_type = res?;
                    let ename = e.name.clone().ok_or_else(|| CompileError::new(
                        "sic tagged enum with payload variants must be named".to_string()))?;
                    let mut tvars = Vec::new();
                    for v in variants {
                        let tag = *self.enum_consts.get(&v.name).unwrap();
                        let payload = match &v.payload {
                            Some(p) => Some(types::lower_type(p, &self.struct_types, self.ptr_size)?),
                            None => None,
                        };
                        tvars.push(TaggedVariant { name: v.name.clone(), tag, payload });
                        self.variant_enum.insert(v.name.clone(), ename.clone());
                    }
                    // Register the struct under the enum name so `Option a` (an
                    // `AstType::Named`) resolves to the tagged representation.
                    self.struct_types.insert(ename.clone(), struct_type.clone());
                    self.enum_defs.insert(ename.clone(), TaggedEnum {
                        name: ename, struct_type, variants: tvars,
                    });
                }
            }
        }
        Ok(())
    }

    /// Instantiate every generic-enum use in the unit (sic.md §"Match"). Collects
    /// all `AstType::Generic` spellings (inner args before outer, so nested
    /// `Option<Option<int>>` register in order), then monomorphizes each.
    fn monomorphize_generics(&mut self, tu: &TranslationUnit) -> Result<()> {
        if self.generic_enum_defs.is_empty() { return Ok(()); }
        let mut uses: Vec<(String, Vec<QualType>)> = Vec::new();
        for d in &tu.decls { collect_generics_decl(d, &mut uses); }
        for (name, args) in uses {
            self.instantiate_generic_enum(&name, &args)?;
        }
        Ok(())
    }

    /// Monomorphize `name<args…>` into a concrete tagged enum registered under its
    /// mangled name (`Option<i32>`), reusing the ordinary tagged-enum machinery.
    /// Idempotent; returns the concrete struct type.
    fn instantiate_generic_enum(&mut self, name: &str, args: &[QualType]) -> Result<Type> {
        let mut arg_tys = Vec::new();
        for a in args {
            arg_tys.push(types::lower_type(a, &self.struct_types, self.ptr_size)?);
        }
        let mangled = types::generic_enum_mangled(name, &arg_tys);
        if let Some(t) = self.struct_types.get(&mangled) { return Ok(t.clone()); }
        let template = self.generic_enum_defs.get(name).cloned().ok_or_else(|| {
            CompileError::new(format!("unknown generic enum '{}'", name))
        })?;
        if template.type_params.len() != args.len() {
            return Err(CompileError::new(format!(
                "generic enum '{}' expects {} type argument(s), got {}",
                name, template.type_params.len(), args.len())));
        }
        let mut subst: HashMap<String, AstType> = HashMap::new();
        for (p, a) in template.type_params.iter().zip(args) {
            subst.insert(p.clone(), a.ty.clone());
        }
        let variants = template.variants.as_ref().map(|vs| {
            vs.iter().map(|v| EnumVariant {
                name: v.name.clone(),
                value: v.value.clone(),
                payload: v.payload.as_ref().map(|p| QualType {
                    ty: subst_ast_type(&p.ty, &subst),
                    qualifiers: p.qualifiers.clone(),
                    storage: p.storage.clone(),
                }),
                span: v.span.clone(),
            }).collect()
        });
        let concrete = EnumDef {
            name: Some(mangled.clone()), variants, packed: template.packed,
            type_params: Vec::new(), span: template.span.clone(),
        };
        self.register_enum(&concrete)?;
        self.struct_types.get(&mangled).cloned().ok_or_else(|| {
            CompileError::new(format!("failed to instantiate generic enum '{}'", name))
        })
    }

    fn lower_translation_unit(&mut self, tu: &TranslationUnit) -> Result<()> {
        // All enums are registered by now; make them available to array-size
        // folding in the global-lowering pass.
        types::set_enum_consts(&self.enum_consts);
        for decl in &tu.decls {
            self.lower_global_decl(decl)?;
        }
        Ok(())
    }

    fn lower_global_decl(&mut self, decl: &Decl) -> Result<()> {
        match decl {
            Decl::Func { name, ret_ty, params, variadic, body: Some(body), storage, inline, constructor, .. } => {
                if *inline && !self.emit_inline.contains(name) { return Ok(()); }
                self.lower_function(name, ret_ty, params, *variadic, body, storage, *inline, *constructor)?;
            }
            Decl::Func { body: None, .. } => {
                // Already handled in collect_declarations
            }
            Decl::Var { base_ty, declarators, weak, thread_local, .. } => {
                // Check for struct/union/enum definitions within the base type
                match &base_ty.ty {
                    AstType::Struct(s) => { self.register_struct_type_from_def(s)?; }
                    AstType::Union(u)  => { self.register_union_type_from_def(u)?; }
                    AstType::Enum(e)   => { self.register_enum(e)?; }
                    _ => {}
                }
                for d in declarators {
                    self.lower_global_var(d, base_ty, *weak, *thread_local)?;
                }
            }
            Decl::TypeDef { names, .. } => {
                for (name, ty) in names {
                    if let Ok(ir_ty) = lower_type(ty, &self.struct_types, self.ptr_size) {
                        // Also register named struct/union by their own name
                        match &ty.ty {
                            AstType::Struct(s) if s.name.is_some() && s.fields.is_some() => {
                                self.struct_types.insert(s.name.clone().unwrap(), ir_ty.clone());
                            }
                            AstType::Union(u) if u.name.is_some() && u.fields.is_some() => {
                                self.struct_types.insert(u.name.clone().unwrap(), ir_ty.clone());
                            }
                            AstType::Enum(e) => { self.register_enum(e)?; }
                            _ => {}
                        }
                        self.register_type_name(name.clone(), ir_ty);
                    }
                }
            }
            Decl::StructDecl(s) => { self.register_struct_type_from_def(s)?; }
            Decl::UnionDecl(u)  => { self.register_union_type_from_def(u)?; }
            Decl::EnumDecl(e)   => { self.register_enum(e)?; }
            Decl::ExprStmt(_, _) => {
                // Top-level expression statements — deferred to fake_main synthesis
            }
            // `module x;` handled in collect_declarations; `import` in a later pass.
            Decl::Module(_, _) | Decl::Import { .. } => {}
        }
        Ok(())
    }

    fn lower_global_var(&mut self, d: &Declarator, base_ty: &QualType, weak: bool, thread_local: bool) -> Result<()> {
        let mut ir_ty = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        // An array dimension that `lower_type` couldn't fold (it has no global
        // symbol table) is re-evaluated with the global-aware evaluator, so
        // `T a[ARRAY_SIZE(g)]` — `sizeof(g)/sizeof(g[0])` over another global —
        // gets its real length instead of 0. QEMU's tcg.c sizes
        // `all_cts[ARRAY_SIZE(constraint_sets)][...]` this way; a 0 made the
        // array 1 byte and process_constraint_sets scribbled over neighbours.
        self.resolve_global_array_dims(&mut ir_ty, &d.ty.ty);
        // A declaration whose type is a function (e.g. `static Handler foo;` where
        // `Handler` is a function typedef) is a function prototype, not a variable.
        // Register it as an extern function so the real definition can supply it.
        if let Type::Function(ft) = &ir_ty {
            if self.module.func_ref_by_name(&d.name).is_none() {
                self.module.add_extern(ExternFunc { name: d.name.clone(), sig: (**ft).clone() });
            }
            return Ok(());
        }
        // Reserve the global's ref and register it BEFORE building the
        // initializer, so a self-referential static initializer resolves — e.g.
        // QEMU's `QTAILQ_HEAD_INITIALIZER(list)` sets `list.tqh_circ.tql_prev =
        // &list.tqh_circ`. Without this the self-pointer serializes to NULL and
        // the first list insert dereferences it (SIGSEGV).
        if !self.globals_map.contains_key(&d.name) {
            let placeholder_linkage = match base_ty.storage {
                Some(StorageClass::Static) => Linkage::Internal,
                Some(StorageClass::Extern) => Linkage::Import,
                _ if weak => Linkage::Weak,
                _ => Linkage::External,
            };
            let g = Global {
                name: d.name.clone(), ty: ir_ty.clone(), init: None,
                linkage: placeholder_linkage, constant: type_is_const(&d.ty),
                thread_local,
            };
            let gref = self.module.add_global(g);
            self.globals_map.insert(d.name.clone(), (ir_ty.clone(), gref));
        }
        let init = self.build_global_init(d, &mut ir_ty);
        // If already declared, a definition must upgrade a prior `extern`
        // declaration — otherwise the definition is dropped and the symbol left
        // undefined at link time. This covers both a real initializer (`extern
        // const T arr[];` then `const T arr[] = {...}`) and a *tentative*
        // definition — a non-`extern` file-scope declaration with no initializer
        // (`extern int g;` from a header, then `int g;` in the .c), which C makes
        // a zero-initialized (bss) definition. QEMU's `error_abort`,
        // `trace_events_enabled_count`, etc. are declared exactly this way.
        let new_is_definition =
            init.is_some() || !matches!(base_ty.storage, Some(StorageClass::Extern));
        if let Some((_, gref)) = self.globals_map.get(&d.name).cloned() {
            let existing = &self.module.globals[gref.0 as usize];
            let existing_is_decl = existing.init.is_none() || existing.linkage == Linkage::Import;
            if new_is_definition && existing_is_decl {
                let new_linkage = match base_ty.storage {
                    Some(StorageClass::Static) => Linkage::Internal,
                    _ if weak => Linkage::Weak,
                    _ => Linkage::External,
                };
                let constant = type_is_const(&d.ty);
                // If the prior declaration carried a larger explicit array size
                // (e.g. `extern T a[N];` then a sparse `T a[] = { [i]=... }`), keep
                // the larger so every valid index stays in bounds.
                if let (Type::Array { len: nl, .. }, Type::Array { len: el, .. }) =
                    (&mut ir_ty, &existing.ty)
                {
                    if *el > *nl { *nl = *el; }
                }
                let g = &mut self.module.globals[gref.0 as usize];
                g.ty = ir_ty.clone();
                g.init = init;
                g.linkage = new_linkage;
                g.constant = constant;
                self.globals_map.insert(d.name.clone(), (ir_ty, gref));
            }
            return Ok(());
        }
        let linkage = match base_ty.storage {
            Some(StorageClass::Static) => Linkage::Internal,
            // `extern T x;` with no initializer is a pure declaration: the
            // object lives in another translation unit (e.g. libc's `stdout`).
            // Emit it as an import so we don't shadow it with a zero definition.
            Some(StorageClass::Extern) if init.is_none() => Linkage::Import,
            // A `__attribute__((weak))` definition merges with duplicates across
            // objects (e.g. QEMU's `global_qtest` in libqtest-single.h, included
            // by every qtest binary's translation units).
            _ if weak => Linkage::Weak,
            Some(StorageClass::Extern) => Linkage::External,
            _ => Linkage::External,
        };
        let ty_for_map = ir_ty.clone();
        let g = Global { name: d.name.clone(), ty: ir_ty, init, linkage, constant: type_is_const(&d.ty), thread_local };
        let gref = self.module.add_global(g);
        self.globals_map.insert(d.name.clone(), (ty_for_map, gref));
        Ok(())
    }

    /// Create an internal global backing a function-scope `static` local, and
    /// return its type and ref. Uses the same constant-initializer serialization
    /// as file-scope globals; the caller binds the local name to this global.
    fn add_static_local_global(&mut self, name: String, d: &Declarator, _base_ty: &QualType) -> Result<(Type, GlobalRef)> {
        let mut ir_ty = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        let init = self.build_global_init(d, &mut ir_ty);
        let ty_for_map = ir_ty.clone();
        let g = Global { name, ty: ir_ty, init, linkage: Linkage::Internal, constant: type_is_const(&d.ty), thread_local: false };
        let gref = self.module.add_global(g);
        Ok((ty_for_map, gref))
    }

    /// Infer the length of an incomplete-size array from its brace initializer,
    /// honoring designated indices (`[i] = ...`, `[lo ... hi] = ...`) which can
    /// reach past the positional element count. Mirrors the C cursor semantics:
    /// an index designator sets the cursor, each element then advances it.
    /// If `ir_ty` is a struct whose last member is a flexible array (`T arr[]`,
    /// length 0) and the brace initializer supplies elements for it, replace
    /// `ir_ty` with an extended struct type whose final member is sized to the
    /// initializer's element count. Without this the object's size excludes the
    /// trailing elements and serialization writes out of bounds → the whole
    /// aggregate is zero-filled (QEMU's `QemuOptsList { ...; QemuOptDesc desc[]; }`).
    fn size_flexible_array_member(&self, ir_ty: &mut Type, items: &[InitItem]) {
        use crate::ast::Designator;
        let resolved = types::resolve_aggregate(ir_ty, &self.struct_types);
        let Type::Struct(st) = &resolved else { return };
        let Some(last_idx) = st.fields.len().checked_sub(1) else { return };
        let last_name = st.fields[last_idx].0.clone();
        if !matches!(&st.fields[last_idx].1, Type::Array { len: 0, .. }) { return; }
        // Find the initializer for the flexible member: a `.name = { ... }`
        // designator, or the positional element at the last field index.
        let flex = items.iter().enumerate().find_map(|(pos, it)| {
            match it.designators.first() {
                Some(Designator::Field(n)) if *n == last_name => Some(&it.init),
                None if pos == last_idx => Some(&it.init),
                _ => None,
            }
        });
        let Some(Initializer::List(sub)) = flex else { return };
        let n = self.infer_array_len(sub);
        if n == 0 { return; }
        let mut new_st = st.clone();
        if let Type::Array { len, .. } = &mut new_st.fields[last_idx].1 {
            *len = n;
        }
        *ir_ty = Type::Struct(new_st);
    }

    /// Walk an array type in parallel with its AST form and fill in any
    /// still-zero dimension by folding its size expression with the global-aware
    /// evaluator (`eval_const_int` resolves `sizeof(global)` via `const_expr_type`,
    /// which `lower_type`'s dimension pass — lacking the symbol table — cannot).
    fn resolve_global_array_dims(&self, ir_ty: &mut Type, ast_ty: &AstType) {
        if let (Type::Array { elem, len }, AstType::Array { base, size }) = (&mut *ir_ty, ast_ty) {
            if *len == 0 {
                if let Some(sz) = size {
                    if let Some(n) = self.eval_const_int(sz) {
                        if n > 0 { *len = n as usize; }
                    }
                }
            }
            self.resolve_global_array_dims(elem, &base.ty);
        }
    }

    fn infer_array_len(&self, items: &[InitItem]) -> usize {
        let mut cursor: usize = 0;
        let mut max_len: usize = 0;
        for item in items {
            match item.designators.first() {
                Some(Designator::Index(e)) => {
                    cursor = eval_const_expr(e, &self.enum_consts).unwrap_or(0).max(0) as usize;
                }
                Some(Designator::IndexRange(_, hi)) => {
                    cursor = eval_const_expr(hi, &self.enum_consts).unwrap_or(0).max(0) as usize;
                }
                // A field designator at array top level isn't valid C; treat the
                // element as positional.
                _ => {}
            }
            cursor += 1;
            max_len = max_len.max(cursor);
        }
        max_len
    }

    /// Serialize a variable's constant initializer to an IR `Constant`, adjusting
    /// `ir_ty` for inferred array lengths. Shared by file-scope globals and
    /// function-scope `static` locals.
    fn build_global_init(&mut self, d: &Declarator, ir_ty: &mut Type) -> Option<Constant> {
        // `char a[] = { "str" }` — a brace list wrapping a single string literal —
        // is equivalent to `char a[] = "str"` (C11 6.7.9p14). Rewrite to the bare
        // string initializer so it sizes/fills the array (QEMU's
        // `static const char eip_name[] = { "rip" };` otherwise came out empty).
        let target_is_char_array = matches!(&*ir_ty,
            Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }));
        if target_is_char_array {
            if let Some(inner) = unwrap_string_brace(d.init.as_ref()) {
                let d2 = Declarator { init: Some(Initializer::Expr(inner.clone())), ..d.clone() };
                return self.build_global_init(&d2, ir_ty);
            }
        }
        match &d.init {
            // sic `string g = "..."` at file scope: a `{ data, size }` slice
            // descriptor — pointer reloc to the cstring + the byte length.
            Some(Initializer::Expr(e))
                if types::is_sic_string(ir_ty) && matches!(&e.kind, ExprKind::StringLit(_)) =>
            {
                let ExprKind::StringLit(s) = &e.kind else { unreachable!() };
                let len = s.len();
                let mut bytes = s.clone().into_bytes();
                bytes.push(0); // NUL terminator
                let gref = self.add_cstring_global(bytes);
                let ps = self.ptr_size as usize;
                // { char* data; usize size; usize* rc } — data reloc, size, rc=NULL.
                let mut b = vec![0u8; ps * 3];
                let size_le = (len as u64).to_le_bytes();
                b[ps..ps * 2].copy_from_slice(&size_le[..ps]);
                Some(Constant::Aggregate { bytes: b, relocs: vec![(0, RelocTarget::Global(gref, 0))] })
            }
            // `char arr[] = "..."` / `char *p = "..."`.
            Some(Initializer::Expr(e)) if matches!(&e.kind, ExprKind::StringLit(_)) => {
                let ExprKind::StringLit(s) = &e.kind else { unreachable!() };
                let mut bytes = s.clone().into_bytes();
                bytes.push(0); // NUL terminator
                match &mut *ir_ty {
                    // Array target: store the bytes inline, sizing an
                    // unspecified length to fit the string.
                    Type::Array { len, .. } => {
                        if *len == 0 { *len = bytes.len(); }
                        Some(Constant::Bytes(bytes))
                    }
                    // Pointer target: emit the string as a private global and
                    // point at it.
                    _ => {
                        let gref = self.add_cstring_global(bytes);
                        Some(Constant::GlobalAddr(gref))
                    }
                }
            }
            Some(Initializer::Expr(e)) => {
                // Use the fuller integer evaluator (it also folds `sizeof(expr)` /
                // `offsetof` / `alignof` against global types), so a scalar global
                // like `const unsigned n = sizeof(arr)/sizeof(arr[0]);` gets a real
                // value instead of being left undefined.
                match self.eval_const_int(e).ok_or(()) {
                    Ok(v) => Some(Constant::Int(v)),
                    Err(_) => {
                        // A pointer global initialized with a symbolic address:
                        // another array/function name, `&x`, or a string.
                        if matches!(&*ir_ty, Type::Pointer(_)) {
                            if let Some(reloc) = self.eval_ptr_reloc(e) {
                                return match reloc {
                                    RelocTarget::Global(g, 0) => Some(Constant::GlobalAddr(g)),
                                    other => {
                                        let ps = self.ptr_size as usize;
                                        Some(Constant::Aggregate {
                                            bytes: vec![0u8; ps],
                                            relocs: vec![(0, other)],
                                        })
                                    }
                                };
                            }
                        }
                        match &e.kind {
                            ExprKind::FloatLit(f) => Some(Constant::Float(*f)),
                            ExprKind::Cast { expr: inner, .. } => {
                                if let ExprKind::FloatLit(f) = &inner.kind {
                                    Some(Constant::Float(*f))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                }
            }
            Some(Initializer::List(items)) => {
                // Infer an unspecified top-level array length from the brace list.
                // Designated initializers (`[i] = ...`) can place elements past the
                // positional count, so the length is the highest index reached, not
                // just `items.len()`.
                if let Type::Array { len, .. } = &mut *ir_ty {
                    if *len == 0 { *len = self.infer_array_len(items); }
                }
                // A struct ending in a flexible array member (`T arr[];`) whose
                // initializer supplies elements grows past its declared size;
                // size the member so the buffer and emitted symbol cover them
                // (QEMU's `QemuOptsList` ends in `QemuOptDesc desc[]`).
                self.size_flexible_array_member(ir_ty, items);
                let total = ir_ty.size_of(self.ptr_size) as usize;
                let ty_snapshot = ir_ty.clone();
                let init = d.init.as_ref().unwrap();
                let mut buf = vec![0u8; total.max(1)];
                let mut relocs = Vec::new();
                if self.serialize_const(init, &ty_snapshot, &mut buf, 0, &mut relocs) {
                    buf.truncate(total);
                    if relocs.is_empty() {
                        Some(Constant::Bytes(buf))
                    } else {
                        Some(Constant::Aggregate { bytes: buf, relocs })
                    }
                } else {
                    // Couldn't fully serialize as a constant; zero-fill rather
                    // than emit garbage.
                    Some(Constant::Zeroinit)
                }
            }
            _ => None,
        }
    }

    /// Recursively serialize `init` for a value of `ty` into `buf[base..]`,
    /// collecting pointer relocations for embedded symbol addresses. Returns
    /// false if some component isn't a translation-time constant.
    fn serialize_const(
        &mut self,
        init: &Initializer,
        ty: &Type,
        buf: &mut [u8],
        base: usize,
        relocs: &mut Vec<(usize, RelocTarget)>,
    ) -> bool {
        let ty = types::resolve_aggregate(ty, &self.struct_types);
        match &ty {
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => {
                // `char arr[] = "..."` inside a larger aggregate.
                if let (Type::Array { elem, .. }, Initializer::Expr(e)) = (&ty, init) {
                    if let ExprKind::StringLit(s) = &e.kind {
                        if elem.size_of(self.ptr_size) == 1 {
                            let mut bytes = s.clone().into_bytes();
                            bytes.push(0);
                            let n = bytes.len().min(buf.len().saturating_sub(base));
                            buf[base..base + n].copy_from_slice(&bytes[..n]);
                            return true;
                        }
                    }
                    return false;
                }
                let Initializer::List(items) = init else { return false };
                let items = expand_init_ranges(items, &self.enum_consts);
                let mut cursor = 0usize;
                for item in &items {
                    let (target, next) =
                        self.designated_const_target(&ty, &item.designators, cursor, base);
                    if let Some((off, leaf, bf)) = target {
                        if let Some(bf) = bf {
                            // Bit-field member: pack (RMW) so neighbours sharing
                            // the storage unit survive.
                            let e = match &item.init {
                                Initializer::Expr(e) => e,
                                Initializer::List(its) => match its.first() {
                                    Some(InitItem { init: Initializer::Expr(e), .. }) => e,
                                    _ => return false,
                                },
                            };
                            if !self.serialize_bitfield(e, &leaf, bf, buf, off) {
                                return false;
                            }
                        } else if !self.serialize_const(&item.init, &leaf, buf, off, relocs) {
                            return false;
                        }
                    }
                    cursor = next;
                }
                true
            }
            _ => {
                // Scalar leaf. A braced scalar (`{ x }`) is also accepted.
                let e = match init {
                    Initializer::Expr(e) => e,
                    Initializer::List(items) => match items.first() {
                        Some(InitItem { init: Initializer::Expr(e), .. }) => e,
                        _ => return false,
                    },
                };
                self.serialize_scalar(e, &ty, buf, base, relocs)
            }
        }
    }

    /// Resolve a global brace-list element's byte offset, leaf type and the next
    /// positional cursor — the constant-serialization analogue of
    /// `resolve_init_target`. Handles designators (including chained ones) and
    /// anonymous members.
    fn designated_const_target(&self, agg: &Type, designators: &[crate::ast::Designator], cursor: usize, base: usize)
        -> (Option<(usize, Type, Option<crate::lower::expr::BitField>)>, usize)
    {
        use crate::ast::Designator;
        type Tgt = (usize, Type, Option<crate::lower::expr::BitField>);
        let member_at = |me: &Self, agg: &Type, idx: usize, base: usize| -> Option<Tgt> {
            let r = types::resolve_aggregate(agg, &me.struct_types);
            match &r {
                Type::Struct(st) => {
                    let fty = st.fields.get(idx)?.1.clone();
                    if let Some(Some(width)) = st.bitfields.get(idx).copied() {
                        let (offs, bit_offs, _) = st.layout_full(me.ptr_size);
                        let bf = crate::lower::expr::BitField::new(*bit_offs.get(idx).unwrap_or(&0), width, fty.is_signed());
                        return Some((base + *offs.get(idx).unwrap_or(&0) as usize, fty, Some(bf)));
                    }
                    Some((base + st.field_offset(idx, me.ptr_size) as usize, fty, None))
                }
                Type::Union(u) => Some((base, u.fields.get(idx)?.1.clone(), None)),
                Type::Array { elem, len } => {
                    if *len > 0 && idx >= *len { return None; }
                    Some((base + idx * elem.size_of(me.ptr_size) as usize, (**elem).clone(), None))
                }
                _ => None,
            }
        };
        let (first, top_index) = match designators.first() {
            Some(Designator::Field(name)) => {
                match crate::lower::expr::resolve_field_access(agg, name, self.ptr_size, &self.struct_types) {
                    Some((foff, fty, bf)) => (Some((base + foff as usize, fty, bf)),
                                             crate::lower::func::top_field_index(agg, name, &self.struct_types)),
                    None => return (None, cursor + 1),
                }
            }
            Some(Designator::Index(e)) => {
                let i = eval_const_expr(e, &self.enum_consts).unwrap_or(0).max(0) as usize;
                (member_at(self, agg, i, base), i)
            }
            Some(Designator::IndexRange(..)) => unreachable!("ranges expanded before resolution"),
            None => (member_at(self, agg, cursor, base), cursor),
        };
        let Some((mut off, mut cur_ty, mut bf)) = first else { return (None, top_index + 1); };
        let rest = if designators.is_empty() { &designators[..] } else { &designators[1..] };
        for d in rest {
            match d {
                Designator::Field(name) => {
                    match crate::lower::expr::resolve_field_access(&cur_ty, name, self.ptr_size, &self.struct_types) {
                        Some((foff, fty, sub_bf)) => { off += foff as usize; cur_ty = fty; bf = sub_bf; }
                        None => return (None, top_index + 1),
                    }
                }
                Designator::Index(e) => {
                    let i = eval_const_expr(e, &self.enum_consts).unwrap_or(0).max(0) as usize;
                    let Some((o, t, sub_bf)) = member_at(self, &cur_ty, i, off) else { return (None, top_index + 1); };
                    off = o; cur_ty = t; bf = sub_bf;
                }
                Designator::IndexRange(..) => return (None, top_index + 1),
            }
        }
        (Some((off, cur_ty, bf)), top_index + 1)
    }

    /// Pack a bit-field's constant value into `buf` at byte offset `base` (the
    /// storage unit), read-modify-write so neighbouring bit-fields are preserved.
    fn serialize_bitfield(&self, e: &Expr, ty: &Type, bf: crate::lower::expr::BitField, buf: &mut [u8], base: usize) -> bool {
        let size = ty.size_of(self.ptr_size) as usize;
        if size == 0 || base + size > buf.len() { return false; }
        let v = match self.eval_const_int(e) { Some(v) => v as u64, None => return false };
        let field_mask: u64 = if bf.width >= 64 { !0 } else { (1u64 << bf.width) - 1 };
        let mut cur: u64 = 0;
        for i in 0..size { cur |= (buf[base + i] as u64) << (8 * i); }
        cur &= !(field_mask << bf.bit_offset);
        cur |= (v & field_mask) << bf.bit_offset;
        for i in 0..size { buf[base + i] = (cur >> (8 * i)) as u8; }
        true
    }

    /// Serialize a scalar constant expression into `buf[base..base+size]`.
    fn serialize_scalar(
        &mut self,
        e: &Expr,
        ty: &Type,
        buf: &mut [u8],
        base: usize,
        relocs: &mut Vec<(usize, RelocTarget)>,
    ) -> bool {
        let size = ty.size_of(self.ptr_size) as usize;
        if size == 0 || base + size > buf.len() { return false; }
        match ty {
            Type::Float32 => match self.eval_const_float(e) {
                Some(f) => { buf[base..base + 4].copy_from_slice(&(f as f32).to_le_bytes()); true }
                None => false,
            },
            Type::Float64 | Type::Float80 => match self.eval_const_float(e) {
                Some(f) => { buf[base..base + 8].copy_from_slice(&f.to_le_bytes()); true }
                None => false,
            },
            Type::Pointer(_) => {
                if let Some(reloc) = self.eval_ptr_reloc(e) {
                    relocs.push((base, reloc));
                    return true;
                }
                // NULL or an integer cast to a pointer.
                match self.eval_const_int(e) {
                    Some(v) => { buf[base..base + size].copy_from_slice(&v.to_le_bytes()[..size]); true }
                    None => false,
                }
            }
            _ => match self.eval_const_int(e) {
                Some(v) => { buf[base..base + size].copy_from_slice(&v.to_le_bytes()[..size]); true }
                None => false,
            },
        }
    }

    /// Evaluate a constant integer expression, extending [`eval_const_expr`] with
    /// type-dependent operators (`sizeof`) that need the type table. Recurses so
    /// `sizeof(T)` nested in arithmetic still folds.
    fn eval_const_int(&self, e: &Expr) -> Option<i64> {
        // A cast to a narrower integer type truncates to that width and re-signs.
        // Handle it before the type-blind `eval_const_expr`, so `(uint32_t)-1`
        // folds to 0xFFFFFFFF instead of a 64-bit -1 — QEMU's DEFINE_PROP_UNSIGNED
        // stores `.defval.u = (uint32_t)_defval`, and a 0xFFFFFFFFFFFFFFFF default
        // (guest-phys-bits = -1) then failed QAPI's uint32 range check at boot.
        if let ExprKind::Cast { ty, expr } = &e.kind {
            let inner = self.eval_const_int(expr)?;
            return Some(match lower_type(ty, &self.struct_types, self.ptr_size) {
                Ok(t) => apply_int_cast(inner, &t),
                Err(_) => inner,
            });
        }
        if let Ok(v) = eval_const_expr(e, &self.enum_consts) {
            return Some(v);
        }
        match &e.kind {
            ExprKind::SizeofType(qt) => {
                lower_type(qt, &self.struct_types, self.ptr_size).ok()
                    .map(|t| t.size_of(self.ptr_size) as i64)
            }
            // `__alignof__(T)` / `_Alignof(T)` in a static initializer — e.g.
            // QEMU's OBJECT_DEFINE_TYPE `.instance_align = __alignof__(T)`. Without
            // this the field failed to fold and the WHOLE TypeInfo aggregate was
            // zero-filled, so `type_register_static` saw a NULL `.parent`.
            ExprKind::AlignofType(qt) => {
                lower_type(qt, &self.struct_types, self.ptr_size).ok()
                    .map(|t| t.align_of(self.ptr_size) as i64)
            }
            // `sizeof(expr)` — notably `ARRAY_SIZE(global_array)` in static
            // initializers, which needs the operand's (global) type.
            ExprKind::SizeofExpr(inner) => {
                self.const_expr_type(inner).map(|t| t.size_of(self.ptr_size) as i64)
            }
            ExprKind::AlignofExpr(inner) => {
                self.const_expr_type(inner).map(|t| t.align_of(self.ptr_size) as i64)
            }
            // `offsetof(...)` — so `offsetofend` (= offsetof + sizeof(member)) and
            // other offsetof-based enum values fold. Delegates to the size-aware
            // evaluator which knows the member layout.
            ExprKind::OffsetOf { .. } => {
                types::eval_const_size(e, &self.struct_types, self.ptr_size, &self.enum_consts)
            }
            ExprKind::Cast { expr, .. } => self.eval_const_int(expr),
            ExprKind::Unary { op: UnOpKind::Neg, expr } => self.eval_const_int(expr).map(|v| v.wrapping_neg()),
            ExprKind::Unary { op: UnOpKind::BitNot, expr } => self.eval_const_int(expr).map(|v| !v),
            ExprKind::Unary { op: UnOpKind::Not, expr } => self.eval_const_int(expr).map(|v| (v == 0) as i64),
            ExprKind::BinOp { op, lhs, rhs } => {
                let l = self.eval_const_int(lhs)?;
                let r = self.eval_const_int(rhs)?;
                Some(match op {
                    BinOpKind::Add => l.wrapping_add(r),
                    BinOpKind::Sub => l.wrapping_sub(r),
                    BinOpKind::Mul => l.wrapping_mul(r),
                    BinOpKind::Div => if r != 0 { l.wrapping_div(r) } else { 0 },
                    BinOpKind::Rem => if r != 0 { l.wrapping_rem(r) } else { 0 },
                    BinOpKind::Shl => l.wrapping_shl(r as u32),
                    BinOpKind::Shr => l.wrapping_shr(r as u32),
                    BinOpKind::BitAnd => l & r,
                    BinOpKind::BitOr => l | r,
                    BinOpKind::BitXor => l ^ r,
                    _ => return None,
                })
            }
            ExprKind::Ternary { cond, then, else_ } => {
                if self.eval_const_int(cond)? != 0 { self.eval_const_int(then) } else { self.eval_const_int(else_) }
            }
            _ => None,
        }
    }

    /// Best-effort type of a constant expression at file scope, using the global
    /// symbol table. Covers what `sizeof(expr)` / `_Alignof(expr)` in static
    /// initializers need — notably `sizeof(global_array)` for `ARRAY_SIZE`.
    fn const_expr_type(&self, e: &Expr) -> Option<Type> {
        match &e.kind {
            ExprKind::Ident(name) => self.globals_map.get(name).map(|(t, _)| t.clone())
                .or_else(|| self.global_types.get(name).cloned()),
            ExprKind::Index { base, .. } => {
                match types::resolve_aggregate(&self.const_expr_type(base)?, &self.struct_types) {
                    Type::Array { elem, .. } | Type::Pointer(elem) => Some(*elem),
                    _ => None,
                }
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr } => {
                // An array decays to a pointer, so `*arr` is its element type (like
                // `arr[0]`) — needed for `sizeof(*global_array)`.
                match types::resolve_aggregate(&self.const_expr_type(expr)?, &self.struct_types) {
                    Type::Pointer(t) | Type::Array { elem: t, .. } => Some(*t),
                    _ => None,
                }
            }
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name } => {
                let bt = types::resolve_aggregate(&self.const_expr_type(base)?, &self.struct_types);
                let bt = if let ExprKind::Arrow { .. } = &e.kind {
                    match bt { Type::Pointer(t) => types::resolve_aggregate(&t, &self.struct_types), other => other }
                } else { bt };
                crate::lower::expr::resolve_field_access(&bt, name, self.ptr_size, &self.struct_types)
                    .map(|(_, fty, _)| fty)
            }
            ExprKind::Cast { ty, .. } => lower_type(ty, &self.struct_types, self.ptr_size).ok(),
            ExprKind::StringLit(s) => Some(Type::Array {
                elem: Box::new(Type::Int { bits: 8, signed: true }),
                len: s.len() + 1,
            }),
            _ => None,
        }
    }

    /// Evaluate a constant floating-point expression.
    fn eval_const_float(&self, e: &Expr) -> Option<f64> {
        match &e.kind {
            ExprKind::FloatLit(f) => Some(*f),
            ExprKind::Unary { op: UnOpKind::Neg, expr } => self.eval_const_float(expr).map(|f| -f),
            ExprKind::Cast { expr, .. } => self.eval_const_float(expr),
            _ => eval_const_expr(e, &self.enum_consts).ok().map(|v| v as f64),
        }
    }

    /// Evaluate a constant expression producing a pointer to a symbol.
    fn eval_ptr_reloc(&mut self, e: &Expr) -> Option<RelocTarget> {
        match &e.kind {
            ExprKind::Cast { expr, .. } => self.eval_ptr_reloc(expr),
            // A constant-condition ternary selecting a pointer, e.g. QEMU's
            // `.out_rr = TCG_TARGET_HAS_x ? tgen_x : NULL` in the TCG outop tables.
            // Fold the condition and evaluate the taken branch (a NULL branch has
            // no reloc → the field stays 0). Without this the pointer field failed
            // to resolve and the whole static struct was zero-filled.
            ExprKind::Ternary { cond, then, else_ } => {
                let c = self.eval_const_int(cond)?;
                if c != 0 { self.eval_ptr_reloc(then) } else { self.eval_ptr_reloc(else_) }
            }
            ExprKind::StringLit(s) => {
                let mut bytes = s.clone().into_bytes();
                bytes.push(0);
                let g = self.add_cstring_global(bytes);
                Some(RelocTarget::Global(g, 0))
            }
            ExprKind::Unary { op: UnOpKind::Addr, expr } => self.addr_of_reloc(expr),
            // `_Generic(...)` in a static initializer: select the matching
            // association at compile time and evaluate it. QEMU's TCG `all_outop[]`
            // table is `[OP] = _Generic(outop_X, T: &outop_X.base)` — without this
            // every entry was NULL, so ld/st/etc. had no constraint set and TCG
            // register allocation read `all_cts[-1]` garbage on the first TB.
            ExprKind::Generic { controlling, assocs } => {
                let idx = self.select_generic_const(controlling, assocs)?;
                self.eval_ptr_reloc(&assocs[idx].1.clone())
            }
            // A compound literal in a static initializer (e.g. QEnumLookup's
            // `.array = (const char *const[]){ [i] = "..." }`): materialize it as a
            // private global and point at it. An array literal decays to its first
            // element's address.
            ExprKind::CompoundLiteral { ty, init } => {
                let gref = self.emit_compound_literal_global(ty, init)?;
                Some(RelocTarget::Global(gref, 0))
            }
            // A bare function or array name decays to its own address.
            ExprKind::Ident(name) => {
                if let Some(fref) = self.module.func_ref_by_name(name) {
                    return Some(RelocTarget::Func(fref));
                }
                if let Some((ty, gref)) = self.globals_map.get(name) {
                    if matches!(ty, Type::Array { .. }) {
                        return Some(RelocTarget::Global(*gref, 0));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Materialize a static compound literal `(T){...}` as a private, constant
    /// global and return its ref. Used when a compound literal appears in another
    /// global's initializer (it needs a real address to point at).
    fn emit_compound_literal_global(&mut self, ty: &QualType, items: &[InitItem]) -> Option<GlobalRef> {
        let mut ir_ty = lower_type(ty, &self.struct_types, self.ptr_size).ok()?;
        if let Type::Array { len, .. } = &mut ir_ty {
            if *len == 0 { *len = self.infer_array_len(items); }
        }
        let total = ir_ty.size_of(self.ptr_size) as usize;
        let init = Initializer::List(items.to_vec());
        let mut buf = vec![0u8; total.max(1)];
        let mut relocs = Vec::new();
        if !self.serialize_const(&init, &ir_ty, &mut buf, 0, &mut relocs) {
            return None;
        }
        buf.truncate(total);
        let constant = if relocs.is_empty() {
            Constant::Bytes(buf)
        } else {
            Constant::Aggregate { bytes: buf, relocs }
        };
        let name = format!(".compound.{}", self.module.globals.len());
        let g = Global { name, ty: ir_ty, init: Some(constant), linkage: Linkage::Private, constant: true, thread_local: false };
        Some(self.module.add_global(g))
    }

    /// Select the matching `_Generic` association at file scope (for static
    /// initializers): compare the controlling expression's type against each
    /// association type, falling back to the `default` association. Returns the
    /// chosen association index.
    fn select_generic_const(&self, controlling: &Expr, assocs: &[(Option<QualType>, Box<Expr>)]) -> Option<usize> {
        fn decay(t: Type) -> Type {
            match t {
                Type::Array { elem, .. } => Type::Pointer(elem),
                Type::Function(_) => Type::void_ptr(),
                other => other,
            }
        }
        let ctrl = decay(self.const_expr_type(controlling)?);
        let mut default_idx = None;
        for (i, (aty, _)) in assocs.iter().enumerate() {
            match aty {
                None => default_idx = Some(i),
                Some(qt) => {
                    if let Ok(at) = lower_type(qt, &self.struct_types, self.ptr_size) {
                        if types::type_matches_generic(&decay(at), &ctrl) {
                            return Some(i);
                        }
                    }
                }
            }
        }
        default_idx
    }

    /// Resolve `&expr` to a relocation target.
    fn addr_of_reloc(&mut self, e: &Expr) -> Option<RelocTarget> {
        if let ExprKind::Ident(name) = &e.kind {
            if let Some(fref) = self.module.func_ref_by_name(name) {
                return Some(RelocTarget::Func(fref));
            }
        }
        let (gref, off, _) = self.base_addr(e)?;
        Some(RelocTarget::Global(gref, off))
    }

    /// Resolve a constant lvalue expression to (global, byte offset, type).
    fn base_addr(&self, e: &Expr) -> Option<(GlobalRef, i64, Type)> {
        match &e.kind {
            ExprKind::Ident(name) => {
                let (ty, gref) = self.globals_map.get(name)?;
                Some((*gref, 0, ty.clone()))
            }
            ExprKind::Index { base, index } => {
                let (gref, off, bty) = self.base_addr(base)?;
                let elem = match types::resolve_aggregate(&bty, &self.struct_types) {
                    Type::Array { elem, .. } => *elem,
                    _ => return None,
                };
                let idx = eval_const_expr(index, &self.enum_consts).ok()?;
                let esize = elem.size_of(self.ptr_size) as i64;
                Some((gref, off + idx * esize, elem))
            }
            ExprKind::Field { base, name } => {
                let (gref, off, bty) = self.base_addr(base)?;
                let st = types::resolve_aggregate(&bty, &self.struct_types);
                let (foff, fty) = field_offset_by_name(&st, name, self.ptr_size)?;
                Some((gref, off + foff as i64, fty))
            }
            _ => None,
        }
    }

    /// Synthesize `int main() { ...; return <last>; }` for SIC files without main.
    /// Returns the value of the last top-level item (expr or var decl).
    fn synthesize_fake_main(&mut self, tu: &TranslationUnit) -> Result<()> {
        // Synthesize a `main` only for sic REPL-style inputs: files made up of
        // bare top-level expressions and/or variable declarations, with no
        // function definitions of their own. A normal C translation unit that
        // *defines* functions but happens to lack `main` is a library unit —
        // fabricating a `main` there causes "multiple definition of main" when
        // several such objects are linked together.
        // Fabricating a `main` is a sic-lang REPL convenience. A C translation
        // unit must have an explicit `main`; inventing one for a `.c` library unit
        // that merely lacks it (e.g. testfloat's data-only functionInfos.c) causes
        // "multiple definition of main" when several such objects are linked.
        if !self.repl_main { return Ok(()); }
        let defines_functions = tu.decls.iter()
            .any(|d| matches!(d, Decl::Func { body: Some(_), .. }));
        let has_content = tu.decls.iter().any(|d| !matches!(d, Decl::Func { .. }));
        if defines_functions || !has_content { return Ok(()); }

        let sig = FunctionType { ret: Type::i32(), params: vec![], variadic: false };
        let mut func = Function::new("main".to_string(), sig, vec![], Linkage::External);

        let entry_id = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry_id));

        let mut fc = func::FuncCtx::new_with_func(self, &mut func);

        let mut last_val: Val = Constant::zero();

        for decl in &tu.decls.clone() {
            match decl {
                Decl::ExprStmt(e, _) => {
                    last_val = fc.lower_expr(e)?;
                }
                Decl::Var { declarators, .. } => {
                    // Read the last global from this var decl
                    for d in declarators {
                        if let Some((ty, gref)) = fc.lowerer.globals_map.get(&d.name) {
                            let ty = ty.clone();
                            let gref = *gref;
                            let dest = fc.alloc_val();
                            fc.push_instr(Instr::Load { dest, ptr: Val::Global(gref), ty });
                            last_val = Val::Local(dest);
                        }
                    }
                }
                _ => {}
            }
        }

        let ret = fc.coerce(last_val, &Type::i32())?;
        fc.set_terminator(Terminator::Ret(Some(ret)));
        drop(fc);

        self.module.add_function(func);
        Ok(())
    }
}

/// Whether an object of this declared type belongs in read-only storage.
/// A `const` qualifier makes the object read-only; for arrays the qualification
/// applies to the element type, so `const char arr[]` is read-only but
/// `const char *arr[]` (array of pointers to const char) is writable.
fn type_is_const(qt: &QualType) -> bool {
    if qt.is_const() { return true; }
    if let AstType::Array { base, .. } = &qt.ty {
        return type_is_const(base);
    }
    false
}

/// Look up a struct/union field by name, returning its byte offset and type.
fn field_offset_by_name(st: &Type, name: &str, ptr_size: u32) -> Option<(u64, Type)> {
    match st {
        Type::Struct(s) => {
            let idx = s.fields.iter().position(|(n, _)| n == name)?;
            Some((s.field_offset(idx, ptr_size), s.fields[idx].1.clone()))
        }
        Type::Union(u) => {
            let (_, fty) = u.fields.iter().find(|(n, _)| n == name)?;
            Some((0, fty.clone()))
        }
        _ => None,
    }
}

/// Evaluate a constant expression (only literals and simple arithmetic).
/// Expand any leading GNU range designator `[lo ... hi]` in a brace-list into one
/// `Index` item per index. Ranges are (nearly) always the sole/first designator,
/// so only the first designator is expanded; the rest of the chain is preserved.
/// Non-range items are returned unchanged.
pub(crate) fn expand_init_ranges(items: &[InitItem], enum_consts: &HashMap<String, i64>) -> Vec<InitItem> {
    if !items.iter().any(|it| matches!(it.designators.first(), Some(Designator::IndexRange(..)))) {
        return items.to_vec();
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if let Some(Designator::IndexRange(lo, hi)) = item.designators.first() {
            let lo = eval_const_expr(lo, enum_consts).unwrap_or(0).max(0);
            let hi = eval_const_expr(hi, enum_consts).unwrap_or(lo);
            let rest = &item.designators[1..];
            let mut i = lo;
            while i <= hi {
                let mut ds = Vec::with_capacity(rest.len() + 1);
                ds.push(Designator::Index(Box::new(Expr::new(
                    ExprKind::IntLit(i, false), crate::lexer::Span::default()))));
                ds.extend(rest.iter().cloned());
                out.push(InitItem { designators: ds, init: item.init.clone() });
                i += 1;
            }
        } else {
            out.push(item.clone());
        }
    }
    out
}

/// Build an IR function signature applying the aggregate-return sret ABI: a
/// Struct/Union return prepends a hidden `Pointer(ret)` first parameter (the
/// caller-provided result slot). `ret` is preserved unchanged so call sites can
/// detect the ABI from the signature.
pub(crate) fn build_fn_sig(ret: Type, params: Vec<Type>, variadic: bool, ptr_size: u32) -> FunctionType {
    if ret_is_sret(&ret, ptr_size) {
        let mut ps = Vec::with_capacity(params.len() + 1);
        ps.push(Type::Pointer(Box::new(ret.clone())));
        ps.extend(params);
        FunctionType { ret, params: ps, variadic }
    } else {
        FunctionType { ret, params, variadic }
    }
}

/// Whether a return type uses the sret ABI (aggregate returned by value).
/// Linkage for a function definition. `static` is internal; an `inline`
/// definition is emitted internal too — sic does not truly inline, so each
/// translation unit keeps its own copy, and giving them external linkage makes
/// multiple TUs that use the same header inline (e.g. `_mm_shuffle_epi8`,
/// `_mm_aesimc_si128`) collide with "multiple definition" at link.
pub(crate) fn fn_linkage(storage: &Option<StorageClass>, inline: bool, declared_static: bool) -> Linkage {
    match storage {
        Some(StorageClass::Static) => Linkage::Internal,
        // A prior `static` declaration gives internal linkage even if this
        // definition omits the keyword (C11 6.2.2p5).
        _ if declared_static => Linkage::Internal,
        _ if inline => Linkage::Internal,
        _ => Linkage::External,
    }
}

pub(crate) fn ret_is_sret(ret: &Type, ptr_size: u32) -> bool {
    // Under System V, only a MEMORY-class aggregate (>16 bytes / x87 / unaligned)
    // is returned through the hidden result pointer; a small struct/union is
    // returned in registers (see sic_ir::abi). `vector_size` arrays keep the sret
    // path for now (ABI.md follow-up).
    sic_ir::abi::ret_in_memory(ret, ptr_size)
}

/// Apply an integer cast's truncation/re-signing to a folded constant: mask to
/// the target type's width, then sign- or zero-extend back to i64.
fn apply_int_cast(v: i64, ty: &Type) -> i64 {
    match ty {
        Type::Bool => (v != 0) as i64,
        Type::Int { bits, signed } if *bits < 64 => {
            let masked = (v as u64) & ((1u64 << *bits) - 1);
            if *signed {
                let sh = 64 - *bits;
                ((masked << sh) as i64) >> sh
            } else {
                masked as i64
            }
        }
        _ => v,
    }
}

/// If `init` is a brace list wrapping exactly one (undesignated) string literal
/// — `{ "str" }` — return that string-literal expression. C treats this as the
/// bare string initializer for a char array.
fn unwrap_string_brace(init: Option<&Initializer>) -> Option<&Expr> {
    if let Some(Initializer::List(items)) = init {
        return string_brace_items(items);
    }
    None
}

/// If `items` is `{ "str" }` (one undesignated string-literal element), return
/// its string-literal expression.
pub(super) fn string_brace_items(items: &[InitItem]) -> Option<&Expr> {
    if items.len() == 1 && items[0].designators.is_empty() {
        if let Initializer::Expr(e) = &items[0].init {
            if matches!(&e.kind, ExprKind::StringLit(_)) {
                return Some(e);
            }
        }
    }
    None
}

/// The array length (chars + NUL) for a `{ "str" }` char-array initializer.
pub(super) fn string_brace_len(items: &[InitItem]) -> Option<usize> {
    string_brace_items(items).and_then(|e| match &e.kind {
        ExprKind::StringLit(s) => Some(s.len() + 1),
        _ => None,
    })
}

pub fn eval_const_expr(e: &Expr, enum_consts: &HashMap<String, i64>) -> Result<i64> {
    match &e.kind {
        ExprKind::IntLit(v, _) => Ok(*v),
        // `__builtin_constant_p(x)` folds to 0 here (sic can't prove constness),
        // matching how `lower_call` lowers it. This lets a
        // `__builtin_constant_p(x) ? <fold> : <runtime>` ternary fold to its
        // runtime arm and drop the dead `<fold>` arm (QEMU's dup_const/tcg
        // macros whose dead arm ends in `qemu_build_not_reached_always()`).
        ExprKind::Call { func, .. }
            if matches!(&func.kind, ExprKind::Ident(n) if n == "__builtin_constant_p") =>
        {
            Ok(0)
        }
        ExprKind::UIntLit(v, _) => Ok(*v as i64),
        ExprKind::BoolLit(b) => Ok(*b as i64),
        ExprKind::CharLit(v) => Ok(*v as i64),
        ExprKind::Ident(name) => {
            enum_consts.get(name.as_str()).copied().ok_or_else(|| {
                CompileError::at(format!("'{}' is not a constant", name), None, 0, 0)
            })
        }
        ExprKind::Unary { op: UnOpKind::Neg, expr } => Ok(-eval_const_expr(expr, enum_consts)?),
        ExprKind::Unary { op: UnOpKind::BitNot, expr } => Ok(!eval_const_expr(expr, enum_consts)?),
        ExprKind::Unary { op: UnOpKind::Not, expr } => {
            Ok(if eval_const_expr(expr, enum_consts)? == 0 { 1 } else { 0 })
        }
        ExprKind::BinOp { op, lhs, rhs } => {
            // Short-circuit `&&`/`||`: a constant-false `&&` (or constant-true `||`)
            // folds even when the other operand is not constant. This is what makes
            // `if (kvm_enabled() && x)` — where `kvm_enabled()` is `(0)` in a
            // user-mode build — a dead branch, so its call to the (unstubbed)
            // `kvm_arch_get_supported_cpuid` is never emitted.
            if matches!(op, BinOpKind::LogAnd) {
                if eval_const_expr(lhs, enum_consts)? == 0 { return Ok(0); }
                return Ok(if eval_const_expr(rhs, enum_consts)? != 0 { 1 } else { 0 });
            }
            if matches!(op, BinOpKind::LogOr) {
                if eval_const_expr(lhs, enum_consts)? != 0 { return Ok(1); }
                return Ok(if eval_const_expr(rhs, enum_consts)? != 0 { 1 } else { 0 });
            }
            let l = eval_const_expr(lhs, enum_consts)?;
            let r = eval_const_expr(rhs, enum_consts)?;
            Ok(match op {
                BinOpKind::Add => l.wrapping_add(r),
                BinOpKind::Sub => l.wrapping_sub(r),
                BinOpKind::Mul => l.wrapping_mul(r),
                BinOpKind::Div if r != 0 => l / r,
                BinOpKind::Rem if r != 0 => l % r,
                BinOpKind::BitAnd => l & r,
                BinOpKind::BitOr  => l | r,
                BinOpKind::BitXor => l ^ r,
                BinOpKind::Shl    => l << (r & 63),
                BinOpKind::Shr    => l >> (r & 63),
                BinOpKind::Eq     => if l == r { 1 } else { 0 },
                BinOpKind::Ne     => if l != r { 1 } else { 0 },
                BinOpKind::Lt     => if l < r  { 1 } else { 0 },
                BinOpKind::Le     => if l <= r { 1 } else { 0 },
                BinOpKind::Gt     => if l > r  { 1 } else { 0 },
                BinOpKind::Ge     => if l >= r { 1 } else { 0 },
                BinOpKind::LogAnd => if l != 0 && r != 0 { 1 } else { 0 },
                BinOpKind::LogOr  => if l != 0 || r != 0 { 1 } else { 0 },
                _ => return Err(CompileError::new("non-constant expression")),
            })
        }
        ExprKind::Ternary { cond, then, else_ } => {
            if eval_const_expr(cond, enum_consts)? != 0 {
                eval_const_expr(then, enum_consts)
            } else {
                eval_const_expr(else_, enum_consts)
            }
        }
        // `__builtin_choose_expr(cond, a, b)` selects an arm at compile time from
        // the constant condition; the unchosen arm is discarded and never
        // evaluated. The condition here uses an *accurate* `__builtin_constant_p`
        // (see `choose_cond_const`), unlike the conservative always-0 above:
        // QEMU's MIN_CONST/MAX_CONST (BDRV_REQUEST_MAX_SECTORS default in
        // virtio_blk_properties) is `__builtin_choose_expr(__builtin_constant_p(a)
        // && ..., min, (void)0)` — a wrong 0 selects the un-foldable `(void)0`.
        ExprKind::ChooseExpr { cond, then, else_ } => {
            if choose_cond_const(cond, enum_consts) != 0 {
                eval_const_expr(then, enum_consts)
            } else {
                eval_const_expr(else_, enum_consts)
            }
        }
        ExprKind::Cast { expr, .. } => eval_const_expr(expr, enum_consts),
        _ => {
            let sp = &e.span;
            Err(CompileError::at("non-constant expression", sp.file.clone(), sp.line, sp.col))
        }
    }
}

/// Evaluate a `__builtin_choose_expr` condition at compile time, where
/// `__builtin_constant_p(E)` is accurate (1 iff E folds to a constant). This
/// differs from the top-level `eval_const_expr`, which conservatively folds
/// `__builtin_constant_p` to 0 so runtime-value `?:` selects its runtime arm.
fn choose_cond_const(e: &Expr, enum_consts: &HashMap<String, i64>) -> i64 {
    match &e.kind {
        ExprKind::Call { func, args }
            if matches!(&func.kind, ExprKind::Ident(n) if n == "__builtin_constant_p") =>
        {
            match args.first() {
                Some(a) if eval_const_expr(a, enum_consts).is_ok() => 1,
                _ => 0,
            }
        }
        ExprKind::BinOp { op: BinOpKind::LogAnd, lhs, rhs } =>
            (choose_cond_const(lhs, enum_consts) != 0 && choose_cond_const(rhs, enum_consts) != 0) as i64,
        ExprKind::BinOp { op: BinOpKind::LogOr, lhs, rhs } =>
            (choose_cond_const(lhs, enum_consts) != 0 || choose_cond_const(rhs, enum_consts) != 0) as i64,
        ExprKind::Unary { op: UnOpKind::Not, expr } =>
            (choose_cond_const(expr, enum_consts) == 0) as i64,
        ExprKind::ChooseExpr { cond, then, else_ } =>
            if choose_cond_const(cond, enum_consts) != 0 { choose_cond_const(then, enum_consts) }
            else { choose_cond_const(else_, enum_consts) },
        _ => eval_const_expr(e, enum_consts).unwrap_or(0),
    }
}

/// Determine which `inline` functions are reachable — and therefore must be
/// emitted — starting from the always-emitted roots (non-inline function bodies
/// and global-variable initializers) and following references transitively
/// through inline function bodies. Unreachable inline definitions are dropped,
/// which is what lets sic ignore the thousands of unused `extern __inline`
/// SIMD intrinsics pulled in by `<immintrin.h>` and friends.
fn compute_emitted_inlines(tu: &TranslationUnit) -> HashSet<String> {
    let mut inline_bodies: HashMap<&str, &Vec<Stmt>> = HashMap::new();
    for d in &tu.decls {
        if let Decl::Func { name, body: Some(b), inline: true, .. } = d {
            inline_bodies.insert(name.as_str(), b);
        }
    }
    if inline_bodies.is_empty() {
        return HashSet::new();
    }

    // Seed with everything referenced from always-emitted code.
    let mut worklist: Vec<String> = Vec::new();
    for d in &tu.decls {
        match d {
            Decl::Func { body: Some(b), inline: false, .. } => {
                for s in b { collect_stmt_names(s, &mut worklist); }
            }
            Decl::Var { declarators, .. } => {
                for decl in declarators {
                    if let Some(init) = &decl.init { collect_init_names(init, &mut worklist); }
                }
            }
            _ => {}
        }
    }

    // Transitively pull in referenced inline functions.
    let mut emitted: HashSet<String> = HashSet::new();
    while let Some(name) = worklist.pop() {
        if let Some(body) = inline_bodies.get(name.as_str()) {
            if emitted.insert(name) {
                for s in *body { collect_stmt_names(s, &mut worklist); }
            }
        }
    }
    emitted
}

fn collect_init_names(init: &Initializer, out: &mut Vec<String>) {
    match init {
        Initializer::Expr(e) => collect_expr_names(e, out),
        Initializer::List(items) => {
            for it in items {
                for d in &it.designators {
                    if let Designator::Index(e) | Designator::IndexRange(e, _) = d {
                        collect_expr_names(e, out);
                    }
                }
                collect_init_names(&it.init, out);
            }
        }
    }
}

/// The sic prelude's built-in generic enums (sic.md §"Match"): `Option<T>` and
/// `Result<T,E>`, so users get them without declaring `enum Option<T> {…}`.
fn blessed_enum_templates() -> Vec<EnumDef> {
    let named = |n: &str| QualType {
        ty: AstType::Named(n.to_string()), qualifiers: Vec::new(), storage: None,
    };
    let variant = |name: &str, payload: Option<QualType>| EnumVariant {
        name: name.to_string(), value: None, payload, span: crate::lexer::Span::default(),
    };
    vec![
        EnumDef {
            name: Some("Option".to_string()),
            variants: Some(vec![variant("Some", Some(named("T"))), variant("None", None)]),
            packed: false, type_params: vec!["T".to_string()], span: crate::lexer::Span::default(),
        },
        EnumDef {
            name: Some("Result".to_string()),
            variants: Some(vec![variant("Ok", Some(named("T"))), variant("Err", Some(named("E")))]),
            packed: false, type_params: vec!["T".to_string(), "E".to_string()], span: crate::lexer::Span::default(),
        },
    ]
}

// ─── generic-enum monomorphization collectors (sic.md §"Match") ────────────────

/// Substitute type parameters (bound to concrete `AstType`s) throughout a type,
/// e.g. `T` → `int`, `T*` → `int*`. Used to specialize a generic enum's payloads.
fn subst_ast_type(ty: &AstType, subst: &HashMap<String, AstType>) -> AstType {
    use AstType::*;
    match ty {
        Named(n) => subst.get(n).cloned().unwrap_or_else(|| ty.clone()),
        Pointer { base, quals } => Pointer {
            base: Box::new(QualType { ty: subst_ast_type(&base.ty, subst), qualifiers: base.qualifiers.clone(), storage: base.storage.clone() }),
            quals: quals.clone(),
        },
        Array { base, size } => Array {
            base: Box::new(QualType { ty: subst_ast_type(&base.ty, subst), qualifiers: base.qualifiers.clone(), storage: base.storage.clone() }),
            size: size.clone(),
        },
        Generic { name, args } => Generic {
            name: name.clone(),
            args: args.iter().map(|a| QualType { ty: subst_ast_type(&a.ty, subst), qualifiers: a.qualifiers.clone(), storage: a.storage.clone() }).collect(),
        },
        other => other.clone(),
    }
}

/// Collect every generic-enum instantiation `Name<args…>` in a type (inner args
/// pushed before the outer type, so nested instantiations register in order).
fn collect_generics_type(ty: &AstType, out: &mut Vec<(String, Vec<QualType>)>) {
    use AstType::*;
    match ty {
        Generic { name, args } => {
            for a in args { collect_generics_type(&a.ty, out); }
            out.push((name.clone(), args.clone()));
        }
        Pointer { base, .. } | Array { base, .. } => collect_generics_type(&base.ty, out),
        Function { ret, params, .. } => {
            collect_generics_type(&ret.ty, out);
            for p in params { collect_generics_type(&p.ty.ty, out); }
        }
        _ => {}
    }
}

fn collect_generics_decl(d: &Decl, out: &mut Vec<(String, Vec<QualType>)>) {
    match d {
        Decl::Var { base_ty, declarators, .. } => {
            collect_generics_type(&base_ty.ty, out);
            for dc in declarators { collect_generics_type(&dc.ty.ty, out); }
        }
        Decl::Func { ret_ty, params, body, .. } => {
            collect_generics_type(&ret_ty.ty, out);
            for p in params { collect_generics_type(&p.ty.ty, out); }
            if let Some(b) = body { for s in b { collect_generics_stmt(s, out); } }
        }
        Decl::TypeDef { names, .. } => { for (_, qt) in names { collect_generics_type(&qt.ty, out); } }
        _ => {}
    }
}

fn collect_generics_stmt(s: &Stmt, out: &mut Vec<(String, Vec<QualType>)>) {
    match s {
        Stmt::Decl(d) => collect_generics_decl(d, out),
        Stmt::Block(ss, _) | Stmt::Unsafe(ss, _) => for x in ss { collect_generics_stmt(x, out); },
        Stmt::Guard { binding, else_body, .. } => {
            if let Some((Some(ty), _)) = binding { collect_generics_type(&ty.ty, out); }
            collect_generics_stmt(else_body, out);
        }
        Stmt::If { then, else_, .. } => {
            collect_generics_stmt(then, out);
            if let Some(e) = else_ { collect_generics_stmt(e, out); }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::Switch { body, .. }
        | Stmt::Label(_, body, _) | Stmt::Default(body, _) | Stmt::Defer(body, _)
        | Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) => collect_generics_stmt(body, out),
        Stmt::For { init, body, .. } => {
            if let Some(crate::ast::ForInit::Decl(d)) = init { collect_generics_decl(d, out); }
            collect_generics_stmt(body, out);
        }
        Stmt::Match { arms, .. } => for a in arms { collect_generics_stmt(&a.body, out); },
        _ => {}
    }
}

fn collect_stmt_names(s: &Stmt, out: &mut Vec<String>) {
    match s {
        Stmt::Decl(d) => collect_decl_names(d, out),
        Stmt::Expr(e, _) => collect_expr_names(e, out),
        Stmt::Block(ss, _) => { for s in ss { collect_stmt_names(s, out); } }
        Stmt::If { cond, then, else_, .. } => {
            collect_expr_names(cond, out);
            collect_stmt_names(then, out);
            if let Some(e) = else_ { collect_stmt_names(e, out); }
        }
        Stmt::While { cond, body, .. } => { collect_expr_names(cond, out); collect_stmt_names(body, out); }
        Stmt::DoWhile { body, cond, .. } => { collect_stmt_names(body, out); collect_expr_names(cond, out); }
        Stmt::For { init, cond, post, body, .. } => {
            match init {
                Some(ForInit::Decl(d)) => collect_decl_names(d, out),
                Some(ForInit::Expr(e)) => collect_expr_names(e, out),
                None => {}
            }
            if let Some(e) = cond { collect_expr_names(e, out); }
            if let Some(e) = post { collect_expr_names(e, out); }
            collect_stmt_names(body, out);
        }
        Stmt::Return(Some(e), _) => collect_expr_names(e, out),
        Stmt::Label(_, body, _) => collect_stmt_names(body, out),
        Stmt::Case(e, body, _) => { collect_expr_names(e, out); collect_stmt_names(body, out); }
        Stmt::CaseRange(lo, hi, body, _) => {
            collect_expr_names(lo, out); collect_expr_names(hi, out); collect_stmt_names(body, out);
        }
        Stmt::Default(body, _) => collect_stmt_names(body, out),
        Stmt::Defer(body, _) => collect_stmt_names(body, out),
        Stmt::Delete(e, _) => collect_expr_names(e, out),
        Stmt::Switch { val, body, .. } => { collect_expr_names(val, out); collect_stmt_names(body, out); }
        Stmt::Match { scrutinee, arms, .. } => {
            collect_expr_names(scrutinee, out);
            for a in arms { collect_stmt_names(&a.body, out); }
        }
        Stmt::Unsafe(body, _) => { for s in body { collect_stmt_names(s, out); } }
        Stmt::Guard { binding, cond, else_body, .. } => {
            collect_expr_names(cond, out);
            if let Some((_, n)) = binding { out.push(n.clone()); }
            collect_stmt_names(else_body, out);
        }
        Stmt::Return(None, _) | Stmt::Break(_) | Stmt::Continue(_)
        | Stmt::Goto(_, _) | Stmt::Null(_) | Stmt::Fallthrough(_) => {}
    }
}

fn collect_decl_names(d: &Decl, out: &mut Vec<String>) {
    if let Decl::Var { declarators, .. } = d {
        for decl in declarators {
            if let Some(init) = &decl.init { collect_init_names(init, out); }
            // A `__attribute__((cleanup(fn)))` function is referenced only by the
            // cleanup emission, not by an Ident — record it so a `static inline`
            // cleanup (glib's `g_autoptr`) is still emitted.
            if let Some(f) = &decl.cleanup { out.push(f.clone()); }
        }
    }
}

fn collect_expr_names(e: &Expr, out: &mut Vec<String>) {
    use ExprKind::*;
    match &e.kind {
        Ident(name) => out.push(name.clone()),
        BinOp { lhs, rhs, .. } | Comma(lhs, rhs) => {
            collect_expr_names(lhs, out); collect_expr_names(rhs, out);
        }
        Assign { lhs, rhs, .. } | Swap { lhs, rhs } => { collect_expr_names(lhs, out); collect_expr_names(rhs, out); }
        Unary { expr, .. } | PreInc { expr, .. } | PostInc { expr, .. }
        | SizeofExpr(expr) | AlignofExpr(expr) => collect_expr_names(expr, out),
        Ternary { cond, then, else_ } => {
            collect_expr_names(cond, out); collect_expr_names(then, out); collect_expr_names(else_, out);
        }
        Elvis { cond, else_ } => { collect_expr_names(cond, out); collect_expr_names(else_, out); }
        ChooseExpr { cond, then, else_ } => {
            collect_expr_names(cond, out); collect_expr_names(then, out); collect_expr_names(else_, out);
        }
        Call { func, args } => {
            collect_expr_names(func, out);
            for a in args { collect_expr_names(a, out); }
        }
        Index { base, index } => { collect_expr_names(base, out); collect_expr_names(index, out); }
        Slice { base, lo, hi } => {
            collect_expr_names(base, out);
            if let Some(e) = lo { collect_expr_names(e, out); }
            if let Some(e) = hi { collect_expr_names(e, out); }
        }
        New { count, .. } => { if let Some(e) = count { collect_expr_names(e, out); } }
        Ref { expr, .. } => collect_expr_names(expr, out),
        Field { base, .. } | Arrow { base, .. } => collect_expr_names(base, out),
        Cast { expr, .. } => collect_expr_names(expr, out),
        Generic { controlling, assocs } => {
            collect_expr_names(controlling, out);
            for (_, e) in assocs { collect_expr_names(e, out); }
        }
        StmtExpr(stmts) => { for s in stmts { collect_stmt_names(s, out); } }
        CompoundLiteral { init, .. } => {
            for it in init {
                for d in &it.designators {
                    if let Designator::Index(e) | Designator::IndexRange(e, _) = d {
                        collect_expr_names(e, out);
                    }
                }
                collect_init_names(&it.init, out);
            }
        }
        VaStart { list, last } => { collect_expr_names(list, out); collect_expr_names(last, out); }
        VaArg { list, .. } => collect_expr_names(list, out),
        VaEnd { list } => collect_expr_names(list, out),
        VaCopy { dst, src } => { collect_expr_names(dst, out); collect_expr_names(src, out); }
        OffsetOf { designators, .. } => {
            for d in designators {
                if let OffsetDesignator::Index(e) = d { collect_expr_names(e, out); }
            }
        }
        TupleExpr(elems) => { for e in elems { collect_expr_names(e, out); } }
        Guard { body, .. } => { for s in body { collect_stmt_names(s, out); } }
        OptField { base, .. } => collect_expr_names(base, out),
        // `typeid(e)` inspects only the type — `e` is never evaluated.
        TypeId(_) => {}
        IntLit(..) | UIntLit(..) | BoolLit(_) | BigIntLit(_) | DecimalLit(_) | FloatLit(_) | StringLit(_) | CharLit(_) | Nullptr
        | SizeofType(_) | AlignofType(_) | TypesCompatible(..) | EnumVariant { .. } | TypeIdOf(_) => {}
    }
}
