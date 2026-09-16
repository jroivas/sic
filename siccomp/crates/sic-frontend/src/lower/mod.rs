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
    /// sic `atomic` globals (sic.md §"Atomics"): names of atomic-qualified globals.
    pub atomic_globals: std::collections::HashSet<String>,
    /// Known enum variant values
    pub enum_consts: HashMap<String, i64>,
    /// Named struct/union types
    pub struct_types: HashMap<String, Type>,
    /// Target pointer size in bytes
    pub ptr_size: u32,
    /// sic struct reordering (sic.md §"Struct reordering"): the global default mode
    /// from `-fstruct-order` (a per-struct `order_*` attribute overrides it).
    /// `StructOrder::Default` means "follow the language default" (Sic for `.sic`,
    /// C for C sources).
    pub struct_order_default: crate::ast::StructOrder,
    /// Process-wide seed for `order_random` layouts, shared by every TU in one
    /// build so they agree on field offsets (a `randstruct`-style build seed).
    pub struct_order_seed: u64,
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
    /// sic payload-less named enums (`enum vals { NONE, ONE, … }`): enum name →
    /// its `(variant, value)` list, for `enumvalue.str` → `"vals::ONE"`.
    pub c_enum_defs: HashMap<String, Vec<(String, i64)>>,
    /// Reverse index for a bare enum constant: variant name → owning payload-less
    /// enum name (so `ONE.str` knows it is a `vals`).
    pub c_enum_variant: HashMap<String, String>,
    /// sic strict enum typing (sic.md §"Enums"): `(function, param index)` → the
    /// param's payload-less enum name, so a call site can reject a plain `int` or a
    /// different enum passed without an explicit cast. Populated order-independently
    /// in a pre-pass over all function declarations.
    pub c_enum_param: HashMap<(String, usize), String>,
    /// sic bitfield params (sic.md §"Bitfields"): `(function, param index)` → the
    /// param's bitfield type, so a bare flag argument resolves against it (the IR
    /// type is a plain unsigned int, losing the nominal identity).
    pub bitfield_param: HashMap<(String, usize), String>,
    /// sic strict enum typing: function name → its payload-less enum return type, so
    /// `return <wrong>;` is rejected and a call's result classifies as that enum.
    pub c_enum_ret: HashMap<String, String>,
    /// sic struct methods (sic.md §"Memory safety" / §"Iterators"): `(struct name,
    /// method name)` → the mangled free-function name the method was hoisted to.
    /// Populated before lowering; `obj.method(args)` resolves through it.
    pub struct_methods: HashMap<(String, String), String>,
    /// sic namespaces (sic.md §"Namespace"): `(namespace, member)` → the mangled
    /// top-level symbol the member was flattened to, so `N::member` resolves.
    pub namespace_members: HashMap<(String, String), String>,
    /// sic module type export (sic.md §"Namespace"/§"Imports"): names of aggregate
    /// types *defined in this module*, in definition order, to publish in the
    /// manifest so consumers can name `mod::Type`. Excludes `private` ones.
    pub module_defined_types: Vec<String>,
    /// Type names marked `private` (module-internal), excluded from the manifest.
    pub private_types: std::collections::HashSet<String>,
    /// sic (sic.md §"Imports"): type/enum/struct names brought in from an *imported*
    /// module (via its manifest). When THIS unit is itself built as a module, these
    /// are excluded from its manifest — a module re-exports only what it defines, not
    /// its dependencies' symbols (a consumer imports those modules directly).
    pub imported_type_names: std::collections::HashSet<String>,
    /// sic (sic.md §"Imports"): a plain `import module;` makes the module's symbols
    /// (enums, generics) reachable ONLY as `module::name`; using such a name bare is
    /// an error. This maps each such name → its module. `import module::name` /
    /// `import module::*` removes the entry (brings the name into the global scope).
    pub qualified_only: HashMap<String, String>,
    /// sic: per imported module, the enum + generic-template names it contributes —
    /// so `import module::*` can un-gate all of them at once.
    pub module_ns_names: HashMap<String, Vec<String>>,
    /// sic (sic.md §"Memory safety"): struct name → its constructor's mangled free
    /// function `__sic_ctor_<S>(S* self)`, called when a local of that type is
    /// declared. Present only for structs that define `S()`.
    pub struct_ctor: HashMap<String, String>,
    /// sic: struct name → its destructor's mangled free function
    /// `__sic_dtor_<S>(S* self)`, called at scope exit. Present only for `~S()`.
    pub struct_dtor: HashMap<String, String>,
    /// sic (sic.md §"Memory safety"): struct name → the field names its destructor
    /// `del`s (its OWNED, refcounted fields). A managed-struct copy (`v = other`)
    /// retains exactly these — never a borrowed pointer field the dtor leaves alone.
    pub struct_owned_fields: HashMap<String, Vec<String>>,
    /// sic strict enum typing: a typedef alias for a payload-less enum → the
    /// canonical enum name (a key in `c_enum_defs`). Lets `typedef enum {…} E;` be
    /// type-checked as strictly as `enum E`. An anonymous enum's typedef name is its
    /// own canonical key.
    pub c_enum_alias: HashMap<String, String>,
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
    /// sic generic functions (sic.md §"Generics"): `name` → the un-lowered template
    /// `Decl::Func` (with its `type_params`). Kept out of ordinary lowering and
    /// monomorphized per concrete call (instantiation lands in a later step).
    pub generic_fn_defs: HashMap<String, crate::ast::Decl>,
    /// sic named parameters (sic.md §"Named parameters"): source function name →
    /// (fixed parameter names, is-variadic), so a call site can map `name = value`
    /// arguments to positions. An empty name marks a parameter whose name is unknown
    /// (e.g. an imported prototype), which only positional/variadic use can fill.
    pub fn_param_names: HashMap<String, (Vec<String>, bool)>,
    /// sic bitfields (sic.md §"Bitfields"): bitfield name → its member list, in
    /// declaration order, including `_` placeholders (a member's value is `1 <<
    /// index_in_this_list`). The list length is the flag capacity (bit count).
    pub bitfield_defs: HashMap<String, Vec<String>>,
    /// Reverse index: a bitfield member name → its owning bitfield, so a bare
    /// `Member` (not just `Bits::Member`) resolves. `_` holes are not recorded.
    pub bitfield_variant: HashMap<String, String>,
    /// sic lambdas (sic.md §"Lambdas"): monotonic counter for the synthetic name of
    /// each lifted captureless lambda (`__sic_lambda_<n>`).
    pub lambda_counter: u32,
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
            atomic_globals: std::collections::HashSet::new(),
            enum_consts: HashMap::new(),
            struct_types: HashMap::new(),
            ptr_size: 8, // assume 64-bit
            struct_order_default: crate::ast::StructOrder::Default,
            struct_order_seed: 0,
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
            c_enum_defs: HashMap::new(),
            c_enum_variant: HashMap::new(),
            c_enum_param: HashMap::new(),
            bitfield_param: HashMap::new(),
            c_enum_ret: HashMap::new(),
            c_enum_alias: HashMap::new(),
            struct_methods: HashMap::new(),
            namespace_members: HashMap::new(),
            module_defined_types: Vec::new(),
            imported_type_names: std::collections::HashSet::new(),
            qualified_only: HashMap::new(),
            module_ns_names: HashMap::new(),
            private_types: std::collections::HashSet::new(),
            struct_ctor: HashMap::new(),
            struct_dtor: HashMap::new(),
            struct_owned_fields: HashMap::new(),
            tuple_param_types: HashMap::new(),
            float_vararg_externs: HashSet::new(),
            type_info_globals: HashMap::new(),
            bitfield_defs: HashMap::new(),
            bitfield_variant: HashMap::new(),
            lambda_counter: 0,
            generic_enum_defs: HashMap::new(),
            generic_fn_defs: HashMap::new(),
            fn_param_names: HashMap::new(),
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

    /// Set the global struct-ordering default (`-fstruct-order`) and the build-wide
    /// random seed (`-fstruct-order-seed`). See sic.md §"Struct reordering".
    pub fn set_struct_order(&mut self, default: crate::ast::StructOrder, seed: u64) {
        self.struct_order_default = default;
        self.struct_order_seed = seed;
    }

    /// Resolve a struct's requested order mode against the global default and the
    /// language default (never returns `Default`).
    fn resolve_struct_order(&self, attr: &crate::ast::StructOrder) -> crate::ast::StructOrder {
        use crate::ast::StructOrder;
        match attr {
            StructOrder::Default => match &self.struct_order_default {
                StructOrder::Default => if self.sic { StructOrder::Sic } else { StructOrder::C },
                global => global.clone(),
            },
            explicit => explicit.clone(),
        }
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
        // sic struct methods (sic.md §"Memory safety" / §"Iterators"): hoist each
        // struct's member functions into ordinary free functions before lowering,
        // recording the method table. Only clones the unit when methods are present.
        let needs_rewrite = self.sic && tu.decls.iter().any(|d|
            decl_has_methods(d) || matches!(d, Decl::Namespace { .. }));
        let owned_tu: Option<TranslationUnit> = if needs_rewrite {
            let mut t = tu.clone();
            // Flatten namespaces first (they may contain structs with methods).
            self.flatten_namespaces(&mut t);
            self.hoist_struct_methods(&mut t);
            Some(t)
        } else { None };
        let tu: &TranslationUnit = owned_tu.as_ref().unwrap_or(tu);

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
            // Record which function params/returns are payload-less enums, so call
            // sites and `return` can enforce strict enum typing (sic.md §"Enums").
            self.collect_enum_signatures(tu);
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
        // sic module type export: publish this module's public aggregate types so a
        // consumer can name `mod::Type`. `private` types are withheld.
        if self.current_module.is_some() {
            let names = std::mem::take(&mut self.module_defined_types);
            for name in names {
                if self.private_types.contains(&name) { continue; }
                if let Some(ty) = self.struct_types.get(&name) {
                    if matches!(ty, Type::Struct(_) | Type::Union(_)) {
                        self.module.type_defs.push((name.clone(), ty.clone()));
                    }
                }
            }
            // A module re-exports only what IT defines — not symbols pulled in from
            // its own imports (those travel via `dep` chain-loading). `imp` filters
            // an imported name out of this module's manifest.
            let imp = |name: &str| self.imported_type_names.contains(name);
            // Public payload-less enums (their variants), for `mod::Enum::Variant`.
            for (ename, variants) in &self.c_enum_defs {
                if self.private_types.contains(ename) || imp(ename) { continue; }
                self.module.sic_enum_exports.push((ename.clone(), variants.clone()));
            }
            // Public tagged enums (variant tags + payload types). Generic-enum
            // monomorphs (`Option<i32>`) carry `<` in their name — skip those; a
            // consumer re-instantiates built-in generics itself.
            for (ename, info) in &self.enum_defs {
                if ename.contains('<') || self.private_types.contains(ename) || imp(ename) { continue; }
                let vs: Vec<(String, i64, Option<Type>)> = info.variants.iter()
                    .map(|v| (v.name.clone(), v.tag, v.payload.clone())).collect();
                self.module.sic_tagenum_exports.push((ename.clone(), vs));
            }
            // sic generic functions (sic.md §"Generics"): export each public
            // template's source text so a consumer re-instantiates it locally.
            // `static` templates are module-private.
            for decl in self.generic_fn_defs.values() {
                if let Decl::Func { storage, template_src: Some(src), .. } = decl {
                    if matches!(storage, Some(StorageClass::Static)) { continue; }
                    self.module.sic_generic_fn_exports.push(src.clone());
                }
            }
            // sic struct constructors/destructors (sic.md §"Memory safety"): publish
            // `(struct, symbol)` so a consumer's `new S()` / `del p` / scope-exit runs
            // the module's `S()` / `~S()`. The symbols are exported (see `in_module`).
            for (sname, sym) in &self.struct_ctor {
                if self.private_types.contains(sname) || imp(sname) { continue; }
                self.module.sic_struct_ctors.push((sname.clone(), sym.clone()));
            }
            for (sname, sym) in &self.struct_dtor {
                if self.private_types.contains(sname) || imp(sname) { continue; }
                self.module.sic_struct_dtors.push((sname.clone(), sym.clone()));
            }
            // Dependencies: the other modules this one imports, for chain-loading.
            let mut deps: Vec<String> = self.imported_modules.keys().cloned().collect();
            deps.sort();
            self.module.sic_module_deps = deps;
        }
        self.module.imported_links = std::mem::take(&mut self.imported_links);
        self.module.float_vararg_externs =
            std::mem::take(&mut self.float_vararg_externs).into_iter().collect();

        Ok(self.module)
    }

    /// Rename external, defined top-level functions/globals to `<module>_<name>`.
    /// `static` (Internal/Private) symbols and imports/externs keep their names.
    fn mangle_module_exports(&mut self, module: &str) {
        for f in &mut self.module.functions {
            // `main` is reserved by the C runtime and never mangled. Compiler runtime
            // helpers (`__sic_*`: the bigint/dict/… weak runtime) keep their stable
            // global names so a consumer that didn't prepend the runtime itself (e.g.
            // it only calls a `va_dict`-taking `std::Print`) resolves them from this
            // module's object; the weak copies dedupe at link.
            if f.linkage == Linkage::External
                && f.name != "main"
                && !f.name.starts_with("__sic_")
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
            // sic generic functions (sic.md §"Generics"): stash templates so they are
            // kept out of ordinary lowering and monomorphized per concrete call.
            if let Decl::Func { name, type_params, body: Some(_), .. } = decl {
                if !type_params.is_empty() {
                    self.generic_fn_defs.insert(name.clone(), decl.clone());
                }
            }
            // sic named parameters (sic.md §"Named parameters"): record each
            // function's parameter names + variadic flag, so a call site can bind
            // `name = value`. A definition's names win over a prior prototype's.
            if let Decl::Func { name, params, variadic, body, .. } = decl {
                let names: Vec<String> = params.iter()
                    .map(|p| p.name.clone().unwrap_or_default()).collect();
                let entry = self.fn_param_names.entry(name.clone());
                match entry {
                    std::collections::hash_map::Entry::Vacant(v) => { v.insert((names, *variadic)); }
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        // Prefer the definition (or any record with more real names).
                        if body.is_some() || o.get().0.iter().all(|n| n.is_empty()) {
                            o.insert((names, *variadic));
                        }
                    }
                }
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
                Decl::Func { name, ret_ty, params, variadic, body: None, is_async, .. } => {
                    // Forward declaration / extern. A struct/union/enum *defined*
                    // in the return type or a parameter (`struct S {..} *f(void)`)
                    // must be registered so its fields resolve later.
                    self.register_nested_struct_defs(&ret_ty.ty)?;
                    for p in params { self.register_nested_struct_defs(&p.ty.ty)?; }
                    let mut ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
                    if *is_async { ir_ret = types::task_type(&ir_ret); }
                    let ir_params: Result<Vec<_>> = params.iter().map(|p| {
                        lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
                    }).collect();
                    let sig = build_fn_sig(ir_ret, ir_params?, *variadic, self.ptr_size);
                    if self.module.func_ref_by_name(name).is_none() {
                        self.module.add_extern(ExternFunc { name: name.clone(), sig });
                    }
                }
                Decl::Func { name, ret_ty, params, variadic, body: Some(_), storage, inline, type_params, is_async, .. } => {
                    // sic generic template: not emitted directly; instantiated per call.
                    if !type_params.is_empty() { continue; }
                    // Skip unreferenced inline definitions (see `emit_inline`).
                    if *inline && !self.emit_inline.contains(name) { continue; }
                    // Register any struct/union/enum defined in the return type or
                    // parameters before lowering them.
                    self.register_nested_struct_defs(&ret_ty.ty)?;
                    for p in params { self.register_nested_struct_defs(&p.ty.ty)?; }
                    // Function definition — pre-register with empty body for stable FuncRef
                    let mut ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
                    // sic async: the signature returns `Task<ret>` (sic.md §"Async").
                    if *is_async { ir_ret = types::task_type(&ir_ret); }
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
                                AstType::Enum(e) => {
                                    self.register_enum(e)?;
                                    // sic strict enum typing (sic.md §"Enums"): link
                                    // this typedef alias to the payload-less enum so
                                    // `typedef enum {…} E;` is checked like `enum E`.
                                    self.register_c_enum_typedef(name, e);
                                }
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
                // sic bitfield (sic.md §"Bitfields"): `bitfield B {…};`.
                Decl::Var { base_ty: QualType { ty: AstType::Bitfield(b), .. }, .. } => {
                    self.register_bitfield(b)?;
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

    /// sic generic functions (sic.md §"Generics"): re-parse a generic-function
    /// template's source text (from a module manifest) back into declarations. A
    /// parse error yields nothing (the import simply won't offer that template).
    fn parse_generic_template(src: &str) -> Vec<Decl> {
        use crate::{lexer::Lexer, parser::Parser};
        let mut lexer = Lexer::new_lang(src, std::collections::HashSet::new(), crate::Lang::Sic);
        let tokens = match lexer.tokenize() { Ok(t) => t, Err(_) => return Vec::new() };
        let mut parser = Parser::new_lang(tokens, String::new(), crate::Lang::Sic);
        match parser.parse() {
            Ok(tu) => tu.decls,
            Err(_) => Vec::new(),
        }
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
            // sic module type export (sic.md §"Namespace"): register the module's
            // public aggregate types so the consumer can name `mod::Type` (which
            // resolves to the last segment) and bare `Type`.
            for (name, ty) in &manifest.types {
                self.struct_types.entry(name.clone()).or_insert_with(|| ty.clone());
                self.imported_type_names.insert(name.clone());
            }
            // Register imported payload-less enums so `mod::Enum::Variant` (and the
            // bare variant/`Enum::Variant` forms) resolve to their discriminants.
            for (ename, variants) in &manifest.enums {
                for (v, val) in variants {
                    self.enum_consts.entry(v.clone()).or_insert(*val);
                    self.c_enum_variant.entry(v.clone()).or_insert_with(|| ename.clone());
                }
                self.c_enum_defs.entry(ename.clone()).or_insert_with(|| variants.clone());
                self.imported_type_names.insert(ename.clone());
            }
            // Register imported tagged enums (rebuild their `{tag,union}` type +
            // variant table) so `mod::Enum::Variant(x)` and `match` work.
            for (ename, variants) in &manifest.tagenums {
                let payload_fields: Vec<(String, Type)> = variants.iter()
                    .filter_map(|(v, _, p)| p.clone().map(|t| (v.clone(), t))).collect();
                let data = Type::Union(sic_ir::UnionType {
                    name: None, fields: payload_fields, field_aligns: vec![], min_align: None });
                let struct_type = Type::Struct(sic_ir::StructType::plain(Some(ename.clone()), vec![
                    ("tag".to_string(), Type::Int { bits: 32, signed: true }),
                    ("data".to_string(), data),
                ], false));
                let tvars: Vec<TaggedVariant> = variants.iter()
                    .map(|(v, tag, p)| TaggedVariant { name: v.clone(), tag: *tag, payload: p.clone() })
                    .collect();
                for (v, tag, _) in variants {
                    self.variant_enum.entry(v.clone()).or_insert_with(|| ename.clone());
                    self.enum_consts.entry(v.clone()).or_insert(*tag);
                }
                self.struct_types.entry(ename.clone()).or_insert_with(|| struct_type.clone());
                self.enum_defs.entry(ename.clone()).or_insert(TaggedEnum {
                    name: ename.clone(), struct_type, variants: tvars });
                self.imported_type_names.insert(ename.clone());
            }
            // sic module struct ctor/dtor (sic.md §"Memory safety"): register the
            // module's `S()`/`~S()` symbols so the consumer's `new S()` / `del p` /
            // scope-exit cleanup calls them (the symbol is exported by the module;
            // `emit_cleanup_call` declares the extern on first use).
            for (sname, sym) in &manifest.struct_ctors {
                self.struct_ctor.entry(sname.clone()).or_insert_with(|| sym.clone());
                self.imported_type_names.insert(sname.clone());
            }
            for (sname, sym) in &manifest.struct_dtors {
                self.struct_dtor.entry(sname.clone()).or_insert_with(|| sym.clone());
                self.imported_type_names.insert(sname.clone());
            }
            for l in &manifest.links {
                if !self.imported_links.contains(l) {
                    self.imported_links.push(l.clone());
                }
            }
            // sic chain-loading (sic.md §"Imports"): a module names the other modules
            // it imports; pull each in so its types/enums/dtors + link flags come
            // along (`import extra` transitively loads `std`). Recurse before this
            // import returns; the `imported_modules` guard above breaks any cycle.
            let deps: Vec<String> = manifest.deps.clone();
            for dep in deps {
                if !self.imported_modules.contains_key(&dep) {
                    self.resolve_import(&dep, None, None, span)?;
                }
            }
            // sic generic functions (sic.md §"Generics"): re-parse each exported
            // template's source into a `Decl::Func` and register it, so the consumer
            // monomorphizes it locally (like a C++ template in a header). There is no
            // symbol to import — each instance is internal to whoever instantiates.
            let mut ns_names: Vec<String> = Vec::new();
            for src in &manifest.generic_fns {
                for decl in Self::parse_generic_template(src) {
                    if let Decl::Func { name, type_params, .. } = &decl {
                        if !type_params.is_empty() {
                            ns_names.push(name.clone());
                            self.generic_fn_defs.entry(name.clone()).or_insert(decl);
                        }
                    }
                }
            }
            // sic (sic.md §"Imports"): the module's enum and generic-template names
            // are, by a plain `import module;`, reachable ONLY as `module::name`.
            // Record them as qualified-only; a later `import module::name` / `::*`
            // un-gates them. (Functions/globals are already namespaced via
            // `imported_modules`, and locally-defined names are never gated.)
            for (e, _) in &manifest.enums { ns_names.push(e.clone()); }
            for (e, _) in &manifest.tagenums { ns_names.push(e.clone()); }
            for n in &ns_names {
                if !self.module_defined_types.contains(n) {
                    self.qualified_only.entry(n.clone()).or_insert_with(|| module.to_string());
                }
            }
            self.module_ns_names.insert(module.to_string(), ns_names);
        }

        // `import module::*;` — bring every symbol into the global namespace: bind
        // each exported function/global bare, and un-gate every namespaced enum /
        // generic (sic.md §"Imports").
        if sym == Some("*") {
            if let Some(exports) = self.imported_modules.get(module).cloned() {
                for (name, export) in exports {
                    self.imported_syms.entry(name).or_insert(export);
                }
            }
            if let Some(names) = self.module_ns_names.get(module).cloned() {
                for n in names { self.qualified_only.remove(&n); }
            }
            return Ok(());
        }
        // Selective / renamed import `import module::sym [as alias];` — bring one
        // symbol into the global namespace. A function/global binds its bare (or
        // aliased) name; a namespaced enum / generic is simply un-gated.
        if let Some(s) = sym {
            if let Some(export) = self.imported_modules.get(module).and_then(|m| m.get(s)).cloned() {
                let bind = alias.unwrap_or(s);
                self.imported_syms.insert(bind.to_string(), export);
            } else if self.qualified_only.get(s).map(|m| m == module).unwrap_or(false) {
                // An enum/generic export: un-gate it (an alias for these is not
                // supported — they keep their own name).
                self.qualified_only.remove(s);
            } else {
                return Err(CompileError::at(
                    format!("module '{}' has no exported symbol '{}'", module, s),
                    span.file.clone(), span.line, span.col,
                ));
            }
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
            // sic struct reordering (sic.md §"Struct reordering"): choose the
            // physical field order per the struct's mode (its `order_*` attribute,
            // or the global `-fstruct-order` default). The concrete permutations
            // live on `StructType`; the override layout forms (packed / bit-field /
            // `aligned`) are declined there and stay in declaration order.
            let mut st = StructType {
                name: Some(name.clone()),
                fields: ir_fields,
                packed: false,
                bitfields: if any_bitfield { bitfields } else { Vec::new() },
                field_aligns: if any_align { field_aligns } else { Vec::new() },
                min_align: s.align,
                layout_order: None,
            };
            use crate::ast::StructOrder;
            st.layout_order = match self.resolve_struct_order(&s.order) {
                StructOrder::C => None,
                StructOrder::Sic => st.compute_size_order(self.ptr_size),
                StructOrder::Random(seed) =>
                    st.compute_random_order(seed.unwrap_or(self.struct_order_seed)),
                StructOrder::Custom(names) => st.compute_custom_order(&names)
                    .map_err(|m| crate::CompileError::at(
                        &format!("struct `{}`: {}", name, m),
                        s.span.file.clone(), s.span.line, s.span.col,
                    ))?,
                StructOrder::Default => unreachable!("resolve_struct_order never returns Default"),
            };
            let ir_ty = Type::Struct(st);
            self.register_type_name(name.clone(), ir_ty);
            if self.sic && !name.starts_with("__") && !self.module_defined_types.contains(name) {
                self.module_defined_types.push(name.clone());
            }
            if s.private { self.private_types.insert(name.clone()); }
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

    /// Synthesize `i64 __sic_str_find / __sic_str_rfind(char* h, i64 hlen, char* n,
    /// i64 nlen)` (sic.md §"Built-in string"): the byte index of the first (or, for
    /// `reverse`, last) occurrence of needle `n` in haystack `h`, or `-1`. Both are
    /// length-counted (no NUL); the match test is `memcmp(h+i, n, nlen) == 0` over a
    /// window `0 ..= hlen-nlen`. Powers `.contains` / `.split` / `.rsplit`.
    pub(crate) fn ensure_str_find_fn(&mut self, reverse: bool) -> FuncRef {
        let fname = if reverse { "__sic_str_rfind" } else { "__sic_str_find" };
        if let Some(f) = self.module.func_ref_by_name(fname) { return f; }
        let i8p = Type::char_ptr();
        let i64t = Type::i64();
        let memcmp = self.module.func_ref_by_name("memcmp").unwrap_or_else(|| {
            self.module.add_extern(sic_ir::ExternFunc {
                name: "memcmp".to_string(),
                sig: FunctionType { ret: Type::i32(),
                    params: vec![Type::void_ptr(), Type::void_ptr(), Type::Int { bits: self.ptr_size * 8, signed: false }],
                    variadic: false },
            })
        });
        let sig = FunctionType { ret: i64t.clone(),
            params: vec![i8p.clone(), i64t.clone(), i8p.clone(), i64t.clone()], variadic: false };
        let params = vec![
            sic_ir::Param { name: "h".into(), ty: i8p.clone() },
            sic_ir::Param { name: "hlen".into(), ty: i64t.clone() },
            sic_ir::Param { name: "n".into(), ty: i8p.clone() },
            sic_ir::Param { name: "nlen".into(), ty: i64t.clone() },
        ];
        let usize_bits = self.ptr_size * 8;
        let mut func = Function::new(fname.to_string(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            // Spill params to slots (raw entry values across a back-edge miscompile).
            let hslot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: hslot, ty: i8p.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10000)), ptr: Val::Local(hslot) });
            let nslot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: nslot, ty: i8p.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10002)), ptr: Val::Local(nslot) });
            let nlen_slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: nlen_slot, ty: i64t.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(ValId(0x10003)), ptr: Val::Local(nlen_slot) });
            // last = hlen - nlen
            let last = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: last, op: BinOp::Sub, lhs: Val::Local(ValId(0x10001)), rhs: Val::Local(ValId(0x10003)), ty: i64t.clone() });
            let last_slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: last_slot, ty: i64t.clone(), align: None });
            fc.push_instr(Instr::Store { val: Val::Local(last), ptr: Val::Local(last_slot) });
            // i = reverse ? last : 0
            let i_slot = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: i_slot, ty: i64t.clone(), align: None });
            let init = if reverse { Val::Local(last) } else { fc.coerce(Constant::int(0), &i64t).unwrap() };
            fc.push_instr(Instr::Store { val: init, ptr: Val::Local(i_slot) });

            let cond_bb = fc.new_block_after_current();
            let body_bb = fc.new_block_after_current();
            let found_bb = fc.new_block_after_current();
            let next_bb = fc.new_block_after_current();
            let notfound_bb = fc.new_block_after_current();
            fc.set_terminator(Terminator::Jump(cond_bb));

            // cond: reverse ? i >= 0 : i <= last
            fc.switch_to_block(cond_bb);
            let iv = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: iv, ptr: Val::Local(i_slot), ty: i64t.clone() });
            let go = fc.alloc_val();
            if reverse {
                fc.push_instr(Instr::Cmp { dest: go, op: CmpOp::ISGe, lhs: Val::Local(iv), rhs: Constant::int(0), ty: i64t.clone() });
            } else {
                let lastv = fc.alloc_val();
                fc.push_instr(Instr::Load { dest: lastv, ptr: Val::Local(last_slot), ty: i64t.clone() });
                fc.push_instr(Instr::Cmp { dest: go, op: CmpOp::ISLe, lhs: Val::Local(iv), rhs: Val::Local(lastv), ty: i64t.clone() });
            }
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(go), then_bb: body_bb, else_bb: notfound_bb });

            // body: if memcmp(h+i, n, nlen) == 0 -> found
            fc.switch_to_block(body_bb);
            let iv2 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: iv2, ptr: Val::Local(i_slot), ty: i64t.clone() });
            let hp = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: hp, ptr: Val::Local(hslot), ty: i8p.clone() });
            let hip = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: hip, base: Val::Local(hp), index: Val::Local(iv2), elem_size: 1, result_ty: i8p.clone() });
            let np = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: np, ptr: Val::Local(nslot), ty: i8p.clone() });
            let nl = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: nl, ptr: Val::Local(nlen_slot), ty: i64t.clone() });
            let nlu = fc.coerce(Val::Local(nl), &Type::Int { bits: usize_bits, signed: false }).unwrap();
            let hipv = fc.coerce(Val::Local(hip), &Type::void_ptr()).unwrap();
            let npv = fc.coerce(Val::Local(np), &Type::void_ptr()).unwrap();
            let cmp = fc.alloc_val();
            fc.push_instr(Instr::Call { dest: Some(cmp), func: memcmp, args: vec![hipv, npv, nlu], ret_ty: Type::i32() });
            let eq = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: Val::Local(cmp), rhs: Constant::int(0), ty: Type::i32() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(eq), then_bb: found_bb, else_bb: next_bb });

            // found: return i
            fc.switch_to_block(found_bb);
            let ir = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: ir, ptr: Val::Local(i_slot), ty: i64t.clone() });
            fc.set_terminator(Terminator::Ret(Some(Val::Local(ir))));

            // next: i += reverse ? -1 : 1
            fc.switch_to_block(next_bb);
            let iv3 = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: iv3, ptr: Val::Local(i_slot), ty: i64t.clone() });
            let step = if reverse { -1 } else { 1 };
            let ni = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: ni, op: BinOp::Add, lhs: Val::Local(iv3), rhs: Constant::int(step), ty: i64t.clone() });
            fc.push_instr(Instr::Store { val: Val::Local(ni), ptr: Val::Local(i_slot) });
            fc.set_terminator(Terminator::Jump(cond_bb));

            // notfound: return -1
            fc.switch_to_block(notfound_bb);
            let neg1 = fc.coerce(Constant::int(-1), &i64t).unwrap();
            fc.set_terminator(Terminator::Ret(Some(neg1)));
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
            // Skip a non-owning rc: NULL (0) is a static/borrowed view, and the
            // sentinel 1 marks a view of a LOCAL stack buffer (copy-on-escape,
            // never freed/refcounted). Only a real heap rc (>1) is refcounted.
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IULe, lhs: Val::Local(r), rhs: Constant::int(1), ty: rcp.clone() });
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
            // rc <= 1 is non-owning: 0 = static/borrowed view, 1 = local-stack view
            // (copy-on-escape sentinel). Neither is freed/refcounted.
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IULe, lhs: Val::Local(r), rhs: Constant::int(1), ty: rcp.clone() });
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

    /// Synthesize `void __sic_any_{retain,release}(void* ty, u64 slot)` — refcount
    /// the string an `any` wraps (sic.md std / §"Built-in string"). An `any` is
    /// `{ ty, slot }`; when its runtime `type` is a `string` (RTTI kind 9), `slot`
    /// is a string descriptor and its `rc` field (offset 16) is the block's refcount
    /// cell — so `retain`/`release` forward to `__sic_str_{retain,release}`. For any
    /// other kind (or a null `ty`) it is a no-op. This lets an `any` local that read
    /// a refcounted container string share ownership of it (retain on bind, release
    /// at scope exit), so a later container overwrite/remove doesn't dangle it.
    pub(crate) fn ensure_any_release_fn(&mut self) -> FuncRef {
        self.ensure_any_refcount_fn("__sic_any_release", false)
    }
    pub(crate) fn ensure_any_retain_fn(&mut self) -> FuncRef {
        self.ensure_any_refcount_fn("__sic_any_retain", true)
    }
    fn ensure_any_refcount_fn(&mut self, name: &str, retain: bool) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name(name) {
            return f;
        }
        let inner = if retain { self.ensure_str_retain_fn() } else { self.ensure_str_release_fn() };
        let usize_ty = Type::Int { bits: self.ptr_size * 8, signed: false };
        let rcp = Type::Pointer(Box::new(usize_ty.clone()));
        let voidp = Type::void_ptr();
        let u32_ty = Type::Int { bits: 32, signed: false };
        let sig = FunctionType { ret: Type::Void, params: vec![voidp.clone(), usize_ty.clone()], variadic: false };
        let params = vec![
            sic_ir::Param { name: "ty".to_string(), ty: voidp.clone() },
            sic_ir::Param { name: "slot".to_string(), ty: usize_ty.clone() },
        ];
        let mut func = Function::new(name.to_string(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            // Params: ty = %0x10000, slot = %0x10001 (arg ValIds).
            let ty_arg = Val::Local(ValId(0x10000));
            let slot_arg = Val::Local(ValId(0x10001));
            let kindok_bb = fc.new_block_after_current();
            let body_bb = fc.new_block_after_current();
            let done_bb = fc.new_block_after_current();
            // if (ty == NULL) goto done;
            let ty_i = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: ty_i, op: CastOp::BitCast, val: ty_arg.clone(), to_ty: usize_ty.clone() });
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: Val::Local(ty_i), rhs: Constant::int(0), ty: usize_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done_bb, else_bb: kindok_bb });
            // kindok: k = *(u32*)(ty + 20); if (k != 9) goto done;
            fc.switch_to_block(kindok_bb);
            let kindp = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: kindp, base: ty_arg, index: Constant::int(types::TYPEINFO_OFF_KIND as i64), elem_size: 1, result_ty: Type::Pointer(Box::new(u32_ty.clone())) });
            let k = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: k, ptr: Val::Local(kindp), ty: u32_ty.clone() });
            let is_str = fc.alloc_val();
            let str_kind = types::type_kind(&types::sic_string_type(fc.ptr_size())) as i64;
            fc.push_instr(Instr::Cmp { dest: is_str, op: CmpOp::IEq, lhs: Val::Local(k), rhs: Constant::int(str_kind), ty: u32_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_str), then_bb: body_bb, else_bb: done_bb });
            // body: rc = *(usize*)(slot + 16); __sic_str_{retain,release}(rc);
            fc.switch_to_block(body_bb);
            let slotp = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: slotp, op: CastOp::BitCast, val: slot_arg, to_ty: voidp.clone() });
            let rcfieldp = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: rcfieldp, base: Val::Local(slotp), index: Constant::int(16), elem_size: 1, result_ty: Type::Pointer(Box::new(rcp.clone())) });
            let rc = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: rc, ptr: Val::Local(rcfieldp), ty: rcp.clone() });
            fc.push_instr(Instr::Call { dest: None, func: inner, args: vec![Val::Local(rc)], ret_ty: Type::Void });
            fc.set_terminator(Terminator::Jump(done_bb));
            fc.switch_to_block(done_bb);
            fc.set_terminator(Terminator::Ret(None));
        }
        self.module.add_function(func)
    }

    /// sic closure destructor (sic.md §"Lambdas"): synthesize (once per env type)
    /// `void __sic_closure_dtor_<env>(void* self)` that releases the closure's
    /// retained (refcounted) captures. Its address is stored in the env's `__dtor`
    /// field and run when the environment is freed. `None` if nothing is retained.
    pub(crate) fn ensure_closure_dtor(&mut self, env_ty: &Type, retained: &[(String, Type)]) -> Option<FuncRef> {
        if retained.is_empty() { return None; }
        let env_name = match env_ty { Type::Struct(st) => st.name.clone()?, _ => return None };
        let dname = format!("__sic_closure_dtor_{}", env_name);
        if let Some(f) = self.module.func_ref_by_name(&dname) { return Some(f); }
        let voidp = Type::void_ptr();
        let sig = build_fn_sig(Type::Void, vec![voidp.clone()], false, self.ptr_size);
        let params = vec![sic_ir::Param { name: "self".to_string(), ty: voidp.clone() }];
        let mut func = Function::new(dname.clone(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        let sp = crate::lexer::Span::default();
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let self_arg = Val::Local(ValId(0x10000));
            let env_ptr_ty = Type::Pointer(Box::new(env_ty.clone()));
            let envp = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: envp, op: CastOp::BitCast, val: self_arg, to_ty: env_ptr_ty.clone() });
            fc.val_types.insert(envp.0, env_ptr_ty);
            for (fname, fty) in retained {
                if let Ok(flv) = fc.field_ptr_from(crate::lower::expr::LValue::plain(Val::Local(envp), env_ty.clone()), fname, false, &sp) {
                    if types::is_sic_string(fty) {
                        fc.emit_string_release_at(flv.ptr);
                    } else if types::is_closure(fty) {
                        if let Ok(h) = fc.load_lvalue(&flv) { let _ = fc.emit_closure_release(h); }
                    } else if let Ok(h) = fc.load_lvalue(&flv) {
                        let _ = fc.emit_rc_release(h);
                    }
                }
            }
            fc.set_terminator(Terminator::Ret(None));
        }
        Some(self.module.add_function(func))
    }

    /// Synthesize `i64 __sic_any_to_i64(void* ty, u64 slot)` — convert the value an
    /// `any` wraps to a 64-bit integer using its RTTI kind (sic.md std): a boxed
    /// FLOAT (kind 4/5/6, whose slot is its f64 bits) is truncated toward zero; any
    /// other kind's slot already holds the integer, so it passes through. A null `ty`
    /// passes the bits through. Lets `any a = 3.5; int i = a;` yield 3 (not the bit
    /// pattern), i.e. a real numeric conversion rather than a reinterpret.
    pub(crate) fn ensure_any_to_i64_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_any_to_i64") { return f; }
        let u64_ty = Type::u64();
        let i64_ty = Type::i64();
        let u32_ty = Type::Int { bits: 32, signed: false };
        let voidp = Type::void_ptr();
        let sig = FunctionType { ret: i64_ty.clone(), params: vec![voidp.clone(), u64_ty.clone()], variadic: false };
        let params = vec![
            sic_ir::Param { name: "ty".to_string(), ty: voidp.clone() },
            sic_ir::Param { name: "slot".to_string(), ty: u64_ty.clone() },
        ];
        let mut func = Function::new("__sic_any_to_i64".to_string(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let ty_arg = Val::Local(ValId(0x10000));
            let slot_arg = Val::Local(ValId(0x10001));
            let check_bb = fc.new_block_after_current();
            let fbb = fc.new_block_after_current();       // float → truncate
            let passthru_bb = fc.new_block_after_current(); // int-kinds → bits
            // if (ty == NULL) goto passthru;
            let ty_i = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: ty_i, op: CastOp::BitCast, val: ty_arg.clone(), to_ty: u64_ty.clone() });
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: Val::Local(ty_i), rhs: Constant::int(0), ty: u64_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: passthru_bb, else_bb: check_bb });
            // check: is the kind a float (4..=6)?  (kind-4) <=u 2
            fc.switch_to_block(check_bb);
            let kindp = fc.alloc_val();
            fc.push_instr(Instr::GetElemPtr { dest: kindp, base: ty_arg.clone(), index: Constant::int(types::TYPEINFO_OFF_KIND as i64), elem_size: 1, result_ty: Type::Pointer(Box::new(u32_ty.clone())) });
            let kind = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: kind, ptr: Val::Local(kindp), ty: u32_ty.clone() });
            let km4 = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: km4, op: BinOp::Sub, lhs: Val::Local(kind), rhs: Constant::int(4), ty: u32_ty.clone() });
            let is_f = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_f, op: CmpOp::IULe, lhs: Val::Local(km4), rhs: Constant::int(2), ty: u32_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_f), then_bb: fbb, else_bb: passthru_bb });
            // float: truncate `*(double*)&slot`. Reinterpret the slot's bits as a
            // double via a memory round-trip — an int↔float `BitCast` would CONVERT
            // the value, not reinterpret the bits.
            fc.switch_to_block(fbb);
            let mem = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: mem, ty: u64_ty.clone(), align: None });
            fc.push_instr(Instr::Store { val: slot_arg.clone(), ptr: Val::Local(mem) });
            let d = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: d, ptr: Val::Local(mem), ty: Type::Float64 });
            let n = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: n, op: CastOp::FPToSI, val: Val::Local(d), to_ty: i64_ty.clone() });
            fc.set_terminator(Terminator::Ret(Some(Val::Local(n))));
            // int kinds: the slot already holds the value.
            fc.switch_to_block(passthru_bb);
            let n2 = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: n2, op: CastOp::BitCast, val: slot_arg, to_ty: i64_ty.clone() });
            fc.set_terminator(Terminator::Ret(Some(Val::Local(n2))));
        }
        self.module.add_function(func)
    }

    /// Synthesize `f64 __sic_any_to_f64(void* ty, u64 slot)` — convert the value an
    /// `any` wraps to a double using its RTTI kind (sic.md std): a boxed float's slot
    /// is its f64 bits (reinterpret); a signed int (kind 2) uses `SIToFP`; any other
    /// integer kind uses `UIToFP`. A null `ty` reinterprets the bits as a double
    /// (matching the old cast). Lets `any a = 3; double d = a;` yield 3.0.
    pub(crate) fn ensure_any_to_f64_fn(&mut self) -> FuncRef {
        if let Some(f) = self.module.func_ref_by_name("__sic_any_to_f64") { return f; }
        let u64_ty = Type::u64();
        let i64_ty = Type::i64();
        let u32_ty = Type::Int { bits: 32, signed: false };
        let voidp = Type::void_ptr();
        let sig = FunctionType { ret: Type::Float64, params: vec![voidp.clone(), u64_ty.clone()], variadic: false };
        let params = vec![
            sic_ir::Param { name: "ty".to_string(), ty: voidp.clone() },
            sic_ir::Param { name: "slot".to_string(), ty: u64_ty.clone() },
        ];
        let mut func = Function::new("__sic_any_to_f64".to_string(), sig, params, Linkage::Internal);
        let entry = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry));
        {
            let mut fc = func::FuncCtx::new_with_func(self, &mut func);
            let ty_arg = Val::Local(ValId(0x10000));
            let slot_arg = Val::Local(ValId(0x10001));
            let check_bb = fc.new_block_after_current();
            let floatbits_bb = fc.new_block_after_current();
            let intcvt_bb = fc.new_block_after_current();
            let sbb = fc.new_block_after_current();
            let ubb = fc.new_block_after_current();
            let read_kind = |fc: &mut func::FuncCtx| -> Val {
                let kindp = fc.alloc_val();
                fc.push_instr(Instr::GetElemPtr { dest: kindp, base: ty_arg.clone(), index: Constant::int(types::TYPEINFO_OFF_KIND as i64), elem_size: 1, result_ty: Type::Pointer(Box::new(u32_ty.clone())) });
                let kind = fc.alloc_val();
                fc.push_instr(Instr::Load { dest: kind, ptr: Val::Local(kindp), ty: u32_ty.clone() });
                Val::Local(kind)
            };
            // if (ty == NULL) goto floatbits (reinterpret, matching the old cast);
            let ty_i = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: ty_i, op: CastOp::BitCast, val: ty_arg.clone(), to_ty: u64_ty.clone() });
            let is_null = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: Val::Local(ty_i), rhs: Constant::int(0), ty: u64_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: floatbits_bb, else_bb: check_bb });
            // check: float kind (4..=6)? → reinterpret; else → integer convert.
            fc.switch_to_block(check_bb);
            let kind = read_kind(&mut fc);
            let km4 = fc.alloc_val();
            fc.push_instr(Instr::BinOp { dest: km4, op: BinOp::Sub, lhs: kind, rhs: Constant::int(4), ty: u32_ty.clone() });
            let is_f = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_f, op: CmpOp::IULe, lhs: Val::Local(km4), rhs: Constant::int(2), ty: u32_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_f), then_bb: floatbits_bb, else_bb: intcvt_bb });
            // floatbits: reinterpret the slot's bits as a double via a memory
            // round-trip (an int↔float `BitCast` would convert, not reinterpret).
            fc.switch_to_block(floatbits_bb);
            let mem = fc.alloc_val();
            fc.push_instr(Instr::Alloca { dest: mem, ty: u64_ty.clone(), align: None });
            fc.push_instr(Instr::Store { val: slot_arg.clone(), ptr: Val::Local(mem) });
            let d = fc.alloc_val();
            fc.push_instr(Instr::Load { dest: d, ptr: Val::Local(mem), ty: Type::Float64 });
            fc.set_terminator(Terminator::Ret(Some(Val::Local(d))));
            // intcvt: signed (kind 2) → SIToFP, else UIToFP.
            fc.switch_to_block(intcvt_bb);
            let kind2 = read_kind(&mut fc);
            let is_signed = fc.alloc_val();
            fc.push_instr(Instr::Cmp { dest: is_signed, op: CmpOp::IEq, lhs: kind2, rhs: Constant::int(2), ty: u32_ty.clone() });
            fc.set_terminator(Terminator::CondJump { cond: Val::Local(is_signed), then_bb: sbb, else_bb: ubb });
            fc.switch_to_block(sbb);
            let si = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: si, op: CastOp::BitCast, val: slot_arg.clone(), to_ty: i64_ty.clone() });
            let ds = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: ds, op: CastOp::SIToFP, val: Val::Local(si), to_ty: Type::Float64 });
            fc.set_terminator(Terminator::Ret(Some(Val::Local(ds))));
            fc.switch_to_block(ubb);
            let du = fc.alloc_val();
            fc.push_instr(Instr::Cast { dest: du, op: CastOp::UIToFP, val: slot_arg, to_ty: Type::Float64 });
            fc.set_terminator(Terminator::Ret(Some(Val::Local(du))));
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

    /// If `ty` names a payload-less enum (one recorded in `c_enum_defs`), return
    /// that enum's name. `enum E`, and a bare `Named`/typedef referring to one, all
    /// resolve; a tagged (payload-carrying) enum has struct identity already and is
    /// not tracked here.
    pub(crate) fn c_enum_name_of_ast(&self, ty: &crate::ast::AstType) -> Option<String> {
        use crate::ast::AstType;
        match ty {
            AstType::Enum(e) => e.name.as_ref()
                .filter(|n| self.c_enum_defs.contains_key(*n)).cloned(),
            AstType::Named(n) | AstType::Builtin(n) => {
                if let Some(canon) = self.c_enum_alias.get(n) { return Some(canon.clone()); }
                if self.c_enum_defs.contains_key(n) { return Some(n.clone()); }
                None
            }
            _ => None,
        }
    }

    /// Link a typedef alias to the payload-less enum it names (sic.md §"Enums"), so
    /// strict enum checking treats `typedef enum {…} E;` exactly like `enum E`. A
    /// tagged (payload-carrying) enum already has struct identity and is skipped.
    /// An anonymous enum is registered under the alias as its own canonical name.
    fn register_c_enum_typedef(&mut self, alias: &str, e: &EnumDef) {
        if !self.sic { return; }
        let Some(variants) = &e.variants else { return; };
        if variants.iter().any(|v| v.payload.is_some()) { return; }
        let canonical = match &e.name {
            Some(en) if self.c_enum_defs.contains_key(en) => en.clone(),
            _ => {
                // Anonymous enum: register its variant table under the alias.
                let mut vs = Vec::new();
                for v in variants {
                    if let Some(val) = self.enum_consts.get(&v.name).copied() {
                        vs.push((v.name.clone(), val));
                        self.c_enum_variant.entry(v.name.clone()).or_insert_with(|| alias.to_string());
                    }
                }
                self.c_enum_defs.entry(alias.to_string()).or_insert(vs);
                alias.to_string()
            }
        };
        self.c_enum_alias.insert(alias.to_string(), canonical);
    }

    /// sic struct methods (sic.md §"Memory safety" / §"Iterators"): rewrite each
    /// struct's `Method`-kind member functions into ordinary internal free functions
    /// (mangled `__sic_m_<Struct>_<method>`) appended to the unit, and record the
    /// `(struct, method) → mangled` table so `obj.method(args)` can resolve and pass
    /// `&obj` as the explicit `self`. Constructors/destructors are handled elsewhere.
    /// sic namespaces (sic.md §"Namespace"): replace each `namespace N { … }` with
    /// its members flattened to mangled top-level symbols (`N__member`), recording
    /// `(N, member) → mangled` so `N::member` resolves. Nested namespaces flatten
    /// with a combined prefix.
    fn flatten_namespaces(&mut self, tu: &mut TranslationUnit) {
        let decls = std::mem::take(&mut tu.decls);
        let mut out = Vec::with_capacity(decls.len());
        for d in decls {
            match d {
                Decl::Namespace { name, decls, .. } => self.flatten_ns_into(&name, decls, &mut out),
                other => out.push(other),
            }
        }
        tu.decls = out;
    }

    /// `scope` is the `::`-joined path (`"A"`, `"A::B"`) used as the lookup key;
    /// symbols are mangled with `__` (`A__B__member`), a valid linker identifier.
    fn flatten_ns_into(&mut self, scope: &str, decls: Vec<Decl>, out: &mut Vec<Decl>) {
        let prefix = scope.replace("::", "__");
        for d in decls {
            match d {
                Decl::Func { name, ret_ty, params, variadic, type_params, template_src, body, storage, inline, constructor, is_async, span } => {
                    let mangled = format!("{}__{}", prefix, name);
                    self.namespace_members.insert((scope.to_string(), name), mangled.clone());
                    out.push(Decl::Func { name: mangled, ret_ty, params, variadic, type_params, template_src, body, storage, inline, constructor, is_async, span });
                }
                Decl::Var { base_ty, mut declarators, weak, thread_local, span } => {
                    for de in &mut declarators {
                        let mangled = format!("{}__{}", prefix, de.name);
                        self.namespace_members.insert((scope.to_string(), de.name.clone()), mangled.clone());
                        de.name = mangled;
                    }
                    out.push(Decl::Var { base_ty, declarators, weak, thread_local, span });
                }
                Decl::Namespace { name: inner, decls, .. } => {
                    self.flatten_ns_into(&format!("{}::{}", scope, inner), decls, out);
                }
                // Types (struct/union/enum/typedef) are hoisted to file scope as-is;
                // qualified `N::Type` access is not supported yet.
                other => out.push(other),
            }
        }
    }

    fn hoist_struct_methods(&mut self, tu: &mut TranslationUnit) {
        // In a module build the synthesized ctor/dtor must be EXTERNAL so an
        // importing unit can link them (a struct's `~S()` runs on the consumer's
        // `del p` / scope exit); in a plain build they stay `static` (unit-local).
        // The exported symbol is module-qualified (`{module}_{S}__ctor`) so two
        // modules that each export a struct of the same name don't collide.
        let module_name: Option<String> = tu.decls.iter().find_map(|d| match d {
            Decl::Module(name, _) => Some(name.clone()), _ => None,
        });
        let in_module = module_name.is_some();
        let mut synthesized: Vec<Decl> = Vec::new();
        for d in &tu.decls {
            for (sname, sdef) in struct_defs_with_methods(d) {
                // `struct S *self` — a bodiless reference to the owning struct.
                let self_param = |sp: &crate::lexer::Span| crate::ast::Param {
                    name: Some("self".to_string()),
                    ty: QualType::new(AstType::Pointer {
                        base: Box::new(QualType::new(AstType::Struct(StructDef {
                            name: Some(sname.clone()), fields: None, align: None,
                            order: crate::ast::StructOrder::Default, methods: vec![], private: false, span: sp.clone(),
                        }))),
                        quals: vec![],
                    }),
                    span: sp.clone(),
                };
                // Field names, so a constructor/destructor's bare `field` reference
                // rewrites to `self->field` (implicit `self`).
                let fields: std::collections::HashSet<String> = sdef.fields.iter().flatten()
                    .filter_map(|f| f.name.clone()).collect();
                for m in &sdef.methods {
                    let (mangled, params, body) = match m.kind {
                        MethodKind::Method => {
                            let mangled = format!("__sic_m_{}_{}", sname, m.name);
                            self.struct_methods.insert((sname.clone(), m.name.clone()), mangled.clone());
                            (mangled, m.params.clone(), m.body.clone())
                        }
                        MethodKind::Ctor | MethodKind::Dtor => {
                            // Module ctor/dtor symbols are module-qualified and
                            // exported (`{module}_{S}__ctor`), unique across modules;
                            // a plain build keeps the unit-local `__sic_ctor_{S}` form.
                            let kind = if m.kind == MethodKind::Ctor { "ctor" } else { "dtor" };
                            let n = match &module_name {
                                Some(md) => format!("{}_{}__{}", md, sname, kind),
                                None => format!("__sic_{}_{}", kind, sname),
                            };
                            let mangled = n.clone();
                            if m.kind == MethodKind::Ctor {
                                self.struct_ctor.insert(sname.clone(), n);
                            } else {
                                self.struct_dtor.insert(sname.clone(), n);
                                // Record the fields the destructor `del`s — the
                                // struct's OWNED, refcounted fields — so a copy
                                // (`v = other`) retains exactly those and never a
                                // borrowed pointer field the dtor leaves alone.
                                let mut owned = Vec::new();
                                collect_deleted_fields(&m.body, &fields, &mut owned);
                                self.struct_owned_fields.insert(sname.clone(), owned);
                            }
                            // Prepend the implicit `self`, then rewrite bare field
                            // references in the body to go through it.
                            let mut params = vec![self_param(&m.span)];
                            params.extend(m.params.clone());
                            let mut body = m.body.clone();
                            rewrite_implicit_self(&mut body, &fields);
                            (mangled, params, body)
                        }
                    };
                    synthesized.push(Decl::Func {
                        name: mangled,
                        ret_ty: m.ret_ty.clone(),
                        params,
                        variadic: m.variadic,
                        type_params: Vec::new(),
                        template_src: None,
                        is_async: false,
                        body: Some(body),
                        // Methods stay local; a module's ctor/dtor is exported so
                        // consumers can link it (see `in_module`).
                        storage: if in_module && matches!(m.kind, MethodKind::Ctor | MethodKind::Dtor) {
                            None
                        } else {
                            Some(StorageClass::Static)
                        },
                        inline: false,
                        constructor: None,
                        span: m.span.clone(),
                    });
                }
            }
        }
        tu.decls.extend(synthesized);
    }

    /// Record each function's payload-less-enum parameters and return type
    /// (sic.md §"Enums") so call sites and `return` can enforce strict enum typing.
    /// Runs after `collect_declarations` (so `c_enum_defs` is populated) and covers
    /// prototypes and definitions alike, independent of declaration order.
    fn collect_enum_signatures(&mut self, tu: &TranslationUnit) {
        for d in &tu.decls {
            if let Decl::Func { name, ret_ty, params, .. } = d {
                if let Some(en) = self.c_enum_name_of_ast(&ret_ty.ty) {
                    self.c_enum_ret.insert(name.clone(), en);
                }
                for (i, p) in params.iter().enumerate() {
                    if let Some(en) = self.c_enum_name_of_ast(&p.ty.ty) {
                        self.c_enum_param.insert((name.clone(), i), en);
                    }
                    if let Some(bf) = self.bitfield_name_of_ast(&p.ty.ty) {
                        self.bitfield_param.insert((name.clone(), i), bf);
                    }
                }
            }
        }
    }

    /// sic bitfield (sic.md §"Bitfields"): if AST type `ty` names a bitfield, its name.
    pub(crate) fn bitfield_name_of_ast(&self, ty: &crate::ast::AstType) -> Option<String> {
        use crate::ast::AstType;
        match ty {
            AstType::Bitfield(b) => Some(b.name.clone()),
            AstType::Named(n) | AstType::Builtin(n)
                if self.bitfield_defs.contains_key(n) => Some(n.clone()),
            _ => None,
        }
    }

    /// sic bitfield (sic.md §"Bitfields"): record the flag set and each member's
    /// implicit constant (`1 << index`), register the type name so `Bits b;`
    /// resolves to the unsigned storage type, and index members for bare use.
    fn register_bitfield(&mut self, b: &crate::ast::BitfieldDef) -> Result<()> {
        if !self.sic { return Ok(()); }
        // Validate capacity up front (≤64 positions) — surfaces a clear error.
        let storage = types::bitfield_storage_type(b.members.len())?;
        self.bitfield_defs.insert(b.name.clone(), b.members.clone());
        for (i, m) in b.members.iter().enumerate() {
            if m == "_" { continue; } // a hole: not a named flag
            // The member's value is `1 << i`; publish it like an enum constant so
            // it folds in constant contexts, and index it for bare resolution.
            self.enum_consts.insert(m.clone(), 1i64 << i);
            self.bitfield_variant.insert(m.clone(), b.name.clone());
        }
        types::set_enum_consts(&self.enum_consts);
        // `Bits b;` (an `AstType::Named`) resolves to the storage integer.
        self.struct_types.insert(b.name.clone(), storage);
        if b.private { self.private_types.insert(b.name.clone()); }
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
                } else if let Some(ename) = &e.name {
                    // Payload-less named enum (a plain C enum): record its variants
                    // for `value.str` → `"vals::ONE"` (sic.md §"Match").
                    let mut vs = Vec::new();
                    for v in variants {
                        let val = *self.enum_consts.get(&v.name).unwrap();
                        vs.push((v.name.clone(), val));
                        self.c_enum_variant.insert(v.name.clone(), ename.clone());
                    }
                    self.c_enum_defs.insert(ename.clone(), vs);
                    if e.private { self.private_types.insert(ename.clone()); }
                    // sic: the bare enum tag is usable as a type name (`OpenMode m`);
                    // resolve it to the enum's underlying integer type.
                    if let Ok(int_ty) = lower_type(
                        &QualType::new(AstType::Enum(e.clone())), &self.struct_types, self.ptr_size) {
                        self.struct_types.entry(ename.clone()).or_insert(int_ty);
                    }
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
            type_params: Vec::new(), private: template.private, span: template.span.clone(),
        };
        self.register_enum(&concrete)?;
        self.struct_types.get(&mangled).cloned().ok_or_else(|| {
            CompileError::new(format!("failed to instantiate generic enum '{}'", name))
        })
    }

    /// sic generic functions (sic.md §"Generics"): monomorphize `name<args…>` into a
    /// concrete function under its mangled name (`add$i32`) and lower it, reusing the
    /// ordinary function machinery. Idempotent; returns the mangled name.
    ///
    /// The type parameters are bound in the type table for the duration of lowering,
    /// so every `Named(T)` in the signature *and body* resolves to its concrete type
    /// with no AST rewriting. A defined placeholder is registered first so a
    /// recursive call inside the body resolves to the same symbol.
    pub fn instantiate_generic_fn(&mut self, base_name: &str, arg_tys: &[Type]) -> Result<String> {
        let decl = self.generic_fn_defs.get(base_name).cloned().ok_or_else(|| {
            CompileError::new(format!("unknown generic function '{}'", base_name))
        })?;
        let (type_params, ret_ty, params, variadic, body) = match decl {
            Decl::Func { type_params, ret_ty, params, variadic, body: Some(body), .. } =>
                (type_params, ret_ty, params, variadic, body),
            _ => return Err(CompileError::new(format!("'{}' is not a generic function", base_name))),
        };
        if type_params.len() != arg_tys.len() {
            return Err(CompileError::new(format!(
                "generic function '{}' expects {} type argument(s), got {}",
                base_name, type_params.len(), arg_tys.len())));
        }
        let mangled = types::generic_fn_mangled(base_name, arg_tys);
        if self.module.func_ref_by_name(&mangled).is_some() { return Ok(mangled); }

        // Bind each type parameter to its concrete type; save the previous binding.
        let saved: Vec<(String, Option<Type>)> = type_params.iter()
            .map(|p| (p.clone(), self.struct_types.get(p).cloned())).collect();
        for (p, t) in type_params.iter().zip(arg_tys) {
            self.struct_types.insert(p.clone(), t.clone());
        }

        let res = (|| -> Result<()> {
            // Pre-register a defined placeholder so recursion resolves to this symbol.
            let ir_ret = lower_type(&ret_ty, &self.struct_types, self.ptr_size)?;
            let ir_params: Result<Vec<_>> = params.iter()
                .map(|p| lower_param_type(&p.ty, &self.struct_types, self.ptr_size)).collect();
            let sig = build_fn_sig(ir_ret, ir_params?, variadic, self.ptr_size);
            if self.module.func_ref_by_name(&mangled).is_none() {
                // Monomorphs are internal: each TU that needs one gets its own copy,
                // so two objects instantiating `add<i32>` don't clash at link time.
                let linkage = fn_linkage(&Some(StorageClass::Static), false, true);
                self.module.add_function(Function::new(mangled.clone(), sig, vec![], linkage));
            }
            self.lower_function(&mangled, &ret_ty, &params, variadic, &body,
                &Some(StorageClass::Static), false, None, false)
        })();

        // Restore the type-parameter bindings.
        for (p, old) in saved {
            match old {
                Some(t) => { self.struct_types.insert(p, t); }
                None => { self.struct_types.remove(&p); }
            }
        }
        res.map(|_| mangled)
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
            Decl::Func { name, ret_ty, params, variadic, body: Some(body), storage, inline, constructor, type_params, is_async, .. } => {
                // sic generic template: instantiated per concrete call, not here.
                if !type_params.is_empty() { return Ok(()); }
                if *inline && !self.emit_inline.contains(name) { return Ok(()); }
                self.lower_function(name, ret_ty, params, *variadic, body, storage, *inline, *constructor, *is_async)?;
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
            // Namespaces are flattened away before lowering (see flatten_namespaces).
            Decl::Namespace { .. } => {}
        }
        Ok(())
    }

    fn lower_global_var(&mut self, d: &Declarator, base_ty: &QualType, weak: bool, thread_local: bool) -> Result<()> {
        let mut ir_ty = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        // sic module-level lambda (sic.md §"Lambdas"): a captureless lambda at file
        // scope initializes a function pointer with the lifted function's address.
        // A capturing closure needs a runtime environment, so it can't const-init a
        // global — define it inside a function (or export a function) instead.
        if self.sic {
            if let Some(Initializer::Expr(e)) = &d.init {
                if let crate::ast::ExprKind::Lambda { captures, params, ret, body } = &e.kind {
                    if !captures.is_empty() {
                        return Err(CompileError::at(
                            "a capturing closure cannot initialize a module-level global — \
                             define it inside a function, or export a function instead".to_string(),
                            d.span.file.clone(), d.span.line, d.span.col));
                    }
                    // Infer the function-pointer type for an inferred (`auto`) global.
                    if matches!(d.ty.ty, AstType::Auto) || matches!(base_ty.storage, Some(StorageClass::Auto)) {
                        ir_ty = self.lambda_type_global(captures, params, ret, body, &d.span)?;
                    }
                }
            }
        }
        // sic `atomic` global (sic.md §"Atomics"): record it so accesses lower to
        // atomic ops (top-level qualifier only — see lower_local_decl).
        if self.sic && d.ty.qualifiers.contains(&crate::ast::TypeQual::Atomic) {
            func::FuncCtx::check_atomic_type(&ir_ty, &d.span)?;
            self.atomic_globals.insert(d.name.clone());
        }
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
            // sic module-level captureless lambda (sic.md §"Lambdas"): lift it to a
            // function and initialize the (function-pointer) global with its address.
            Some(Initializer::Expr(e))
                if matches!(&e.kind, ExprKind::Lambda { captures, .. } if captures.is_empty()) =>
            {
                let ExprKind::Lambda { params, ret, body, .. } = &e.kind else { unreachable!() };
                let n = self.lambda_counter;
                self.lambda_counter += 1;
                let name = format!("__sic_lambda_{}", n);
                let ret_qt = ret.clone().unwrap_or_else(|| QualType::new(AstType::Auto));
                if self.lower_function(&name, &ret_qt, params, false, body,
                    &Some(StorageClass::Static), false, None, false).is_err() {
                    return None;
                }
                let fref = self.module.func_ref_by_name(&name)?;
                let ps = self.ptr_size as usize;
                Some(Constant::Aggregate { bytes: vec![0u8; ps], relocs: vec![(0, RelocTarget::Func(fref))] })
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
        // sic (sic.md §"Match"/§"Namespace"): a possibly scope-qualified enum
        // variant `Enum::VARIANT` (`std::FileStatus::IO`) folds to its discriminant/
        // tag — e.g. as a `switch` case label. Keyed by the variant (last segment).
        ExprKind::EnumVariant { variant, .. } => {
            enum_consts.get(variant.as_str()).copied().ok_or_else(|| {
                CompileError::at(format!("'{}' is not a constant", variant), None, 0, 0)
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

/// The named struct definitions (with their canonical name) carried by a top-level
/// declaration that actually declare member functions (sic.md §"Memory safety").
fn struct_defs_with_methods(d: &Decl) -> Vec<(String, &StructDef)> {
    let mut out = Vec::new();
    match d {
        Decl::StructDecl(s) | Decl::Var { base_ty: QualType { ty: AstType::Struct(s), .. }, .. } => {
            if !s.methods.is_empty() {
                if let Some(n) = &s.name { out.push((n.clone(), s)); }
            }
        }
        Decl::TypeDef { names, .. } => {
            for (alias, qt) in names {
                if let AstType::Struct(s) = &qt.ty {
                    if !s.methods.is_empty() {
                        out.push((s.name.clone().unwrap_or_else(|| alias.clone()), s));
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Does this declaration introduce any sic struct member functions?
fn decl_has_methods(d: &Decl) -> bool {
    !struct_defs_with_methods(d).is_empty()
}

/// Rewrite a constructor/destructor body so a bare reference to a struct field
/// `f` becomes `self->f` (sic.md §"Memory safety"). A name shadowed by a local
/// declared in the body is left alone (it refers to the local, not the field).
fn rewrite_implicit_self(body: &mut [Stmt], fields: &HashSet<String>) {
    let mut local_set: HashSet<String> = HashSet::new();
    for s in body.iter() { collect_declared_locals(s, &mut local_set); }
    let targets: HashSet<String> = fields.difference(&local_set).cloned().collect();
    if targets.is_empty() { return; }
    for s in body.iter_mut() { rw_self_stmt(s, &targets); }
}

/// Collect the struct fields a destructor `del`s (sic.md §"Memory safety"): the
/// struct's OWNED, refcounted fields. Scans for `del <field>` / `del self->field` /
/// `del self.field` (before implicit-`self` rewriting). Used so a managed-struct
/// copy retains exactly the owned fields, never a borrowed pointer.
fn collect_deleted_fields(body: &[Stmt], fields: &HashSet<String>, out: &mut Vec<String>) {
    fn field_of(e: &Expr, fields: &HashSet<String>) -> Option<String> {
        match &e.kind {
            ExprKind::Ident(n) if fields.contains(n) => Some(n.clone()),
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name }
                if matches!(&base.kind, ExprKind::Ident(b) if b == "self") && fields.contains(name)
                => Some(name.clone()),
            _ => None,
        }
    }
    fn walk(s: &Stmt, fields: &HashSet<String>, out: &mut Vec<String>) {
        match s {
            Stmt::Delete(e, _) => {
                if let Some(f) = field_of(e, fields) {
                    if !out.contains(&f) { out.push(f); }
                }
            }
            Stmt::Block(ss, _) | Stmt::Unsafe(ss, _) => for s in ss { walk(s, fields, out); },
            Stmt::If { then, else_, .. } => {
                walk(then, fields, out);
                if let Some(e) = else_ { walk(e, fields, out); }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. }
            | Stmt::Default(body, _) | Stmt::Label(_, body, _) | Stmt::Defer(body, _)
            | Stmt::For { body, .. } => walk(body, fields, out),
            Stmt::ForEach { body, .. } => walk(body, fields, out),
            Stmt::Switch { body, .. } => walk(body, fields, out),
            Stmt::Match { arms, .. } => for a in arms { walk(&a.body, fields, out); },
            Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) => walk(body, fields, out),
            Stmt::Guard { else_body, .. } => walk(else_body, fields, out),
            _ => {}
        }
    }
    for s in body { walk(s, fields, out); }
}

/// Names of variables *declared* (not merely used) anywhere within a statement —
/// so a field shadowed by a local is excluded from implicit-`self` rewriting.
fn collect_declared_locals(s: &Stmt, out: &mut HashSet<String>) {
    let decl_names = |d: &Decl, out: &mut HashSet<String>| {
        if let Decl::Var { declarators, .. } = d {
            for de in declarators { out.insert(de.name.clone()); }
        }
    };
    match s {
        Stmt::Decl(d) => decl_names(d, out),
        Stmt::Block(ss, _) | Stmt::Unsafe(ss, _) => for s in ss { collect_declared_locals(s, out); },
        Stmt::If { then, else_, .. } => {
            collect_declared_locals(then, out);
            if let Some(e) = else_ { collect_declared_locals(e, out); }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. }
        | Stmt::Default(body, _) | Stmt::Label(_, body, _) | Stmt::Defer(body, _) =>
            collect_declared_locals(body, out),
        Stmt::For { init, body, .. } => {
            if let Some(ForInit::Decl(d)) = init { decl_names(d, out); }
            collect_declared_locals(body, out);
        }
        Stmt::ForEach { name, body, .. } => { out.insert(name.clone()); collect_declared_locals(body, out); }
        Stmt::Switch { body, .. } => collect_declared_locals(body, out),
        Stmt::Match { arms, .. } => for a in arms {
            if let Some(b) = &a.binding { out.insert(b.clone()); }
            collect_declared_locals(&a.body, out);
        },
        Stmt::Case(_, body, _) | Stmt::CaseRange(_, _, body, _) => collect_declared_locals(body, out),
        Stmt::Guard { binding, else_body, .. } => {
            if let Some((_, n)) = binding { out.insert(n.clone()); }
            collect_declared_locals(else_body, out);
        }
        _ => {}
    }
}

fn rw_self_expr(e: &mut Expr, t: &HashSet<String>) {
    use ExprKind::*;
    match &mut e.kind {
        Ident(n) if t.contains(n) => {
            let name = n.clone();
            let sp = e.span.clone();
            e.kind = Arrow { base: Box::new(Expr { kind: Ident("self".to_string()), span: sp }), name };
        }
        BinOp { lhs, rhs, .. } | Assign { lhs, rhs, .. } | Swap { lhs, rhs }
        | Comma(lhs, rhs) => { rw_self_expr(lhs, t); rw_self_expr(rhs, t); }
        Unary { expr, .. } | PreInc { expr, .. } | Ref { expr, .. }
        | SizeofExpr(expr) | AlignofExpr(expr) | TypeId(expr) => rw_self_expr(expr, t),
        Cast { expr, .. } => rw_self_expr(expr, t),
        Call { func, args } => { rw_self_expr(func, t); for a in args { rw_self_expr(a, t); } }
        Index { base, index } => { rw_self_expr(base, t); rw_self_expr(index, t); }
        Field { base, .. } | Arrow { base, .. } | OptField { base, .. } => rw_self_expr(base, t),
        New { args, .. } => { for c in args { rw_self_expr(c, t); } }
        Slice { base, lo, hi } => {
            rw_self_expr(base, t);
            if let Some(x) = lo { rw_self_expr(x, t); }
            if let Some(x) = hi { rw_self_expr(x, t); }
        }
        Ternary { cond, then, else_ } | ChooseExpr { cond, then, else_ } => {
            rw_self_expr(cond, t); rw_self_expr(then, t); rw_self_expr(else_, t);
        }
        Elvis { cond, else_ } => { rw_self_expr(cond, t); rw_self_expr(else_, t); }
        TupleExpr(items) => { for i in items { rw_self_expr(i, t); } }
        _ => {}
    }
}

fn rw_self_stmt(s: &mut Stmt, t: &HashSet<String>) {
    match s {
        Stmt::Expr(e, _) | Stmt::Return(Some(e), _) | Stmt::Delete(e, _) => rw_self_expr(e, t),
        Stmt::Block(ss, _) | Stmt::Unsafe(ss, _) => { for s in ss { rw_self_stmt(s, t); } }
        Stmt::Decl(Decl::Var { declarators, .. }) => {
            for d in declarators {
                if let Some(Initializer::Expr(e)) = &mut d.init { rw_self_expr(e, t); }
            }
        }
        Stmt::If { cond, then, else_, .. } => {
            rw_self_expr(cond, t); rw_self_stmt(then, t);
            if let Some(e) = else_ { rw_self_stmt(e, t); }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
            rw_self_expr(cond, t); rw_self_stmt(body, t);
        }
        Stmt::For { init, cond, post, body, .. } => {
            match init {
                Some(ForInit::Expr(e)) => rw_self_expr(e, t),
                Some(ForInit::Decl(Decl::Var { declarators, .. })) => {
                    for d in declarators { if let Some(Initializer::Expr(e)) = &mut d.init { rw_self_expr(e, t); } }
                }
                _ => {}
            }
            if let Some(e) = cond { rw_self_expr(e, t); }
            if let Some(e) = post { rw_self_expr(e, t); }
            rw_self_stmt(body, t);
        }
        Stmt::ForEach { iterable, body, .. } => { rw_self_expr(iterable, t); rw_self_stmt(body, t); }
        Stmt::Switch { val, body, .. } => { rw_self_expr(val, t); rw_self_stmt(body, t); }
        Stmt::Match { scrutinee, arms, .. } => {
            rw_self_expr(scrutinee, t);
            for a in arms { rw_self_stmt(&mut a.body, t); }
        }
        Stmt::Case(e, body, _) => { rw_self_expr(e, t); rw_self_stmt(body, t); }
        Stmt::CaseRange(lo, hi, body, _) => { rw_self_expr(lo, t); rw_self_expr(hi, t); rw_self_stmt(body, t); }
        Stmt::Default(body, _) | Stmt::Label(_, body, _) | Stmt::Defer(body, _) => rw_self_stmt(body, t),
        Stmt::Guard { cond, else_body, .. } => { rw_self_expr(cond, t); rw_self_stmt(else_body, t); }
        _ => {}
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
            packed: false, type_params: vec!["T".to_string()], private: false, span: crate::lexer::Span::default(),
        },
        EnumDef {
            name: Some("Result".to_string()),
            variants: Some(vec![variant("Ok", Some(named("T"))), variant("Err", Some(named("E")))]),
            packed: false, type_params: vec!["T".to_string(), "E".to_string()], private: false, span: crate::lexer::Span::default(),
        },
        // sic iterators (sic.md §"Iterators"): a custom `next()` returns this so the
        // range-`for` knows whether to yield another element or stop.
        EnumDef {
            name: Some("Iterator".to_string()),
            variants: Some(vec![variant("Stop", None), variant("Next", Some(named("T")))]),
            packed: false, type_params: vec!["T".to_string()], private: false, span: crate::lexer::Span::default(),
        },
    ]
}

// ─── generic-enum monomorphization collectors (sic.md §"Match") ────────────────

/// Substitute type parameters (bound to concrete `AstType`s) throughout a type,
/// e.g. `T` → `int`, `T*` → `int*`. Used to specialize a generic enum's payloads.
/// sic named parameters (sic.md §"Named parameters"): map a call's arguments — some
/// positional, some `name = value` — onto the callee's fixed parameters, returning a
/// purely positional list (fixed slots in order, then the variadic tail in written
/// order). Rules: named arguments may only follow positional ones; each name must
/// match an as-yet-unfilled fixed parameter (or, for a variadic callee, drop to the
/// tail with its name discarded — a future `va_dict` will capture the pairs); and
/// every fixed parameter must end up filled.
fn reorder_named_args(
    args: &[Expr],
    param_names: &[String],
    variadic: bool,
    sp: &crate::lexer::Span,
) -> Result<Vec<Expr>> {
    use crate::ast::ExprKind;
    let err = |m: String| CompileError::at(m, sp.file.clone(), sp.line, sp.col);
    let k = param_names.len();
    let mut slots: Vec<Option<Expr>> = (0..k).map(|_| None).collect();
    let mut tail: Vec<Expr> = Vec::new();
    let mut seen_named = false;
    let mut pos = 0usize;
    for arg in args {
        match &arg.kind {
            ExprKind::NamedArg { name, value } => {
                seen_named = true;
                if let Some(i) = param_names.iter().position(|p| !p.is_empty() && p == name) {
                    if slots[i].is_some() {
                        return Err(err(format!("parameter `{}` given more than once", name)));
                    }
                    slots[i] = Some((**value).clone());
                } else if variadic {
                    // A variadic (or unknown-name) argument: drop the name, keep order.
                    tail.push((**value).clone());
                } else {
                    return Err(err(format!("function has no parameter named `{}`", name)));
                }
            }
            _ => {
                if seen_named {
                    return Err(err("positional argument after a named argument".to_string()));
                }
                if pos < k {
                    slots[pos] = Some(arg.clone());
                } else {
                    // Beyond the fixed parameters: a variadic positional (or an
                    // arity error the normal call path will report).
                    tail.push(arg.clone());
                }
                pos += 1;
            }
        }
    }
    let mut out = Vec::with_capacity(k + tail.len());
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(e) => out.push(e),
            None => {
                let pname = &param_names[i];
                let which = if pname.is_empty() { format!("#{}", i + 1) } else { format!("`{}`", pname) };
                return Err(err(format!("missing argument for parameter {}", which)));
            }
        }
    }
    out.extend(tail);
    Ok(out)
}

/// sic generic functions (sic.md §"Generics"): infer type parameters by matching a
/// parameter's declared type `pattern` (which may mention type parameters) against
/// the concrete argument type. A bare type parameter binds to `concrete`; `T*`/`T[]`
/// recurse into the pointee/element. Re-binding a parameter to a different type is a
/// conflict (`add(1, 2.0)`). Positions that don't mention a parameter contribute
/// nothing; an ultimately-unbound parameter is reported by the caller.
fn unify_type(
    pattern: &AstType,
    concrete: &Type,
    params: &std::collections::HashSet<String>,
    out: &mut HashMap<String, Type>,
) -> Result<()> {
    use AstType::*;
    match pattern {
        Named(n) if params.contains(n) => {
            if let Some(prev) = out.get(n) {
                if prev != concrete {
                    return Err(CompileError::new(format!(
                        "conflicting types for type parameter `{}`: `{}` vs `{}`",
                        n, types::type_display_name(prev), types::type_display_name(concrete))));
                }
            } else {
                out.insert(n.clone(), concrete.clone());
            }
        }
        // A `T*` parameter also matches an array argument (it decays to a pointer).
        Pointer { base, .. } => match concrete {
            Type::Pointer(inner) | Type::Array { elem: inner, .. } =>
                unify_type(&base.ty, inner, params, out)?,
            _ => {}
        },
        Array { base, .. } => match concrete {
            Type::Pointer(inner) | Type::Array { elem: inner, .. } =>
                unify_type(&base.ty, inner, params, out)?,
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

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
            // `dict<K,V>` / `Task<T>` are built-ins, not user generic enums — don't
            // try to monomorphize them as one (sic.md §"Dict", §"Async").
            if name != "dict" && name != "Task" && name != "set" && name != "list" {
                out.push((name.clone(), args.clone()));
            }
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
        Stmt::ForEach { name, iterable, body, .. } => {
            collect_expr_names(iterable, out);
            out.push(name.clone());
            collect_stmt_names(body, out);
        }
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
        Match { scrutinee, arms } => {
            collect_expr_names(scrutinee, out);
            for a in arms {
                if let Some(b) = &a.binding { out.push(b.clone()); }
                collect_stmt_names(&a.body, out);
            }
        }
        ChooseExpr { cond, then, else_ } => {
            collect_expr_names(cond, out); collect_expr_names(then, out); collect_expr_names(else_, out);
        }
        Call { func, args } => {
            collect_expr_names(func, out);
            for a in args { collect_expr_names(a, out); }
        }
        GenericRef { name, .. } => out.push(name.clone()),
        NamedArg { value, .. } => collect_expr_names(value, out),
        Await(e) => collect_expr_names(e, out),
        Index { base, index } => { collect_expr_names(base, out); collect_expr_names(index, out); }
        Slice { base, lo, hi } => {
            collect_expr_names(base, out);
            if let Some(e) = lo { collect_expr_names(e, out); }
            if let Some(e) = hi { collect_expr_names(e, out); }
        }
        New { args, .. } => { for e in args { collect_expr_names(e, out); } }
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
        Lambda { body, .. } => { for s in body { collect_stmt_names(s, out); } }
        Guard { body, .. } => { for s in body { collect_stmt_names(s, out); } }
        OptField { base, .. } => collect_expr_names(base, out),
        // `typeid(e)` inspects only the type — `e` is never evaluated.
        TypeId(_) => {}
        IntLit(..) | UIntLit(..) | BoolLit(_) | BigIntLit(_) | DecimalLit(_) | FloatLit(_) | StringLit(_) | CharLit(_) | Nullptr
        | SizeofType(_) | AlignofType(_) | TypesCompatible(..) | EnumVariant { .. } | TypeIdOf(_) => {}
    }
}
