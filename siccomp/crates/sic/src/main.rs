use std::collections::HashSet;
use std::fs;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser as ClapParser;
use sic_cranelift::CraneliftBackend;
use sic_frontend::{preprocess_ex, Lexer, Parser, Lowerer};
use sic_ir::{Backend, display::print_module};
use sic_opt::ConstFold;

/// Value of a GCC/Clang-style `-f<name>` option.
#[derive(Debug, Clone, PartialEq)]
enum FOption {
    /// `-f<name>` — the feature is enabled.
    Enabled,
    /// `-fno-<name>` — the feature is disabled.
    Disabled,
    /// `-f<name>=<value>` — the feature carries a value.
    Value(String),
}

#[derive(ClapParser, Debug)]
#[command(name = "sic", about = "SIC compiler (Rust/Cranelift)")]
struct Args {
    /// Input files: C sources to compile and/or object files to link
    #[arg(value_name = "FILE")]
    filenames: Vec<String>,

    /// Output file
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Emit IR text instead of compiling
    #[arg(short = 'S', long = "emit-ir")]
    emit_ir: bool,

    /// Compile to object file, do not link
    #[arg(short = 'c', long = "emit-obj")]
    emit_obj: bool,

    /// Optimization level: 0 = none, 1 = const fold, 2/3 = + Cranelift optimizer
    /// (speed), s/z = optimize for size (Cranelift speed_and_size)
    #[arg(short = 'O', long = "opt", default_value = "0", value_name = "LEVEL")]
    opt: String,

    /// Preprocessor defines
    #[arg(short = 'D', action = clap::ArgAction::Append, value_name = "MACRO")]
    defines: Vec<String>,

    /// Include directories
    #[arg(short = 'I', action = clap::ArgAction::Append, value_name = "DIR")]
    includes: Vec<String>,

    /// C standard to preprocess against (e.g. c99, c11, c17, c23)
    #[arg(long = "std", value_name = "STD", default_value = "c23")]
    std: String,

    /// Link against a library (passed to the linker as -l<LIB>)
    #[arg(short = 'l', action = clap::ArgAction::Append, value_name = "LIB")]
    libs: Vec<String>,

    /// Add a directory to the library search path (passed as -L<DIR>)
    #[arg(short = 'L', action = clap::ArgAction::Append, value_name = "DIR")]
    lib_dirs: Vec<String>,

    /// Warning flags (`-Wall`, `-Wextra`, `-Werror`, `-Wno-...`, ...). Accepted
    /// for gcc/clang compatibility. Most are no-ops for now (sic does not yet
    /// emit diagnostics); `-Wl,<args>` is forwarded to the linker.
    #[arg(short = 'W', action = clap::ArgAction::Append, value_name = "WARNING")]
    warnings: Vec<String>,

    /// Dump AST
    #[arg(long = "ast")]
    ast: bool,

    /// Enable debug output
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Generate debug information (`-g` and variants). Set from the argv pre-pass
    /// rather than parsed by clap. sic emits an ELF symbol table (function-level
    /// backtraces work); full DWARF line/variable info is not yet produced.
    #[arg(skip)]
    debug_info: bool,

    /// Preprocess only (`-E`): write the preprocessed source and stop. Set from
    /// the argv pre-pass.
    #[arg(skip)]
    preprocess_only: bool,

    /// GCC `-d<letters>` dump flag (e.g. `-dM` to dump macros) forwarded to the
    /// preprocessor. Implies preprocess-only. Set from the argv pre-pass.
    #[arg(skip)]
    dump_flag: Option<String>,

    /// GCC/Clang-style `-f<name>[=<value>]` options, parsed into a map. Accepted
    /// for compatibility and stored (mostly no-ops for now); e.g. `-fPIC` →
    /// `{"PIC": Enabled}`, `-fno-builtin` → `{"builtin": Disabled}`,
    /// `-fdiagnostics-color=always` → `{"diagnostics-color": Value("always")}`.
    /// Set from the argv pre-pass.
    #[arg(skip)]
    f_options: std::collections::HashMap<String, FOption>,

    /// Dependency-generation flags (`-MD`, `-MMD`, `-MF <file>`, `-MT`/`-MQ
    /// <target>`, `-MP`, ...) forwarded verbatim to the preprocessor. Set from
    /// the argv pre-pass.
    #[arg(skip)]
    dep_flags: Vec<String>,

    /// Dependency-only mode (`-M` / `-MM`): emit make rules and don't compile.
    #[arg(skip)]
    deps_only: bool,

    /// `-pthread`: compile with `_REENTRANT` defined and link the pthread
    /// library. Set from the argv pre-pass.
    #[arg(skip)]
    pthread: bool,

    /// `-shared`: produce a shared object (`.so`) instead of an executable.
    /// Passed through to the linker; implies position-independent code.
    #[arg(skip)]
    shared: bool,
}

/// The dependency-generation flags to hand to cpp. When the user didn't give a
/// `-MT`/`-MQ` target but did give an output (`-o`), default the rule's target
/// to that output — matching gcc, which otherwise derives it from the input.
fn effective_dep_flags(args: &Args) -> Vec<String> {
    // Nothing to do unless dependency generation was actually requested.
    if args.dep_flags.is_empty() {
        return Vec::new();
    }
    let mut flags = args.dep_flags.clone();
    let has_target = flags.iter()
        .any(|f| f.starts_with("-MT") || f.starts_with("-MQ"));
    if !has_target {
        if let Some(out) = &args.output {
            flags.push("-MQ".to_string());
            flags.push(out.clone());
        }
    }
    flags
}

/// Parse a `-f<...>` argument into its (name, value) map entry. Returns `None`
/// for a bare `-f` with no name.
fn parse_f_option(arg: &str) -> Option<(String, FOption)> {
    let rest = arg.strip_prefix("-f")?;
    if rest.is_empty() {
        return None;
    }
    if let Some((name, value)) = rest.split_once('=') {
        // `-fname=value`
        Some((name.to_string(), FOption::Value(value.to_string())))
    } else if let Some(name) = rest.strip_prefix("no-") {
        // `-fno-name` disables the feature (canonical key is the base name).
        Some((name.to_string(), FOption::Disabled))
    } else {
        // `-fname`
        Some((rest.to_string(), FOption::Enabled))
    }
}

/// GCC/Clang-style target triple describing this build's host.
fn target_triple() -> String {
    format!("{}-unknown-{}-gnu", std::env::consts::ARCH, std::env::consts::OS)
}

/// Handle GCC/Clang-style version queries that short-circuit compilation:
/// `--version`, `-dumpversion`, `-dumpmachine`. Returns true if one was handled
/// (and the program should exit 0). These are checked before clap so they work
/// without any input files, exactly as gcc/clang do.
fn handle_version_query(args: &[String]) -> bool {
    let version = env!("CARGO_PKG_VERSION");
    for a in args {
        match a.as_str() {
            "--version" => {
                // clang-like banner.
                println!("sic version {} (SIC Compiler, clang compatible, Cranelift)", version);
                println!("Target: {}", target_triple());
                println!("Thread model: posix");
                return true;
            }
            "-dumpversion" | "--dumpversion" => {
                // Just the version number — build systems (e.g. CMake) parse this.
                println!("{}", version);
                return true;
            }
            "-dumpmachine" | "--dumpmachine" => {
                println!("{}", target_triple());
                return true;
            }
            _ => {}
        }
    }
    false
}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    if handle_version_query(&raw_args) {
        return;
    }

    // Normalize a few GCC-style flags before clap sees them.
    let mut want_debug = false;
    let mut preprocess_only = false;
    let mut dump_flag: Option<String> = None;
    let mut f_options: std::collections::HashMap<String, FOption> = std::collections::HashMap::new();
    let mut dep_flags: Vec<String> = Vec::new();
    let mut deps_only = false;
    let mut pthread = false;
    let mut shared = false;
    let mut argv: Vec<String> = Vec::new();
    let mut iter = std::env::args().peekable();
    while let Some(a) = iter.next() {
        if a == "-pthread" || a == "-pthreads" {
            // Compile with `_REENTRANT` and link the pthread library.
            pthread = true;
        } else if a == "-shared" {
            // Produce a shared object; pass through to the linker.
            shared = true;
        } else if a == "-std" {
            // Accept `-std c99` in addition to clap's `--std c99`.
            argv.push("--std".to_string());
        } else if let Some(rest) = a.strip_prefix("-std=") {
            // Accept GCC-style single-dash `-std=c99`.
            argv.push(format!("--std={}", rest));
        } else if a.starts_with("-g") {
            // Debug-info flags: `-g`, `-g0..3`, `-ggdb`, `-gdwarf-4`, ... These
            // are always attached in GCC/Clang, so a plain prefix match is safe
            // and avoids clap swallowing the following filename as a value.
            want_debug = true;
        } else if a == "-O" {
            // Bare `-O` means `-O1` in GCC/Clang; clap requires an attached value.
            argv.push("-O1".to_string());
        } else if a == "-E" {
            // Preprocess only.
            preprocess_only = true;
        } else if a == "-P" {
            // Inhibit linemarkers in preprocessed output (`cpp -P`). meson passes
            // `-E -P` for its header-detection probes; forward it to cpp. Without
            // accepting it, clap rejected the whole invocation → every such probe
            // failed at configure time (HAVE_PTY_H etc. wrongly came out unset).
            dep_flags.push("-P".to_string());
        } else if a == "-x" {
            // `-x <lang>` selects the input language. sic only handles C, so
            // accept and ignore the language argument (consume it).
            let _lang = iter.next();
        } else if a.starts_with("-x") && a.len() > 2 {
            // Attached form `-xc` — likewise ignored.
        } else if a == "-isystem" || a == "-iquote" || a == "-idirafter" {
            // GCC include-path variants: treat like `-I<dir>` (the following arg
            // is the directory). sic has a single include search list.
            if let Some(dir) = iter.next() {
                argv.push(format!("-I{}", dir));
            }
        } else if let Some(dir) = a.strip_prefix("-isystem")
            .or_else(|| a.strip_prefix("-iquote"))
            .or_else(|| a.strip_prefix("-idirafter"))
            .filter(|d| !d.is_empty())
        {
            // Attached form, e.g. `-isystem../linux-headers`.
            argv.push(format!("-I{}", dir));
        } else if a == "-include" || a == "-imacros" {
            // Force-include a file / its macros: forward to cpp verbatim.
            dep_flags.push(a);
            if let Some(v) = iter.next() { dep_flags.push(v); }
        } else if a.starts_with("-f") && a.len() > 2 {
            // GCC/Clang `-f<name>[=<value>]` options: parse and store. Accepted
            // for compatibility; acted upon only where sic implements them.
            if let Some((name, value)) = parse_f_option(&a) {
                f_options.insert(name, value);
            }
        } else if a == "-m64" {
            // sic targets x86-64; `-m64` is the default. Accept as a no-op.
        } else if a == "-m32" || a == "-mx32" {
            // sic can only produce 64-bit code — fail loudly rather than
            // silently emitting a 64-bit object for a 32-bit request.
            eprintln!("sic: error: '{}' is not supported (sic only targets 64-bit x86-64)", a);
            std::process::exit(1);
        } else if a.starts_with("-m") && a.len() > 2 {
            // Other machine-dependent flags (`-msse2`, `-mavx`, `-march=...`,
            // `-mtune=...`, `-mfpmath=...`, ...) are CPU feature/tuning hints.
            // Accept and ignore them: they affect optimization, not correctness.
        } else if a == "-M" || a == "-MM" {
            // Dependency-only: emit make rules and don't compile.
            deps_only = true;
            dep_flags.push(a);
        } else if a == "-MD" || a == "-MMD" || a == "-MG" || a == "-MP" {
            // Generate dependencies as a side effect of compilation.
            dep_flags.push(a);
        } else if a == "-MF" || a == "-MT" || a == "-MQ" || a == "-MJ" {
            // These take a following argument (dep file / target name).
            dep_flags.push(a);
            if let Some(v) = iter.next() {
                dep_flags.push(v);
            }
        } else if a.len() > 3
            && (a.starts_with("-MF") || a.starts_with("-MT") || a.starts_with("-MQ")) {
            // Attached forms `-MF<file>`, `-MT<target>`, `-MQ<target>`.
            dep_flags.push(a);
        } else if a.len() > 2 && a.starts_with("-d") && !a.starts_with("-dump") {
            // GCC `-d<letters>` dump flags (`-dM`, `-dD`, `-dN`, ...). `-d` alone
            // is sic's own --debug (handled by clap), and `-dump*` are separate
            // (handled earlier). These dump macros/defines and imply -E output.
            dump_flag = Some(a.clone());
            preprocess_only = true;
        } else {
            argv.push(a);
        }
    }
    let mut args = Args::parse_from(argv);
    args.debug_info = want_debug;
    args.preprocess_only = preprocess_only;
    args.dump_flag = dump_flag;
    args.f_options = f_options;
    args.dep_flags = dep_flags;
    args.pthread = pthread;
    args.shared = shared;
    args.deps_only = deps_only;

    if let Err(e) = run(&args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

/// Resolve the external C driver used to perform the final link.
///
/// We deliberately do NOT honor `$CC` here: build systems (CMake, autotools)
/// commonly set `CC=sic` to use sic as *their* compiler, and if sic then read
/// `$CC` to find its own linker it would invoke itself recursively forever.
/// Precedence: `SIC_CC`, then `LD`, then the system `cc`. Whatever is chosen,
/// we refuse anything that resolves back to this very executable (e.g. a build
/// system that also set `LD=sic`) and fall back to `cc`.
fn resolve_linker() -> String {
    let choice = std::env::var("SIC_CC").ok().filter(|s| !s.is_empty())
        .or_else(|| std::env::var("LD").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "cc".to_string());

    if resolves_to_self(&choice) { "cc".to_string() } else { choice }
}

/// True if `prog` names this very executable — by file stem (`sic`) or by
/// resolving to the same canonical path as the running binary.
fn resolves_to_self(prog: &str) -> bool {
    if PathBuf::from(prog).file_stem().and_then(|s| s.to_str()) == Some("sic") {
        return true;
    }
    match (std::env::current_exe(), std::fs::canonicalize(prog)) {
        (Ok(exe), Ok(p)) => p == exe,
        _ => false,
    }
}

/// Whether the given `-O` level runs the frontend constant-folding pass — every
/// level except `-O0`.
fn opt_runs_constfold(opt: &str) -> bool {
    opt != "0"
}

/// Map a GCC-style `-O` level to a Cranelift `opt_level` setting.
///   0/1        → none        (no Cranelift optimizer)
///   2/3/higher → speed       (optimize for speed)
///   s/z        → speed_and_size (optimize for size)
fn opt_cranelift_level(opt: &str) -> &'static str {
    match opt {
        "s" | "z" => "speed_and_size",
        _ => match opt.parse::<u32>() {
            Ok(0) | Ok(1) => "none",
            Ok(_) => "speed",
            Err(_) => "none", // unrecognized level: stay safe
        },
    }
}

/// An input file is a linker input (object/archive/shared lib) rather than a
/// C source to compile, based on its extension.
fn is_link_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".o") || lower.ends_with(".a") || lower.ends_with(".so")
        || lower.contains(".so.") // versioned shared libs, e.g. libfoo.so.1
}

/// An assembly source (`.s` = plain, `.S` = needs the C preprocessor). sic has
/// no assembler; these are handed to the system compiler driver as-is.
fn is_assembly(path: &str) -> bool {
    path.ends_with(".s") || path.ends_with(".S")
}

/// Assemble a `.s`/`.S` source to an object file via the system compiler driver
/// (which preprocesses `.S` and runs the assembler), forwarding the include and
/// define flags an `.S` file may rely on.
fn assemble_source(src: &str, obj: &str, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let cc = resolve_linker();
    let mut cmd = Command::new(&cc);
    cmd.arg("-c").arg(src).arg("-o").arg(obj);
    for d in &args.defines { cmd.arg(format!("-D{}", d)); }
    for i in &args.includes { cmd.arg(format!("-I{}", i)); }
    if args.pthread { cmd.arg("-pthread"); }
    for f in effective_dep_flags(args) { cmd.arg(f); }
    let status = cmd.status()?;
    if status.success() { Ok(()) }
    else { Err(format!("assembler failed with exit code {:?}", status.code()).into()) }
}

/// Compile one C source through the front end to an IR module.
fn build_ir(path: &str, args: &Args) -> Result<sic_ir::Module, Box<dyn std::error::Error>> {
    // Forward dependency-generation flags (`-MD`/`-MF`/...) so cpp writes the
    // `.d` file as a side effect of preprocessing.
    let dep_owned = effective_dep_flags(args);
    let mut extra: Vec<&str> = dep_owned.iter().map(|s| s.as_str()).collect();
    // `-pthread` compiles with `_REENTRANT` defined.
    if args.pthread {
        extra.push("-D_REENTRANT");
    }
    let preprocessed = preprocess_ex(path, &args.defines, &args.includes, &args.std, &extra)
        .map_err(|e| format!("{}", e))?;

    // Pick the source language from the file extension: `.sic` is sic-lang (its
    // Rust-style primitive aliases `i32`/`u64`/`isize`/… are reserved types);
    // everything else is C, where those names are ordinary identifiers.
    let lang = if path.to_ascii_lowercase().ends_with(".sic") {
        sic_frontend::Lang::Sic
    } else {
        sic_frontend::Lang::C
    };
    let mut lexer = Lexer::new_lang(&preprocessed, HashSet::new(), lang);
    let tokens = lexer.tokenize().map_err(|e| format!("{}", e))?;

    let mut parser = Parser::new_lang(tokens, path.to_string(), lang);
    let mut tu = parser.parse().map_err(|e| format!("{}", e))?;

    if args.ast {
        eprintln!("{:#?}", tu);
    }

    if opt_runs_constfold(&args.opt) {
        ConstFold::fold_tu(&mut tu);
    }

    let module_name = PathBuf::from(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("module")
        .to_string();

    let mut lowerer = Lowerer::new(module_name);
    // `.sic` REPL inputs may synthesize a `main` from top-level statements; a C
    // translation unit must define `main` itself.
    lowerer.set_repl_main(lang == sic_frontend::Lang::Sic);
    let mut ir_module = lowerer.lower(&tu).map_err(|e| format!("{}", e))?;
    ir_module.source_file = Some(path.to_string());

    if args.debug {
        eprintln!("{}", print_module(&ir_module));
    }
    Ok(ir_module)
}

/// Compile one C source all the way to object-file bytes.
fn compile_source(path: &str, args: &Args) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ir_module = build_ir(path, args)?;
    let mut backend = CraneliftBackend::new()
        .with_opt_level(opt_cranelift_level(&args.opt))
        .with_debug_info(args.debug_info);
    backend.compile_module(&ir_module)
        .map_err(|e| format!("codegen error: {}", e).into())
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.debug && !args.f_options.is_empty() {
        eprintln!("-f options: {:?}", args.f_options);
    }

    // Split inputs into C sources (compiled) and object files (linked as-is).
    let sources: Vec<&String> = args.filenames.iter().filter(|f| !is_link_input(f)).collect();
    let objects: Vec<&String> = args.filenames.iter().filter(|f| is_link_input(f)).collect();

    // ── Preprocess only (-E / -dM ...) or dependency-only (-M / -MM) ────────────
    if args.preprocess_only || args.deps_only || args.dump_flag.is_some() {
        // Forward a `-d<letters>` dump flag and any dependency-generation flags
        // (`-M`, `-MF <file>`, `-MT`, ...) to cpp verbatim.
        let dep_owned = effective_dep_flags(args);
        let mut extra: Vec<&str> = args.dump_flag.as_deref().into_iter().collect();
        extra.extend(dep_owned.iter().map(|s| s.as_str()));
        let mut out_text = String::new();
        for src in &sources {
            out_text.push_str(&preprocess_ex(src, &args.defines, &args.includes, &args.std, &extra)
                .map_err(|e| format!("{}", e))?);
        }
        // With `-MF`/`-o` cpp writes to that file itself; otherwise emit here.
        match &args.output {
            Some(o) if o != "-" => fs::write(o, out_text)?,
            _ => print!("{}", out_text),
        }
        return Ok(());
    }

    // ── Emit IR (-S) ───────────────────────────────────────────────────────────
    if args.emit_ir {
        for src in &sources {
            let ir_module = build_ir(src, args)?;
            let ir_text = print_module(&ir_module);
            match &args.output {
                Some(out) if sources.len() == 1 => fs::write(out, &ir_text)?,
                _ => print!("{}", ir_text),
            }
        }
        return Ok(());
    }

    // ── Emit object (-c) ───────────────────────────────────────────────────────
    if args.emit_obj {
        if args.output.is_some() && sources.len() > 1 {
            return Err("cannot specify -o with -c and multiple source files".into());
        }
        for src in &sources {
            let obj_path = match &args.output {
                Some(out) => out.clone(),
                // default: foo.c → foo.o
                None => PathBuf::from(src).with_extension("o").to_string_lossy().into_owned(),
            };
            if is_assembly(src) {
                assemble_source(src, &obj_path, args)?;
                continue;
            }
            let obj_bytes = compile_source(src, args)?;
            fs::write(&obj_path, &obj_bytes)?;
        }
        return Ok(());
    }

    // ── Link ───────────────────────────────────────────────────────────────────
    let cc = resolve_linker();

    // Collect linker pass-through flags: search paths, libraries, and `-Wl,`.
    let mut link_flags: Vec<String> = Vec::new();
    // `-pthread` links the pthread library (the driver handles the specifics).
    if args.pthread {
        link_flags.push("-pthread".to_string());
    }
    for dir in &args.lib_dirs {
        link_flags.push(format!("-L{}", dir));
    }
    for lib in &args.libs {
        link_flags.push(format!("-l{}", lib));
    }
    // `-Wl,a,b,c` passes a, b, c straight through to the linker.
    for w in &args.warnings {
        if let Some(rest) = w.strip_prefix("l,") {
            for opt in rest.split(',') {
                link_flags.push(format!("-Wl,{}", opt));
            }
        }
    }

    // No input files: this is a linker query/utility invocation such as
    // `-Wl,--version` (which asks the linker to print its version and exit).
    // Forward the linker flags to the driver and let it respond, like gcc/clang.
    if sources.is_empty() && objects.is_empty() {
        if link_flags.is_empty() {
            return Err("no input files".into());
        }
        let status = Command::new(&cc).args(&link_flags).status()?;
        return if status.success() {
            Ok(())
        } else {
            Err(format!("linker failed with exit code {:?}", status.code()).into())
        };
    }

    // Compile each source to a temp object; keep the handles alive until linking.
    let mut tmp_objs: Vec<tempfile::NamedTempFile> = Vec::new();
    for src in &sources {
        let mut tmp = tempfile::Builder::new().suffix(".o").tempfile()?;
        if is_assembly(src) {
            assemble_source(src, &tmp.path().to_string_lossy(), args)?;
        } else {
            let obj_bytes = compile_source(src, args)?;
            tmp.write_all(&obj_bytes)?;
        }
        tmp_objs.push(tmp);
    }

    let out_path = args.output.as_deref().unwrap_or("a.out");
    let mut link = Command::new(&cc);

    // Compiled sources (temp objects) and user-provided object files.
    for tmp in &tmp_objs {
        link.arg(tmp.path());
    }
    for obj in &objects {
        link.arg(obj);
    }
    link.arg("-o").arg(out_path);

    // Produce a shared object rather than an executable.
    if args.shared {
        link.arg("-shared");
    }

    // Preserve debug info through the link step when `-g` was requested.
    if args.debug_info {
        link.arg("-g");
    }

    link.args(&link_flags);

    let status = link.status()?;
    if !status.success() {
        return Err(format!("linker failed with exit code {:?}", status.code()).into());
    }

    Ok(())
}
