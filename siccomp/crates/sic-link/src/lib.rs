//! sic's link driver.
//!
//! A C compiler driver (`cc`) does two things when it links: it works out the
//! *system* part of the link — the C runtime start files, the dynamic loader,
//! the library search paths, a compiler runtime for helper routines — and then
//! runs a linker with that full `ld` command line. sic does the first part
//! itself (here) and runs the linker:
//!
//!   * **wild** in-process (the default; Cargo feature `wild`), a pure-Rust
//!     linker used as a library — no external tools needed;
//!   * any external ld-compatible linker when `SIC_LD=/path/to/ld` is set (GNU
//!     ld, ld.lld, mold, …), given the very same command line.
//!
//! Discovery hard-codes no C library or distribution: the dynamic loader is read
//! from an existing system binary's `PT_INTERP`, the C runtime files are found
//! by probing the library directories for `crt1.o`, and a compiler runtime
//! (libgcc or compiler-rt builtins) is used when one is installed — sic's code
//! only needs it for a few helper calls (128-bit division).
//!
//! The one piece of gcc's start files sic code needs is `__dso_handle` (glibc's
//! `atexit` refers to it); the driver generates that object itself.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A link as a compiler driver sees it.
#[derive(Debug, Default, Clone)]
pub struct LinkRequest {
    /// Output file.
    pub output: String,
    /// Driver-level inputs in command-line order: objects, archives, shared
    /// libraries, `-l<lib>`, `-L<dir>`, `-Wl,<args>`, `-pthread`.
    pub inputs: Vec<String>,
    /// Produce a shared object.
    pub shared: bool,
    /// Link statically.
    pub static_link: bool,
    /// Garbage-collect unreferenced sections (`--gc-sections`).
    pub gc_sections: bool,
}

/// Which linker runs the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// The wild linker, in this process.
    Wild,
    /// An external program taking an `ld` command line.
    External(String),
}

/// The linker to use: `SIC_LD` if set (`wild` selects the built-in one), else
/// wild when compiled in, else the system `ld`.
pub fn backend() -> Backend {
    match std::env::var("SIC_LD").ok().filter(|s| !s.is_empty()) {
        Some(s) if s == "wild" && cfg!(feature = "wild") => Backend::Wild,
        Some(s) => Backend::External(s),
        None if cfg!(feature = "wild") => Backend::Wild,
        None => Backend::External("ld".to_string()),
    }
}

/// A human-readable name for the linker in use (for `-print-prog-name=ld`).
pub fn backend_name() -> String {
    match backend() {
        Backend::Wild => format!("wild {} (built in)", WILD_VERSION),
        Backend::External(p) => p,
    }
}

const WILD_VERSION: &str = "0.10.0";

// ─── System discovery ───────────────────────────────────────────────────────

/// What the link needs from the system.
#[derive(Debug, Clone)]
pub struct Toolchain {
    /// The dynamic loader (`PT_INTERP`), e.g. `/lib64/ld-linux-x86-64.so.2`.
    pub interp: Option<String>,
    /// Directory holding the C runtime start files (`crt1.o`, `crti.o`, …).
    pub crt_dir: Option<PathBuf>,
    /// System library search directories, in order.
    pub lib_dirs: Vec<PathBuf>,
    /// Compiler runtime archive (libgcc.a / libclang_rt.builtins), if any.
    pub rt: Option<PathBuf>,
    /// Unwinder archive for static links (libgcc_eh.a), if any.
    pub rt_eh: Option<PathBuf>,
    /// ld emulation for `-m`.
    pub emulation: Option<&'static str>,
}

/// The system toolchain, discovered once per process.
pub fn toolchain() -> &'static Toolchain {
    static TC: OnceLock<Toolchain> = OnceLock::new();
    TC.get_or_init(discover)
}

fn arch() -> &'static str { std::env::consts::ARCH }

fn discover() -> Toolchain {
    let interp = ["/bin/sh", "/usr/bin/env", "/bin/ls", "/usr/bin/ls"]
        .iter()
        .find_map(|p| read_interp(Path::new(p)));

    // Multiarch directories for this CPU: /usr/lib/<arch>-*-linux-* (Debian,
    // Ubuntu), then the plain layouts (/usr/lib64, /usr/lib, …) and musl's.
    let mut triples: Vec<String> = read_dir_names("/usr/lib")
        .into_iter()
        .filter(|n| n.starts_with(arch()) && n.contains("-linux"))
        .collect();
    triples.sort();
    let mut candidates: Vec<PathBuf> = triples.iter().map(|t| Path::new("/usr/lib").join(t)).collect();
    for d in ["/usr/lib64", "/usr/lib", "/lib64", "/lib", "/usr/lib/musl/lib", "/usr/local/musl/lib"] {
        candidates.push(PathBuf::from(d));
    }
    let crt_dir = candidates.iter().find(|d| d.join("crt1.o").is_file()).cloned();
    let triple: Option<String> = crt_dir.as_ref().and_then(|d| {
        d.parent().filter(|p| p == &Path::new("/usr/lib"))
            .and_then(|_| d.file_name()).map(|n| n.to_string_lossy().into_owned())
    });

    // Library search path, as a gcc driver would give it: the C runtime's own
    // directory first, then the multiarch and plain system directories.
    let mut lib_dirs: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| if p.is_dir() && !lib_dirs.contains(&p) { lib_dirs.push(p) };
    if let Some(d) = &crt_dir { push(d.clone()); }
    if let Some(t) = &triple {
        push(Path::new("/lib").join(t));
        push(Path::new("/usr/lib").join(t));
    }
    for d in ["/lib64", "/usr/lib64", "/lib", "/usr/lib"] { push(PathBuf::from(d)); }

    let (rt, rt_eh) = find_compiler_runtime(triple.as_deref());
    let emulation = match arch() {
        "x86_64" => Some("elf_x86_64"),
        "aarch64" => Some("aarch64linux"),
        "riscv64" => Some("elf64lriscv"),
        _ => None,
    };
    Toolchain { interp, crt_dir, lib_dirs, rt, rt_eh, emulation }
}

/// The `PT_INTERP` (dynamic loader path) of a 64-bit little-endian ELF binary.
fn read_interp(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 { return None; }
    let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap()) as usize;
    let (phoff, phentsize, phnum) = (u64_at(0x20), u16_at(0x36), u16_at(0x38));
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if ph + 56 > data.len() { return None; }
        if u32_at(ph) == 3 {
            let (off, size) = (u64_at(ph + 8), u64_at(ph + 32));
            let bytes = data.get(off..off + size)?;
            let s = bytes.split(|b| *b == 0).next()?;
            return String::from_utf8(s.to_vec()).ok();
        }
    }
    None
}

fn read_dir_names(dir: &str) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

/// Compare dotted version strings numerically ("12.2.0" < "15").
fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0)).collect()
}

/// A compiler runtime archive for the host: gcc's libgcc.a (newest version,
/// the host triple preferred over other triples of this CPU — never a cross
/// toolchain's), else LLVM compiler-rt builtins.
fn find_compiler_runtime(triple: Option<&str>) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut best: Option<(u8, Vec<u64>, PathBuf)> = None;
    for root in ["/usr/lib/gcc", "/usr/lib64/gcc", "/usr/local/lib/gcc"] {
        for t in read_dir_names(root) {
            let rank = if Some(t.as_str()) == triple { 2 }
                else if t.starts_with(arch()) && t.contains("linux") { 1 }
                else { 0 };
            if rank == 0 { continue; }
            for v in read_dir_names(&format!("{}/{}", root, t)) {
                let dir = Path::new(root).join(&t).join(&v);
                if !dir.join("libgcc.a").is_file() { continue; }
                let key = version_key(&v);
                if best.as_ref().map_or(true, |(r, k, _)| (rank, &key) > (*r, k)) {
                    best = Some((rank, key, dir));
                }
            }
        }
    }
    if let Some((_, _, dir)) = best {
        let eh = dir.join("libgcc_eh.a");
        return (Some(dir.join("libgcc.a")), eh.is_file().then_some(eh));
    }
    // compiler-rt: /usr/lib/clang/<v>/lib/linux/libclang_rt.builtins-<arch>.a
    // or …/lib/<triple>/libclang_rt.builtins.a (also under /usr/lib/llvm-*/).
    let mut roots: Vec<PathBuf> = vec![PathBuf::from("/usr/lib/clang")];
    for n in read_dir_names("/usr/lib") {
        if n.starts_with("llvm") { roots.push(Path::new("/usr/lib").join(n).join("lib/clang")); }
    }
    let mut found: Option<(Vec<u64>, PathBuf)> = None;
    for root in roots {
        for v in read_dir_names(&root.to_string_lossy()) {
            let base = root.join(&v).join("lib");
            let mut cands = vec![base.join("linux").join(format!("libclang_rt.builtins-{}.a", arch()))];
            if let Some(t) = triple { cands.push(base.join(t).join("libclang_rt.builtins.a")); }
            for c in cands {
                if c.is_file() && found.as_ref().map_or(true, |(k, _)| version_key(&v) > *k) {
                    found = Some((version_key(&v), c));
                }
            }
        }
    }
    (found.map(|(_, p)| p), None)
}

// ─── The `__dso_handle` object ──────────────────────────────────────────────

/// An object defining `__dso_handle` (hidden, pointing at itself), the one
/// symbol from gcc's crtbegin that C code linked against glibc needs: its
/// `atexit` registers handlers with `__cxa_atexit(fn, arg, __dso_handle)`.
fn dso_handle_object() -> Result<Vec<u8>, String> {
    use object::write::{Object, Relocation, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags,
                 RelocationKind, SymbolFlags, SymbolKind, SymbolScope};
    let arch = match arch() {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        "riscv64" => Architecture::Riscv64,
        a => return Err(format!("sic-link: unsupported architecture {}", a)),
    };
    let mut obj = Object::new(BinaryFormat::Elf, arch, Endianness::Little);
    let data = obj.section_id(object::write::StandardSection::Data);
    let off = obj.append_section_data(data, &[0u8; 8], 8);
    let sym = obj.add_symbol(Symbol {
        name: b"__dso_handle".to_vec(),
        value: off,
        size: 8,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,   // global, hidden
        weak: false,
        section: SymbolSection::Section(data),
        flags: SymbolFlags::None,
    });
    obj.add_relocation(data, Relocation {
        offset: off,
        symbol: sym,
        addend: 0,
        flags: RelocationFlags::Generic {
            kind: RelocationKind::Absolute,
            encoding: RelocationEncoding::Generic,
            size: 64,
        },
    }).map_err(|e| e.to_string())?;
    obj.write().map_err(|e| e.to_string())
}

// ─── The ld command line ────────────────────────────────────────────────────

/// Expand driver-level tokens into ld arguments: `-Wl,a,b` → `a b`,
/// `-pthread` → `-lpthread`; `-static` is a mode, not an input.
fn ld_inputs(tokens: &[String]) -> (Vec<String>, Vec<String>) {
    let mut search = Vec::new();   // -L…, which apply globally: put first
    let mut rest = Vec::new();
    for t in tokens {
        if let Some(w) = t.strip_prefix("-Wl,") {
            rest.extend(w.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()));
        } else if t == "-pthread" || t == "-pthreads" {
            rest.push("-lpthread".to_string());
        } else if t == "-static" {
        } else if t.starts_with("-L") {
            search.push(t.clone());
        } else {
            rest.push(t.clone());
        }
    }
    (search, rest)
}

/// The full ld command line for `req` (without argv[0]). `dso` is the path of
/// the `__dso_handle` object.
pub fn ld_args(req: &LinkRequest, tc: &Toolchain, dso: &Path) -> Result<Vec<String>, String> {
    let crt = |name: &str| -> Result<String, String> {
        let d = tc.crt_dir.as_ref().ok_or("sic-link: no C runtime start files (crt1.o) found")?;
        Ok(d.join(name).to_string_lossy().into_owned())
    };
    let pie = !req.shared && !req.static_link;
    let mut a: Vec<String> = Vec::new();
    a.push("--build-id".into());
    a.push("--eh-frame-hdr".into());
    if let Some(m) = tc.emulation { a.push("-m".into()); a.push(m.into()); }
    a.push("--hash-style=gnu".into());
    if req.shared {
        a.push("-shared".into());
    } else if req.static_link {
        a.push("-static".into());
    } else {
        a.push("-pie".into());
        let interp = tc.interp.as_ref().ok_or("sic-link: cannot determine the dynamic loader")?;
        a.push("-dynamic-linker".into());
        a.push(interp.clone());
    }
    for z in ["now", "relro"] { a.push("-z".into()); a.push(z.into()); }
    a.push("-o".into());
    a.push(req.output.clone());

    // Start files.
    if !req.shared {
        let first = if pie && tc.crt_dir.as_ref().map_or(false, |d| d.join("Scrt1.o").is_file()) { "Scrt1.o" } else { "crt1.o" };
        a.push(crt(first)?);
    }
    a.push(crt("crti.o")?);
    a.push(dso.to_string_lossy().into_owned());

    // Search paths: the request's own first, then the system's.
    let (search, rest) = ld_inputs(&req.inputs);
    a.extend(search);
    for d in &tc.lib_dirs { a.push(format!("-L{}", d.display())); }

    a.extend(rest);
    if req.gc_sections { a.push("--gc-sections".into()); }

    // The C library, with the compiler runtime around it (libc itself may need
    // a helper; objects need it for e.g. 128-bit division).
    let rt: Vec<String> = tc.rt.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    if req.static_link {
        a.push("--start-group".into());
        a.extend(rt.iter().cloned());
        if let Some(eh) = &tc.rt_eh { a.push(eh.to_string_lossy().into_owned()); }
        a.push("-lc".into());
        a.push("--end-group".into());
    } else {
        a.extend(rt.iter().cloned());
        a.push("-lc".into());
        a.extend(rt.iter().cloned());
    }
    a.push(crt("crtn.o")?);
    Ok(a)
}

// ─── Running the linker ─────────────────────────────────────────────────────

/// Link `req`.
pub fn link(req: &LinkRequest) -> Result<(), String> {
    let tc = toolchain();
    let dir = std::env::temp_dir();
    let dso = dir.join(format!("sic-dso-{}.o", std::process::id()));
    std::fs::write(&dso, dso_handle_object()?).map_err(|e| format!("sic-link: {}: {}", dso.display(), e))?;
    let res = ld_args(req, tc, &dso).and_then(|args| run_linker(&args));
    let _ = std::fs::remove_file(&dso);
    res
}

/// Run the linker with raw ld arguments (also used for queries such as
/// `-Wl,--version` with no inputs).
pub fn run_linker(args: &[String]) -> Result<(), String> {
    if std::env::var_os("SIC_LINK_VERBOSE").is_some() {
        eprintln!("sic-link: {} {}", backend_name(), args.join(" "));
    }
    match backend() {
        Backend::Wild => run_wild(args),
        Backend::External(prog) => {
            let status = std::process::Command::new(&prog).args(args).status()
                .map_err(|e| format!("sic-link: cannot run {}: {}", prog, e))?;
            if status.success() { Ok(()) }
            else { Err(format!("linker {} failed with exit code {:?}", prog, status.code())) }
        }
    }
}

#[cfg(feature = "wild")]
fn run_wild(args: &[String]) -> Result<(), String> {
    let argv: Vec<String> = std::iter::once("ld.wild".to_string()).chain(args.iter().cloned()).collect();
    let mut parsed = libwild::Args::new(|| argv.iter()).map_err(|e| format!("wild: {:?}", e))?;
    parsed.set_version(WILD_VERSION);
    parsed.parse(|| argv.iter()).map_err(|e| format!("wild: {:?}", e))?;
    libwild::run(parsed).map_err(|e| format!("wild: {:?}", e))
}

#[cfg(not(feature = "wild"))]
fn run_wild(_args: &[String]) -> Result<(), String> {
    Err("sic was built without the wild linker; set SIC_LD to an ld-compatible linker".into())
}

/// Turn driver-level linker query tokens (`-Wl,--version`) into ld arguments.
pub fn query_args(tokens: &[String]) -> Vec<String> {
    let (mut s, r) = ld_inputs(tokens);
    s.extend(r);
    s
}
