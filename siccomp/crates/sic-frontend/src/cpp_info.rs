//! What a C preprocessor needs to know to preprocess for sic — produced by sic
//! itself, with no other toolchain: the system include directories (a
//! filesystem probe), the target's predefined macros (a built-in table) and the
//! answers to `__has_attribute`/`__has_builtin`/… (what sic actually supports).
//!
//! sic hands this to sic-cpp as `SIC_CPP_INFO` (with `SIC_RECURSION=1`); a
//! standalone sic-cpp asks for it with `SIC_RECURSION=1 sic -print-cpp-info`.
//! Line format (one record per line):
//!   include DIR                       system `#include <...>` dir, in order
//!   define NAME VALUE                 predefined object-like macro
//!   has KIND [NAME[=VALUE] ...]       `__has_KIND` exists; listed NAMEs answer
//!                                     VALUE (default 1), all others 0

use std::path::{Path, PathBuf};

/// Set (to "1") in the environment of a preprocessor sic starts, and of the
/// sic a standalone sic-cpp asks for its info: a sic that sees it never starts
/// a preprocessor, so sic and sic-cpp cannot start each other without end.
pub const RECURSION_ENV: &str = "SIC_RECURSION";
/// The [`info_text`] handed to the preprocessor.
pub const INFO_ENV: &str = "SIC_CPP_INFO";

/// The full info text (computed once per process).
pub fn info_text() -> String {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let mut s = String::new();
        for d in system_include_dirs() {
            s.push_str(&format!("include {}\n", d));
        }
        for (n, v) in target_macros() {
            s.push_str(&format!("define {} {}\n", n, v));
        }
        let line = |kind: &str, names: Vec<String>| {
            let mut l = format!("has {}", kind);
            for n in names { l.push(' '); l.push_str(&n); }
            l.push('\n');
            l
        };
        s.push_str(&line("attribute", ATTRIBUTES.iter().map(|a| a.to_string()).collect()));
        // sic does not parse C23 `[[...]]` attributes yet: none are available.
        s.push_str(&line("c_attribute", vec![]));
        s.push_str(&line("cpp_attribute", vec![]));
        s.push_str(&line("builtin", builtin_names()));
        s.push_str(&line("feature", FEATURES.iter().map(|a| a.to_string()).collect()));
        s.push_str(&line("extension", FEATURES.iter().map(|a| a.to_string()).collect()));
        s
    }).clone()
}

/// Whether this sic was started (directly or through `sh -c`) by a sic-cpp,
/// or with `SIC_RECURSION` set. Such a sic must not start a preprocessor.
pub fn in_recursion() -> bool {
    std::env::var_os(RECURSION_ENV).is_some() || spawned_by_sic_cpp()
}

/// Whether a `sic-cpp` process is among our ancestors — catches recursion even
/// when a build tool scrubbed `SIC_RECURSION` from the environment. Linux `/proc`.
fn spawned_by_sic_cpp() -> bool {
    let ppid_of = |pid: u32| -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        // `pid (comm) state ppid ...` — comm may hold spaces/parens: split after the last ')'.
        stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
    };
    let mut pid = std::process::id();
    for _ in 0..64 {
        pid = match ppid_of(pid) { Some(p) if p > 1 => p, _ => return false };
        if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
            if exe.file_name().map_or(false, |n| n == "sic-cpp") { return true; }
        }
    }
    false
}

// ── Include directories ─────────────────────────────────────────────────────

/// Subdirectories of `dir` (sorted; empty if unreadable).
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).map(|rd| {
        rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect()
    }).unwrap_or_default();
    v.sort();
    v
}

fn name_of(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Compare dotted version strings numerically ("12.2.0" < "15").
fn ver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let num = |s: &str| -> Vec<u64> {
        s.split('.').map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>()
            .parse().unwrap_or(0)).collect()
    };
    let (x, y) = (num(a), num(b));
    for i in 0..x.len().max(y.len()) {
        let (p, q) = (x.get(i).copied().unwrap_or(0), y.get(i).copied().unwrap_or(0));
        if p != q { return p.cmp(&q); }
    }
    std::cmp::Ordering::Equal
}

/// The `#include <...>` search list, as gcc would report it: the compiler's
/// builtin-header dir (stddef.h, stdarg.h, … — gcc's, else clang's), then
/// `/usr/local/include`, the multiarch `/usr/include/<triple>`, `/usr/include`.
pub fn system_include_dirs() -> Vec<String> {
    let machine = std::env::consts::ARCH;
    // Multiarch dir: /usr/include/<triple> holding bits/ (glibc) or asm/ (kernel);
    // one for this machine preferred.
    let mut multiarch: Option<String> = None;
    for d in subdirs(Path::new("/usr/include")) {
        let t = name_of(&d);
        if !t.contains('-') || !(d.join("bits").is_dir() || d.join("asm").is_dir()) { continue; }
        let better = match &multiarch {
            None => true,
            Some(m) => t.starts_with(machine) && !m.starts_with(machine),
        };
        if better { multiarch = Some(t); }
    }
    let host = multiarch.clone().unwrap_or_default();

    // gcc's per-triple/per-version include dir: exact multiarch triple first,
    // then any linux triple for this machine, then any for this machine; newest
    // version wins. Cross toolchains for other machines are ignored.
    let mut builtin: Option<(u8, String, PathBuf)> = None;
    for root in ["/usr/lib/gcc", "/usr/lib64/gcc", "/usr/local/lib/gcc"] {
        for tdir in subdirs(Path::new(root)) {
            let triple = name_of(&tdir);
            let rank = if !host.is_empty() && triple == host { 3 }
                else if triple.starts_with(&format!("{}-", machine)) && triple.contains("linux") { 2 }
                else if triple.starts_with(&format!("{}-", machine)) { 1 }
                else { continue };
            for vdir in subdirs(&tdir) {
                let inc = vdir.join("include");
                if !inc.join("stddef.h").is_file() { continue; }
                let ver = name_of(&vdir);
                let better = match &builtin {
                    None => true,
                    Some((r, v, _)) => rank > *r || (rank == *r && ver_cmp(&ver, v).is_gt()),
                };
                if better { builtin = Some((rank, ver, inc)); }
            }
        }
    }
    // Else clang's resource dir (target-independent), newest version.
    if builtin.is_none() {
        let mut roots = vec![PathBuf::from("/usr/lib/clang"), PathBuf::from("/usr/lib64/clang")];
        for d in subdirs(Path::new("/usr/lib")) {
            if name_of(&d).starts_with("llvm") { roots.push(d.join("lib/clang")); }
        }
        for root in roots {
            for vdir in subdirs(&root) {
                let inc = vdir.join("include");
                if !inc.join("stddef.h").is_file() { continue; }
                let ver = name_of(&vdir);
                if builtin.as_ref().map_or(true, |(_, v, _)| ver_cmp(&ver, v).is_gt()) {
                    builtin = Some((0, ver, inc));
                }
            }
        }
    }

    let mut dirs = Vec::new();
    if let Some((_, _, inc)) = builtin { dirs.push(inc.to_string_lossy().into_owned()); }
    if Path::new("/usr/local/include").is_dir() { dirs.push("/usr/local/include".into()); }
    if let Some(m) = multiarch { dirs.push(format!("/usr/include/{}", m)); }
    if Path::new("/usr/include").is_dir() { dirs.push("/usr/include".into()); }
    dirs
}

// ── Predefined target macros ────────────────────────────────────────────────

/// The target's predefined object-like macros: architecture, OS, data model,
/// type sizes/limits/underlying types, float properties, byte order, atomic ABI
/// — what headers branch on. No compiler identity/feature macros (sic-cpp and
/// sic add their own identity).
pub fn target_macros() -> Vec<(&'static str, String)> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        X86_64_LINUX.iter().map(|(n, v)| (*n, v.to_string())).collect()
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        // Other hosts: the data model from this compiler's own types and the
        // arch/OS identification; no limits/float tables (yet).
        let mut v: Vec<(&'static str, String)> = vec![
            ("__CHAR_BIT__", "8".into()),
            ("__SIZEOF_SHORT__", std::mem::size_of::<i16>().to_string()),
            ("__SIZEOF_INT__", std::mem::size_of::<i32>().to_string()),
            ("__SIZEOF_LONG__", std::mem::size_of::<std::os::raw::c_long>().to_string()),
            ("__SIZEOF_LONG_LONG__", "8".into()),
            ("__SIZEOF_POINTER__", std::mem::size_of::<usize>().to_string()),
            ("__SIZEOF_FLOAT__", "4".into()),
            ("__SIZEOF_DOUBLE__", "8".into()),
            ("__ORDER_LITTLE_ENDIAN__", "1234".into()),
            ("__ORDER_BIG_ENDIAN__", "4321".into()),
            ("__ORDER_PDP_ENDIAN__", "3412".into()),
            ("__BYTE_ORDER__", if cfg!(target_endian = "little") { "__ORDER_LITTLE_ENDIAN__" } else { "__ORDER_BIG_ENDIAN__" }.into()),
            ("__USER_LABEL_PREFIX__", "".into()),
        ];
        for m in crate::preprocess::target_predefines() { v.push((m, "1".into())); }
        v
    }
}

include!("cpp_info_x86_64_linux.rs");

// ── `__has_*` answers ───────────────────────────────────────────────────────

/// GCC attributes sic accepts: implemented (aligned, packed, cleanup,
/// vector_size, weak, constructor, sic's struct-order ones) or pure hints whose
/// absence changes no behavior (inlining, warnings, optimization, sanitizers,
/// visibility of an executable's symbols, …). Attributes sic silently ignores
/// although they change behavior (alias, destructor, section, mode, ifunc,
/// weakref, transparent_union, tls_model, …) are NOT listed.
const ATTRIBUTES: &[&str] = &[
    // implemented
    "aligned", "packed", "cleanup", "vector_size", "weak", "constructor",
    "order", "order_c", "order_sic", "order_random",
    // hints
    "access", "alloc_align", "alloc_size", "always_inline", "artificial", "assume",
    "assume_aligned", "cold", "const", "deprecated", "designated_init", "error",
    "externally_visible", "fallthrough", "flag_enum", "flatten", "format", "format_arg",
    "hot", "indirect_return", "leaf", "malloc", "may_alias", "no_address_safety_analysis", "no_icf",
    "no_instrument_function", "no_profile_instrument_function", "no_reorder",
    "no_sanitize", "no_sanitize_address", "no_sanitize_thread", "no_sanitize_undefined",
    "no_split_stack", "no_stack_protector", "noclone", "noinline", "noipa", "nonnull",
    "nonstring", "noplt", "noreturn", "nothrow", "optimize", "pure", "retain",
    "returns_nonnull", "returns_twice", "sentinel", "target", "unavailable",
    "uninitialized", "unused", "used", "visibility", "warn_if_not_aligned",
    "warn_unused_result", "warning",
];

/// `__has_feature` / `__has_extension` answers: the C features sic supports
/// (the set gcc answers 1 for; glibc's C23 `strchr`/`memchr` qualifier-preserving
/// macros key on `c_generic_selections`).
const FEATURES: &[&str] = &[
    "attribute_deprecated_with_message", "attribute_unavailable_with_message", "c_alignas",
    "c_alignof", "c_atomic", "c_generic_selections", "c_static_assert", "c_thread_local",
    "cxx_binary_literals",
];

/// Builtins sic lowers itself (besides the families below).
const BUILTINS: &[&str] = &[
    "__builtin_addc", "__builtin_addcl", "__builtin_addcll", "__builtin_add_overflow",
    "__builtin_alloca", "__builtin_alloca_with_align", "__builtin_assume_aligned",
    "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64", "__builtin_c23_va_start",
    "__builtin_choose_expr", "__builtin_constant_p", "__builtin_dwarf_cfa",
    "__builtin_dynamic_object_size", "__builtin_expect", "__builtin_expect_with_probability",
    "__builtin_extract_return_addr", "__builtin_fpclassify", "__builtin_frame_address",
    "__builtin_frob_return_addr", "__builtin_huge_val", "__builtin_huge_valf",
    "__builtin_huge_vall", "__builtin_ia32_aesdec128", "__builtin_ia32_aesdeclast128",
    "__builtin_ia32_aesenc128", "__builtin_ia32_aesenclast128", "__builtin_ia32_aesimc128",
    "__builtin_ia32_bsfdi", "__builtin_ia32_bsfsi", "__builtin_ia32_bsrdi", "__builtin_ia32_bsrsi",
    "__builtin_ia32_pclmulqdq128", "__builtin_ia32_pcmpeqb128", "__builtin_ia32_pcmpeqb256",
    "__builtin_ia32_pmovmskb128", "__builtin_ia32_pmovmskb256", "__builtin_ia32_pshufb128",
    "__builtin_inf", "__builtin_inff", "__builtin_infl", "__builtin_isfinite",
    "__builtin_isgreater", "__builtin_isgreaterequal", "__builtin_isinf", "__builtin_isinf_sign",
    "__builtin_isless", "__builtin_islessequal", "__builtin_islessgreater", "__builtin_isnan",
    "__builtin_isnormal", "__builtin_isunordered", "__builtin_mul_overflow", "__builtin_nan",
    "__builtin_nanf", "__builtin_nanl", "__builtin_object_size", "__builtin_offsetof",
    "__builtin_prefetch", "__builtin_return_address", "__builtin_signbit", "__builtin_signbitf",
    "__builtin_signbitl", "__builtin_subc", "__builtin_subcl", "__builtin_subcll",
    "__builtin_sub_overflow", "__builtin_types_compatible_p", "__builtin_unreachable",
    "__builtin_va_arg", "__builtin_va_copy", "__builtin_va_end", "__builtin_va_start",
    // atomics (type-generic forms)
    "__atomic_always_lock_free", "__atomic_clear", "__atomic_compare_exchange",
    "__atomic_compare_exchange_n", "__atomic_exchange", "__atomic_exchange_n",
    "__atomic_is_lock_free", "__atomic_load", "__atomic_load_n", "__atomic_signal_fence",
    "__atomic_store", "__atomic_store_n", "__atomic_test_and_set", "__atomic_thread_fence",
    "__sync_bool_compare_and_swap", "__sync_lock_release", "__sync_lock_test_and_set",
    "__sync_synchronize", "__sync_val_compare_and_swap",
];

/// `__builtin_<f>` that sic lowers as the libc function `f` (when `f` is
/// declared, as with its header included).
const LIBC_BUILTINS: &[&str] = &[
    "memcpy", "memmove", "memset", "memcmp", "memchr", "strlen", "strnlen", "strcmp",
    "strncmp", "strcpy", "strncpy", "strcat", "strncat", "strchr", "strrchr", "strstr",
    "strdup", "printf", "fprintf", "sprintf", "snprintf", "vsnprintf", "puts", "putchar",
    "abort", "exit", "malloc", "calloc", "realloc", "free", "abs", "labs", "llabs",
    "fabs", "fabsf", "fabsl", "sqrt", "sqrtf", "floor", "floorf", "ceil", "ceilf", "round",
    "roundf", "trunc", "truncf", "copysign", "copysignf", "fmin", "fmax", "pow", "exp",
    "log", "sin", "cos",
];

/// Every `__has_builtin` name sic answers 1 for.
pub fn builtin_names() -> Vec<String> {
    let mut v: Vec<String> = BUILTINS.iter().map(|s| s.to_string()).collect();
    for base in ["clz", "ctz", "popcount", "ffs", "clrsb", "parity"] {
        for suf in ["", "l", "ll"] { v.push(format!("__builtin_{}{}", base, suf)); }
    }
    for op in ["add", "sub", "or", "and", "xor"] {
        v.push(format!("__atomic_fetch_{}", op));
        v.push(format!("__atomic_{}_fetch", op));
        v.push(format!("__sync_fetch_and_{}", op));
        v.push(format!("__sync_{}_and_fetch", op));
    }
    for f in LIBC_BUILTINS { v.push(format!("__builtin_{}", f)); }
    v
}
