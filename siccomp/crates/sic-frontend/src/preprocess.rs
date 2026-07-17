use std::process::Command;
use crate::{Result, CompileError};

/// Run the system C preprocessor on `file`, returning the preprocessed text.
pub fn preprocess(
    file: &str,
    defines: &[String],
    include_dirs: &[String],
    std: &str,
) -> Result<String> {
    preprocess_ex(file, defines, include_dirs, std, &[])
}

/// Like [`preprocess`], but forwards extra flags to `cpp` (e.g. `-dM` to dump
/// macro definitions). Used to implement the driver's `-E`/`-dM` options.
pub fn preprocess_ex(
    file: &str,
    defines: &[String],
    include_dirs: &[String],
    std: &str,
    extra_flags: &[&str],
) -> Result<String> {
    let mut cmd = Command::new("cpp");
    cmd.arg("-undef");
    // Default to C23 so newer library features (e.g. C23's `timespec_get`
    // bases like `TIME_MONOTONIC`) are exposed by the system headers. Callers
    // can request an older standard via `-std=` (e.g. `c99`, `c11`).
    cmd.arg(format!("-std={}", std));
    // Define common macros that tests rely on
    cmd.arg("-DNULL=((void*)0)");
    cmd.arg("-D__attribute__(x)=");

    // `-undef` strips the compiler's predefined target macros, but system
    // headers (e.g. <gnu/stubs.h>) branch on them to pick the right ABI
    // variant. Re-supply the ones describing *this* build's target so the
    // headers resolve to the matching (64-bit) stubs instead of stubs-32.h.
    for m in target_predefines() {
        cmd.arg(format!("-D{}", m));
    }

    // `-undef` also strips numeric/type predefined macros like `__INT_MAX__`,
    // `__LONG_LONG_MAX__`, `__SIZEOF_LONG__`, and `__*_TYPE__` that <limits.h>,
    // <stdint.h>, <float.h> etc. rely on. Re-supply them from the host compiler
    // (filtered to safe value-only macros — never feature flags like __GNUC__).
    for (name, value) in host_numeric_predefines(std) {
        cmd.arg(format!("-D{}={}", name, value));
    }

    for d in defines {
        cmd.arg(format!("-D{}", d));
    }
    for i in include_dirs {
        cmd.arg(format!("-I{}", i));
    }

    for f in extra_flags {
        cmd.arg(f);
    }

    cmd.arg(file);

    // For `-` (read from standard input), `cpp` must see our stdin. `Command`'s
    // `output()` otherwise defaults stdin to null, so the child would read EOF.
    if file == "-" {
        cmd.stdin(std::process::Stdio::inherit());
    }

    let output = cmd.output().map_err(|e| {
        CompileError::new(format!("failed to run cpp: {}", e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CompileError::new(format!("preprocessor error:\n{}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Target-describing predefined macros for the host this compiler was built
/// for. Mirrors what GCC/Clang would define so `-undef`'d system headers pick
/// the correct ABI branch (e.g. `<gnu/stubs.h>` → `stubs-64.h`).
fn target_predefines() -> Vec<&'static str> {
    let mut defs = Vec::new();

    #[cfg(target_arch = "x86_64")]
    {
        defs.push("__x86_64__");
        defs.push("__x86_64");
        defs.push("__amd64__");
        defs.push("__amd64");
        #[cfg(target_pointer_width = "64")]
        {
            defs.push("__LP64__");
            defs.push("_LP64");
        }
    }

    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    {
        defs.push("__aarch64__");
        defs.push("__LP64__");
        defs.push("_LP64");
    }

    // Operating-system predefines. `-undef` strips these too, but programs very
    // commonly branch on them (`#ifdef __linux__`, `_WIN32`, `__unix__`, ...).
    // Define the set matching the OS this compiler runs on, mirroring GCC/Clang.
    #[cfg(target_os = "linux")]
    {
        defs.push("__linux__");
        defs.push("__linux");
        defs.push("__gnu_linux__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(target_os = "macos")]
    {
        defs.push("__APPLE__");
        defs.push("__MACH__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(target_os = "windows")]
    {
        defs.push("_WIN32");
        #[cfg(target_pointer_width = "64")]
        {
            defs.push("_WIN64");
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        defs.push("__FreeBSD__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(target_os = "openbsd")]
    {
        defs.push("__OpenBSD__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(target_os = "netbsd")]
    {
        defs.push("__NetBSD__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(target_os = "dragonfly")]
    {
        defs.push("__DragonFly__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    {
        defs.push("__sun__");
        defs.push("__sun");
        defs.push("__svr4__");
        defs.push("__unix__");
        defs.push("__unix");
    }
    #[cfg(target_os = "emscripten")]
    {
        defs.push("__EMSCRIPTEN__");
        defs.push("EMSCRIPTEN");
    }

    defs
}

/// Query the host C compiler for its predefined macros and return the safe,
/// value-only numeric/type ones (limits, type sizes, underlying types, byte
/// order). These are needed by `<limits.h>`, `<stdint.h>`, `<float.h>` etc. but
/// are stripped by `-undef`. Feature-flag macros (`__GNUC__`, `__STDC_*`,
/// `__has_*`, ...) are deliberately excluded so we don't re-enable header code
/// paths that assume a full GCC/Clang frontend.
fn host_numeric_predefines(std: &str) -> Vec<(String, String)> {
    let cc = std::env::var("SIC_CC").ok().filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cc".to_string());
    let output = Command::new(&cc)
        .args(["-dM", "-E", &format!("-std={}", std), "-x", "c", "/dev/null"])
        .output();
    let stdout = match output {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(), // best effort: headers may still work
    };

    let mut defs = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        // Lines look like: `#define NAME VALUE` (object-like) or
        // `#define NAME(args) ...` (function-like — skipped).
        let rest = match line.strip_prefix("#define ") {
            Some(r) => r,
            None => continue,
        };
        let (name, value) = match rest.split_once(' ') {
            Some((n, v)) => (n, v),
            None => continue, // valueless (e.g. `#define NAME`) — skip
        };
        if name.contains('(') { continue; } // function-like macro
        if is_safe_predefine(name) {
            defs.push((name.to_string(), value.to_string()));
        }
    }
    defs
}

/// Whether a predefined macro name is a safe value-only numeric/type macro to
/// forward (as opposed to a compiler feature flag).
fn is_safe_predefine(name: &str) -> bool {
    name == "__CHAR_BIT__"
        || name == "__BYTE_ORDER__"
        || name == "__FLOAT_WORD_ORDER__"
        || name.starts_with("__ORDER_")
        || name.starts_with("__SIZEOF_")
        // Memory-order constants for the `__atomic_*` builtins (integer 0..5).
        || name.starts_with("__ATOMIC_")
        || name.ends_with("_MAX__")
        || name.ends_with("_MIN__")
        || name.ends_with("_WIDTH__")
        || name.ends_with("_TYPE__")
}
