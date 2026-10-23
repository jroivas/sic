use std::process::Command;
use crate::{Result, CompileError};

/// The C preprocessor to run, resolved once per process:
///   1. `SIC_CPP` from the environment, when set (an explicit override wins);
///   2. `sic-cpp` found on `PATH` (an installed sic toolchain);
///   3. `sic-cpp/sic-cpp` of the sic repository this compiler was built in —
///      the binary lives at `<repo>/siccomp/target/<profile>/sic`, so that is
///      `<exe dir>/../../../sic-cpp/sic-cpp`;
///   4. the system `cpp`.
///
/// The preprocessor must accept GCC `cpp`'s command line
/// (`cpp -DNAME[=val] -UNAME -Idir -std=std [-undef] … file`) and write the
/// preprocessed text to stdout.
pub fn preprocessor_bin() -> String {
    static BIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(v) = std::env::var("SIC_CPP").ok().filter(|s| !s.is_empty()) {
            return v;
        }
        if let Some(p) = find_in_path("sic-cpp") {
            return p;
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let cand = dir.join("../../../sic-cpp/sic-cpp");
                if is_executable(&cand) {
                    if let Ok(c) = cand.canonicalize() { return c.to_string_lossy().into_owned(); }
                }
            }
        }
        "cpp".to_string()
    }).clone()
}

/// Whether `bin` is sic's own preprocessor (by file name), which provides the
/// target/identity macros itself.
pub fn is_sic_cpp(bin: &str) -> bool {
    std::path::Path::new(bin).file_name().map_or(false, |n| n == "sic-cpp")
}

fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map_or(false, |m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `name` resolved against `PATH` (first executable match).
fn find_in_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|c| is_executable(c))
        .map(|c| c.to_string_lossy().into_owned())
}

/// Run the system C preprocessor on `file`, returning the preprocessed text.
pub fn preprocess(
    file: &str,
    defines: &[String],
    include_dirs: &[String],
    std: &str,
) -> Result<String> {
    preprocess_ex(file, defines, include_dirs, std, &[])
}

/// A byte of a string literal's contents, written so the literal means the same.
fn push_literal_char(out: &mut String, c: char) {
    match c {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\t' => out.push_str("\\t"),
        '\r' => out.push_str("\\r"),
        c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\{:03o}", c as u32)),
        c => out.push(c),
    }
}

/// SIC's multiline strings (`"""…"""`, raw `r"""…"""`) span lines, which no C
/// preprocessor knows: it takes their later lines for code — blanks collapse, a
/// `//` reads as a comment, a leading `#` as a directive. Each one is rewritten as
/// the ordinary string literal it denotes, on one line, followed by the newlines
/// it spanned (so every later token keeps its line). None when there is none.
pub fn protect_multiline_strings(src: &str) -> Option<String> {
    let c: Vec<char> = src.chars().collect();
    let triple = |i: usize| c.get(i) == Some(&'"') && c.get(i + 1) == Some(&'"') && c.get(i + 2) == Some(&'"');
    let mut out = String::with_capacity(src.len());
    let mut changed = false;
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        // comments, and ordinary string and character literals, are skipped whole
        if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' { out.push(c[i]); i += 1; }
            continue;
        }
        if ch == '/' && c.get(i + 1) == Some(&'*') {
            out.push_str("/*");
            i += 2;
            while i < c.len() && !(c[i] == '*' && c.get(i + 1) == Some(&'/')) { out.push(c[i]); i += 1; }
            if i < c.len() { out.push_str("*/"); i += 2; }
            continue;
        }
        let ident_before = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
        let raw = ch == 'r' && !ident_before && triple(i + 1);
        if raw || (ch == '"' && triple(i)) {
            let start = if raw { i + 4 } else { i + 3 };
            let mut j = start;
            while j < c.len() && !triple(j) {
                if !raw && c[j] == '\\' { j += 1; }
                j += 1;
            }
            if j >= c.len() {
                return None;            // unterminated: the lexer reports it
            }
            let body = &c[start..j];
            let mut lit = String::from("\"");
            if raw {
                for &b in body { push_literal_char(&mut lit, b); }
            } else {
                // as the lexer reads it: a newline and the indentation after it
                // are one space; escapes keep their meaning
                let (mut k, mut pending, mut any) = (0, false, false);
                while k < body.len() {
                    let b = body[k];
                    if b == '\n' { pending = true; k += 1; continue; }
                    if pending {
                        if b == ' ' || b == '\t' || b == '\r' { k += 1; continue; }
                        if any { lit.push(' '); }
                        pending = false;
                    }
                    any = true;
                    if b == '\\' && k + 1 < body.len() {
                        let e = body[k + 1];
                        if (e as u32) < 0x20 { push_literal_char(&mut lit, e); } else { lit.push('\\'); lit.push(e); }
                        k += 2;
                        continue;
                    }
                    push_literal_char(&mut lit, b);
                    k += 1;
                }
            }
            lit.push('"');
            out.push_str(&lit);
            for _ in body.iter().filter(|&&b| b == '\n') { out.push('\n'); }
            changed = true;
            i = j + 3;
            continue;
        }
        if ch == '"' || ch == '\'' {
            out.push(ch);
            i += 1;
            while i < c.len() && c[i] != ch && c[i] != '\n' {
                if c[i] == '\\' && i + 1 < c.len() { out.push(c[i]); i += 1; }
                out.push(c[i]);
                i += 1;
            }
            if i < c.len() && c[i] == ch { out.push(ch); i += 1; }
            continue;
        }
        out.push(ch);
        i += 1;
    }
    changed.then_some(out)
}

/// The source path into a `.d` dependency list made from standard input (the
/// preprocessor read the file's protected text there, see
/// [`protect_multiline_strings`]): in place of `<stdin>`, or first.
fn fix_stdin_dependency(deps: &str, path: &str) -> String {
    if deps.contains("<stdin>") {
        return deps.replace("<stdin>", path);
    }
    match deps.find(": ") {
        Some(k) => format!("{}: {} {}", &deps[..k], path, &deps[k + 2..]),
        None => deps.to_string(),
    }
}

/// Like [`preprocess`], but forwards extra flags to the preprocessor (e.g. `-dM` to dump
/// macro definitions). Used to implement the driver's `-E`/`-dM` options.
pub fn preprocess_ex(
    file: &str,
    defines: &[String],
    include_dirs: &[String],
    std: &str,
    extra_flags: &[&str],
) -> Result<String> {
    // A sic started by sic-cpp (to ask for its info) must never start a
    // preprocessor: with `CC=sic` that was sic -> sic-cpp -> sic -> ... forever.
    if crate::cpp_info::in_recursion() {
        return Err(CompileError::new(format!(
            "refusing to preprocess '{}': {} is set or sic was started by sic-cpp \
             (sic and sic-cpp would call each other recursively)",
            file, crate::cpp_info::RECURSION_ENV)));
    }
    let bin = preprocessor_bin();

    let mut cmd = Command::new(&bin);
    // Everything the preprocessor needs, from sic itself (sic-cpp then runs no
    // host-compiler queries); and the recursion marker for anything it starts.
    cmd.env(crate::cpp_info::INFO_ENV, crate::cpp_info::info_text());
    cmd.env(crate::cpp_info::RECURSION_ENV, "1");
    cmd.arg("-undef");
    // Default to C23 so newer library features (e.g. C23's `timespec_get`
    // bases like `TIME_MONOTONIC`) are exposed by the system headers. Callers
    // can request an older standard via `-std=` (e.g. `c99`, `c11`).
    cmd.arg(format!("-std={}", std));
    // Define common macros that tests rely on
    cmd.arg("-DNULL=((void*)0)");
    // NB: `__attribute__` is NOT stripped — the parser skips attributes in every
    // position itself (`skip_attributes`) and captures `vector_size(N)` to size
    // SIMD vector types. Most attributes are parsed then discarded.

    // `-undef` strips the compiler's predefined target macros, but system
    // headers (e.g. <gnu/stubs.h>) branch on them to pick the right ABI
    // variant. Re-supply the ones describing *this* build's target so the
    // headers resolve to the matching (64-bit) stubs instead of stubs-32.h.
    for m in target_predefines() {
        cmd.arg(format!("-D{}", m));
    }

    // When using the system `cpp`, also re-supply host numeric predefines
    // and compiler-identity predefines (the sic-cpp built-in already defines
    // its own set of predefined macros, so we skip these extra flags to avoid
    // redefinition noise).
    if !is_sic_cpp(&bin) {
        for (name, value) in host_numeric_predefines(std) {
            cmd.arg(format!("-D{}={}", name, value));
        }
        for (name, value) in compiler_identity_predefines() {
            cmd.arg(format!("-D{}={}", name, value));
        }
    }

    for d in defines {
        cmd.arg(format!("-D{}", d));
    }
    // Now that we advertise `__GNUC__`, glibc would turn on `_FORTIFY_SOURCE`,
    // rewriting libc calls into `__*_chk` builtins (`__builtin_object_size`,
    // `__builtin___memcpy_chk`, …) that sic doesn't implement. Force fortify off
    // (after user `-D` so it wins). The unfortified calls are equivalent.
    cmd.arg("-U_FORTIFY_SOURCE");
    cmd.arg("-D_FORTIFY_SOURCE=0");
    for i in include_dirs {
        cmd.arg(format!("-I{}", i));
    }

    // A SIC source with multiline strings goes in protected (through standard
    // input, named by a #line, its directory still searched for "includes").
    let protected = if file != "-" && file.to_ascii_lowercase().ends_with(".sic") {
        std::fs::read_to_string(file).ok().and_then(|t| protect_multiline_strings(&t))
    } else {
        None
    };
    if protected.is_some() {
        let dir = std::path::Path::new(file).parent()
            .map(|d| d.to_string_lossy().into_owned()).filter(|d| !d.is_empty())
            .unwrap_or_else(|| ".".to_string());
        cmd.arg("-iquote");
        cmd.arg(dir);
    }

    for f in extra_flags {
        cmd.arg(f);
    }

    let output = if let Some(text) = &protected {
        cmd.arg("-");
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| CompileError::new(format!("failed to run {}: {}", bin, e)))?;
        let input = format!("#line 1 \"{}\"\n{}", file.replace('\\', "\\\\").replace('"', "\\\""), text);
        let mut stdin = child.stdin.take().expect("piped stdin");
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(input.as_bytes());
        });
        let out = child.wait_with_output().map_err(|e| CompileError::new(format!("failed to run {}: {}", bin, e)))?;
        let _ = writer.join();
        out
    } else {
        cmd.arg(file);
        // For `-` (read from standard input), the preprocessor must see our stdin.
        if file == "-" {
            cmd.stdin(std::process::Stdio::inherit());
        }
        cmd.output().map_err(|e| CompileError::new(format!("failed to run {}: {}", bin, e)))?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CompileError::new(format!("preprocessor ({}) error:\n{}", bin, stderr)));
    }

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if protected.is_some() {
        // The dependencies were read from standard input: name the source.
        let mf = extra_flags.iter().position(|f| *f == "-MF").and_then(|k| extra_flags.get(k + 1).map(|s| s.to_string()))
            .or_else(|| extra_flags.iter().find_map(|f| f.strip_prefix("-MF").filter(|p| !p.is_empty()).map(|p| p.to_string())));
        if let Some(d) = mf {
            if let Ok(deps) = std::fs::read_to_string(&d) {
                let _ = std::fs::write(&d, fix_stdin_dependency(&deps, file));
            }
        } else if extra_flags.iter().any(|f| *f == "-M" || *f == "-MM") {
            text = fix_stdin_dependency(&text, file);
        }
    }
    Ok(text)
}

/// Target-describing predefined macros for the host this compiler was built
/// for. Mirrors what GCC/Clang would define so `-undef`'d system headers pick
/// the correct ABI branch (e.g. `<gnu/stubs.h>` → `stubs-64.h`).
pub(crate) fn target_predefines() -> Vec<&'static str> {
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

/// Compiler-identity predefines. sic is neither GCC nor Clang, but many programs
/// refuse to build unless they recognize a compiler of a sufficient version
/// (e.g. QEMU errors out unless `__clang_major__ >= 10`). We advertise Clang
/// 15.0.0.
///
/// We deliberately DO NOT also define `__GNUC__`, even though a real Clang does.
/// `__GNUC__` gates glibc/library headers into GNU code paths that emit builtins
/// sic doesn't implement yet (`__builtin_clz`, the `__extension__ ({...})`
/// statement-expression form of `assert`, etc.). Advertising just the Clang
/// version satisfies the common minimum-compiler checks without turning those on.
fn compiler_identity_predefines() -> Vec<(&'static str, &'static str)> {
    vec![
        ("__clang__", "1"),
        ("__clang_major__", "15"),
        ("__clang_minor__", "0"),
        ("__clang_patchlevel__", "0"),
        ("__clang_version__", "\"15.0.0\""),
        ("__VERSION__", "\"Clang 15.0.0\""),
        // A real Clang also defines __GNUC__ (as GCC 4.2.1) for compatibility, and
        // much library code gates GNU extensions (e.g. libslirp's
        // `SLIRP_PACKED_BEGIN/END`, which are ONLY defined under `#ifdef __GNUC__`)
        // on it. Advertise the same low version: `#ifdef __GNUC__` checks pass,
        // while `__GNUC__ >= 7`-style checks for newer-GCC-only header paths stay
        // off. sic implements enough GNU builtins/extensions to handle the rest.
        ("__GNUC__", "4"),
        ("__GNUC_MINOR__", "2"),
        ("__GNUC_PATCHLEVEL__", "1"),
    ]
}

/// The target's safe, value-only numeric/type predefines (limits, type sizes,
/// underlying types, byte order, float properties) from sic's own table — needed
/// by `<limits.h>`, `<stdint.h>`, `<float.h>` etc. but stripped by `-undef`.
/// Feature-flag macros (`__GNUC__`, `__STDC_*`, `__has_*`, ...) are excluded so
/// we don't re-enable header code paths that assume a full GCC/Clang frontend.
fn host_numeric_predefines(_std: &str) -> Vec<(String, String)> {
    crate::cpp_info::target_macros().into_iter()
        .filter(|(n, _)| is_safe_predefine(n))
        .map(|(n, v)| (n.to_string(), v))
        .collect()
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
        // Floating-point property macros used by <float.h>: __FLT_RADIX__,
        // __FLT_MANT_DIG__, __DBL_EPSILON__, __LDBL_MIN_EXP__, … — all numeric.
        || name.starts_with("__FLT")
        || name.starts_with("__DBL_")
        || name.starts_with("__LDBL_")
        || name.starts_with("__DEC")
        || name == "__FLT_RADIX__"
        // Symbol-name prefixes (empty on ELF). glibc builds asm labels with
        // `__ASMNAME (x)` → `__STRING (__USER_LABEL_PREFIX__) "x"`; with the
        // macro missing that became the literal label "__USER_LABEL_PREFIX__x".
        || name == "__USER_LABEL_PREFIX__"
        || name == "__REGISTER_PREFIX__"
        // Atomic ABI of the target (sic's atomics are lock-free): the
        // `__GCC_ATOMIC_*_LOCK_FREE` levels behind <stdatomic.h>'s
        // `ATOMIC_*_LOCK_FREE`, and `__GCC_ATOMIC_TEST_AND_SET_TRUEVAL`, which
        // picks `atomic_flag`'s member type (`_Bool` vs `unsigned char`).
        || name.starts_with("__GCC_ATOMIC_")
}
