use std::process::Command;
use crate::{Result, CompileError};

/// Run the system C preprocessor on `file`, returning the preprocessed text.
pub fn preprocess(
    file: &str,
    defines: &[String],
    include_dirs: &[String],
) -> Result<String> {
    let mut cmd = Command::new("cpp");
    cmd.arg("-undef");
    cmd.arg("-std=c99");
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

    for d in defines {
        cmd.arg(format!("-D{}", d));
    }
    for i in include_dirs {
        cmd.arg(format!("-I{}", i));
    }

    cmd.arg(file);

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

    defs
}
