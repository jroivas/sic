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
