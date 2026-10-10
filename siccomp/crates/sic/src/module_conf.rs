//! `module.conf`: build settings of a folder module (`sic --emit-module DIR`).
//!
//! ```text
//! # module.conf
//! cflags   = -DUSE_X=1 -I/opt/x/include      # compiling the module's sources
//! ldflags  = -lm -L/opt/x/lib                # linking lib<name>.so + consumers
//! packages = zlib libpng                     # pkg-config --cflags / --libs
//! ```
//!
//! One `key = value` per line (`key += value` appends too; a repeated key
//! accumulates). Keys are case-insensitive. Values are split like a shell command
//! line (`'…'`, `"…"` and `\` quote); `#` starts a comment outside quotes. An
//! unknown key is an error, so a typo does not silently drop settings.

use std::path::Path;
use std::process::Command;

/// The settings of one folder module, with `packages` already expanded through
/// pkg-config into `cflags` / `ldflags`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ModuleConf {
    pub cflags: Vec<String>,
    pub ldflags: Vec<String>,
    pub packages: Vec<String>,
}

pub const FILE_NAME: &str = "module.conf";

/// Read `DIR/module.conf` (none → the default, empty settings) and expand its
/// `packages` through pkg-config.
pub fn load(dir: &Path) -> Result<ModuleConf, String> {
    let path = dir.join(FILE_NAME);
    if !path.is_file() {
        return Ok(ModuleConf::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    let mut conf = parse(&text).map_err(|e| format!("{}:{}", path.display(), e))?;
    if !conf.packages.is_empty() {
        let (cflags, libs) = pkg_config(&conf.packages)
            .map_err(|e| format!("{}: {}", path.display(), e))?;
        conf.cflags.extend(cflags);
        conf.ldflags.extend(libs);
    }
    Ok(conf)
}

/// Parse the text of a `module.conf` (no pkg-config expansion). Errors are
/// `"<line>: <message>"`.
pub fn parse(text: &str) -> Result<ModuleConf, String> {
    let mut conf = ModuleConf::default();
    for (i, line) in text.lines().enumerate() {
        let lineno = i + 1;
        let words = split_words(line).map_err(|e| format!("{}: {}", lineno, e))?;
        if words.is_empty() { continue; }
        // `key = value…` / `key += value…`; also `key=value` glued.
        let (key, rest): (String, Vec<String>) = {
            let first = &words[0];
            if let Some(pos) = first.find("+=").or_else(|| first.find('=')) {
                let key = first[..pos].to_string();
                let after = first[pos..].trim_start_matches('+').trim_start_matches('=');
                let mut rest = Vec::new();
                if !after.is_empty() { rest.push(after.to_string()); }
                rest.extend(words[1..].iter().cloned());
                (key, rest)
            } else if words.len() >= 2 && (words[1] == "=" || words[1] == "+=") {
                (first.clone(), words[2..].to_vec())
            } else if words.len() >= 2 && (words[1].starts_with('=') || words[1].starts_with("+=")) {
                let after = words[1].trim_start_matches('+').trim_start_matches('=');
                let mut rest = Vec::new();
                if !after.is_empty() { rest.push(after.to_string()); }
                rest.extend(words[2..].iter().cloned());
                (first.clone(), rest)
            } else {
                return Err(format!("{}: expected `key = value`, got '{}'", lineno, line.trim()));
            }
        };
        let target = match key.to_ascii_lowercase().as_str() {
            "cflags" => &mut conf.cflags,
            "ldflags" | "libs" => &mut conf.ldflags,
            "packages" | "pkg-config" | "pkgconfig" => &mut conf.packages,
            other => return Err(format!(
                "{}: unknown key '{}' (expected cflags, ldflags or packages)", lineno, other)),
        };
        target.extend(rest);
    }
    Ok(conf)
}

/// Split a line into shell-like words: whitespace separates, `'…'` is literal,
/// `"…"` allows `\"`/`\\`, a bare `\` escapes the next character, and an
/// unquoted `#` at a word start begins a comment.
fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word { words.push(std::mem::take(&mut cur)); in_word = false; }
            }
            '#' if !in_word => break,
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err("unterminated ' quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(ch @ ('"' | '\\' | '$' | '`')) => cur.push(ch),
                            Some(ch) => { cur.push('\\'); cur.push(ch); }
                            None => return Err("unterminated \" quote".into()),
                        },
                        Some(ch) => cur.push(ch),
                        None => return Err("unterminated \" quote".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(ch) = chars.next() { cur.push(ch); }
            }
            c => { in_word = true; cur.push(c); }
        }
    }
    if in_word { words.push(cur); }
    Ok(words)
}

/// `pkg-config --cflags` and `--libs` for `packages` (`$PKG_CONFIG` names the
/// program). A missing package or program is an error carrying its message.
pub fn pkg_config(packages: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
    let prog = std::env::var("PKG_CONFIG").ok().filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pkg-config".to_string());
    let run = |what: &str| -> Result<Vec<String>, String> {
        let out = Command::new(&prog).arg(what).args(packages).output()
            .map_err(|e| format!("cannot run {}: {}", prog, e))?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(format!("{} {} {} failed{}", prog, what, packages.join(" "),
                if msg.is_empty() { String::new() } else { format!(":\n{}", msg) }));
        }
        split_words(String::from_utf8_lossy(&out.stdout).trim())
    };
    Ok((run("--cflags")?, run("--libs")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keys_quotes_comments_and_appends() {
        let c = parse("# settings\n\
                       cflags = -DA=1 \"-DMSG=\\\"hi there\\\"\"   # trailing comment\n\
                       CFLAGS += -I'/opt/my inc'\n\
                       ldflags=-lm -L/x\n\
                       packages = zlib\n\
                       \n").unwrap();
        assert_eq!(c.cflags, vec!["-DA=1", "-DMSG=\"hi there\"", "-I/opt/my inc"]);
        assert_eq!(c.ldflags, vec!["-lm", "-L/x"]);
        assert_eq!(c.packages, vec!["zlib"]);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_lines() {
        assert!(parse("cflag = -DX").unwrap_err().contains("unknown key 'cflag'"));
        assert!(parse("just words").unwrap_err().starts_with("1: expected"));
        assert!(parse("cflags = 'open").unwrap_err().contains("unterminated"));
    }
}
