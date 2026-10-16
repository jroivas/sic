//! Warning diagnostics and the gcc/clang `-W` flags.
//!
//! Every warning sic emits goes through [`warn`] with a name from [`WARNINGS`].
//! The driver configures the flags once ([`configure`]); afterwards a warning
//! prints in gcc's format — `file:line:col: warning: msg [-Wname]` — or, when
//! promoted by `-Werror` / `-Werror=name`, as `error: msg [-Werror=name]`, and
//! the compilation then fails ([`promoted_errors`]).
//!
//! Supported flags: `-Wall`, `-Wextra`, `-Wunused`, `-W<name>`, `-Wno-<name>`,
//! `-Werror`, `-Wno-error`, `-Werror=<name>`, `-Wno-error=<name>`, `-w`, and
//! `-pedantic`/`-Wpedantic` (accepted; sic has no pedantic warnings yet).
//! Unknown names are accepted silently, as real build systems pass many
//! (QEMU compiles every file with `-Wall -Werror` and ~40 more `-W` options).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Which flag group turns a warning on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Group {
    /// On unless disabled (`-Wno-<name>`, `-w`).
    Default,
    /// Enabled by `-Wall` (and `-Wextra` does not add it).
    All,
    /// Enabled by `-Wextra` (`-W`).
    Extra,
}

/// Every warning sic can emit: `(name, group, also enabled by -Wunused)`.
pub const WARNINGS: &[(&str, Group, bool)] = &[
    // gcc: on by default.
    ("div-by-zero", Group::Default, false),
    ("shift-count-overflow", Group::Default, false),
    ("shift-count-negative", Group::Default, false),
    // gcc -Wall.
    ("unused-variable", Group::All, true),
    // sic: an inline-asm template sic cannot lower; it traps if executed.
    ("unsupported-asm", Group::Default, false),
    // sic: `long double` is deprecated; it is computed as a 64-bit double.
    ("long-double", Group::Default, false),
];

#[derive(Default)]
struct Config {
    /// `-w`: no warnings at all.
    silent: bool,
    all: bool,
    extra: bool,
    /// `-Wunused` (Some(true)) / `-Wno-unused` (Some(false), wins over -Wall).
    unused: Option<bool>,
    /// `-Werror`.
    werror: bool,
    /// Explicit `-W<name>` (true) / `-Wno-<name>` (false); last one wins.
    explicit: HashMap<String, bool>,
    /// Explicit `-Werror=<name>` (true) / `-Wno-error=<name>` (false).
    error: HashMap<String, bool>,
    /// Already printed (file, line, col, name): lowering may visit code twice.
    seen: HashSet<(String, u32, u32, &'static str)>,
    promoted: usize,
    printed: usize,
}

static CONFIG: Mutex<Option<Config>> = Mutex::new(None);

/// Files the preprocessor marked as system headers (line-marker flag `3`):
/// like gcc, no warnings are reported from them.
static SYSTEM_FILES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Record that `file` is a system header (from a `# N "file" 1 3` marker).
pub fn mark_system_file(file: &str) {
    let mut g = SYSTEM_FILES.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashSet::new).insert(file.to_string());
}

fn is_system_file(file: &str) -> bool {
    let g = SYSTEM_FILES.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().map_or(false, |s| s.contains(file))
}

fn with<R>(f: impl FnOnce(&mut Config) -> R) -> R {
    let mut g = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Config::default))
}

/// Configure from the driver: `flags` are the `-W` option values without the
/// leading `-W` (e.g. `all`, `no-unused-variable`, `error=div-by-zero`), in
/// command-line order; `silent` is `-w`. Resets all state (one compilation).
pub fn configure<S: AsRef<str>>(flags: &[S], silent: bool) {
    let mut c = Config { silent, ..Config::default() };
    for f in flags {
        let f = f.as_ref();
        match f {
            "all" => c.all = true,
            "extra" | "" => c.extra = true, // a bare `-W` is the old name of -Wextra
            "unused" => c.unused = Some(true),
            "no-unused" => c.unused = Some(false),
            "error" => c.werror = true,
            "no-error" => c.werror = false,
            "pedantic" | "no-pedantic" => {}
            _ => {
                if let Some(n) = f.strip_prefix("no-error=") {
                    c.error.insert(n.to_string(), false);
                } else if let Some(n) = f.strip_prefix("error=") {
                    // -Werror=name also enables the warning.
                    c.error.insert(n.to_string(), true);
                    c.explicit.insert(n.to_string(), true);
                } else if let Some(n) = f.strip_prefix("no-") {
                    c.explicit.insert(n.to_string(), false);
                } else {
                    // `-Wname` and `-Wname=level` (e.g. -Wimplicit-fallthrough=2).
                    let n = f.split('=').next().unwrap_or(f);
                    c.explicit.insert(n.to_string(), true);
                }
            }
        }
    }
    *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
}

/// Whether warning `name` is currently enabled.
pub fn enabled(name: &str) -> bool {
    with(|c| is_enabled(c, name))
}

fn is_enabled(c: &Config, name: &str) -> bool {
    if c.silent { return false; }
    if let Some(&on) = c.explicit.get(name) { return on; }
    match WARNINGS.iter().find(|w| w.0 == name) {
        Some(&(_, group, in_unused)) => {
            if in_unused && c.unused.is_some() { return c.unused == Some(true); }
            match group {
                Group::Default => true,
                Group::All => c.all,
                Group::Extra => c.extra,
            }
        }
        None => false,
    }
}

/// Emit warning `name` (one of [`WARNINGS`]) at `file:line:col`, if enabled.
pub fn warn(name: &'static str, file: Option<&str>, line: u32, col: u32, msg: &str) {
    debug_assert!(WARNINGS.iter().any(|w| w.0 == name), "unregistered warning {name}");
    let file = file.unwrap_or("<input>");
    if is_system_file(file) { return; }
    let out = with(|c| {
        if !is_enabled(c, name) { return None; }
        if !c.seen.insert((file.to_string(), line, col, name)) { return None; }
        let as_error = c.error.get(name).copied().unwrap_or(c.werror);
        c.printed += 1;
        if as_error {
            c.promoted += 1;
            Some(format!("{}:{}:{}: error: {} [-Werror={}]", file, line, col, msg, name))
        } else {
            Some(format!("{}:{}:{}: warning: {} [-W{}]", file, line, col, msg, name))
        }
    });
    if let Some(line) = out { eprintln!("{}", line); }
}

/// Number of warnings promoted to errors by `-Werror`/`-Werror=` so far: the
/// driver fails the compilation when this is nonzero.
pub fn promoted_errors() -> usize {
    with(|c| c.promoted)
}
