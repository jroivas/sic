//! `cargo sic` — Rust crates for SIC (doc/rust-crates.md).
//!
//! ```text
//! cargo sic add hashbrown@0.15      # fetch, generate the binding, build it
//! cargo sic add --path ../mylib     # a local crate
//! cargo sic build                   # (re)build every binding in sic.toml
//! cargo sic remove hashbrown
//! ```
//!
//! A project lists its crates in `sic.toml` (Cargo's `[dependencies]` syntax).
//! Each crate gets a binding crate in `sic-deps/<module>/` — a generated
//! `src/generated.rs` (wrappers over the crate's public API, read from rustdoc's
//! JSON output) plus a `src/lib.rs` you may edit — and `sic --emit-module` turns
//! it into a SIC module there. `sic` searches `sic-deps/*` of the nearest
//! `sic.toml` automatically, so `import hashbrown;` needs no flags.

mod bindgen;

use std::path::{Path, PathBuf};
use std::process::Command;

use toml_edit::{DocumentMut, Item, Value};

const MANIFEST: &str = "sic.toml";
const DEPS: &str = "sic-deps";

/// One crate of `sic.toml`.
#[derive(Clone, Debug)]
struct Dep {
    /// The crate's (package) name.
    name: String,
    version: Option<String>,
    /// A local crate, relative to the project root.
    path: Option<String>,
    features: Vec<String>,
    default_features: bool,
    /// The SIC module name (default: the crate's name, `-` → `_`).
    module: String,
    /// Generic types to bind at concrete types: (Rust type, SIC name).
    instances: Vec<(String, String)>,
}

struct Project {
    root: PathBuf,
}

impl Project {
    fn manifest(&self) -> PathBuf { self.root.join(MANIFEST) }
    fn deps_dir(&self) -> PathBuf { self.root.join(DEPS) }
    fn target_dir(&self) -> PathBuf { self.deps_dir().join("target") }
}

struct Opts {
    global: bool,
    verbose: bool,
    offline: bool,
}

fn usage() -> &'static str {
    "cargo sic — Rust crates as SIC modules

usage:
  cargo sic add <crate>[@<version>] [--features a,b] [--no-default-features] [--module NAME]
                [--instance NAME=TYPE]    bind a generic type at concrete types, e.g.
                                          --instance 'StrIntMap=HashMap<String, i64>'
  cargo sic add --path <dir> [--module NAME]
  cargo sic build [<crate>...]       (re)generate and build the bindings
  cargo sic update [<crate>...]      update the locked versions, then build
  cargo sic remove <crate>
  cargo sic show <crate>             print the SIC interface of a binding
  cargo sic list

options:
  --global     use ~/.local/lib/sic instead of the project (found via sic.toml)
  --offline    do not touch the network (cargo --offline)
  -v           show cargo's warnings and the commands run

The project is the nearest directory at or above the current one holding a
sic.toml (`add` creates one in the current directory). Bindings are built in
sic-deps/; `sic` finds them there with no -I flags."
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // As a cargo subcommand (`cargo sic …`) cargo passes `sic` first.
    if args.first().map(|s| s.as_str()) == Some("sic") { args.remove(0); }
    let mut opts = Opts { global: false, verbose: false, offline: false };
    args.retain(|a| match a.as_str() {
        "--global" => { opts.global = true; false }
        "-v" | "--verbose" => { opts.verbose = true; false }
        "--offline" => { opts.offline = true; false }
        _ => true,
    });
    if let Err(e) = run(&args, &opts) {
        eprintln!("cargo-sic: error: {}", e);
        std::process::exit(1);
    }
}

fn run(args: &[String], opts: &Opts) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        println!("{}", usage());
        return Ok(());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "help" | "-h" | "--help" => { println!("{}", usage()); Ok(()) }
        "add" => cmd_add(rest, opts),
        "build" => { let p = find_project(opts, false)?; build(&p, rest, opts, false) }
        "update" => { let p = find_project(opts, false)?; build(&p, rest, opts, true) }
        "remove" | "rm" => cmd_remove(rest, opts),
        "show" => cmd_show(rest, opts),
        "list" | "ls" => cmd_list(opts),
        other => Err(format!("unknown command '{}' (see `cargo sic help`)", other)),
    }
}

// ── The project and sic.toml ─────────────────────────────────────────────────

fn global_root() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/lib/sic"))
}

/// The project: `--global`'s root, else the nearest directory with a sic.toml;
/// `create` makes one in the current directory when there is none.
fn find_project(opts: &Opts, create: bool) -> Result<Project, String> {
    let root = if opts.global {
        global_root()?
    } else {
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        match cwd.ancestors().find(|d| d.join(MANIFEST).is_file()) {
            Some(r) => r.to_path_buf(),
            None if create => cwd,
            None => return Err(format!("no {} here or in any parent directory (`cargo sic add <crate>` creates one)", MANIFEST)),
        }
    };
    let p = Project { root };
    if create && !p.manifest().is_file() {
        std::fs::create_dir_all(&p.root).map_err(|e| format!("{}: {}", p.root.display(), e))?;
        std::fs::write(p.manifest(),
            "# Rust crates used from SIC; `cargo sic build` builds their bindings into sic-deps/.\n\
             # Entries use Cargo's [dependencies] syntax, plus an optional `module = \"name\"`.\n\
             [dependencies]\n").map_err(|e| e.to_string())?;
        eprintln!("     Created {}", p.manifest().display());
    }
    Ok(p)
}

fn read_doc(p: &Project) -> Result<DocumentMut, String> {
    let text = std::fs::read_to_string(p.manifest()).map_err(|e| format!("{}: {}", p.manifest().display(), e))?;
    text.parse::<DocumentMut>().map_err(|e| format!("{}: {}", p.manifest().display(), e))
}

fn write_doc(p: &Project, doc: &DocumentMut) -> Result<(), String> {
    std::fs::write(p.manifest(), doc.to_string()).map_err(|e| format!("{}: {}", p.manifest().display(), e))
}

fn module_name(crate_name: &str) -> String {
    crate_name.replace('-', "_")
}

fn valid_module(m: &str) -> bool {
    !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !m.starts_with(|c: char| c.is_ascii_digit())
}

fn read_deps(doc: &DocumentMut) -> Result<Vec<Dep>, String> {
    let mut out = Vec::new();
    let Some(tab) = doc.get("dependencies").and_then(|t| t.as_table_like()) else { return Ok(out) };
    for (name, item) in tab.iter() {
        let mut d = Dep {
            name: name.to_string(), version: None, path: None, features: Vec::new(),
            default_features: true, module: module_name(name), instances: Vec::new(),
        };
        match item {
            Item::Value(Value::String(s)) => d.version = Some(s.value().clone()),
            _ => {
                let t = item.as_table_like().ok_or_else(|| format!("{}: dependency `{}`: expected a version or a table", MANIFEST, name))?;
                let s = |k: &str| t.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
                d.version = s("version");
                d.path = s("path");
                if let Some(m) = s("module") { d.module = m; }
                if let Some(df) = t.get("default-features").and_then(|v| v.as_bool()) { d.default_features = df; }
                if let Some(fs) = t.get("features").and_then(|v| v.as_array()) {
                    d.features = fs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                }
                // `instantiate = [{ type = "HashMap<String, i64>", as = "StrIntMap" }]`
                if let Some(arr) = t.get("instantiate").and_then(|v| v.as_array()) {
                    for v in arr.iter() {
                        let it = v.as_inline_table().ok_or_else(|| format!("{}: `{}`: instantiate entries are {{ type = \"...\", as = \"...\" }}", MANIFEST, name))?;
                        let ty = it.get("type").and_then(|v| v.as_str());
                        let als = it.get("as").and_then(|v| v.as_str());
                        match (ty, als) {
                            (Some(ty), Some(als)) => d.instances.push((ty.to_string(), als.to_string())),
                            _ => return Err(format!("{}: `{}`: an instantiate entry needs `type` and `as`", MANIFEST, name)),
                        }
                    }
                }
            }
        }
        if !valid_module(&d.module) {
            return Err(format!("{}: `{}` is not a valid SIC module name (set `module = \"...\"`)", MANIFEST, d.module));
        }
        out.push(d);
    }
    Ok(out)
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn cmd_add(args: &[String], opts: &Opts) -> Result<(), String> {
    let mut spec: Option<String> = None;
    let mut path: Option<String> = None;
    let mut features: Vec<String> = Vec::new();
    let mut no_default = false;
    let mut module: Option<String> = None;
    let mut instances: Vec<(String, String)> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |what: &str| it.next().cloned().ok_or_else(|| format!("{} needs a value", what));
        match a.as_str() {
            "--path" => path = Some(val("--path")?),
            "--features" | "-F" => features.extend(val("--features")?.split([',', ' ']).filter(|s| !s.is_empty()).map(String::from)),
            "--no-default-features" => no_default = true,
            "--module" => module = Some(val("--module")?),
            "--instance" => {
                let v = val("--instance")?;
                let (n, t) = v.split_once('=').ok_or("--instance takes NAME=TYPE (StrIntMap='HashMap<String, i64>')")?;
                instances.push((t.trim().to_string(), n.trim().to_string()));
            }
            s if s.starts_with('-') => return Err(format!("unknown option '{}'", s)),
            s if spec.is_none() => spec = Some(s.to_string()),
            s => return Err(format!("unexpected argument '{}'", s)),
        }
    }
    let p = find_project(opts, true)?;
    // A local crate is named by its own Cargo.toml.
    let (name, version, rel_path) = match (&spec, &path) {
        (_, Some(dir)) => {
            let abs = std::env::current_dir().map_err(|e| e.to_string())?.join(dir);
            let abs = std::fs::canonicalize(&abs).map_err(|e| format!("{}: {}", dir, e))?;
            let n = package_name(&abs)?;
            if let Some(s) = &spec { if *s != n { return Err(format!("{} is the crate `{}`, not `{}`", dir, n, s)); } }
            // The global list keeps absolute paths (it is not moved around with a project).
            let rel = if opts.global { abs.to_string_lossy().into_owned() } else { relative_to(&abs, &p.root) };
            (n, None, Some(rel))
        }
        (Some(s), None) => match s.split_once('@') {
            Some((n, v)) => (n.to_string(), Some(v.to_string()), None),
            None => (s.clone(), None, None),
        },
        (None, None) => return Err("usage: cargo sic add <crate>[@<version>] | --path <dir>".into()),
    };
    // Without a version, ask cargo for the newest one (cargo search).
    let version = match (version, &rel_path) {
        (Some(v), _) => Some(v),
        (None, None) => Some(latest_version(&name, opts)?),
        (None, Some(_)) => None,
    };
    let mut doc = read_doc(&p)?;
    if doc.get("dependencies").is_none() { doc["dependencies"] = toml_edit::table(); }
    let simple = rel_path.is_none() && features.is_empty() && !no_default && module.is_none() && instances.is_empty();
    if simple {
        doc["dependencies"][&name] = toml_edit::value(version.clone().unwrap());
    } else {
        let mut t = toml_edit::InlineTable::new();
        if let Some(v) = &version { t.insert("version", v.as_str().into()); }
        if let Some(pth) = &rel_path { t.insert("path", pth.as_str().into()); }
        if !features.is_empty() {
            let mut a = toml_edit::Array::new();
            for f in &features { a.push(f.as_str()); }
            t.insert("features", Value::Array(a));
        }
        if no_default { t.insert("default-features", false.into()); }
        if let Some(m) = &module { t.insert("module", m.as_str().into()); }
        if !instances.is_empty() {
            let mut a = toml_edit::Array::new();
            for (ty, n) in &instances {
                let mut e = toml_edit::InlineTable::new();
                e.insert("type", ty.as_str().into());
                e.insert("as", n.as_str().into());
                a.push(Value::InlineTable(e));
            }
            t.insert("instantiate", Value::Array(a));
        }
        doc["dependencies"][&name] = toml_edit::value(Value::InlineTable(t));
    }
    write_doc(&p, &doc)?;
    let what = match (&version, &rel_path) {
        (_, Some(pth)) => format!("{} ({})", name, pth),
        (Some(v), None) => format!("{} {}", name, v),
        _ => name.clone(),
    };
    eprintln!("       Added {} to {}", what, p.manifest().display());
    build(&p, &[name], opts, false)
}

fn cmd_remove(args: &[String], opts: &Opts) -> Result<(), String> {
    let name = args.first().ok_or("usage: cargo sic remove <crate>")?;
    let p = find_project(opts, false)?;
    let mut doc = read_doc(&p)?;
    let deps = read_deps(&doc)?;
    let d = deps.iter().find(|d| d.name == *name || d.module == *name)
        .ok_or_else(|| format!("`{}` is not in {}", name, p.manifest().display()))?.clone();
    doc["dependencies"].as_table_like_mut().map(|t| t.remove(&d.name));
    write_doc(&p, &doc)?;
    let dir = p.deps_dir().join(&d.module);
    if dir.is_dir() {
        // Keep a hand-edited lib.rs around rather than deleting someone's work.
        let lib = dir.join("src/lib.rs");
        if std::fs::read_to_string(&lib).map(|s| s != lib_template(&d)).unwrap_or(false) {
            let keep = p.deps_dir().join(format!("{}.lib.rs.removed", d.module));
            let _ = std::fs::rename(&lib, &keep);
            eprintln!("        Kept your edited lib.rs as {}", keep.display());
        }
        std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    let remaining = read_deps(&doc)?;
    write_workspace(&p, &remaining)?;
    eprintln!("     Removed {}", d.name);
    Ok(())
}

fn cmd_show(args: &[String], opts: &Opts) -> Result<(), String> {
    let name = args.first().ok_or("usage: cargo sic show <crate>")?;
    let p = find_project(opts, false)?;
    let deps = read_deps(&read_doc(&p)?)?;
    let d = deps.iter().find(|d| d.name == *name || d.module == *name)
        .ok_or_else(|| format!("`{}` is not in {}", name, p.manifest().display()))?;
    let sic = p.target_dir().join("sic-glue").join(&d.module).join(format!("{}.sic", d.module));
    let text = std::fs::read_to_string(&sic)
        .map_err(|_| format!("`{}` is not built yet (cargo sic build {})", d.name, d.name))?;
    print!("{}", text);
    Ok(())
}

fn cmd_list(opts: &Opts) -> Result<(), String> {
    let p = find_project(opts, false)?;
    for d in read_deps(&read_doc(&p)?)? {
        let built = p.deps_dir().join(&d.module).join(format!("module_{}.smod", d.module)).is_file();
        let src = match (&d.path, &d.version) {
            (Some(pth), _) => format!("path {}", pth),
            (None, Some(v)) => v.clone(),
            _ => "*".into(),
        };
        println!("{:<20} {:<16} import {};{}", d.name, src, d.module, if built { "" } else { "   (not built)" });
    }
    Ok(())
}

// ── Building ─────────────────────────────────────────────────────────────────

fn cargo() -> String {
    std::env::var("CARGO").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "cargo".into())
}

/// `sic` itself: `$SIC`, else the one next to this binary, else `sic` on PATH.
fn sic() -> PathBuf {
    if let Some(s) = std::env::var_os("SIC").filter(|s| !s.is_empty()) { return PathBuf::from(s); }
    if let Ok(exe) = std::env::current_exe() {
        let side = exe.with_file_name("sic");
        if side.is_file() { return side; }
    }
    PathBuf::from("sic")
}

fn run_cmd(cmd: &mut Command, opts: &Opts, what: &str) -> Result<(), String> {
    if opts.verbose { eprintln!("     Running {:?}", cmd); }
    let st = cmd.status().map_err(|e| format!("cannot run {}: {}", what, e))?;
    if st.success() { Ok(()) } else { Err(format!("{} failed", what)) }
}

fn package_name(dir: &Path) -> Result<String, String> {
    let toml = dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&toml).map_err(|e| format!("{}: {}", toml.display(), e))?;
    let doc = text.parse::<DocumentMut>().map_err(|e| format!("{}: {}", toml.display(), e))?;
    doc.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str()).map(String::from)
        .ok_or_else(|| format!("{}: no [package] name", toml.display()))
}

/// `path` relative to `base` (`../mylib`), so sic.toml stays portable; both are
/// made absolute first.
fn relative_to(path: &Path, base: &Path) -> String {
    let base = std::fs::canonicalize(base).unwrap_or(base.to_path_buf());
    let (p, b): (Vec<_>, Vec<_>) = (path.components().collect(), base.components().collect());
    let common = p.iter().zip(&b).take_while(|(x, y)| x == y).count();
    if common == 0 { return path.to_string_lossy().into_owned(); }
    let mut out = PathBuf::new();
    for _ in common..b.len() { out.push(".."); }
    for c in &p[common..] { out.push(c); }
    if out.as_os_str().is_empty() { ".".into() } else { out.to_string_lossy().into_owned() }
}

/// The newest published version of `name` (`cargo search`).
fn latest_version(name: &str, opts: &Opts) -> Result<String, String> {
    if opts.offline { return Ok("*".into()); }
    let out = Command::new(cargo()).args(["search", "--limit", "1", name]).output()
        .map_err(|e| format!("cannot run cargo: {}", e))?;
    let text = String::from_utf8_lossy(&out.stdout);
    // `name = "1.2.3"    # description`
    for line in text.lines() {
        let Some((n, rest)) = line.split_once('=') else { continue };
        if n.trim() != name { continue; }
        if let Some(v) = rest.trim().strip_prefix('"').and_then(|r| r.split('"').next()) {
            return Ok(v.to_string());
        }
    }
    Err(format!("crate `{}` was not found on crates.io", name))
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `sic-deps/Cargo.toml`: one workspace for every binding (a shared lock file).
fn write_workspace(p: &Project, deps: &[Dep]) -> Result<(), String> {
    let dir = p.deps_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    let members: Vec<String> = deps.iter().map(|d| quote(&d.module)).collect();
    let ws = format!(
        "# Generated by `cargo sic` from ../sic.toml; do not edit.\n[workspace]\nresolver = \"2\"\nmembers = [{}]\nexclude = [\"target\"]\n",
        members.join(", "));
    write_if_changed(&dir.join("Cargo.toml"), &ws)?;
    let ignore = "# Generated by `cargo sic`. Commit Cargo.lock and your edited */src/lib.rs;\n\
                  # everything else is rebuilt from ../sic.toml.\n\
                  /Cargo.toml\n/target/\n/*/Cargo.toml\n/*/src/generated.rs\n/*/lib*.a\n/*/lib*.so\n/*/module_*\n";
    write_if_changed(&dir.join(".gitignore"), ignore)?;
    Ok(())
}

fn write_if_changed(path: &Path, text: &str) -> Result<(), String> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(text) { return Ok(()); }
    std::fs::write(path, text).map_err(|e| format!("{}: {}", path.display(), e))
}

fn lib_template(d: &Dep) -> String {
    format!(
        "//! The SIC binding of `{}` — edit freely. `cargo sic build` regenerates\n\
         //! `generated.rs` (wrappers over the crate's public API) but never this file.\n\
         //! Add hand-written wrappers here: plain Rust with SIC-friendly types\n\
         //! (doc/rust-crates.md); they are bound like the generated ones.\n\n\
         mod generated;\npub use generated::*;\n",
        d.name)
}

/// The binding crate of one dependency: Cargo.toml (generated) and lib.rs (once).
fn write_member(p: &Project, d: &Dep) -> Result<PathBuf, String> {
    let dir = p.deps_dir().join(&d.module);
    std::fs::create_dir_all(dir.join("src")).map_err(|e| format!("{}: {}", dir.display(), e))?;
    let mut spec: Vec<String> = Vec::new();
    if let Some(v) = &d.version { spec.push(format!("version = {}", quote(v))); }
    if let Some(pth) = &d.path {
        let abs = p.root.join(pth);
        let abs = std::fs::canonicalize(&abs).map_err(|e| format!("{}: path {}: {}", MANIFEST, pth, e))?;
        spec.push(format!("path = {}", quote(&abs.to_string_lossy())));
    }
    if !d.features.is_empty() {
        let fs: Vec<String> = d.features.iter().map(|f| quote(f)).collect();
        spec.push(format!("features = [{}]", fs.join(", ")));
    }
    if !d.default_features { spec.push("default-features = false".into()); }
    let toml = format!(
        "# Generated by `cargo sic` from sic.toml; do not edit.\n[package]\nname = {}\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n\
         [package.metadata.sic]\nmodule = {}\n\n[dependencies]\n{} = {{ {} }}\n",
        quote(&format!("sic-{}", d.module.replace('_', "-"))), quote(&d.module), quote(&d.name), spec.join(", "));
    write_if_changed(&dir.join("Cargo.toml"), &toml)?;
    let lib = dir.join("src/lib.rs");
    if !lib.is_file() {
        std::fs::write(&lib, lib_template(d)).map_err(|e| format!("{}: {}", lib.display(), e))?;
    }
    // A placeholder so the workspace parses before the first generation.
    let generated = dir.join("src/generated.rs");
    if !generated.is_file() { std::fs::write(&generated, "").map_err(|e| e.to_string())?; }
    Ok(dir)
}

/// The library target name and version of package `name` (cargo metadata).
fn lib_info(p: &Project, name: &str, opts: &Opts) -> Result<(String, String), String> {
    let mut cmd = Command::new(cargo());
    cmd.args(["metadata", "--format-version", "1", "--manifest-path"]).arg(p.deps_dir().join("Cargo.toml"));
    if opts.offline { cmd.arg("--offline"); }
    let out = cmd.output().map_err(|e| format!("cannot run cargo: {}", e))?;
    if !out.status.success() {
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
        return Err("cargo metadata failed".into());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    // The dependency of our binding member, not some other package of that name.
    let pkgs = v["packages"].as_array().cloned().unwrap_or_default();
    for pk in &pkgs {
        if pk["name"] != name { continue; }
        let lib = pk["targets"].as_array().into_iter().flatten()
            .find(|t| t["kind"].as_array().map_or(false, |k| k.iter().any(|k| k == "lib" || k == "rlib" || k == "proc-macro")));
        let Some(lib) = lib else { return Err(format!("crate `{}` has no library", name)) };
        if lib["kind"].as_array().map_or(false, |k| k.iter().any(|k| k == "proc-macro")) {
            return Err(format!("crate `{}` is a proc-macro crate; it has no run-time API to bind", name));
        }
        let lname = lib["name"].as_str().unwrap_or(name).replace('-', "_");
        return Ok((lname, pk["version"].as_str().unwrap_or("").to_string()));
    }
    Err(format!("cargo metadata does not list `{}`", name))
}

/// Generate and build the bindings (`only`: crate or module names; all if empty).
fn build(p: &Project, only: &[String], opts: &Opts, update: bool) -> Result<(), String> {
    let deps = read_deps(&read_doc(p)?)?;
    for n in only {
        if !deps.iter().any(|d| d.name == *n || d.module == *n) {
            return Err(format!("`{}` is not in {}", n, p.manifest().display()));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for d in &deps {
        if !seen.insert(d.module.clone()) {
            return Err(format!("{}: two crates bind as module `{}` (set `module = \"...\"`)", MANIFEST, d.module));
        }
    }
    write_workspace(p, &deps)?;
    for d in &deps { write_member(p, d)?; }
    let ws = p.deps_dir().join("Cargo.toml");
    if update {
        let mut cmd = Command::new(cargo());
        cmd.arg("update").arg("--manifest-path").arg(&ws);
        for n in only {
            if let Some(d) = deps.iter().find(|d| d.name == *n || d.module == *n) { cmd.arg("-p").arg(&d.name); }
        }
        if opts.offline { cmd.arg("--offline"); }
        run_cmd(&mut cmd, opts, "cargo update")?;
    }
    let chosen: Vec<&Dep> = deps.iter().filter(|d| only.is_empty() || only.iter().any(|n| *n == d.name || *n == d.module)).collect();
    if chosen.is_empty() {
        eprintln!("     Nothing to build ({} lists no crates)", p.manifest().display());
        return Ok(());
    }
    for d in chosen {
        let (lname, version) = lib_info(p, &d.name, opts)?;
        eprintln!("  Generating {} {} → import {};", d.name, version, d.module);
        // The crate's public API, as rustdoc's JSON (stable cargo needs
        // RUSTC_BOOTSTRAP for the unstable output format).
        let mut cmd = Command::new(cargo());
        cmd.arg("rustdoc").arg("--quiet").arg("--lib").arg("-p").arg(format!("{}@{}", d.name, version))
            .arg("--manifest-path").arg(&ws).arg("--target-dir").arg(p.target_dir())
            .env("RUSTC_BOOTSTRAP", "1");
        if opts.offline { cmd.arg("--offline"); }
        cmd.args(["--", "-Z", "unstable-options", "--output-format", "json", "--cap-lints", "allow"]);
        run_cmd(&mut cmd, opts, "cargo rustdoc")?;
        let json_path = p.target_dir().join("doc").join(format!("{}.json", lname));
        let json = std::fs::read_to_string(&json_path).map_err(|e| format!("{}: {}", json_path.display(), e))?;
        let api: serde_json::Value = serde_json::from_str(&json).map_err(|e| format!("{}: {}", json_path.display(), e))?;
        let insts: Vec<bindgen::Instance> = d.instances.iter()
            .map(|(t, n)| bindgen::Instance { ty: t.clone(), name: n.clone() }).collect();
        let g = bindgen::generate(&api, &lname, &d.name, &version, &insts)?;
        let dir = p.deps_dir().join(&d.module);
        write_if_changed(&dir.join("src/generated.rs"), &g.code)?;
        eprintln!("       Bound {} item(s); skipped {} (listed at the end of {})",
            g.bound, g.skipped, dir.join("src/generated.rs").display());
        let mut cmd = Command::new(sic());
        cmd.arg("--emit-module").arg(&dir)
            .env("SIC_CARGO_TARGET_DIR", p.target_dir())
            .env("SIC_CARGO_LOCK", p.deps_dir().join("Cargo.lock"));
        if opts.offline { cmd.env("CARGO_NET_OFFLINE", "true"); }
        run_cmd(&mut cmd, opts, "sic --emit-module")?;
        eprintln!("       Built {} in {}", d.module, dir.display());
    }
    Ok(())
}
