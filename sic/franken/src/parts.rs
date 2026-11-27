//! The stages a part written in SIC can take over, and `SIC_PARTS`, which picks
//! the ones that run in SIC (sic/PLAN.md §"SIC_PARTS").

/// A stage that has, or will have, a SIC version.
pub struct Part {
    pub name: &'static str,
    /// Its letter in the compiler's identifier (doc/version.md).
    pub letter: char,
    /// Its SIC version is built into this compiler.
    pub built: bool,
    /// It runs in SIC when `SIC_PARTS` is not set.
    pub default: bool,
}

/// When a part comes, its `built` is `cfg!(sic_<name>)` (build.rs's PARTS lists
/// it) and `stages` puts its function in.
pub const PARTS: &[Part] = &[
    Part { name: "lexer", letter: 'l', built: cfg!(sic_lexer), default: false },
    Part { name: "parser", letter: 'p', built: false, default: false },
    Part { name: "lower", letter: 'i', built: false, default: false },
    Part { name: "opt", letter: 'o', built: false, default: false },
    Part { name: "llvm", letter: 'b', built: false, default: false },
];

fn names() -> String { PARTS.iter().map(|p| p.name).collect::<Vec<_>>().join(", ") }

/// The stages that run in SIC for `SIC_PARTS` (`None`: not set).
///
/// A comma-separated list: a name adds that stage, `-name` takes it out, `+name`
/// adds it too; `all` is every built stage, `none` no stage. A list whose items
/// all start with `+` or `-` changes the default set; any other starts from
/// nothing. A name that is not a stage is an error, and so is asking for a stage
/// that is not built: a run must not test the Rust stage thinking it is the SIC one.
pub fn active(spec: Option<&str>) -> Result<Vec<&'static str>, String> {
    let defaults: Vec<&'static str> = PARTS.iter().filter(|p| p.default).map(|p| p.name).collect();
    let Some(spec) = spec.filter(|s| !s.trim().is_empty()) else { return Ok(defaults) };
    let items: Vec<&str> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    let relative = items.iter().all(|i| i.starts_with('+') || i.starts_with('-'));
    let mut set = if relative { defaults } else { Vec::new() };
    for item in items {
        match item {
            "all" => set = PARTS.iter().filter(|p| p.built).map(|p| p.name).collect(),
            "none" => set.clear(),
            _ => {
                let (add, name) = match item.strip_prefix('-') {
                    Some(n) => (false, n),
                    None => (true, item.strip_prefix('+').unwrap_or(item)),
                };
                let Some(part) = PARTS.iter().find(|p| p.name == name) else {
                    return Err(format!("unknown stage '{}' (stages: {})", name, names()));
                };
                if !add {
                    set.retain(|n| *n != part.name);
                } else if !part.built {
                    return Err(format!("the stage '{}' is not built into this compiler (sic/build.sh builds sic/{}/)", part.name, part.name));
                } else if !set.contains(&part.name) {
                    set.push(part.name);
                }
            }
        }
    }
    Ok(set)
}

/// `-print-parts`: a header, then one line per stage: name, built, default, active.
pub fn print(active: &[&str]) {
    let yes = |b: bool| if b { "yes" } else { "no" };
    println!("{:<8} {:<6} {:<8} {}", "stage", "built", "default", "active");
    for p in PARTS {
        println!("{:<8} {:<6} {:<8} {}", p.name, yes(p.built), yes(p.default), yes(active.contains(&p.name)));
    }
}

/// The driver's stages: Rust, with the active ones replaced by their SIC version.
/// The back end's letter comes from the back end in use (`Backend::sic`).
pub fn stages(active: &[&str]) -> sic::Stages {
    let mut stages = sic::Stages::RUST;
    #[cfg(sic_lexer)]
    if active.contains(&"lexer") { stages.lex = crate::lexer::lex; }
    let letters: String = PARTS.iter()
        .filter(|p| p.letter != 'b' && active.contains(&p.name)).map(|p| p.letter).collect();
    stages.sic = Box::leak(letters.into_boxed_str());
    stages
}
