//! The x86 instruction-set extensions a compilation may assume, from `-m…`
//! and `-march=…` (as GCC reads them), and the feature macros that announce
//! them (`__SSE4_1__`, `__AVX2__`, …), so code picks the SIMD paths sic can
//! compile. Only extensions whose intrinsics sic implements are offered:
//! `-march=native` on an AVX-512 machine still stops at AVX2.

/// An extension, in implication order where one includes another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature { Sse3, Ssse3, Sse41, Sse42, Popcnt, Avx, Avx2, Fma, F16c, Aes, Pclmul, Cx16 }

use Feature::*;

impl Feature {
    fn flag(self) -> &'static str {
        match self {
            Sse3 => "sse3", Ssse3 => "ssse3", Sse41 => "sse4.1", Sse42 => "sse4.2", Popcnt => "popcnt",
            Avx => "avx", Avx2 => "avx2", Fma => "fma", F16c => "f16c", Aes => "aes", Pclmul => "pclmul",
            Cx16 => "cx16",
        }
    }
    fn macro_name(self) -> &'static str {
        match self {
            Sse3 => "__SSE3__", Ssse3 => "__SSSE3__", Sse41 => "__SSE4_1__", Sse42 => "__SSE4_2__",
            Popcnt => "__POPCNT__", Avx => "__AVX__", Avx2 => "__AVX2__", Fma => "__FMA__",
            F16c => "__F16C__", Aes => "__AES__", Pclmul => "__PCLMUL__",
            Cx16 => "__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16",
        }
    }
    /// The name a back end knows the extension by (GCC's).
    fn backend_name(self) -> &'static str {
        match self {
            Sse3 => "sse3", Ssse3 => "ssse3", Sse41 => "sse4.1", Sse42 => "sse4.2",
            Popcnt => "popcnt", Avx => "avx", Avx2 => "avx2", Fma => "fma",
            F16c => "f16c", Aes => "aes", Pclmul => "pclmul", Cx16 => "cx16",
        }
    }
    /// The extensions this one requires (GCC's `-m` implications).
    fn requires(self) -> &'static [Feature] {
        match self {
            Sse3 | Popcnt => &[],
            Ssse3 => &[Sse3],
            Sse41 => &[Ssse3],
            Sse42 => &[Sse41],
            Avx => &[Sse42],
            Avx2 | Fma | F16c => &[Avx],
            Aes | Pclmul | Cx16 => &[],
        }
    }
    const ALL: [Feature; 12] = [Sse3, Ssse3, Sse41, Sse42, Popcnt, Avx, Avx2, Fma, F16c, Aes, Pclmul, Cx16];
}

/// The extensions in use, and the x86-64 baseline (MMX, SSE, SSE2, the x87
/// FPU), which only an explicit `-mno-…` turns off — Linux builds its kernel
/// with `-mno-sse -mno-mmx -mno-sse2 -mno-80387`.
#[derive(Debug, Clone)]
pub struct Isa {
    on: std::collections::BTreeSet<Feature>,
    mmx: bool,
    sse: bool,
    sse2: bool,
    x87: bool,
}

impl Default for Isa {
    fn default() -> Self { Isa { on: Default::default(), mmx: true, sse: true, sse2: true, x87: true } }
}

impl Isa {
    fn enable(&mut self, f: Feature) {
        if self.on.insert(f) {
            for &r in f.requires() { self.enable(r); }
        }
    }

    /// Off, with everything that requires it.
    fn disable(&mut self, f: Feature) {
        if self.on.remove(&f) {
            for g in Feature::ALL {
                if g.requires().contains(&f) { self.disable(g); }
            }
        }
    }

    fn march(&mut self, cpu: &str) -> Result<(), String> {
        let v2 = [Sse42, Popcnt, Cx16];
        let v3 = [Sse42, Popcnt, Cx16, Avx2, Fma, F16c];
        let set: Vec<Feature> = match cpu {
            "native" => return Ok(self.native()),
            "x86-64" | "k8" | "opteron" | "athlon64" => vec![],
            "x86-64-v2" => v2.to_vec(),
            // AVX-512 is not offered: v4 is v3 here.
            "x86-64-v3" | "x86-64-v4" => v3.to_vec(),
            "core2" => vec![Ssse3, Cx16],
            "nehalem" => v2.to_vec(),
            "westmere" => [&v2[..], &[Aes, Pclmul]].concat(),
            "sandybridge" => vec![Avx, Popcnt, Aes, Pclmul, Cx16],
            "ivybridge" => vec![Avx, F16c, Popcnt, Aes, Pclmul, Cx16],
            "haswell" | "broadwell" | "skylake" | "skylake-avx512" | "cascadelake" | "cooperlake"
            | "cannonlake" | "icelake-client" | "icelake-server" | "tigerlake" | "rocketlake"
            | "alderlake" | "raptorlake" | "meteorlake" | "sapphirerapids" | "emeraldrapids"
            | "graniterapids" | "arrowlake" | "lunarlake" | "znver1" | "znver2" | "znver3"
            | "znver4" | "znver5" | "bdver4" => [&v3[..], &[Aes, Pclmul]].concat(),
            "bdver1" | "bdver2" | "bdver3" => vec![Avx, Popcnt, Aes, Pclmul, Cx16],
            "btver2" => vec![Avx, F16c, Popcnt, Aes, Pclmul, Cx16],
            _ => return Err(format!("unknown -march={}; assuming x86-64", cpu)),
        };
        self.on.clear();
        for f in set { self.enable(f); }
        Ok(())
    }

    /// The host's extensions (CPUID and the OS's register-state support).
    fn native(&mut self) {
        self.on.clear();
        #[cfg(target_arch = "x86_64")]
        {
            macro_rules! has { ($f:tt) => { std::arch::is_x86_feature_detected!($f) } }
            let host = [(Sse3, has!("sse3")), (Ssse3, has!("ssse3")), (Sse41, has!("sse4.1")),
                        (Sse42, has!("sse4.2")), (Popcnt, has!("popcnt")), (Avx, has!("avx")),
                        (Avx2, has!("avx2")), (Fma, has!("fma")), (F16c, has!("f16c")),
                        (Aes, has!("aes")), (Pclmul, has!("pclmulqdq")), (Cx16, has!("cmpxchg16b"))];
            for (f, yes) in host {
                if yes && f.requires().iter().all(|r| host.iter().any(|(g, y)| g == r && *y)) {
                    self.on.insert(f);
                }
            }
        }
    }

    /// Apply the machine flags in command-line order. Returns warnings.
    pub fn from_flags(flags: &[String]) -> (Isa, Vec<String>) {
        let mut isa = Isa::default();
        let mut warnings = Vec::new();
        for a in flags {
            if let Some(cpu) = a.strip_prefix("-march=") {
                if let Err(w) = isa.march(cpu) { warnings.push(w); isa.on.clear(); }
                continue;
            }
            let (on, name) = match a.strip_prefix("-mno-") {
                Some(n) => (false, n),
                None => match a.strip_prefix("-m") { Some(n) => (true, n), None => continue },
            };
            // The baseline: `-mno-sse` turns off SSE2 too, `-msse2` on SSE.
            match (name, on) {
                ("mmx", v) => { isa.mmx = v; continue; }
                ("sse", v) => { isa.sse = v; if !v { isa.sse2 = false; } continue; }
                ("sse2", v) => { isa.sse2 = v; if v { isa.sse = true; } continue; }
                ("80387", v) => { isa.x87 = v; continue; }
                ("soft-float", true) => { isa.x87 = false; continue; }
                _ => {}
            }
            // `-msse4` is SSE4.2; `-mno-sse4` turns off SSE4.1 too.
            let name = match name { "sse4" if on => "sse4.2", "sse4" => "sse4.1", n => n };
            if let Some(f) = Feature::ALL.iter().copied().find(|f| f.flag() == name) {
                if on { isa.enable(f); isa.sse = true; isa.sse2 = true; } else { isa.disable(f) }
            }
        }
        // Every extension builds on SSE2.
        if !isa.sse2 { isa.on.clear(); }
        (isa, warnings)
    }

    /// The enabled extensions: the back end uses exactly what `-march`/`-m…`
    /// allow (GCC's x86-64 baseline by default), never more of the build
    /// machine's CPU.
    pub fn backend_features(&self) -> Vec<&'static str> {
        self.on.iter().map(|f| f.backend_name()).collect()
    }

    /// SSE2 is available: the floating-point and vector registers sic's back
    /// end uses (off for `-mno-sse` / `-mno-sse2`).
    pub fn sse2(&self) -> bool { self.sse2 }

    /// The x87 FPU is available (off for `-mno-80387` / `-msoft-float`).
    pub fn x87(&self) -> bool { self.x87 }

    /// `-D` flags for the feature macros: the x86-64 baseline (MMX, SSE, SSE2)
    /// and the enabled extensions.
    pub fn defines(&self) -> Vec<String> {
        let mut m = vec!["__FXSR__"];
        if self.mmx { m.push("__MMX__"); }
        if self.sse { m.extend(["__SSE__", "__SSE_MATH__"]); }
        if self.sse2 { m.extend(["__SSE2__", "__SSE2_MATH__"]); }
        if self.mmx && self.sse2 { m.push("__MMX_WITH_SSE__"); }
        let mut v: Vec<String> = m.iter().map(|m| format!("-D{}=1", m)).collect();
        for f in &self.on { v.push(format!("-D{}=1", f.macro_name())); }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macros(flags: &[&str]) -> Vec<String> {
        let f: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
        Isa::from_flags(&f).0.defines()
    }

    #[test]
    fn implications_and_negation() {
        let m = macros(&["-mavx2"]);
        for x in ["__AVX2__", "__AVX__", "__SSE4_2__", "__SSE4_1__", "__SSSE3__", "__SSE3__", "__SSE2__"] {
            assert!(m.contains(&format!("-D{}=1", x)), "{} missing from {:?}", x, m);
        }
        let m = macros(&["-mavx2", "-mno-sse4.1"]);
        assert!(!m.iter().any(|d| d.contains("AVX") || d.contains("SSE4")));
        assert!(m.contains(&"-D__SSSE3__=1".to_string()));
        let m = macros(&["-march=x86-64-v3", "-mno-fma"]);
        assert!(m.contains(&"-D__AVX2__=1".to_string()) && !m.contains(&"-D__FMA__=1".to_string()));
        let m = macros(&["-march=haswell", "-march=x86-64"]);
        assert!(!m.iter().any(|d| d.contains("SSE3")));
    }

    #[test]
    fn backend_features_follow_flags() {
        // The back end gets only what -march/-m allow (the baseline: nothing),
        // not the build machine's CPU.
        let flags = |f: &[&str]| { let v: Vec<String> = f.iter().map(|s| s.to_string()).collect(); Isa::from_flags(&v).0.backend_features() };
        assert!(flags(&[]).is_empty());
        assert!(flags(&["-march=x86-64"]).is_empty());
        let v2 = flags(&["-march=x86-64-v2"]);
        for f in ["sse4.2", "popcnt", "cx16"] { assert!(v2.contains(&f), "{} missing: {:?}", f, v2); }
        assert!(!v2.contains(&"avx"));
        assert!(flags(&["-mavx2", "-mno-sse"]).is_empty());
    }

    #[test]
    fn baseline_off() {
        // Linux's kernel flags: no SSE/MMX macros, and no extension survives.
        let f: Vec<String> = ["-mno-sse", "-mno-mmx", "-mno-sse2", "-mno-avx", "-march=x86-64", "-mavx2", "-mno-sse"]
            .iter().map(|s| s.to_string()).collect();
        let (isa, _) = Isa::from_flags(&f);
        let m = isa.defines();
        assert!(!isa.sse2() && isa.x87());
        assert!(!m.iter().any(|d| d.contains("SSE") || d.contains("MMX") || d.contains("AVX")), "{:?}", m);
        let (isa, _) = Isa::from_flags(&["-mno-80387".to_string()]);
        assert!(!isa.x87() && isa.sse2());
        let m = macros(&["-mno-sse2", "-msse"]);
        assert!(m.contains(&"-D__SSE__=1".to_string()) && !m.contains(&"-D__SSE2__=1".to_string()));
    }
}
