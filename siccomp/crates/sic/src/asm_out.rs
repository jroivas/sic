//! `-S`: GNU assembler text for a unit. Cranelift emits machine code directly,
//! so the compiled object is written back as directives — every section's bytes
//! (`.byte`), its symbols, and its relocations (`.reloc`) — which `as`
//! assembles into an equivalent object. The C inline-assembly helpers
//! (`sic_ir::Module::asm_text_helpers`) follow as their own text.

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SymbolKind, SymbolScope};
use object::read::elf::ElfFile64;
use object::elf;
use std::fmt::Write;

/// The ELF x86-64 relocation types sic's objects carry, by name for `.reloc`.
fn reloc_name(t: elf::RelocationType) -> Option<&'static str> {
    Some(match t {
        elf::R_X86_64_64 => "R_X86_64_64",
        elf::R_X86_64_PC32 => "R_X86_64_PC32",
        elf::R_X86_64_GOT32 => "R_X86_64_GOT32",
        elf::R_X86_64_PLT32 => "R_X86_64_PLT32",
        elf::R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
        elf::R_X86_64_32 => "R_X86_64_32",
        elf::R_X86_64_32S => "R_X86_64_32S",
        elf::R_X86_64_16 => "R_X86_64_16",
        elf::R_X86_64_PC16 => "R_X86_64_PC16",
        elf::R_X86_64_8 => "R_X86_64_8",
        elf::R_X86_64_PC8 => "R_X86_64_PC8",
        elf::R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
        elf::R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
        elf::R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
        elf::R_X86_64_TLSGD => "R_X86_64_TLSGD",
        elf::R_X86_64_TLSLD => "R_X86_64_TLSLD",
        elf::R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
        elf::R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF",
        elf::R_X86_64_TPOFF32 => "R_X86_64_TPOFF32",
        elf::R_X86_64_PC64 => "R_X86_64_PC64",
        elf::R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64",
        elf::R_X86_64_GOTPC32 => "R_X86_64_GOTPC32",
        elf::R_X86_64_SIZE32 => "R_X86_64_SIZE32",
        elf::R_X86_64_SIZE64 => "R_X86_64_SIZE64",
        elf::R_X86_64_GOTPCRELX => "R_X86_64_GOTPCRELX",
        elf::R_X86_64_REX_GOTPCRELX => "R_X86_64_REX_GOTPCRELX",
        _ => return None,
    })
}

/// Section flags and type as `.section` spells them.
fn section_spec(flags: u64, sh_type: u32, entsize: u64) -> String {
    let mut f = String::new();
    if flags & elf::SHF_ALLOC.0 != 0 { f.push('a'); }
    if flags & elf::SHF_WRITE.0 != 0 { f.push('w'); }
    if flags & elf::SHF_EXECINSTR.0 != 0 { f.push('x'); }
    if flags & elf::SHF_MERGE.0 != 0 { f.push('M'); }
    if flags & elf::SHF_STRINGS.0 != 0 { f.push('S'); }
    if flags & elf::SHF_TLS.0 != 0 { f.push('T'); }
    let ty = [(elf::SHT_NOBITS, "@nobits"), (elf::SHT_NOTE, "@note"), (elf::SHT_INIT_ARRAY, "@init_array"),
              (elf::SHT_FINI_ARRAY, "@fini_array"), (elf::SHT_PREINIT_ARRAY, "@preinit_array"),
              (elf::SHT_X86_64_UNWIND, "@unwind")]
        .iter().find(|(t, _)| t.0 == sh_type).map_or("@progbits", |(_, n)| *n);
    if flags & elf::SHF_MERGE.0 != 0 {
        format!("\"{}\",{},{}", f, ty, entsize.max(1))
    } else {
        format!("\"{}\",{}", f, ty)
    }
}

/// A symbol name GNU as accepts unquoted.
fn plain(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.$".contains(c))
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

fn sym_ref(name: &str) -> String {
    if plain(name) { name.to_string() } else { format!("\"{}\"", name.replace('"', "\\\"")) }
}

/// The assembler text for `obj` (an ELF object from the backend) followed by
/// the text `helpers` (symbol, body). `source` names the file (`.file`).
pub fn object_to_asm(obj: &[u8], ir_module: &sic_ir::Module, source: &str, function_sections: bool) -> Result<String, String> {
    let file = ElfFile64::<object::Endianness>::parse(obj).map_err(|e| format!("-S: reading the object: {}", e))?;
    let mut out = String::new();
    let _ = writeln!(out, "\t.file\t\"{}\"", source.replace('"', "\\\""));
    // Undefined weak symbols must be declared weak before use.
    for s in file.symbols() {
        if s.is_undefined() && s.is_weak() {
            if let Ok(n) = s.name() { if !n.is_empty() { let _ = writeln!(out, "\t.weak\t{}", sym_ref(n)); } }
        }
    }
    // Parts of one name may differ in flags (a constant with pointers is
    // writable for the dynamic loader, one without is not). An object allows
    // that, but the assembler refuses to reopen a section with other flags:
    // every part gets the union.
    let mut name_flags: std::collections::HashMap<String, u64> = Default::default();
    for sec in file.sections() {
        if let Ok(n) = sec.name() {
            *name_flags.entry(n.to_string()).or_default() |= sec.elf_section_header().sh_flags.get(file.endian()).0;
        }
    }
    for sec in file.sections() {
        let hdr = sec.elf_section_header();
        let e = file.endian();
        let sh_type = hdr.sh_type.get(e).0;
        if [elf::SHT_NULL, elf::SHT_SYMTAB, elf::SHT_STRTAB, elf::SHT_RELA, elf::SHT_REL, elf::SHT_GROUP].iter().any(|t| t.0 == sh_type) {
            continue;
        }
        let name = sec.name().map_err(|e| format!("-S: {}", e))?;
        // `.comment` is written the way GNU as wants it: one `.ident` per string.
        if name == ".comment" {
            let data = sec.data().map_err(|e| format!("-S: {}", e))?;
            for part in data.split(|&b| b == 0).filter(|p| !p.is_empty()) {
                let text: String = part.iter().map(|&b| match b {
                    b'"' => "\\\"".to_string(), b'\\' => "\\\\".to_string(),
                    0x20..=0x7e => (b as char).to_string(), _ => format!("\\{:03o}", b),
                }).collect();
                let _ = writeln!(out, "\t.ident\t\"{}\"", text);
            }
            continue;
        }
        let flags = name_flags.get(name).copied().unwrap_or(hdr.sh_flags.get(e).0);
        let entsize = hdr.sh_entsize.get(e);
        let _ = writeln!(out, "\n\t.section\t{},{}", sym_ref(name), section_spec(flags, sh_type, entsize));
        let align = sec.align().max(1);
        if align > 1 { let _ = writeln!(out, "\t.balign\t{}", align); }
        let idx = sec.index().0;
        let _ = writeln!(out, ".Lsic_sec{}:", idx);
        let size = sec.size();
        // Symbols defined in this section, by offset.
        let mut syms: Vec<(u64, String)> = Vec::new();
        for s in file.symbols() {
            if s.section_index() != Some(sec.index()) { continue; }
            if matches!(s.kind(), SymbolKind::Section | SymbolKind::File) { continue; }
            let Ok(n) = s.name() else { continue };
            if n.is_empty() { continue; }
            let r = sym_ref(n);
            let mut d = String::new();
            if s.is_weak() { let _ = writeln!(d, "\t.weak\t{}", r); }
            else if s.is_global() { let _ = writeln!(d, "\t.globl\t{}", r); }
            if matches!(s.scope(), SymbolScope::Linkage) { let _ = writeln!(d, "\t.hidden\t{}", r); }
            match s.kind() {
                SymbolKind::Text => { let _ = writeln!(d, "\t.type\t{},@function", r); }
                SymbolKind::Data => { let _ = writeln!(d, "\t.type\t{},@object", r); }
                SymbolKind::Tls => { let _ = writeln!(d, "\t.type\t{},@tls_object", r); }
                _ => {}
            }
            if s.size() > 0 { let _ = writeln!(d, "\t.size\t{}, {}", r, s.size()); }
            let _ = writeln!(d, "{}:", r);
            syms.push((s.address() - sec.address(), d));
        }
        syms.sort_by_key(|(o, _)| *o);
        // Relocations by offset.
        let mut relocs: Vec<(u64, String)> = Vec::new();
        for (off, r) in sec.relocations() {
            let object::RelocationFlags::Elf { r_type } = r.flags() else { return Err("-S: not an ELF relocation".into()) };
            let rn = reloc_name(r_type).ok_or_else(|| format!("-S: relocation type {} not supported", r_type))?;
            let target = match r.target() {
                RelocationTarget::Symbol(si) => {
                    let s = file.symbol_by_index(si).map_err(|e| format!("-S: {}", e))?;
                    if s.kind() == SymbolKind::Section {
                        format!(".Lsic_sec{}", s.section_index().map(|i| i.0).unwrap_or(0))
                    } else {
                        sym_ref(s.name().map_err(|e| format!("-S: {}", e))?)
                    }
                }
                RelocationTarget::Absolute => "0".to_string(),
                _ => return Err("-S: unsupported relocation target".into()),
            };
            let a = r.addend();
            let expr = if a == 0 { target } else if a > 0 { format!("{}+{}", target, a) } else { format!("{}{}", target, a) };
            relocs.push((off, format!("\t.reloc\t., {}, {}", rn, expr)));
        }
        relocs.sort_by_key(|(o, _)| *o);
        if sh_type == elf::SHT_NOBITS.0 {
            let mut pos = 0u64;
            for (o, d) in &syms {
                if *o > pos { let _ = writeln!(out, "\t.zero\t{}", o - pos); pos = *o; }
                out.push_str(d);
            }
            if size > pos { let _ = writeln!(out, "\t.zero\t{}", size - pos); }
            continue;
        }
        let data = sec.data().map_err(|e| format!("-S: {}", e))?;
        // Walk the bytes, stopping at every symbol and relocation.
        let mut marks: Vec<u64> = syms.iter().map(|(o, _)| *o).chain(relocs.iter().map(|(o, _)| *o)).collect();
        marks.push(data.len() as u64);
        marks.sort();
        marks.dedup();
        let (mut si, mut ri, mut pos) = (0usize, 0usize, 0u64);
        for m in marks {
            if m > pos {
                for chunk in data[pos as usize..m as usize].chunks(16) {
                    let bytes: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
                    let _ = writeln!(out, "\t.byte\t{}", bytes.join(","));
                }
                pos = m;
            }
            while si < syms.len() && syms[si].0 == pos { out.push_str(&syms[si].1); si += 1; }
            while ri < relocs.len() && relocs[ri].0 == pos { let _ = writeln!(out, "{}", relocs[ri].1); ri += 1; }
        }
        while si < syms.len() { out.push_str(&syms[si].1); si += 1; }
    }
    // Common symbols.
    for s in file.symbols() {
        if s.is_common() {
            if let Ok(n) = s.name() {
                let _ = writeln!(out, "\t.comm\t{},{},{}", sym_ref(n), s.size(), s.address().max(1));
            }
        }
    }
    out.push_str(&helpers_asm(&ir_module.asm_text_helpers, function_sections));
    for text in &ir_module.file_asm {
        let _ = writeln!(out, "\t.text\n{}", text);
    }
    Ok(out)
}

/// The inline-assembly helpers as functions: weak and hidden (identical
/// helpers from several units merge), each in its own section — or all in
/// `.text` without `function_sections` (`-fno-function-sections`: Linux's
/// linker script places `.text`, not stray `.text.*` sections), aligned with
/// `int3` padding.
pub fn helpers_asm(helpers: &[(String, String)], function_sections: bool) -> String {
    let mut out = String::new();
    for (name, body) in helpers {
        let r = sym_ref(name);
        if function_sections {
            let _ = writeln!(out, "\n\t.section\t.text.{},\"ax\",@progbits", name);
        } else {
            let _ = writeln!(out, "\n\t.text\n\t.balign\t16, 0xcc");
        }
        let _ = writeln!(out, "\t.weak\t{r}\n\t.hidden\t{r}\n\t.type\t{r},@function\n{r}:");
        out.push_str(body);
        let _ = writeln!(out, "\t.size\t{r}, .-{r}");
    }
    if !helpers.is_empty() { out.push_str("\t.text\n"); }
    out
}
