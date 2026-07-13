//! Minimal DWARF debug-info emission: a `.debug_line` line-number table plus a
//! `.debug_info` compile unit (with per-function `DW_TAG_subprogram` DIEs), so
//! debuggers can map machine addresses to source lines, set breakpoints by
//! `file:line`, step through source, and show `file:line` in backtraces.
//!
//! Cranelift gives us the address→line mapping (via `set_srcloc` /
//! `get_srclocs_sorted`); we synthesize the DWARF here with `gimli` and attach
//! the sections + relocations to the object with the `object` crate.

use std::collections::HashMap;
use std::path::Path;

use gimli::write::{
    Address, AttributeValue, DwarfUnit, EndianVec, Expression, LineProgram, LineString,
    Result as GimliResult, Sections, UnitEntryId, Writer,
};
use gimli::{Encoding, Format, LineEncoding, Register, RunTimeEndian, SectionId};

use object::write::{Object, Relocation, SymbolId};
use object::{RelocationEncoding, RelocationFlags, RelocationKind, SectionKind};

use sic_ir::Type;

/// DWARF register number for the frame pointer (RBP) on x86-64.
const DW_REG_RBP: u16 = 6;

/// A source variable's DWARF info: its name, type, frame-pointer-relative byte
/// offset, and whether it is a formal parameter.
#[derive(Clone)]
pub struct VarInfo {
    pub name: String,
    pub ty: Type,
    pub fp_offset: i64,
    pub is_param: bool,
}

/// Per-function line information collected from Cranelift.
pub struct FuncLines {
    /// The function's symbol in the object being built.
    pub sym: SymbolId,
    /// Total machine-code size of the function.
    pub size: u64,
    /// Demangled/source function name (for the subprogram DIE).
    pub name: String,
    /// (code offset, source line, prologue_end) rows.
    pub rows: Vec<(u64, u32, bool)>,
    /// Local variables and parameters (for `DW_TAG_variable`/`formal_parameter`).
    pub vars: Vec<VarInfo>,
}

/// Where a DWARF relocation points.
#[derive(Clone)]
enum RelocTarget {
    /// A function symbol (index into the `funcs` slice) — used for addresses.
    Func(usize),
    /// Another DWARF section (its section symbol) — used for inter-section refs.
    Section(SectionId),
}

#[derive(Clone)]
struct DwarfReloc {
    offset: u64,
    target: RelocTarget,
    addend: i64,
    size: u8,
}

/// A `gimli` writer that records relocations for addresses and section-relative
/// offsets (both unknown until link time in a relocatable object).
#[derive(Clone)]
struct WriterRelocate {
    relocs: Vec<DwarfReloc>,
    writer: EndianVec<RunTimeEndian>,
}

impl WriterRelocate {
    fn new(endian: RunTimeEndian) -> Self {
        WriterRelocate { relocs: Vec::new(), writer: EndianVec::new(endian) }
    }
}

impl Writer for WriterRelocate {
    type Endian = RunTimeEndian;

    fn endian(&self) -> RunTimeEndian {
        self.writer.endian()
    }
    fn len(&self) -> usize {
        self.writer.len()
    }
    fn write(&mut self, bytes: &[u8]) -> GimliResult<()> {
        self.writer.write(bytes)
    }
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> GimliResult<()> {
        self.writer.write_at(offset, bytes)
    }

    fn write_address(&mut self, address: Address, size: u8) -> GimliResult<()> {
        match address {
            Address::Constant(val) => self.write_udata(val, size),
            Address::Symbol { symbol, addend } => {
                self.relocs.push(DwarfReloc {
                    offset: self.len() as u64,
                    target: RelocTarget::Func(symbol),
                    addend,
                    size,
                });
                self.write_udata(0, size)
            }
        }
    }

    fn write_offset(&mut self, val: usize, section: SectionId, size: u8) -> GimliResult<()> {
        self.relocs.push(DwarfReloc {
            offset: self.len() as u64,
            target: RelocTarget::Section(section),
            addend: val as i64,
            size,
        });
        self.write_udata(0, size)
    }

    fn write_offset_at(
        &mut self,
        offset: usize,
        val: usize,
        section: SectionId,
        size: u8,
    ) -> GimliResult<()> {
        self.relocs.push(DwarfReloc {
            offset: offset as u64,
            target: RelocTarget::Section(section),
            addend: val as i64,
            size,
        });
        self.write_udata_at(offset, 0, size)
    }
}

/// Build DWARF for `funcs` (from source `source_path`) and add the sections and
/// relocations to `object`. `address_size` is the target pointer size in bytes.
pub fn emit_dwarf(
    object: &mut Object<'static>,
    source_path: &str,
    funcs: &[FuncLines],
    address_size: u8,
) -> Result<(), String> {
    if funcs.is_empty() {
        return Ok(());
    }
    let encoding = Encoding { format: Format::Dwarf32, version: 4, address_size };

    // Split the source path into a compilation directory and file name.
    let path = Path::new(source_path);
    let comp_dir = path
        .parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| std::env::current_dir().ok().and_then(|d| d.to_str().map(|s| s.to_string())))
        .unwrap_or_else(|| ".".to_string());
    let file_name = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(source_path)
        .to_string();

    let mut dwarf = DwarfUnit::new(encoding);

    // ── Line program ───────────────────────────────────────────────────────────
    let comp_dir_ls = LineString::String(comp_dir.clone().into_bytes());
    let comp_file_ls = LineString::String(file_name.clone().into_bytes());
    let mut line_program =
        LineProgram::new(encoding, LineEncoding::default(), comp_dir_ls, comp_file_ls, None);
    let dir_id = line_program.default_directory();
    let file_id =
        line_program.add_file(LineString::String(file_name.clone().into_bytes()), dir_id, None);

    for (fidx, f) in funcs.iter().enumerate() {
        if f.rows.is_empty() {
            continue;
        }
        line_program.begin_sequence(Some(Address::Symbol { symbol: fidx, addend: 0 }));
        for (off, line, prologue_end) in &f.rows {
            let row = line_program.row();
            row.address_offset = *off;
            row.file = file_id;
            row.line = *line as u64;
            row.column = 0;
            row.is_statement = true;
            row.prologue_end = *prologue_end;
            line_program.generate_row();
        }
        line_program.end_sequence(f.size);
    }
    dwarf.unit.line_program = line_program;

    // ── Compile-unit root DIE ──────────────────────────────────────────────────
    let root = dwarf.unit.root();
    {
        let die = dwarf.unit.get_mut(root);
        die.set(gimli::DW_AT_producer, AttributeValue::String(b"sic (SIC Compiler)".to_vec()));
        die.set(gimli::DW_AT_language, AttributeValue::Language(gimli::DW_LANG_C11));
        die.set(gimli::DW_AT_name, AttributeValue::String(file_name.clone().into_bytes()));
        die.set(gimli::DW_AT_comp_dir, AttributeValue::String(comp_dir.clone().into_bytes()));
        die.set(
            gimli::DW_AT_low_pc,
            AttributeValue::Address(Address::Symbol { symbol: 0, addend: 0 }),
        );
    }

    // ── One subprogram DIE per function (name, range, params, locals) ──────────
    let mut type_cache: HashMap<String, UnitEntryId> = HashMap::new();
    for (fidx, f) in funcs.iter().enumerate() {
        let sp = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        {
            let die = dwarf.unit.get_mut(sp);
            die.set(gimli::DW_AT_name, AttributeValue::String(f.name.clone().into_bytes()));
            die.set(
                gimli::DW_AT_low_pc,
                AttributeValue::Address(Address::Symbol { symbol: fidx, addend: 0 }),
            );
            die.set(gimli::DW_AT_high_pc, AttributeValue::Udata(f.size));
            die.set(gimli::DW_AT_external, AttributeValue::Flag(true));
            // The frame base is the frame pointer; variables are `DW_OP_breg6`.
            let mut fb = Expression::new();
            fb.op_reg(Register(DW_REG_RBP));
            die.set(gimli::DW_AT_frame_base, AttributeValue::Exprloc(fb));
        }

        for v in &f.vars {
            let Some(type_id) = add_type(&mut dwarf, root, &mut type_cache, &v.ty) else {
                continue; // unrepresentable type — skip this variable
            };
            let tag = if v.is_param {
                gimli::DW_TAG_formal_parameter
            } else {
                gimli::DW_TAG_variable
            };
            let vdie = dwarf.unit.add(sp, tag);
            let mut loc = Expression::new();
            loc.op_breg(Register(DW_REG_RBP), v.fp_offset);
            let die = dwarf.unit.get_mut(vdie);
            die.set(gimli::DW_AT_name, AttributeValue::String(v.name.clone().into_bytes()));
            die.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
            die.set(gimli::DW_AT_location, AttributeValue::Exprloc(loc));
        }
    }

    // ── Serialize the DWARF, collecting relocations ────────────────────────────
    let mut sections = Sections::new(WriterRelocate::new(RunTimeEndian::Little));
    dwarf.write(&mut sections).map_err(|e| format!("dwarf write: {}", e))?;

    // First pass: add each non-empty section to the object and remember its id.
    let mut section_map: HashMap<SectionId, object::write::SectionId> = HashMap::new();
    sections
        .for_each(|id: SectionId, w: &WriterRelocate| -> Result<(), String> {
            let data = w.writer.slice();
            if data.is_empty() {
                return Ok(());
            }
            let name = id.name();
            let secid =
                object.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Debug);
            object.set_section_data(secid, data.to_vec(), 1);
            section_map.insert(id, secid);
            Ok(())
        })
        .map_err(|e: String| e)?;

    // Second pass: add relocations now that all section symbols exist.
    sections
        .for_each(|id: SectionId, w: &WriterRelocate| -> Result<(), String> {
            let Some(&secid) = section_map.get(&id) else { return Ok(()) };
            for r in &w.relocs {
                let symbol = match &r.target {
                    RelocTarget::Func(idx) => funcs[*idx].sym,
                    RelocTarget::Section(gid) => match section_map.get(gid) {
                        Some(&target_sec) => object.section_symbol(target_sec),
                        None => continue,
                    },
                };
                object
                    .add_relocation(
                        secid,
                        Relocation {
                            offset: r.offset,
                            symbol,
                            addend: r.addend,
                            flags: RelocationFlags::Generic {
                                kind: RelocationKind::Absolute,
                                encoding: RelocationEncoding::Generic,
                                size: r.size * 8,
                            },
                        },
                    )
                    .map_err(|e| format!("dwarf reloc: {}", e))?;
            }
            Ok(())
        })
        .map_err(|e: String| e)?;

    Ok(())
}

/// Get or create a DWARF type DIE for `ty`, returning `None` for types we don't
/// yet describe (struct/union/array — the variable is then simply omitted). Base
/// types and pointers are supported. Types are cached by a structural key so
/// each is emitted once.
fn add_type(
    dwarf: &mut DwarfUnit,
    root: UnitEntryId,
    cache: &mut HashMap<String, UnitEntryId>,
    ty: &Type,
) -> Option<UnitEntryId> {
    let key = type_key(ty);
    if let Some(&id) = cache.get(&key) {
        return Some(id);
    }

    let id = match ty {
        Type::Void => return None,
        Type::Bool => base_type(dwarf, root, "_Bool", 1, gimli::DW_ATE_boolean),
        Type::Int { bits, signed } => {
            let bytes = (*bits / 8).max(1) as u64;
            let (name, enc): (&str, _) = match (*bits, *signed) {
                (8, true) => ("signed char", gimli::DW_ATE_signed_char),
                (8, false) => ("unsigned char", gimli::DW_ATE_unsigned_char),
                (16, true) => ("short", gimli::DW_ATE_signed),
                (16, false) => ("unsigned short", gimli::DW_ATE_unsigned),
                (32, true) => ("int", gimli::DW_ATE_signed),
                (32, false) => ("unsigned int", gimli::DW_ATE_unsigned),
                (64, true) => ("long", gimli::DW_ATE_signed),
                (64, false) => ("unsigned long", gimli::DW_ATE_unsigned),
                (_, true) => ("int", gimli::DW_ATE_signed),
                (_, false) => ("unsigned", gimli::DW_ATE_unsigned),
            };
            base_type(dwarf, root, name, bytes, enc)
        }
        Type::Float32 => base_type(dwarf, root, "float", 4, gimli::DW_ATE_float),
        Type::Float64 => base_type(dwarf, root, "double", 8, gimli::DW_ATE_float),
        Type::Float80 => base_type(dwarf, root, "long double", 16, gimli::DW_ATE_float),
        Type::Pointer(inner) => {
            let inner_id = add_type(dwarf, root, cache, inner);
            let p = dwarf.unit.add(root, gimli::DW_TAG_pointer_type);
            let die = dwarf.unit.get_mut(p);
            die.set(gimli::DW_AT_byte_size, AttributeValue::Udata(8));
            if let Some(iid) = inner_id {
                die.set(gimli::DW_AT_type, AttributeValue::UnitRef(iid));
            }
            p
        }
        // Aggregates and functions aren't described yet.
        _ => return None,
    };

    cache.insert(key, id);
    Some(id)
}

fn base_type(
    dwarf: &mut DwarfUnit,
    root: UnitEntryId,
    name: &str,
    byte_size: u64,
    encoding: gimli::DwAte,
) -> UnitEntryId {
    let id = dwarf.unit.add(root, gimli::DW_TAG_base_type);
    let die = dwarf.unit.get_mut(id);
    die.set(gimli::DW_AT_name, AttributeValue::String(name.as_bytes().to_vec()));
    die.set(gimli::DW_AT_byte_size, AttributeValue::Udata(byte_size));
    die.set(gimli::DW_AT_encoding, AttributeValue::Encoding(encoding));
    id
}

/// A structural cache key for a type (so identical types share one DIE).
fn type_key(ty: &Type) -> String {
    match ty {
        Type::Void => "void".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Int { bits, signed } => format!("i{}:{}", bits, signed),
        Type::Float32 => "f32".to_string(),
        Type::Float64 => "f64".to_string(),
        Type::Float80 => "f80".to_string(),
        Type::Pointer(inner) => format!("*{}", type_key(inner)),
        other => format!("{:?}", other),
    }
}
