//! `-g`: DWARF through LLVM's debug-info builder. What sic's IR carries: a
//! compile unit for the source file, a subprogram per defined function, its lines
//! (`SrcLine`), and its parameters and locals on their stack slots (`DbgVar`).
//! Types: the scalars, pointers, arrays and structs; a union has no members, nor
//! a struct more than two pointers in (a declaration, which a debugger looks up by
//! name: a list's node points at itself).

use std::cell::RefCell;

use inkwell::context::Context;
use inkwell::debug_info::{
    AsDIScope, DICompileUnit, DIFile, DIFlags, DIFlagsConstants, DIScope, DISubprogram, DIType,
    DWARFEmissionKind, DWARFSourceLanguage, DebugInfoBuilder,
};
use inkwell::module::{FlagBehavior, Module as LModule};
use inkwell::values::FunctionValue;
use inkwell::AddressSpace;
use sic_ir::fast_hash::HashMap;
use sic_ir::{Function, Instr, Linkage, Module, Type};

// DWARF base type encodings (DW_ATE_*).
const ATE_BOOLEAN: u32 = 0x02;
const ATE_FLOAT: u32 = 0x04;
const ATE_SIGNED: u32 = 0x05;
const ATE_SIGNED_CHAR: u32 = 0x06;
const ATE_UNSIGNED: u32 = 0x07;
const ATE_UNSIGNED_CHAR: u32 = 0x08;

/// How many pointers in a struct still has its members (see the module comment).
const MEMBERS_DEPTH: u32 = 2;

pub(crate) struct Debug<'ctx> {
    pub di: DebugInfoBuilder<'ctx>,
    pub file: DIFile<'ctx>,
    cu: DICompileUnit<'ctx>,
    ptr_size: u32,
    /// The module's named structs and unions, for a pointer's opaque pointee.
    named: HashMap<String, Type>,
    types: RefCell<HashMap<String, DIType<'ctx>>>,
}

impl<'ctx> Debug<'ctx> {
    /// The compile unit for `ir`, with the module flags LLVM's DWARF needs.
    pub fn new(ctx: &'ctx Context, module: &LModule<'ctx>, ir: &Module, ptr_size: u32, optimized: bool) -> Self {
        let path = ir.source_file.clone().unwrap_or_else(|| ir.name.clone());
        let p = std::path::Path::new(&path);
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.clone());
        let dir = match p.parent().filter(|d| !d.as_os_str().is_empty()) {
            Some(d) => std::fs::canonicalize(d).unwrap_or_else(|_| d.to_path_buf()).to_string_lossy().into_owned(),
            None => std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default(),
        };
        let producer = ir.producer.clone().unwrap_or_else(|| "sic".to_string());
        let i32t = ctx.i32_type();
        module.add_basic_value_flag("Debug Info Version", FlagBehavior::Warning, i32t.const_int(3, false));
        module.add_basic_value_flag("Dwarf Version", FlagBehavior::Warning, i32t.const_int(4, false));
        let (di, cu) = module.create_debug_info_builder(
            true, DWARFSourceLanguage::C11, &name, &dir, &producer, optimized, "", 0, "",
            DWARFEmissionKind::Full, 0, false, false, "", "",
        );
        let file = cu.get_file();
        let named = ir.type_defs.iter().chain(&ir.debug_types).cloned().collect();
        Debug { di, file, cu, ptr_size, named, types: RefCell::new(HashMap::default()) }
    }

    /// The subprogram of the defined function `f` (`lf`), at its first line.
    pub fn subprogram(&self, f: &Function, lf: FunctionValue<'ctx>) -> DISubprogram<'ctx> {
        let line = first_line(f);
        let ret = self.ty(&f.sig.ret);
        let params: Vec<DIType> = f.params.iter().filter_map(|p| self.ty(&p.ty)).collect();
        let st = self.di.create_subroutine_type(self.file, ret, &params, DIFlags::ZERO);
        let local = matches!(f.linkage, Linkage::Internal | Linkage::Private);
        let sp = self.di.create_function(self.cu.as_debug_info_scope(), &f.name, None, self.file, line, st,
            local, true, line, DIFlags::ZERO, false);
        lf.set_subprogram(sp);
        sp
    }

    /// `ty` as a DWARF type; None for `void` and what has no description.
    pub fn ty(&self, ty: &Type) -> Option<DIType<'ctx>> {
        self.ty_at(ty, 0)
    }

    fn ty_at(&self, ty: &Type, depth: u32) -> Option<DIType<'ctx>> {
        let key = format!("{}#{}", ty, depth.min(MEMBERS_DEPTH + 1));
        if let Some(t) = self.types.borrow().get(&key) { return Some(*t); }
        let ps = self.ptr_size;
        let t = match ty {
            Type::Void | Type::Function(_) => return None,
            Type::Bool => self.base("_Bool", 8, ATE_BOOLEAN)?,
            Type::Int { bits, signed } => {
                let (name, enc) = match (*bits, *signed) {
                    (8, true) => ("char", ATE_SIGNED_CHAR),
                    (8, false) => ("unsigned char", ATE_UNSIGNED_CHAR),
                    (16, true) => ("short", ATE_SIGNED),
                    (16, false) => ("unsigned short", ATE_UNSIGNED),
                    (32, true) => ("int", ATE_SIGNED),
                    (32, false) => ("unsigned int", ATE_UNSIGNED),
                    (64, true) => ("long long", ATE_SIGNED),
                    (64, false) => ("unsigned long long", ATE_UNSIGNED),
                    (128, true) => ("__int128", ATE_SIGNED),
                    (128, false) => ("unsigned __int128", ATE_UNSIGNED),
                    (_, true) => ("int", ATE_SIGNED),
                    (_, false) => ("unsigned int", ATE_UNSIGNED),
                };
                self.base(name, *bits as u64, enc)?
            }
            Type::Float32 => self.base("float", 32, ATE_FLOAT)?,
            Type::Float64 => self.base("double", 64, ATE_FLOAT)?,
            // sic computes `long double` in double precision; its value is an
            // x87 one only in memory: a debugger reads the object.
            Type::Float80 => self.base("long double", 80, ATE_FLOAT)?,
            Type::Pointer(p) => {
                let pointee = match self.ty_at(p, depth + 1) {
                    Some(t) => t,
                    None => self.base("void", 8, ATE_UNSIGNED)?,
                };
                self.di.create_pointer_type("", pointee, ps as u64 * 8, ps * 8, AddressSpace::default()).as_type()
            }
            Type::Array { elem, len } => {
                let e = self.ty_at(elem, depth)?;
                self.di.create_array_type(e, ty.size_of(ps) * 8, ty.align_of(ps) as u32 * 8, &[0..*len as i64]).as_type()
            }
            Type::Struct(st) => {
                let full = match &st.name {
                    Some(n) if st.fields.is_empty() => self.named.get(n).cloned().unwrap_or_else(|| ty.clone()),
                    _ => ty.clone(),
                };
                let Type::Struct(full_st) = &full else { return None };
                let name = st.name.clone().unwrap_or_default();
                // Still a name only: a declaration, which a debugger completes by name.
                if full_st.fields.is_empty() && !name.is_empty() {
                    return Some(self.di.create_struct_type(self.cu.as_debug_info_scope(), &name, self.file, 0, 0, 0,
                        DIFlags::FWD_DECL, None, &[], 0, None, "").as_type());
                }
                let size = full.size_of(ps) * 8;
                let align = full.align_of(ps) as u32 * 8;
                if depth > MEMBERS_DEPTH {
                    return Some(self.di.create_struct_type(self.cu.as_debug_info_scope(), &name, self.file, 0, 0, 0,
                        DIFlags::FWD_DECL, None, &[], 0, None, "").as_type());
                }
                let members: Vec<DIType> = {
                    let (offs, _) = full_st.layout(ps);
                    full_st.fields.iter().zip(&offs).filter_map(|((fname, fty), off)| {
                        let t = self.ty_at(fty, depth + 1)?;
                        Some(self.di.create_member_type(self.cu.as_debug_info_scope(), fname, self.file, 0,
                            fty.size_of(ps) * 8, fty.align_of(ps) as u32 * 8, off * 8, DIFlags::ZERO, t).as_type())
                    }).collect()
                };
                self.di.create_struct_type(self.cu.as_debug_info_scope(), &name, self.file, 0, size, align,
                    DIFlags::ZERO, None, &members, 0, None, "").as_type()
            }
            Type::Union(u) => {
                let name = u.name.clone().unwrap_or_default();
                self.di.create_union_type(self.cu.as_debug_info_scope(), &name, self.file, 0,
                    ty.size_of(ps) * 8, ty.align_of(ps) as u32 * 8, DIFlags::ZERO, &[], 0, "").as_type()
            }
        };
        self.types.borrow_mut().insert(key, t);
        Some(t)
    }

    fn base(&self, name: &str, bits: u64, enc: u32) -> Option<DIType<'ctx>> {
        self.di.create_basic_type(name, bits, enc, DIFlags::ZERO).ok().map(|t| t.as_type())
    }

    pub fn scope(sp: DISubprogram<'ctx>) -> DIScope<'ctx> { sp.as_debug_info_scope() }
}

/// A function's first source line (0 when it has none).
pub fn first_line(f: &Function) -> u32 {
    f.blocks.iter().flat_map(|b| b.instrs.iter()).find_map(|i| match i {
        Instr::SrcLine(l) => Some(*l),
        _ => None,
    }).unwrap_or(0)
}
