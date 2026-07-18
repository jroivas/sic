mod types;
mod expr;
mod func;

use std::collections::HashMap;
use crate::ast::*;
use crate::{Result, CompileError};
use sic_ir::*;

pub use types::{lower_type, lower_param_type};

/// State shared across the lowering of one module.
pub struct Lowerer {
    pub module: Module,
    /// Maps name → (type, value pointing to storage)
    pub globals_map: HashMap<String, (Type, GlobalRef)>,
    /// Known enum variant values
    pub enum_consts: HashMap<String, i64>,
    /// Named struct/union types
    pub struct_types: HashMap<String, Type>,
    /// Target pointer size in bytes
    pub ptr_size: u32,
}

impl Lowerer {
    pub fn new(name: String) -> Self {
        Lowerer {
            module: Module::new(name),
            globals_map: HashMap::new(),
            enum_consts: HashMap::new(),
            struct_types: HashMap::new(),
            ptr_size: 8, // assume 64-bit
        }
    }

    pub fn lower(mut self, tu: &TranslationUnit) -> Result<Module> {
        // First pass: collect all function prototypes and global variable names
        // so that forward references work.
        self.collect_declarations(tu)?;

        // Second pass: lower function bodies and global initializers
        self.lower_translation_unit(tu)?;

        // If no main was defined, wrap top-level expression statements in a fake main.
        if self.module.func_ref_by_name("main").is_none() {
            self.synthesize_fake_main(tu)?;
        }

        Ok(self.module)
    }

    fn collect_declarations(&mut self, tu: &TranslationUnit) -> Result<()> {
        for decl in &tu.decls {
            match decl {
                Decl::Func { name, ret_ty, params, variadic, body: None, .. } => {
                    // Forward declaration / extern
                    let ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
                    let ir_params: Result<Vec<_>> = params.iter().map(|p| {
                        lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
                    }).collect();
                    let sig = FunctionType { ret: ir_ret, params: ir_params?, variadic: *variadic };
                    if self.module.func_ref_by_name(name).is_none() {
                        self.module.add_extern(ExternFunc { name: name.clone(), sig });
                    }
                }
                Decl::Func { name, ret_ty, params, variadic, body: Some(_), storage, .. } => {
                    // Function definition — pre-register with empty body for stable FuncRef
                    let ir_ret = lower_type(ret_ty, &self.struct_types, self.ptr_size)?;
                    let ir_params: Result<Vec<_>> = params.iter().map(|p| {
                        lower_param_type(&p.ty, &self.struct_types, self.ptr_size)
                    }).collect();
                    let sig = FunctionType { ret: ir_ret, params: ir_params?, variadic: *variadic };
                    if self.module.func_ref_by_name(name).is_none() {
                        let linkage = match storage {
                            Some(StorageClass::Static) => Linkage::Internal,
                            _ => Linkage::External,
                        };
                        self.module.add_function(Function::new(name.clone(), sig, vec![], linkage));
                    }
                }
                Decl::TypeDef { names, .. } => {
                    for (name, ty) in names {
                        if let Ok(ir_ty) = lower_type(ty, &self.struct_types, self.ptr_size) {
                            // Also register named struct/union by their own name
                            match &ty.ty {
                                AstType::Struct(s) if s.name.is_some() && s.fields.is_some() => {
                                    self.struct_types.insert(s.name.clone().unwrap(), ir_ty.clone());
                                }
                                AstType::Union(u) if u.name.is_some() && u.fields.is_some() => {
                                    self.struct_types.insert(u.name.clone().unwrap(), ir_ty.clone());
                                }
                                AstType::Enum(e) => { self.register_enum(e)?; }
                                _ => {}
                            }
                            self.struct_types.insert(name.clone(), ir_ty);
                        }
                    }
                }
                Decl::StructDecl(s) | Decl::Var { base_ty: QualType { ty: AstType::Struct(s), .. }, .. } => {
                    self.register_struct_type_from_def(s)?;
                }
                Decl::UnionDecl(u) | Decl::Var { base_ty: QualType { ty: AstType::Union(u), .. }, .. } => {
                    self.register_union_type_from_def(u)?;
                }
                Decl::EnumDecl(e) => {
                    self.register_enum(e)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Register any tagged struct/union definitions nested inside a type so they
    /// resolve when later referenced standalone by tag — e.g. a `struct _ht {...}
    /// *ht;` member whose `struct _ht` is used elsewhere as a parameter type.
    fn register_nested_struct_defs(&mut self, ty: &AstType) -> Result<()> {
        match ty {
            AstType::Struct(s) => {
                if s.name.is_some() && s.fields.is_some() {
                    self.register_struct_type_from_def(s)?;
                }
                // Recurse into the body so deeper tagged definitions (even inside
                // anonymous structs/unions) are registered too.
                if let Some(fields) = &s.fields {
                    for f in fields { self.register_nested_struct_defs(&f.ty.ty)?; }
                }
            }
            AstType::Union(u) => {
                if u.name.is_some() && u.fields.is_some() {
                    self.register_union_type_from_def(u)?;
                }
                if let Some(fields) = &u.fields {
                    for f in fields { self.register_nested_struct_defs(&f.ty.ty)?; }
                }
            }
            AstType::Pointer { base, .. } | AstType::Array { base, .. } => {
                self.register_nested_struct_defs(&base.ty)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn register_struct_type_from_def(&mut self, s: &StructDef) -> Result<()> {
        if let (Some(name), Some(fields)) = (&s.name, &s.fields) {
            let mut ir_fields = Vec::new();
            let mut bitfields = Vec::new();
            let mut any_bitfield = false;
            for f in fields {
                self.register_nested_struct_defs(&f.ty.ty)?;
                let fname = f.name.clone().unwrap_or_default();
                let fty = lower_type(&f.ty, &self.struct_types, self.ptr_size)?;
                let bw = f.bit_width.as_ref().map(|e| eval_const_expr(e, &self.enum_consts).unwrap_or(0) as u32);
                if bw.is_some() { any_bitfield = true; }
                ir_fields.push((fname, fty));
                bitfields.push(bw);
            }
            let ir_ty = Type::Struct(StructType {
                name: Some(name.clone()),
                fields: ir_fields,
                packed: false,
                bitfields: if any_bitfield { bitfields } else { Vec::new() },
            });
            self.struct_types.insert(name.clone(), ir_ty);
        }
        Ok(())
    }

    fn register_union_type_from_def(&mut self, u: &UnionDef) -> Result<()> {
        if let (Some(name), Some(fields)) = (&u.name, &u.fields) {
            let mut ir_fields = Vec::new();
            for f in fields {
                self.register_nested_struct_defs(&f.ty.ty)?;
                let fname = f.name.clone().unwrap_or_default();
                let fty = lower_type(&f.ty, &self.struct_types, self.ptr_size)?;
                ir_fields.push((fname, fty));
            }
            let ir_ty = Type::Union(UnionType { name: Some(name.clone()), fields: ir_fields });
            self.struct_types.insert(name.clone(), ir_ty);
        }
        Ok(())
    }

    /// Emit `bytes` (already NUL-terminated) as a private, constant global and
    /// return a reference to it. Used for string-literal pointer initializers.
    fn add_cstring_global(&mut self, bytes: Vec<u8>) -> GlobalRef {
        let name = format!(".str.{}", self.module.globals.len());
        let len = bytes.len();
        let g = Global {
            name,
            ty: Type::Array { elem: Box::new(Type::i8()), len },
            init: Some(Constant::Bytes(bytes)),
            linkage: Linkage::Private,
            constant: true,
        };
        self.module.add_global(g)
    }

    fn register_enum(&mut self, e: &EnumDef) -> Result<()> {
        if let Some(variants) = &e.variants {
            let mut counter = 0i64;
            for v in variants {
                let val = if let Some(init) = &v.value {
                    eval_const_expr(init, &self.enum_consts)?
                } else {
                    counter
                };
                self.enum_consts.insert(v.name.clone(), val);
                counter = val + 1;
            }
        }
        Ok(())
    }

    fn lower_translation_unit(&mut self, tu: &TranslationUnit) -> Result<()> {
        for decl in &tu.decls {
            self.lower_global_decl(decl)?;
        }
        Ok(())
    }

    fn lower_global_decl(&mut self, decl: &Decl) -> Result<()> {
        match decl {
            Decl::Func { name, ret_ty, params, variadic, body: Some(body), storage, .. } => {
                self.lower_function(name, ret_ty, params, *variadic, body, storage)?;
            }
            Decl::Func { body: None, .. } => {
                // Already handled in collect_declarations
            }
            Decl::Var { base_ty, declarators, .. } => {
                // Check for struct/union/enum definitions within the base type
                match &base_ty.ty {
                    AstType::Struct(s) => { self.register_struct_type_from_def(s)?; }
                    AstType::Union(u)  => { self.register_union_type_from_def(u)?; }
                    AstType::Enum(e)   => { self.register_enum(e)?; }
                    _ => {}
                }
                for d in declarators {
                    self.lower_global_var(d, base_ty)?;
                }
            }
            Decl::TypeDef { names, .. } => {
                for (name, ty) in names {
                    if let Ok(ir_ty) = lower_type(ty, &self.struct_types, self.ptr_size) {
                        // Also register named struct/union by their own name
                        match &ty.ty {
                            AstType::Struct(s) if s.name.is_some() && s.fields.is_some() => {
                                self.struct_types.insert(s.name.clone().unwrap(), ir_ty.clone());
                            }
                            AstType::Union(u) if u.name.is_some() && u.fields.is_some() => {
                                self.struct_types.insert(u.name.clone().unwrap(), ir_ty.clone());
                            }
                            AstType::Enum(e) => { self.register_enum(e)?; }
                            _ => {}
                        }
                        self.struct_types.insert(name.clone(), ir_ty);
                    }
                }
            }
            Decl::StructDecl(s) => { self.register_struct_type_from_def(s)?; }
            Decl::UnionDecl(u)  => { self.register_union_type_from_def(u)?; }
            Decl::EnumDecl(e)   => { self.register_enum(e)?; }
            Decl::ExprStmt(_, _) => {
                // Top-level expression statements — deferred to fake_main synthesis
            }
        }
        Ok(())
    }

    fn lower_global_var(&mut self, d: &Declarator, base_ty: &QualType) -> Result<()> {
        // Skip duplicate declarations (e.g. `int a;` declared twice)
        if self.globals_map.contains_key(&d.name) {
            return Ok(());
        }
        let mut ir_ty = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        let init = self.build_global_init(d, &mut ir_ty);
        let linkage = match base_ty.storage {
            Some(StorageClass::Static) => Linkage::Internal,
            // `extern T x;` with no initializer is a pure declaration: the
            // object lives in another translation unit (e.g. libc's `stdout`).
            // Emit it as an import so we don't shadow it with a zero definition.
            Some(StorageClass::Extern) if init.is_none() => Linkage::Import,
            Some(StorageClass::Extern) => Linkage::External,
            _ => Linkage::External,
        };
        let ty_for_map = ir_ty.clone();
        let g = Global { name: d.name.clone(), ty: ir_ty, init, linkage, constant: type_is_const(&d.ty) };
        let gref = self.module.add_global(g);
        self.globals_map.insert(d.name.clone(), (ty_for_map, gref));
        Ok(())
    }

    /// Create an internal global backing a function-scope `static` local, and
    /// return its type and ref. Uses the same constant-initializer serialization
    /// as file-scope globals; the caller binds the local name to this global.
    fn add_static_local_global(&mut self, name: String, d: &Declarator, _base_ty: &QualType) -> Result<(Type, GlobalRef)> {
        let mut ir_ty = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        let init = self.build_global_init(d, &mut ir_ty);
        let ty_for_map = ir_ty.clone();
        let g = Global { name, ty: ir_ty, init, linkage: Linkage::Internal, constant: type_is_const(&d.ty) };
        let gref = self.module.add_global(g);
        Ok((ty_for_map, gref))
    }

    /// Serialize a variable's constant initializer to an IR `Constant`, adjusting
    /// `ir_ty` for inferred array lengths. Shared by file-scope globals and
    /// function-scope `static` locals.
    fn build_global_init(&mut self, d: &Declarator, ir_ty: &mut Type) -> Option<Constant> {
        match &d.init {
            // `char arr[] = "..."` / `char *p = "..."`.
            Some(Initializer::Expr(e)) if matches!(&e.kind, ExprKind::StringLit(_)) => {
                let ExprKind::StringLit(s) = &e.kind else { unreachable!() };
                let mut bytes = s.clone().into_bytes();
                bytes.push(0); // NUL terminator
                match &mut *ir_ty {
                    // Array target: store the bytes inline, sizing an
                    // unspecified length to fit the string.
                    Type::Array { len, .. } => {
                        if *len == 0 { *len = bytes.len(); }
                        Some(Constant::Bytes(bytes))
                    }
                    // Pointer target: emit the string as a private global and
                    // point at it.
                    _ => {
                        let gref = self.add_cstring_global(bytes);
                        Some(Constant::GlobalAddr(gref))
                    }
                }
            }
            Some(Initializer::Expr(e)) => {
                match eval_const_expr(e, &self.enum_consts) {
                    Ok(v) => Some(Constant::Int(v)),
                    Err(_) => {
                        // A pointer global initialized with a symbolic address:
                        // another array/function name, `&x`, or a string.
                        if matches!(&*ir_ty, Type::Pointer(_)) {
                            if let Some(reloc) = self.eval_ptr_reloc(e) {
                                return match reloc {
                                    RelocTarget::Global(g, 0) => Some(Constant::GlobalAddr(g)),
                                    other => {
                                        let ps = self.ptr_size as usize;
                                        Some(Constant::Aggregate {
                                            bytes: vec![0u8; ps],
                                            relocs: vec![(0, other)],
                                        })
                                    }
                                };
                            }
                        }
                        match &e.kind {
                            ExprKind::FloatLit(f) => Some(Constant::Float(*f)),
                            ExprKind::Cast { expr: inner, .. } => {
                                if let ExprKind::FloatLit(f) = &inner.kind {
                                    Some(Constant::Float(*f))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                }
            }
            Some(Initializer::List(items)) => {
                // Infer an unspecified top-level array length from the brace list.
                if let Type::Array { len, .. } = &mut *ir_ty {
                    if *len == 0 { *len = items.len(); }
                }
                let total = ir_ty.size_of(self.ptr_size) as usize;
                let ty_snapshot = ir_ty.clone();
                let init = d.init.as_ref().unwrap();
                let mut buf = vec![0u8; total.max(1)];
                let mut relocs = Vec::new();
                if self.serialize_const(init, &ty_snapshot, &mut buf, 0, &mut relocs) {
                    buf.truncate(total);
                    if relocs.is_empty() {
                        Some(Constant::Bytes(buf))
                    } else {
                        Some(Constant::Aggregate { bytes: buf, relocs })
                    }
                } else {
                    // Couldn't fully serialize as a constant; zero-fill rather
                    // than emit garbage.
                    Some(Constant::Zeroinit)
                }
            }
            _ => None,
        }
    }

    /// Recursively serialize `init` for a value of `ty` into `buf[base..]`,
    /// collecting pointer relocations for embedded symbol addresses. Returns
    /// false if some component isn't a translation-time constant.
    fn serialize_const(
        &mut self,
        init: &Initializer,
        ty: &Type,
        buf: &mut [u8],
        base: usize,
        relocs: &mut Vec<(usize, RelocTarget)>,
    ) -> bool {
        let ty = types::resolve_aggregate(ty, &self.struct_types);
        match &ty {
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => {
                // `char arr[] = "..."` inside a larger aggregate.
                if let (Type::Array { elem, .. }, Initializer::Expr(e)) = (&ty, init) {
                    if let ExprKind::StringLit(s) = &e.kind {
                        if elem.size_of(self.ptr_size) == 1 {
                            let mut bytes = s.clone().into_bytes();
                            bytes.push(0);
                            let n = bytes.len().min(buf.len().saturating_sub(base));
                            buf[base..base + n].copy_from_slice(&bytes[..n]);
                            return true;
                        }
                    }
                    return false;
                }
                let Initializer::List(items) = init else { return false };
                let mut cursor = 0usize;
                for item in items {
                    let (target, next) =
                        self.designated_const_target(&ty, &item.designators, cursor, base);
                    if let Some((off, leaf)) = target {
                        if !self.serialize_const(&item.init, &leaf, buf, off, relocs) {
                            return false;
                        }
                    }
                    cursor = next;
                }
                true
            }
            _ => {
                // Scalar leaf. A braced scalar (`{ x }`) is also accepted.
                let e = match init {
                    Initializer::Expr(e) => e,
                    Initializer::List(items) => match items.first() {
                        Some(InitItem { init: Initializer::Expr(e), .. }) => e,
                        _ => return false,
                    },
                };
                self.serialize_scalar(e, &ty, buf, base, relocs)
            }
        }
    }

    /// Resolve a global brace-list element's byte offset, leaf type and the next
    /// positional cursor — the constant-serialization analogue of
    /// `resolve_init_target`. Handles designators (including chained ones) and
    /// anonymous members.
    fn designated_const_target(&self, agg: &Type, designators: &[crate::ast::Designator], cursor: usize, base: usize)
        -> (Option<(usize, Type)>, usize)
    {
        use crate::ast::Designator;
        let member_at = |me: &Self, agg: &Type, idx: usize, base: usize| -> Option<(usize, Type)> {
            let r = types::resolve_aggregate(agg, &me.struct_types);
            match &r {
                Type::Struct(st) => {
                    let fty = st.fields.get(idx)?.1.clone();
                    Some((base + st.field_offset(idx, me.ptr_size) as usize, fty))
                }
                Type::Union(u) => Some((base, u.fields.get(idx)?.1.clone())),
                Type::Array { elem, len } => {
                    if *len > 0 && idx >= *len { return None; }
                    Some((base + idx * elem.size_of(me.ptr_size) as usize, (**elem).clone()))
                }
                _ => None,
            }
        };
        let (first, top_index) = match designators.first() {
            Some(Designator::Field(name)) => {
                match crate::lower::expr::resolve_field_access(agg, name, self.ptr_size, &self.struct_types) {
                    Some((foff, fty, _)) => (Some((base + foff as usize, fty)),
                                             crate::lower::func::top_field_index(agg, name, &self.struct_types)),
                    None => return (None, cursor + 1),
                }
            }
            Some(Designator::Index(e)) => {
                let i = eval_const_expr(e, &self.enum_consts).unwrap_or(0).max(0) as usize;
                (member_at(self, agg, i, base), i)
            }
            None => (member_at(self, agg, cursor, base), cursor),
        };
        let Some((mut off, mut cur_ty)) = first else { return (None, top_index + 1); };
        let rest = if designators.is_empty() { &designators[..] } else { &designators[1..] };
        for d in rest {
            match d {
                Designator::Field(name) => {
                    match crate::lower::expr::resolve_field_access(&cur_ty, name, self.ptr_size, &self.struct_types) {
                        Some((foff, fty, _)) => { off += foff as usize; cur_ty = fty; }
                        None => return (None, top_index + 1),
                    }
                }
                Designator::Index(e) => {
                    let i = eval_const_expr(e, &self.enum_consts).unwrap_or(0).max(0) as usize;
                    let Some((o, t)) = member_at(self, &cur_ty, i, off) else { return (None, top_index + 1); };
                    off = o; cur_ty = t;
                }
            }
        }
        (Some((off, cur_ty)), top_index + 1)
    }

    /// Serialize a scalar constant expression into `buf[base..base+size]`.
    fn serialize_scalar(
        &mut self,
        e: &Expr,
        ty: &Type,
        buf: &mut [u8],
        base: usize,
        relocs: &mut Vec<(usize, RelocTarget)>,
    ) -> bool {
        let size = ty.size_of(self.ptr_size) as usize;
        if size == 0 || base + size > buf.len() { return false; }
        match ty {
            Type::Float32 => match self.eval_const_float(e) {
                Some(f) => { buf[base..base + 4].copy_from_slice(&(f as f32).to_le_bytes()); true }
                None => false,
            },
            Type::Float64 | Type::Float80 => match self.eval_const_float(e) {
                Some(f) => { buf[base..base + 8].copy_from_slice(&f.to_le_bytes()); true }
                None => false,
            },
            Type::Pointer(_) => {
                if let Some(reloc) = self.eval_ptr_reloc(e) {
                    relocs.push((base, reloc));
                    return true;
                }
                // NULL or an integer cast to a pointer.
                match self.eval_const_int(e) {
                    Some(v) => { buf[base..base + size].copy_from_slice(&v.to_le_bytes()[..size]); true }
                    None => false,
                }
            }
            _ => match self.eval_const_int(e) {
                Some(v) => { buf[base..base + size].copy_from_slice(&v.to_le_bytes()[..size]); true }
                None => false,
            },
        }
    }

    /// Evaluate a constant integer expression, extending [`eval_const_expr`] with
    /// type-dependent operators (`sizeof`) that need the type table. Recurses so
    /// `sizeof(T)` nested in arithmetic still folds.
    fn eval_const_int(&self, e: &Expr) -> Option<i64> {
        if let Ok(v) = eval_const_expr(e, &self.enum_consts) {
            return Some(v);
        }
        match &e.kind {
            ExprKind::SizeofType(qt) => {
                lower_type(qt, &self.struct_types, self.ptr_size).ok()
                    .map(|t| t.size_of(self.ptr_size) as i64)
            }
            ExprKind::Cast { expr, .. } => self.eval_const_int(expr),
            ExprKind::Unary { op: UnOpKind::Neg, expr } => self.eval_const_int(expr).map(|v| v.wrapping_neg()),
            ExprKind::Unary { op: UnOpKind::BitNot, expr } => self.eval_const_int(expr).map(|v| !v),
            ExprKind::Unary { op: UnOpKind::Not, expr } => self.eval_const_int(expr).map(|v| (v == 0) as i64),
            ExprKind::BinOp { op, lhs, rhs } => {
                let l = self.eval_const_int(lhs)?;
                let r = self.eval_const_int(rhs)?;
                Some(match op {
                    BinOpKind::Add => l.wrapping_add(r),
                    BinOpKind::Sub => l.wrapping_sub(r),
                    BinOpKind::Mul => l.wrapping_mul(r),
                    BinOpKind::Div => if r != 0 { l.wrapping_div(r) } else { 0 },
                    BinOpKind::Rem => if r != 0 { l.wrapping_rem(r) } else { 0 },
                    BinOpKind::Shl => l.wrapping_shl(r as u32),
                    BinOpKind::Shr => l.wrapping_shr(r as u32),
                    BinOpKind::BitAnd => l & r,
                    BinOpKind::BitOr => l | r,
                    BinOpKind::BitXor => l ^ r,
                    _ => return None,
                })
            }
            ExprKind::Ternary { cond, then, else_ } => {
                if self.eval_const_int(cond)? != 0 { self.eval_const_int(then) } else { self.eval_const_int(else_) }
            }
            _ => None,
        }
    }

    /// Evaluate a constant floating-point expression.
    fn eval_const_float(&self, e: &Expr) -> Option<f64> {
        match &e.kind {
            ExprKind::FloatLit(f) => Some(*f),
            ExprKind::Unary { op: UnOpKind::Neg, expr } => self.eval_const_float(expr).map(|f| -f),
            ExprKind::Cast { expr, .. } => self.eval_const_float(expr),
            _ => eval_const_expr(e, &self.enum_consts).ok().map(|v| v as f64),
        }
    }

    /// Evaluate a constant expression producing a pointer to a symbol.
    fn eval_ptr_reloc(&mut self, e: &Expr) -> Option<RelocTarget> {
        match &e.kind {
            ExprKind::Cast { expr, .. } => self.eval_ptr_reloc(expr),
            ExprKind::StringLit(s) => {
                let mut bytes = s.clone().into_bytes();
                bytes.push(0);
                let g = self.add_cstring_global(bytes);
                Some(RelocTarget::Global(g, 0))
            }
            ExprKind::Unary { op: UnOpKind::Addr, expr } => self.addr_of_reloc(expr),
            // A bare function or array name decays to its own address.
            ExprKind::Ident(name) => {
                if let Some(fref) = self.module.func_ref_by_name(name) {
                    return Some(RelocTarget::Func(fref));
                }
                if let Some((ty, gref)) = self.globals_map.get(name) {
                    if matches!(ty, Type::Array { .. }) {
                        return Some(RelocTarget::Global(*gref, 0));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Resolve `&expr` to a relocation target.
    fn addr_of_reloc(&mut self, e: &Expr) -> Option<RelocTarget> {
        if let ExprKind::Ident(name) = &e.kind {
            if let Some(fref) = self.module.func_ref_by_name(name) {
                return Some(RelocTarget::Func(fref));
            }
        }
        let (gref, off, _) = self.base_addr(e)?;
        Some(RelocTarget::Global(gref, off))
    }

    /// Resolve a constant lvalue expression to (global, byte offset, type).
    fn base_addr(&self, e: &Expr) -> Option<(GlobalRef, i64, Type)> {
        match &e.kind {
            ExprKind::Ident(name) => {
                let (ty, gref) = self.globals_map.get(name)?;
                Some((*gref, 0, ty.clone()))
            }
            ExprKind::Index { base, index } => {
                let (gref, off, bty) = self.base_addr(base)?;
                let elem = match types::resolve_aggregate(&bty, &self.struct_types) {
                    Type::Array { elem, .. } => *elem,
                    _ => return None,
                };
                let idx = eval_const_expr(index, &self.enum_consts).ok()?;
                let esize = elem.size_of(self.ptr_size) as i64;
                Some((gref, off + idx * esize, elem))
            }
            ExprKind::Field { base, name } => {
                let (gref, off, bty) = self.base_addr(base)?;
                let st = types::resolve_aggregate(&bty, &self.struct_types);
                let (foff, fty) = field_offset_by_name(&st, name, self.ptr_size)?;
                Some((gref, off + foff as i64, fty))
            }
            _ => None,
        }
    }

    /// Synthesize `int main() { ...; return <last>; }` for SIC files without main.
    /// Returns the value of the last top-level item (expr or var decl).
    fn synthesize_fake_main(&mut self, tu: &TranslationUnit) -> Result<()> {
        // Synthesize a `main` only for sic REPL-style inputs: files made up of
        // bare top-level expressions and/or variable declarations, with no
        // function definitions of their own. A normal C translation unit that
        // *defines* functions but happens to lack `main` is a library unit —
        // fabricating a `main` there causes "multiple definition of main" when
        // several such objects are linked together.
        let defines_functions = tu.decls.iter()
            .any(|d| matches!(d, Decl::Func { body: Some(_), .. }));
        let has_content = tu.decls.iter().any(|d| !matches!(d, Decl::Func { .. }));
        if defines_functions || !has_content { return Ok(()); }

        let sig = FunctionType { ret: Type::i32(), params: vec![], variadic: false };
        let mut func = Function::new("main".to_string(), sig, vec![], Linkage::External);

        let entry_id = func.alloc_block();
        func.blocks.push(BasicBlock::new(entry_id));

        let mut fc = func::FuncCtx::new_with_func(self, &mut func);

        let mut last_val: Val = Constant::zero();

        for decl in &tu.decls.clone() {
            match decl {
                Decl::ExprStmt(e, _) => {
                    last_val = fc.lower_expr(e)?;
                }
                Decl::Var { declarators, .. } => {
                    // Read the last global from this var decl
                    for d in declarators {
                        if let Some((ty, gref)) = fc.lowerer.globals_map.get(&d.name) {
                            let ty = ty.clone();
                            let gref = *gref;
                            let dest = fc.alloc_val();
                            fc.push_instr(Instr::Load { dest, ptr: Val::Global(gref), ty });
                            last_val = Val::Local(dest);
                        }
                    }
                }
                _ => {}
            }
        }

        let ret = fc.coerce(last_val, &Type::i32())?;
        fc.set_terminator(Terminator::Ret(Some(ret)));
        drop(fc);

        self.module.add_function(func);
        Ok(())
    }
}

/// Whether an object of this declared type belongs in read-only storage.
/// A `const` qualifier makes the object read-only; for arrays the qualification
/// applies to the element type, so `const char arr[]` is read-only but
/// `const char *arr[]` (array of pointers to const char) is writable.
fn type_is_const(qt: &QualType) -> bool {
    if qt.is_const() { return true; }
    if let AstType::Array { base, .. } = &qt.ty {
        return type_is_const(base);
    }
    false
}

/// Look up a struct/union field by name, returning its byte offset and type.
fn field_offset_by_name(st: &Type, name: &str, ptr_size: u32) -> Option<(u64, Type)> {
    match st {
        Type::Struct(s) => {
            let idx = s.fields.iter().position(|(n, _)| n == name)?;
            Some((s.field_offset(idx, ptr_size), s.fields[idx].1.clone()))
        }
        Type::Union(u) => {
            let (_, fty) = u.fields.iter().find(|(n, _)| n == name)?;
            Some((0, fty.clone()))
        }
        _ => None,
    }
}

/// Evaluate a constant expression (only literals and simple arithmetic).
pub fn eval_const_expr(e: &Expr, enum_consts: &HashMap<String, i64>) -> Result<i64> {
    match &e.kind {
        ExprKind::IntLit(v, _) => Ok(*v),
        ExprKind::UIntLit(v, _) => Ok(*v as i64),
        ExprKind::CharLit(v) => Ok(*v as i64),
        ExprKind::Ident(name) => {
            enum_consts.get(name.as_str()).copied().ok_or_else(|| {
                CompileError::at(format!("'{}' is not a constant", name), None, 0, 0)
            })
        }
        ExprKind::Unary { op: UnOpKind::Neg, expr } => Ok(-eval_const_expr(expr, enum_consts)?),
        ExprKind::Unary { op: UnOpKind::BitNot, expr } => Ok(!eval_const_expr(expr, enum_consts)?),
        ExprKind::Unary { op: UnOpKind::Not, expr } => {
            Ok(if eval_const_expr(expr, enum_consts)? == 0 { 1 } else { 0 })
        }
        ExprKind::BinOp { op, lhs, rhs } => {
            let l = eval_const_expr(lhs, enum_consts)?;
            let r = eval_const_expr(rhs, enum_consts)?;
            Ok(match op {
                BinOpKind::Add => l.wrapping_add(r),
                BinOpKind::Sub => l.wrapping_sub(r),
                BinOpKind::Mul => l.wrapping_mul(r),
                BinOpKind::Div if r != 0 => l / r,
                BinOpKind::Rem if r != 0 => l % r,
                BinOpKind::BitAnd => l & r,
                BinOpKind::BitOr  => l | r,
                BinOpKind::BitXor => l ^ r,
                BinOpKind::Shl    => l << (r & 63),
                BinOpKind::Shr    => l >> (r & 63),
                BinOpKind::Eq     => if l == r { 1 } else { 0 },
                BinOpKind::Ne     => if l != r { 1 } else { 0 },
                BinOpKind::Lt     => if l < r  { 1 } else { 0 },
                BinOpKind::Le     => if l <= r { 1 } else { 0 },
                BinOpKind::Gt     => if l > r  { 1 } else { 0 },
                BinOpKind::Ge     => if l >= r { 1 } else { 0 },
                BinOpKind::LogAnd => if l != 0 && r != 0 { 1 } else { 0 },
                BinOpKind::LogOr  => if l != 0 || r != 0 { 1 } else { 0 },
                _ => return Err(CompileError::new("non-constant expression")),
            })
        }
        ExprKind::Ternary { cond, then, else_ } => {
            if eval_const_expr(cond, enum_consts)? != 0 {
                eval_const_expr(then, enum_consts)
            } else {
                eval_const_expr(else_, enum_consts)
            }
        }
        ExprKind::Cast { expr, .. } => eval_const_expr(expr, enum_consts),
        _ => {
            let sp = &e.span;
            Err(CompileError::at("non-constant expression", sp.file.clone(), sp.line, sp.col))
        }
    }
}
