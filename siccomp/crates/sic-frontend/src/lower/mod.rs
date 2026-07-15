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
            for f in fields {
                self.register_nested_struct_defs(&f.ty.ty)?;
                let fname = f.name.clone().unwrap_or_default();
                let fty = lower_type(&f.ty, &self.struct_types, self.ptr_size)?;
                ir_fields.push((fname, fty));
            }
            let ir_ty = Type::Struct(StructType { name: Some(name.clone()), fields: ir_fields, packed: false });
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
        let init = match &d.init {
            // `char arr[] = "..."` / `char *p = "..."`.
            Some(Initializer::Expr(e)) if matches!(&e.kind, ExprKind::StringLit(_)) => {
                let ExprKind::StringLit(s) = &e.kind else { unreachable!() };
                let mut bytes = s.clone().into_bytes();
                bytes.push(0); // NUL terminator
                match &mut ir_ty {
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
                    Err(_) => match &e.kind {
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
            Some(Initializer::List(items)) => {
                // Serialize a constant array initializer to bytes.
                if let Type::Array { elem: ref elem_ty, ref mut len } = ir_ty {
                    let elem_size = elem_ty.size_of(self.ptr_size) as usize;
                    let count = items.len();
                    if *len == 0 { *len = count; }
                    let total = (*len) * elem_size;
                    let mut bytes = vec![0u8; total];
                    for (i, item) in items.iter().enumerate() {
                        if i >= *len { break; }
                        let v = match item {
                            Initializer::Expr(e) => eval_const_expr(e, &self.enum_consts).unwrap_or(0),
                            _ => 0,
                        };
                        let start = i * elem_size;
                        match elem_size {
                            1 => bytes[start] = v as u8,
                            2 => bytes[start..start+2].copy_from_slice(&(v as i16).to_le_bytes()),
                            4 => bytes[start..start+4].copy_from_slice(&(v as i32).to_le_bytes()),
                            8 => bytes[start..start+8].copy_from_slice(&v.to_le_bytes()),
                            _ => {}
                        }
                    }
                    Some(Constant::Bytes(bytes))
                } else {
                    None
                }
            }
            _ => None,
        };
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
        let g = Global { name: d.name.clone(), ty: ir_ty, init, linkage, constant: base_ty.is_const() };
        let gref = self.module.add_global(g);
        self.globals_map.insert(d.name.clone(), (ty_for_map, gref));
        Ok(())
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
