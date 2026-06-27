mod types;
mod expr;
mod func;

use std::collections::HashMap;
use crate::ast::*;
use crate::{Result, CompileError};
use sic_ir::*;

pub use types::lower_type;

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
                        lower_type(&p.ty, &self.struct_types, self.ptr_size)
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
                        lower_type(&p.ty, &self.struct_types, self.ptr_size)
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

    fn register_struct_type_from_def(&mut self, s: &StructDef) -> Result<()> {
        if let (Some(name), Some(fields)) = (&s.name, &s.fields) {
            let mut ir_fields = Vec::new();
            for f in fields {
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
                let fname = f.name.clone().unwrap_or_default();
                let fty = lower_type(&f.ty, &self.struct_types, self.ptr_size)?;
                ir_fields.push((fname, fty));
            }
            let ir_ty = Type::Union(UnionType { name: Some(name.clone()), fields: ir_fields });
            self.struct_types.insert(name.clone(), ir_ty);
        }
        Ok(())
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
        let ir_ty = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        let init = match &d.init {
            Some(Initializer::Expr(e)) => {
                // Try integer constant evaluation first
                match eval_const_expr(e, &self.enum_consts) {
                    Ok(v) => Some(Constant::Int(v)),
                    Err(_) => {
                        // Try float literal
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
            _ => None,
        };
        let linkage = match base_ty.storage {
            Some(StorageClass::Static) => Linkage::Internal,
            Some(StorageClass::Extern) => Linkage::External,
            _ => Linkage::External,
        };
        let g = Global { name: d.name.clone(), ty: ir_ty, init, linkage, constant: base_ty.is_const() };
        let gref = self.module.add_global(g);
        let ir_ty2 = lower_type(&d.ty, &self.struct_types, self.ptr_size)?;
        self.globals_map.insert(d.name.clone(), (ir_ty2, gref));
        Ok(())
    }

    /// Synthesize `int main() { ...; return <last>; }` for SIC files without main.
    /// Returns the value of the last top-level item (expr or var decl).
    fn synthesize_fake_main(&mut self, tu: &TranslationUnit) -> Result<()> {
        // Only synthesize if the file has no regular function bodies and has at least some content.
        let has_content = tu.decls.iter().any(|d| !matches!(d, Decl::Func { .. }));
        if !has_content { return Ok(()); }

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
        ExprKind::IntLit(v) => Ok(*v),
        ExprKind::UIntLit(v) => Ok(*v as i64),
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
                _ => return Err(CompileError::new("non-constant expression")),
            })
        }
        ExprKind::Cast { expr, .. } => eval_const_expr(expr, enum_consts),
        _ => Err(CompileError::new("non-constant expression")),
    }
}
