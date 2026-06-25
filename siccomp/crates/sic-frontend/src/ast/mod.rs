use crate::lexer::Span;

pub type BoxExpr = Box<Expr>;
pub type BoxStmt = Box<Stmt>;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QualType {
    pub ty: AstType,
    pub qualifiers: Vec<TypeQual>,
    pub storage: Option<StorageClass>,
}

impl QualType {
    pub fn new(ty: AstType) -> Self { QualType { ty, qualifiers: vec![], storage: None } }
    pub fn is_const(&self) -> bool { self.qualifiers.contains(&TypeQual::Const) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeQual {
    Const, Volatile, Restrict, Atomic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageClass {
    Auto, Register, Static, Extern, Typedef,
}

#[derive(Debug, Clone)]
pub enum AstType {
    Void,
    Char { signed: Option<bool> },        // char / signed char / unsigned char
    Short { signed: bool },
    Int { signed: bool },
    Long { signed: bool },
    LongLong { signed: bool },
    Float,
    Double,
    LongDouble,
    Bool,
    Complex,
    Pointer { base: Box<QualType>, quals: Vec<TypeQual> },
    Array { base: Box<QualType>, size: Option<BoxExpr> },
    Function { ret: Box<QualType>, params: Vec<Param>, variadic: bool },
    Struct(StructDef),
    Union(UnionDef),
    Enum(EnumDef),
    Named(String),    // typedef name
    Builtin(String),  // __builtin_va_list etc.
}

// ─── Struct / Union / Enum ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: Option<String>,
    pub fields: Option<Vec<FieldDecl>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct UnionDef {
    pub name: Option<String>,
    pub fields: Option<Vec<FieldDecl>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub name: Option<String>,
    pub ty: QualType,
    pub bit_width: Option<BoxExpr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumDef {
    pub name: Option<String>,
    pub variants: Option<Vec<EnumVariant>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub value: Option<BoxExpr>,
    pub span: Span,
}

// ─── Declarations ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Param {
    pub name: Option<String>,
    pub ty: QualType,
    pub span: Span,
}

/// A single declarator within a declaration: name + optional init.
#[derive(Debug, Clone)]
pub struct Declarator {
    pub name: String,
    pub ty: QualType,            // fully resolved type (pointer levels etc. applied)
    pub init: Option<Initializer>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Initializer {
    Expr(Expr),
    List(Vec<Initializer>),
}

/// A top-level declaration.
#[derive(Debug, Clone)]
pub enum Decl {
    Var {
        base_ty: QualType,
        declarators: Vec<Declarator>,
        span: Span,
    },
    Func {
        name: String,
        ret_ty: QualType,
        params: Vec<Param>,
        variadic: bool,
        body: Option<Vec<Stmt>>,   // None = prototype only
        storage: Option<StorageClass>,
        span: Span,
    },
    TypeDef {
        names: Vec<(String, QualType)>,
        span: Span,
    },
    StructDecl(StructDef),
    UnionDecl(UnionDef),
    EnumDecl(EnumDef),
    /// Top-level standalone expression statement (SIC "fake main" mode)
    ExprStmt(Expr, Span),
}

// ─── Statements ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Stmt {
    Decl(Decl),
    Expr(Expr, Span),
    Block(Vec<Stmt>, Span),
    If { cond: Expr, then: BoxStmt, else_: Option<BoxStmt>, span: Span },
    While { cond: Expr, body: BoxStmt, span: Span },
    DoWhile { body: BoxStmt, cond: Expr, span: Span },
    For {
        init: Option<ForInit>,
        cond: Option<Expr>,
        post: Option<Expr>,
        body: BoxStmt,
        span: Span,
    },
    Return(Option<Expr>, Span),
    Break(Span),
    Continue(Span),
    Goto(String, Span),
    Label(String, BoxStmt, Span),
    Case(Expr, BoxStmt, Span),
    Default(BoxStmt, Span),
    Switch { val: Expr, body: BoxStmt, span: Span },
    Null(Span),
}

#[derive(Debug, Clone)]
pub enum ForInit {
    Decl(Decl),
    Expr(Expr),
}

// ─── Expressions ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

impl Expr {
    pub fn new(kind: ExprKind, span: Span) -> Self { Expr { kind, span } }
}

#[derive(Debug, Clone)]
pub enum ExprKind {
    IntLit(i64),
    UIntLit(u64),
    FloatLit(f64),
    StringLit(String),
    CharLit(i32),
    Ident(String),

    /// Binary operation
    BinOp { op: BinOpKind, lhs: BoxExpr, rhs: BoxExpr },

    /// Compound assignment: a += b, a -= b, etc.
    Assign { op: Option<BinOpKind>, lhs: BoxExpr, rhs: BoxExpr },

    /// Unary prefix
    Unary { op: UnOpKind, expr: BoxExpr },

    /// Pre-increment / pre-decrement
    PreInc { inc: bool, expr: BoxExpr },

    /// Post-increment / post-decrement
    PostInc { inc: bool, expr: BoxExpr },

    /// Ternary: cond ? a : b
    Ternary { cond: BoxExpr, then: BoxExpr, else_: BoxExpr },

    /// Function call: f(args)
    Call { func: BoxExpr, args: Vec<Expr> },

    /// Array subscript: a[i]
    Index { base: BoxExpr, index: BoxExpr },

    /// Field access: a.field
    Field { base: BoxExpr, name: String },

    /// Arrow access: a->field
    Arrow { base: BoxExpr, name: String },

    /// sizeof(expr) or sizeof(type)
    SizeofExpr(BoxExpr),
    SizeofType(QualType),

    /// Cast: (type)expr
    Cast { ty: QualType, expr: BoxExpr },

    /// Comma expression: a, b
    Comma(BoxExpr, BoxExpr),

    /// Compound literal: (Type){ ... }
    CompoundLiteral { ty: QualType, init: Vec<Initializer> },

    /// __builtin_va_start / va_arg / va_end
    VaStart { list: BoxExpr, last: BoxExpr },
    VaArg { list: BoxExpr, ty: QualType },
    VaEnd { list: BoxExpr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    Add, Sub, Mul, Div, Rem,
    BitAnd, BitOr, BitXor,
    Shl, Shr,
    Eq, Ne, Lt, Le, Gt, Ge,
    LogAnd, LogOr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOpKind {
    Neg,      // -x
    Not,      // !x
    BitNot,   // ~x
    Addr,     // &x
    Deref,    // *x
}

/// The translation unit: a list of top-level declarations.
#[derive(Debug, Clone)]
pub struct TranslationUnit {
    pub decls: Vec<Decl>,
    pub source_file: String,
}
