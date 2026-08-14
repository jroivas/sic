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
    /// `_Alignas(N)` / `alignas(N)` — the requested alignment in bytes.
    Align(u32),
    /// `inline` function specifier (carried on the decl-specifier `QualType` so
    /// function definitions can record it; see `Decl::Func::inline`).
    Inline,
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
    Typeof(BoxExpr),  // typeof(expr) — resolved to the operand's type
}

// ─── Struct / Union / Enum ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: Option<String>,
    pub fields: Option<Vec<FieldDecl>>,
    /// Type-level `__attribute__((aligned(N)))` — on the tag (`struct
    /// __attribute__((aligned(N))) T {...}`) or the typedef name (`typedef
    /// struct {...} T QEMU_ALIGNED(N)`). Raises the whole type's alignment.
    pub align: Option<u32>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct UnionDef {
    pub name: Option<String>,
    pub fields: Option<Vec<FieldDecl>>,
    /// Type-level `__attribute__((aligned(N)))` (see `StructDef::align`).
    pub align: Option<u32>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub name: Option<String>,
    pub ty: QualType,
    pub bit_width: Option<BoxExpr>,
    /// `__attribute__((aligned(N)))` on the member: forces the member's (and
    /// hence the aggregate's) alignment to at least N bytes. QEMU's `FPReg`
    /// union uses this on its `floatx80 d` member to make the whole union
    /// 16-aligned, which shifts every following field in `CPUX86State`.
    pub align: Option<u32>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumDef {
    pub name: Option<String>,
    pub variants: Option<Vec<EnumVariant>>,
    /// `__attribute__((packed))`: underlying type is the smallest integer that
    /// holds all enumerators (1 byte for small values), affecting struct layout.
    pub packed: bool,
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
    /// `__attribute__((cleanup(fn)))`: call `fn(&var)` when the variable goes
    /// out of scope (glib's `g_autoptr`, QEMU's `QEMU_LOCK_GUARD`).
    pub cleanup: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Initializer {
    Expr(Expr),
    List(Vec<InitItem>),
}

/// One element of a brace initializer list, with any leading designators
/// (`.field` / `[index]`, possibly chained: `.a.b[2] = ...`). Empty designators
/// means the element is positional.
#[derive(Debug, Clone)]
pub struct InitItem {
    pub designators: Vec<Designator>,
    pub init: Initializer,
}

#[derive(Debug, Clone)]
pub enum Designator {
    Field(String),
    Index(Box<Expr>),
    /// GNU range designator `[lo ... hi] = ...`: fills every index lo..=hi.
    IndexRange(Box<Expr>, Box<Expr>),
}

/// A top-level declaration.
#[derive(Debug, Clone)]
pub enum Decl {
    Var {
        base_ty: QualType,
        declarators: Vec<Declarator>,
        /// `__attribute__((weak))` on the declaration: emit each declared symbol
        /// with weak linkage so duplicate definitions across objects merge.
        weak: bool,
        /// `__thread`/`_Thread_local`: file-scope declarators get per-thread
        /// storage (emitted into TLS, accessed via the TLS ABI).
        thread_local: bool,
        span: Span,
    },
    Func {
        name: String,
        ret_ty: QualType,
        params: Vec<Param>,
        variadic: bool,
        body: Option<Vec<Stmt>>,   // None = prototype only
        storage: Option<StorageClass>,
        /// `inline` keyword present. An inline definition may be omitted when
        /// unreferenced (GNU/C99 inline semantics) — this lets sic skip the
        /// thousands of unused `extern __inline` SIMD intrinsics in system
        /// headers instead of trying to lower their unimplemented builtins.
        inline: bool,
        /// `__attribute__((constructor[(prio)]))`: run before `main` via
        /// `.init_array`. `Some(priority)` (lower priority runs earlier).
        constructor: Option<i32>,
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
    /// GCC case-range extension: `case LOW ... HIGH:`.
    CaseRange(Expr, Expr, BoxStmt, Span),
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
    /// Integer literal; the bool is `true` when its C type is 64-bit (from an
    /// `L`/`LL` suffix or a value that doesn't fit any 32-bit type).
    IntLit(i64, bool),
    UIntLit(u64, bool),
    FloatLit(f64),
    StringLit(String),
    CharLit(i32),
    Ident(String),
    Nullptr,           // C23 null pointer constant

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

    /// GNU `a ?: b`: value is `a` when `a` is truthy, else `b`. `a` is evaluated
    /// exactly once.
    Elvis { cond: BoxExpr, else_: BoxExpr },

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
    AlignofType(QualType),
    AlignofExpr(BoxExpr),

    /// `__builtin_choose_expr(const_cond, then, else)`: a compile-time selection.
    /// Only the selected branch is lowered/type-checked.
    ChooseExpr { cond: BoxExpr, then: BoxExpr, else_: BoxExpr },
    /// `__builtin_types_compatible_p(type1, type2)`: 1 if the types are the same
    /// (ignoring qualifiers), else 0.
    TypesCompatible(QualType, QualType),

    /// Cast: (type)expr
    Cast { ty: QualType, expr: BoxExpr },

    /// C11 `_Generic(controlling, T1: e1, ..., default: eN)`. Each association
    /// pairs an optional type (`None` for `default`) with an expression; the
    /// one whose type matches the controlling expression's type is selected.
    Generic { controlling: BoxExpr, assocs: Vec<(Option<QualType>, BoxExpr)> },

    /// `__builtin_offsetof(type, member)` — byte offset of `member` within
    /// `type`. `designators` is the member path (`.field` / `[index]`).
    OffsetOf { ty: QualType, designators: Vec<OffsetDesignator> },

    /// Comma expression: a, b
    Comma(BoxExpr, BoxExpr),

    /// GCC statement expression: ({ stmts... }). Value is the last statement
    /// when it is an expression statement, otherwise void.
    StmtExpr(Vec<Stmt>),

    /// Compound literal: (Type){ ... }
    CompoundLiteral { ty: QualType, init: Vec<InitItem> },

    /// __builtin_va_start / va_arg / va_end / va_copy
    VaStart { list: BoxExpr, last: BoxExpr },
    VaArg { list: BoxExpr, ty: QualType },
    VaEnd { list: BoxExpr },
    VaCopy { dst: BoxExpr, src: BoxExpr },
}

/// A member designator step inside `__builtin_offsetof(type, member)`.
#[derive(Debug, Clone)]
pub enum OffsetDesignator {
    Field(String),
    Index(BoxExpr),
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
