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
    /// sic-only: `@T` / `@mut T` reference type (sic.md §"References"). A scoped,
    /// reference-counted borrow; codegen-wise it is the underlying pointer type.
    Reference { mutable: bool },
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
    /// sic-only (sic.md §"Bitfields"): a `bitfield B { A, B, C }` flag set. Member
    /// `i` has value `1 << i`; only `& | ^ ~` are allowed, and it converts to an
    /// integer only via an explicit width-checked cast / `.as_uN`.
    Bitfield(BitfieldDef),
    Named(String),    // typedef name
    Builtin(String),  // __builtin_va_list etc.
    Typeof(BoxExpr),  // typeof(expr) — resolved to the operand's type
    /// sic-only: the `tuple` type (sic.md §"Tuples"). Its concrete positional
    /// field types are resolved from context (initializer / return value).
    Tuple,
    /// sic-only: the fixed-point type `fixed<integral,fraction>` (sic.md §"Built-in
    /// fixed point"). `(0, 0)` marks a bare `fixed` whose precision is inferred
    /// from its initializer.
    Fixed { integral: u32, fraction: u32 },
    /// sic-only (sic.md §"Match"): a generic-enum instantiation `Name<Arg, …>`,
    /// e.g. `Option<int>` / `Result<string,int>`. Monomorphized to a concrete
    /// tagged enum when resolved.
    Generic { name: String, args: Vec<QualType> },
    /// sic-only (sic.md §"Lambdas"): an inferred type — the return type of a lambda
    /// with no explicit `-> T`, resolved from its body. Only produced internally;
    /// never resolved by `lower_type` directly (the function lowerer infers it).
    Auto,
    /// sic-only (sic.md §"Lambdas"): a nameable closure type `Fn<ret(params)>` — the
    /// type of a capturing closure with the given callable signature, usable as a
    /// parameter, return, or variable type (unlike a plain function pointer, it
    /// accepts closures that carry captured state).
    Closure { ret: Box<QualType>, params: Vec<QualType> },
    /// sic-only (sic.md §"Weak"): `weak<T>` — a non-owning reference to a
    /// reference-counted container (`list`/`dict`/`set`). It does not keep the
    /// container alive; `.get` upgrades it to a strong handle if still live (else
    /// null), which is how reference cycles are broken.
    Weak(Box<QualType>),
}

// ─── Struct / Union / Enum ─────────────────────────────────────────────────────

/// sic struct field-ordering mode (sic.md §"Struct reordering"), set per struct by
/// an `order_*` attribute and defaulted globally by `-fstruct-order`.
#[derive(Debug, Clone, PartialEq)]
pub enum StructOrder {
    /// No `order_*` attribute: follow the global `-fstruct-order` default (which
    /// itself falls back to `Sic` for `.sic` sources and `C` for C sources).
    Default,
    /// `order_sic`: size-based reorder to minimize padding.
    Sic,
    /// `order_c` / `__order__` / `packed`: keep declaration order (the C layout).
    C,
    /// `order_random[(seed)]`: randomize the layout (randstruct-style hardening).
    /// `Some(seed)` pins it; `None` uses the process-wide build seed.
    Random(Option<u64>),
    /// `order(a, b, c)`: an explicit permutation of the field names.
    Custom(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: Option<String>,
    pub fields: Option<Vec<FieldDecl>>,
    /// Type-level `__attribute__((aligned(N)))` — on the tag (`struct
    /// __attribute__((aligned(N))) T {...}`) or the typedef name (`typedef
    /// struct {...} T QEMU_ALIGNED(N)`). Raises the whole type's alignment.
    pub align: Option<u32>,
    /// sic struct field ordering (sic.md §"Struct reordering"): the mode requested
    /// by this struct's `order_*` attribute, or `Default` to follow the global
    /// `-fstruct-order` default. `packed` forces `C` (declaration order).
    pub order: StructOrder,
    /// sic member functions (sic.md §"Memory safety"): the constructor `S()`,
    /// destructor `~S()`, and methods `Ret m(S* self){…}` declared in the body.
    /// Empty for C structs and for bodiless `struct S` references.
    pub methods: Vec<StructMethod>,
    /// sic (sic.md §"Namespace"): `private struct` — withhold this type from the
    /// module's manifest so consumers cannot name it.
    pub private: bool,
    pub span: Span,
}

/// A sic struct member function (sic.md §"Memory safety" / §"Iterators").
#[derive(Debug, Clone)]
pub struct StructMethod {
    pub kind: MethodKind,
    /// The method's name; for a constructor/destructor this is the struct's name.
    pub name: String,
    pub ret_ty: QualType,
    /// Explicit parameters as written, including the leading `self` for a plain
    /// method (`Ret m(S* self)`). A constructor/destructor takes an implicit `self`
    /// and lists none.
    pub params: Vec<Param>,
    pub variadic: bool,
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind { Method, Ctor, Dtor }

#[derive(Debug, Clone)]
pub struct UnionDef {
    pub name: Option<String>,
    pub fields: Option<Vec<FieldDecl>>,
    /// Type-level `__attribute__((aligned(N)))` (see `StructDef::align`).
    pub align: Option<u32>,
    /// sic (sic.md §"Namespace"): `private union` — withhold from the manifest.
    pub private: bool,
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
    /// sic-only (sic.md §"Match"): generic type parameters, e.g. `T`/`E` in
    /// `enum Option<T> { Some(T), None }`. Empty for an ordinary enum. A generic
    /// enum is a monomorphization *template*, instantiated per concrete `<...>`.
    pub type_params: Vec<String>,
    /// sic (sic.md §"Namespace"): `private enum` — withhold from the manifest.
    pub private: bool,
    pub span: Span,
}

/// sic-only (sic.md §"Bitfields"): a `bitfield B { A, B, C }` declaration. Each
/// member `i` implicitly has value `1 << i`; the set's storage is `u32` (≤32
/// members) or `u64` (≤64). Only `& | ^ ~` are permitted on values.
#[derive(Debug, Clone)]
pub struct BitfieldDef {
    pub name: String,
    pub members: Vec<String>,
    /// sic (sic.md §"Namespace"): `private bitfield` — withhold from the manifest.
    pub private: bool,
    pub span: Span,
}

/// sic-only (sic.md §"Lambdas"): one entry of a lambda capture list — `x` (by
/// value / copy), `@x` (shared borrow), or `@mut x` (mutable borrow). Empty
/// capture list `[]` means the lambda is captureless (a plain function).
#[derive(Debug, Clone)]
pub struct LambdaCapture {
    pub name: String,
    pub by_ref: bool,
    pub mutable: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub value: Option<BoxExpr>,
    /// sic-only (sic.md §"Match"): a payload type turns this into a tagged-union
    /// variant, e.g. `Some<int>` or `CUSTOM(int)`. `None` = plain C enumerator.
    pub payload: Option<QualType>,
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
        /// sic generic functions (sic.md §"Generics"): the `<T, U>` type-parameter
        /// list from `T add<T>(T a, T b)`. Empty for an ordinary function. A
        /// non-empty list makes this a *template* — kept un-lowered and
        /// monomorphized per concrete call, not emitted directly.
        type_params: Vec<String>,
        /// sic generic functions (sic.md §"Generics"): for a template, its exact
        /// source text, captured so a module can export it in its manifest for a
        /// consumer to re-instantiate. `None` for ordinary functions.
        template_src: Option<String>,
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
        /// sic `async` (sic.md §"Async"): the function is asynchronous — it returns
        /// a `Task<ret>`, and each `return v` wraps `v` into a task. `await` runs it.
        is_async: bool,
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
    /// sic-only: `module x;` — this translation unit belongs to module `x`; its
    /// non-`static` top-level symbols are exported (mangled `x_sym`). sic.md §"Imports".
    Module(String, Span),
    /// sic-only: `import x;` / `import x.sym;` / `import x.sym as alias;` — make a
    /// module's exports available (namespaced, selective, or renamed). `sym` is
    /// `None` for a whole-module import; `alias` renames a selective import.
    Import { module: String, sym: Option<String>, alias: Option<String>, span: Span },
    /// sic-only (sic.md §"Namespace"): `namespace N { decls }` — a compile-time
    /// scope. Members are flattened to mangled top-level symbols and accessed as
    /// `N::member`.
    Namespace { name: String, decls: Vec<Decl>, span: Span },
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
    /// sic range-`for` (sic.md §"Iterators"): `for (auto item : iterable) body`.
    /// `ty` is the binding's declared type (`storage: Auto` means infer the element
    /// type from the iterable). Works over arrays, strings, enum types, and any
    /// struct with a `next()` method.
    ForEach {
        ty: QualType,
        name: String,
        iterable: Expr,
        body: BoxStmt,
        span: Span,
    },
    Return(Option<Expr>, Span),
    Break(Span),
    Continue(Span),
    /// sic-only: explicit `fallthrough;` inside a switch (sic.md §"Switch - case").
    /// Semantically a no-op — control simply falls into the next case.
    Fallthrough(Span),
    /// sic-only: `defer <stmt>;` — run the statement at scope exit / return
    /// (sic.md §"Defer keyword").
    Defer(BoxStmt, Span),
    /// sic-only: `del <expr>;` — free a `new`-allocated pointer (refcount--,
    /// free at 0). sic.md §"Scopes and automatic release".
    Delete(Expr, Span),
    Goto(String, Span),
    Label(String, BoxStmt, Span),
    Case(Expr, BoxStmt, Span),
    /// GCC case-range extension: `case LOW ... HIGH:`.
    CaseRange(Expr, Expr, BoxStmt, Span),
    Default(BoxStmt, Span),
    Switch { val: Expr, body: BoxStmt, span: Span },
    /// sic-only: `match (e) { Variant(bind): stmt; _: stmt }` over a tagged enum
    /// (sic.md §"Match").
    Match { scrutinee: Expr, arms: Vec<MatchArm>, span: Span },
    /// sic-only: `unsafe { … }` — inside, integer overflow and `÷0` trap (raise an
    /// exception) instead of the default wrap / `→0` (sic.md §"Integer overflow").
    Unsafe(Vec<Stmt>, Span),
    /// sic-only (sic.md §"Match"): a guard `… else <stmt>`. Two forms:
    /// - bind: `auto x = opt else return;` — `binding = Some((ty?, name))`; binds
    ///   the present payload (Option/Result) or non-null pointer into the CURRENT
    ///   scope, running `else_body` (which must diverge) when absent.
    /// - boolean: `cond else return;` (`binding = None`) — runs `else_body` when
    ///   `cond` is false (a terse `if (!cond)` that reduces nesting).
    Guard { binding: Option<(Option<QualType>, String)>, cond: Expr, else_body: BoxStmt, span: Span },
    Null(Span),
}

/// sic exception-guard kind (sic.md §"Integer overflow", §"Errors and exceptions").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardKind {
    /// `overflow { … }` — catch integer overflow.
    Overflow,
    /// `divide_by_zero { … }` — catch division by zero.
    DivZero,
    /// `exception { … }` — catch any of the above.
    Exception,
}

/// One arm of a `match` (sic.md §"Match"): `Variant(binding): body`. A `variant`
/// of `None` is the `_` wildcard; `binding` names the unwrapped payload.
#[derive(Debug, Clone)]
pub struct MatchArm {
    pub variant: Option<String>,
    pub binding: Option<String>,
    pub body: BoxStmt,
    pub span: Span,
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
    /// sic-only: a `bool` literal (`true`/`false`), typed `bool` (sic.md §"Types").
    /// Kept `bool` through inference; converted to int only at a use site so it
    /// never silently mixes with integers and boxes into `any` with the BOOL type.
    BoolLit(bool),
    /// sic-only: a decimal integer literal too large for `u64` (sic.md §"Integer
    /// sizes"). Carries the digit string (with optional sign) for the bigint
    /// runtime to parse; only meaningful in a `bigint` context.
    BigIntLit(String),
    /// sic-only: a plain decimal-point literal, kept as its EXACT source text
    /// (sic.md §"Built-in fixed point"). In a `fixed` context it is parsed as an
    /// exact fixed-point value (never via a float); anywhere else it behaves as a
    /// `double` (the text is parsed to `f64`).
    DecimalLit(String),
    /// sic-only (sic.md §"RTTI"): `typeid(expr)` / `type(expr)` — a `type` value
    /// (a `const __sic_type_info*`) for the operand's type. The operand is not
    /// evaluated. Compile-time-known for statically-typed operands.
    TypeId(BoxExpr),
    /// sic-only (sic.md §"RTTI"): the `type` value of a named type — from
    /// `typeid(int)` or a bare type name in value position (`… == i64`).
    TypeIdOf(QualType),
    /// sic-only (sic.md §"Match"): none/null-safe access `base?.field`. If `base`
    /// is a present Option/Result or a non-null pointer, yields the field; else a
    /// zero value of the field's type. Chains via zero-propagation.
    OptField { base: BoxExpr, name: String },
    /// sic-only: an exception-guard block `overflow { … }` /
    /// `divide_by_zero { … }` / `exception { … }` (sic.md §"Integer overflow",
    /// §"Errors and exceptions"). Runs the body; if the guarded exception occurs,
    /// the offending operation is not committed, the rest of the body is skipped,
    /// and the expression yields `1` (else `0`).
    Guard { kind: GuardKind, body: Vec<Stmt> },
    FloatLit(f64),
    StringLit(String),
    CharLit(i32),
    Ident(String),
    Nullptr,           // C23 null pointer constant

    /// sic tuple pack `tuple(e0, e1, …)` (sic.md §"Tuples"). Used as a value it
    /// builds a tuple; on the left of `=` it is an unpack pattern of lvalues.
    TupleExpr(Vec<Expr>),

    /// sic-only (sic.md §"Lambdas"): a C++-style lambda
    /// `[captures](params) -> ret { body }` (or the `=> expr` sugar, normalized to
    /// a single `return`). A captureless lambda lowers to a plain function and
    /// yields a function pointer. `ret` is `None` when it is inferred from `body`.
    Lambda {
        captures: Vec<LambdaCapture>,
        params: Vec<Param>,
        ret: Option<QualType>,
        body: Vec<Stmt>,
    },

    /// SIC tagged-enum path `Enum::Variant` (sic.md §"Match"). As a call target
    /// it constructs (`Option::Some(5)`) or, when the argument is an instance of
    /// the enum, unwraps (`Test::CUSTOM(inst)`); bare it names the variant value.
    EnumVariant { enum_name: String, variant: String },

    /// Binary operation
    BinOp { op: BinOpKind, lhs: BoxExpr, rhs: BoxExpr },

    /// Compound assignment: a += b, a -= b, etc.
    Assign { op: Option<BinOpKind>, lhs: BoxExpr, rhs: BoxExpr },

    /// SIC swap operator `a <> b`: exchange two same-typed lvalues (sic.md §"Swap").
    Swap { lhs: BoxExpr, rhs: BoxExpr },

    /// SIC substring slice `s[lo:hi]` (sic.md §"Built-in string"): a half-open,
    /// byte-offset view into a `string`. Either bound may be omitted (`s[lo:]`,
    /// `s[:hi]`, `s[:]`), defaulting `lo` to 0 and `hi` to the string's size.
    Slice { base: BoxExpr, lo: Option<BoxExpr>, hi: Option<BoxExpr> },

    /// SIC `new T` / `new T(count)` (sic.md §"Scopes and automatic release"):
    /// allocate `count` (default 1) elements of `T` with a refcount header;
    /// yields `T*`.
    /// sic `new T` / `new T(n)` / `new T(args…)` (sic.md §"Memory safety"). The
    /// parenthesized list is: empty for `new T`/`new T()` (one object); a single
    /// count for a scalar/no-ctor `new T(n)` (array of n); or the constructor
    /// arguments when `T` is a struct with a constructor.
    New { ty: QualType, args: Vec<Expr> },

    /// SIC `@expr` / `@mut expr` (sic.md §"References"): form a scoped
    /// reference-counted borrow of `expr` — retains the referent's allocation for
    /// the enclosing scope. Value is the referent pointer.
    Ref { mutable: bool, expr: BoxExpr },

    /// Unary prefix
    Unary { op: UnOpKind, expr: BoxExpr },

    /// Pre-increment / pre-decrement
    PreInc { inc: bool, expr: BoxExpr },

    /// Post-increment / post-decrement
    PostInc { inc: bool, expr: BoxExpr },

    /// Ternary: cond ? a : b
    Ternary { cond: BoxExpr, then: BoxExpr, else_: BoxExpr },
    /// sic `match` used as an expression (sic.md §"Match"): each arm yields a value
    /// of a common type. Arm bodies are the same `MatchArm`s as the statement form;
    /// in expression position an arm's value is its trailing expression.
    Match { scrutinee: BoxExpr, arms: Vec<MatchArm> },

    /// GNU `a ?: b`: value is `a` when `a` is truthy, else `b`. `a` is evaluated
    /// exactly once.
    Elvis { cond: BoxExpr, else_: BoxExpr },

    /// Function call: f(args)
    Call { func: BoxExpr, args: Vec<Expr> },

    /// sic `await expr` (sic.md §"Async"): drive an async `Task<T>` to completion and
    /// yield its `T`. Lowers to a runtime hook (`__sic_await`).
    Await(BoxExpr),

    /// sic named argument (sic.md §"Named parameters"): `name = value` in a call's
    /// argument list. Purely a caller-side construct — the call site maps it to the
    /// callee's parameter of that name (or, for a variadic argument, drops the name
    /// and passes the value positionally; a future `va_dict` will capture the
    /// name/value pairs). Only ever appears inside `Call`/`GenericRef` argument
    /// lists; it is resolved away before ordinary expression lowering.
    NamedArg { name: String, value: BoxExpr },

    /// sic generic functions (sic.md §"Generics"): an explicit-type-argument
    /// reference `name<T, U>` (turbofish), used as a call target
    /// (`add<int>(1, 2)`). Carries the written type arguments so the call site can
    /// monomorphize without inference.
    GenericRef { name: String, type_args: Vec<QualType> },

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
    RotL, RotR,
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
