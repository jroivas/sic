#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub file: Option<String>,
    pub line: u32,
    pub col: u32,
}

impl Default for Span {
    fn default() -> Self { Span { file: None, line: 0, col: 0 } }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub text: String,
    pub span: Span,
    /// Half-open char-index range `[start, end)` of this token in the source
    /// character stream, filled in by the lexer. Used to recover the exact source
    /// text of a construct (e.g. a generic-function template exported to a module
    /// manifest). Defaults to `0..0` for synthesized tokens.
    pub start: u32,
    pub end: u32,
}

impl Token {
    pub fn new(kind: TokenKind, text: String, span: Span) -> Self {
        Token { kind, text, span, start: 0, end: 0 }
    }

    pub fn is(&self, kind: TokenKind) -> bool { self.kind == kind }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    // --- Literals ---
    IntLit,
    FloatLit,
    StringLit,
    CharLit,
    BoolLit,     // sic: `true`/`false` typed as `bool` (text "1"/"0")

    // --- Identifiers / type names ---
    Ident,
    TypeName,    // typedef'd name

    // --- Keywords ---
    Auto, Break, Case, Char, Const, Continue, Default, Do, Double,
    Else, Enum, Extern, Float, For, Goto, If, Inline, Int, Long,
    Register, Restrict, Return, Short, Signed, Sizeof, Static,
    Struct, Switch, Typedef, Union, Unsigned, Void, Volatile, While,
    Bool, Complex, Atomic,
    Fallthrough,  // sic-only: explicit switch-case fallthrough (sic.md §"Switch - case")
    Defer,        // sic-only: `defer <stmt>;` scope-exit action (sic.md §"Defer keyword")
    New, Del,     // sic-only: typed allocation / free (sic.md §"Scopes and automatic release")
    Module, Import, // sic-only: module system (sic.md §"Imports")
    Match,          // sic-only: `match` on a tagged enum (sic.md §"Match")
    Tuple,          // sic-only: `tuple` type / pack / unpack (sic.md §"Tuples")
    Bitfield,       // sic-only: `bitfield` flag-set type (sic.md §"Bitfields")
    FatArrow,       // sic-only: `=>` lambda expression body (sic.md §"Lambdas")
    Typeof,   // typeof / __typeof__ (GNU / C23)
    Nullptr,  // nullptr (C23)
    Alignas,  // _Alignas / alignas (C11 / C23)
    Generic,  // _Generic (C11)

    // --- GCC extensions ---
    Attribute, Extension, Asm, ThreadLocal,

    // --- Operators ---
    Plus, Minus, Star, Slash, Percent,
    PlusPlus, MinusMinus,
    PlusAssign, MinusAssign, StarAssign, SlashAssign, PercentAssign,
    Amp, Pipe, Caret, Tilde, Bang,
    AmpAmp, PipePipe,
    AndAssign, OrAssign, XorAssign,
    Shl, Shr, ShlAssign, ShrAssign,
    RotL, RotR,
    Swap,
    Eq, EqEq, BangEq,
    Lt, Gt, LtEq, GtEq,
    Question, Colon, Semi, Comma, Dot, Arrow, Ellipsis,
    ColonColon, // sic-only: `::` path separator for enum variants (sic.md §"Match")
    At,       // sic-only: `@` reference type / reference-taking (sic.md §"References")

    // --- Delimiters ---
    LParen, RParen,
    LBrace, RBrace,
    LBracket, RBracket,

    // --- Special ---
    Eof,
    Unknown,
}
