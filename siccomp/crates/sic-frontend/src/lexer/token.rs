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
}

impl Token {
    pub fn new(kind: TokenKind, text: String, span: Span) -> Self {
        Token { kind, text, span }
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

    // --- Identifiers / type names ---
    Ident,
    TypeName,    // typedef'd name

    // --- Keywords ---
    Auto, Break, Case, Char, Const, Continue, Default, Do, Double,
    Else, Enum, Extern, Float, For, Goto, If, Inline, Int, Long,
    Register, Restrict, Return, Short, Signed, Sizeof, Static,
    Struct, Switch, Typedef, Union, Unsigned, Void, Volatile, While,
    Bool, Complex, Atomic,

    // --- GCC extensions ---
    Attribute, Extension, Asm,

    // --- Operators ---
    Plus, Minus, Star, Slash, Percent,
    PlusPlus, MinusMinus,
    PlusAssign, MinusAssign, StarAssign, SlashAssign, PercentAssign,
    Amp, Pipe, Caret, Tilde, Bang,
    AmpAmp, PipePipe,
    AndAssign, OrAssign, XorAssign,
    Shl, Shr, ShlAssign, ShrAssign,
    Eq, EqEq, BangEq,
    Lt, Gt, LtEq, GtEq,
    Question, Colon, Semi, Comma, Dot, Arrow, Ellipsis,

    // --- Delimiters ---
    LParen, RParen,
    LBrace, RBrace,
    LBracket, RBracket,

    // --- Special ---
    Eof,
    Unknown,
}
