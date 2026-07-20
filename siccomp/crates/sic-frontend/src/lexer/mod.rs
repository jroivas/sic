mod token;
pub use token::{Token, TokenKind, Span};

use std::collections::HashSet;
use crate::{Result, CompileError};

/// Source language being compiled. Chosen from the input file's extension.
/// It only affects whether sic's Rust-style primitive aliases (`i32`, `u64`,
/// `isize`, …) are reserved type keywords: in `Sic` they are types; in `C` they
/// are ordinary identifiers (so C code may use `isize`/`usize` as variables).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    C,
    Sic,
}

pub struct Lexer {
    src: Vec<char>,
    pos: usize,
    line: u32,
    col: u32,
    /// File name from the most recent line marker.
    file: Option<String>,
    /// Typedef names to distinguish from plain identifiers.
    pub typedefs: HashSet<String>,
    /// Source language (affects Rust-style type-alias keywords).
    lang: Lang,
}

impl Lexer {
    /// Construct a lexer for C source (the default for the C front end).
    pub fn new(source: &str, typedefs: HashSet<String>) -> Self {
        Self::new_lang(source, typedefs, Lang::C)
    }

    /// Construct a lexer for a specific source language.
    pub fn new_lang(source: &str, typedefs: HashSet<String>, lang: Lang) -> Self {
        Lexer {
            src: source.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
            file: None,
            typedefs,
            lang,
        }
    }

    /// Tokenize all input and return the token stream (excludes whitespace/comments).
    pub fn tokenize(&mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.src.len() {
                tokens.push(Token::new(TokenKind::Eof, String::new(), self.span()));
                break;
            }
            // Handle preprocessor line markers: `# <num> "file"` or `# <num>`
            if self.src[self.pos] == '#' {
                self.handle_line_marker();
                continue;
            }
            let tok = self.next_token()?;
            tokens.push(tok);
        }
        Ok(tokens)
    }

    fn span(&self) -> Span {
        Span { file: self.file.clone(), line: self.line, col: self.col }
    }

    fn peek(&self) -> char {
        self.src.get(self.pos).copied().unwrap_or('\0')
    }

    fn peek2(&self) -> char {
        self.src.get(self.pos + 1).copied().unwrap_or('\0')
    }

    fn advance(&mut self) -> char {
        let c = self.src[self.pos];
        self.pos += 1;
        if c == '\n' { self.line += 1; self.col = 1; } else { self.col += 1; }
        c
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
                self.advance();
            }
            // single-line comment
            if self.pos + 1 < self.src.len() && self.src[self.pos] == '/' && self.src[self.pos+1] == '/' {
                while self.pos < self.src.len() && self.src[self.pos] != '\n' {
                    self.advance();
                }
                continue;
            }
            // multi-line comment
            if self.pos + 1 < self.src.len() && self.src[self.pos] == '/' && self.src[self.pos+1] == '*' {
                self.advance(); self.advance();
                while self.pos + 1 < self.src.len()
                    && !(self.src[self.pos] == '*' && self.src[self.pos+1] == '/')
                {
                    self.advance();
                }
                if self.pos + 1 < self.src.len() { self.advance(); self.advance(); }
                continue;
            }
            break;
        }
    }

    /// Handle a preprocessor line marker like `# 42 "foo.c" 1`. The directive
    /// states that the line *following* it is line `N` of the named file.
    fn handle_line_marker(&mut self) {
        // consume '#'
        self.advance();
        // skip spaces
        while self.pos < self.src.len() && self.src[self.pos] == ' ' { self.advance(); }
        // read digits for line number
        let mut target_line = self.line;
        if self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            let mut num = String::new();
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                num.push(self.advance());
            }
            if let Ok(n) = num.parse::<u32>() { target_line = n; }
        }
        // skip to optional filename
        while self.pos < self.src.len() && self.src[self.pos] == ' ' { self.advance(); }
        if self.pos < self.src.len() && self.src[self.pos] == '"' {
            self.advance();
            let mut name = String::new();
            while self.pos < self.src.len() && self.src[self.pos] != '"' && self.src[self.pos] != '\n' {
                name.push(self.advance());
            }
            if self.pos < self.src.len() && self.src[self.pos] == '"' { self.advance(); }
            self.file = Some(name);
        }
        // Skip the rest of the directive line *including* its newline, then set
        // the line counter — so the following content is line `target_line`
        // (rather than `target_line + 1` after the newline bumps the counter).
        while self.pos < self.src.len() && self.src[self.pos] != '\n' { self.advance(); }
        if self.pos < self.src.len() && self.src[self.pos] == '\n' { self.advance(); }
        self.line = target_line;
        self.col = 1;
    }

    fn next_token(&mut self) -> Result<Token> {
        let sp = self.span();
        let c = self.peek();

        // Identifier or keyword
        if c.is_alphabetic() || c == '_' {
            return Ok(self.scan_ident_or_keyword(sp));
        }

        // Numbers
        if c.is_ascii_digit() || (c == '.' && self.peek2().is_ascii_digit()) {
            return self.scan_number(sp);
        }

        // String literal
        if c == '"' {
            return self.scan_string_literal(sp);
        }

        // Char literal
        if c == '\'' {
            return self.scan_char_literal(sp);
        }

        // Operators and punctuation
        self.scan_punct(sp)
    }

    fn scan_ident_or_keyword(&mut self, sp: Span) -> Token {
        let mut text = String::new();
        while self.pos < self.src.len() && (self.src[self.pos].is_alphanumeric() || self.src[self.pos] == '_') {
            text.push(self.advance());
        }
        // C23 boolean literals are keywords equivalent to the integer
        // constants 1 and 0; lower them here so the parser sees plain IntLits.
        match text.as_str() {
            "true"  => return Token::new(TokenKind::IntLit, "1".to_string(), sp),
            "false" => return Token::new(TokenKind::IntLit, "0".to_string(), sp),
            _ => {}
        }
        let kind = keyword_or_ident(&text, &self.typedefs, self.lang);
        Token::new(kind, text, sp)
    }

    fn scan_number(&mut self, sp: Span) -> Result<Token> {
        let mut text = String::new();
        let mut is_float = false;

        // hex
        if self.peek() == '0' && (self.peek2() == 'x' || self.peek2() == 'X') {
            text.push(self.advance()); // 0
            text.push(self.advance()); // x
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_hexdigit() {
                text.push(self.advance());
            }
            // Hex float: optional `.hexdigits` and a mandatory binary exponent
            // `p[+-]digits` (e.g. `0x1p64`, `0x1.8p-3`).
            if self.pos < self.src.len() && self.src[self.pos] == '.' {
                is_float = true;
                text.push(self.advance());
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_hexdigit() {
                    text.push(self.advance());
                }
            }
            if self.pos < self.src.len() && (self.src[self.pos] == 'p' || self.src[self.pos] == 'P') {
                is_float = true;
                text.push(self.advance());
                if self.pos < self.src.len() && (self.src[self.pos] == '+' || self.src[self.pos] == '-') {
                    text.push(self.advance());
                }
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                    text.push(self.advance());
                }
            }
        // binary (C23 / GNU extension: 0b1010)
        } else if self.peek() == '0' && (self.peek2() == 'b' || self.peek2() == 'B') {
            text.push(self.advance()); // 0
            text.push(self.advance()); // b
            while self.pos < self.src.len() && matches!(self.src[self.pos], '0' | '1') {
                text.push(self.advance());
            }
        } else {
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                text.push(self.advance());
            }
            if self.pos < self.src.len() && self.src[self.pos] == '.' {
                is_float = true;
                text.push(self.advance());
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                    text.push(self.advance());
                }
            }
            // exponent
            if self.pos < self.src.len() && (self.src[self.pos] == 'e' || self.src[self.pos] == 'E') {
                is_float = true;
                text.push(self.advance());
                if self.pos < self.src.len() && (self.src[self.pos] == '+' || self.src[self.pos] == '-') {
                    text.push(self.advance());
                }
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                    text.push(self.advance());
                }
            }
        }

        // suffixes: u, l, ll, f, ul, ull, etc. (consume but store in text). A
        // float `f`/`F` may carry a C23 `_FloatN` width — `0.0f16`, `1.0f128` —
        // so consume any digits that follow it.
        while self.pos < self.src.len() && matches!(self.src[self.pos], 'u'|'U'|'l'|'L'|'f'|'F') {
            let c = self.advance();
            text.push(c);
            if matches!(c, 'f' | 'F') {
                is_float = true;
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                    text.push(self.advance());
                }
            }
        }

        let kind = if is_float { TokenKind::FloatLit } else { TokenKind::IntLit };
        Ok(Token::new(kind, text, sp))
    }

    fn scan_string_literal(&mut self, sp: Span) -> Result<Token> {
        self.advance(); // opening "
        // A C string literal is a sequence of *bytes*, not Unicode scalars. An
        // octal/hex escape like `\342` or `\xe2` denotes the single raw byte
        // 0xE2 — it must NOT be re-encoded as the UTF-8 of code point U+00E2
        // (which would emit 0xC3 0xA2 and corrupt e.g. box-drawing characters).
        // Ordinary source characters keep their own UTF-8 byte encoding.
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(CompileError::at("unterminated string literal", sp.file.clone(), sp.line, sp.col));
            }
            let c = self.advance();
            if c == '"' { break; }
            if c == '\\' {
                if self.pos >= self.src.len() {
                    return Err(CompileError::at("unterminated escape", sp.file.clone(), sp.line, sp.col));
                }
                let val = self.read_escape_value();
                bytes.push(val as u8);
            } else {
                let mut buf = [0u8; 4];
                bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
        // The token text carries the raw C-string bytes; it may not be valid
        // UTF-8 (e.g. `"\xe2"`). Downstream only ever reads it as bytes
        // (`as_bytes`/`into_bytes`/`len`), so preserve the bytes verbatim.
        // Adjacent string literal concatenation is handled by the parser.
        let s = unsafe { String::from_utf8_unchecked(bytes) };
        Ok(Token::new(TokenKind::StringLit, s, sp))
    }

    fn scan_char_literal(&mut self, sp: Span) -> Result<Token> {
        self.advance(); // opening '
        if self.pos >= self.src.len() {
            return Err(CompileError::at("unterminated char literal", sp.file.clone(), sp.line, sp.col));
        }
        let c = self.advance();
        let val = if c == '\\' {
            if self.pos >= self.src.len() {
                return Err(CompileError::at("unterminated escape", sp.file.clone(), sp.line, sp.col));
            }
            self.read_escape_value()
        } else {
            c as u32
        };
        // closing '
        if self.pos < self.src.len() && self.src[self.pos] == '\'' { self.advance(); }
        Ok(Token::new(TokenKind::CharLit, val.to_string(), sp))
    }

    /// Read an escape sequence's value, with the leading `\` already consumed.
    /// Handles single-char escapes, octal (`\ooo`, 1–3 digits) and hex (`\xH…`).
    fn read_escape_value(&mut self) -> u32 {
        let c = self.advance();
        match c {
            '0'..='7' => {
                // Octal: this digit plus up to two more.
                let mut val = c as u32 - '0' as u32;
                let mut count = 1;
                while count < 3 && self.pos < self.src.len() {
                    let d = self.src[self.pos];
                    if ('0'..='7').contains(&d) {
                        val = val * 8 + (d as u32 - '0' as u32);
                        self.advance();
                        count += 1;
                    } else { break; }
                }
                val
            }
            'x' | 'X' => {
                // Hex: one or more hex digits.
                let mut val = 0u32;
                while self.pos < self.src.len() {
                    if let Some(h) = self.src[self.pos].to_digit(16) {
                        val = val.wrapping_mul(16).wrapping_add(h);
                        self.advance();
                    } else { break; }
                }
                val
            }
            other => unescape_char(other) as u32,
        }
    }

    fn scan_punct(&mut self, sp: Span) -> Result<Token> {
        let c = self.advance();
        let p2 = self.peek();
        let p3 = if self.pos + 1 < self.src.len() { self.src[self.pos + 1] } else { '\0' };

        let (kind, extra) = match (c, p2, p3) {
            ('<', '<', '=') => { self.advance(); self.advance(); (TokenKind::ShlAssign, "<<="  ) }
            ('>', '>', '=') => { self.advance(); self.advance(); (TokenKind::ShrAssign, ">>="  ) }
            ('<', '<', _)   => { self.advance();                 (TokenKind::Shl,       "<<"   ) }
            ('>', '>', _)   => { self.advance();                 (TokenKind::Shr,       ">>"   ) }
            ('+', '+', _)   => { self.advance();                 (TokenKind::PlusPlus,  "++"   ) }
            ('-', '-', _)   => { self.advance();                 (TokenKind::MinusMinus,"--"   ) }
            ('+', '=', _)   => { self.advance();                 (TokenKind::PlusAssign,"+="   ) }
            ('-', '=', _)   => { self.advance();                 (TokenKind::MinusAssign,"-="  ) }
            ('*', '=', _)   => { self.advance();                 (TokenKind::StarAssign,"*="   ) }
            ('/', '=', _)   => { self.advance();                 (TokenKind::SlashAssign,"/="  ) }
            ('%', '=', _)   => { self.advance();                 (TokenKind::PercentAssign,"%=" ) }
            ('&', '=', _)   => { self.advance();                 (TokenKind::AndAssign, "&="   ) }
            ('|', '=', _)   => { self.advance();                 (TokenKind::OrAssign,  "|="   ) }
            ('^', '=', _)   => { self.advance();                 (TokenKind::XorAssign, "^="   ) }
            ('&', '&', _)   => { self.advance();                 (TokenKind::AmpAmp,    "&&"   ) }
            ('|', '|', _)   => { self.advance();                 (TokenKind::PipePipe,  "||"   ) }
            ('-', '>', _)   => { self.advance();                 (TokenKind::Arrow,     "->"   ) }
            ('=', '=', _)   => { self.advance();                 (TokenKind::EqEq,      "=="   ) }
            ('!', '=', _)   => { self.advance();                 (TokenKind::BangEq,    "!="   ) }
            ('<', '=', _)   => { self.advance();                 (TokenKind::LtEq,      "<="   ) }
            ('>', '=', _)   => { self.advance();                 (TokenKind::GtEq,      ">="   ) }
            ('.', '.', '.') => { self.advance(); self.advance(); (TokenKind::Ellipsis,  "..."  ) }
            ('+', _, _)   => (TokenKind::Plus,    "+"),
            ('-', _, _)   => (TokenKind::Minus,   "-"),
            ('*', _, _)   => (TokenKind::Star,    "*"),
            ('/', _, _)   => (TokenKind::Slash,   "/"),
            ('%', _, _)   => (TokenKind::Percent, "%"),
            ('=', _, _)   => (TokenKind::Eq,      "="),
            ('<', _, _)   => (TokenKind::Lt,       "<"),
            ('>', _, _)   => (TokenKind::Gt,       ">"),
            ('!', _, _)   => (TokenKind::Bang,     "!"),
            ('&', _, _)   => (TokenKind::Amp,      "&"),
            ('|', _, _)   => (TokenKind::Pipe,     "|"),
            ('^', _, _)   => (TokenKind::Caret,    "^"),
            ('~', _, _)   => (TokenKind::Tilde,    "~"),
            ('?', _, _)   => (TokenKind::Question, "?"),
            (':', _, _)   => (TokenKind::Colon,    ":"),
            (';', _, _)   => (TokenKind::Semi,     ";"),
            (',', _, _)   => (TokenKind::Comma,    ","),
            ('.', _, _)   => (TokenKind::Dot,      "."),
            ('(', _, _)   => (TokenKind::LParen,   "("),
            (')', _, _)   => (TokenKind::RParen,   ")"),
            ('{', _, _)   => (TokenKind::LBrace,   "{"),
            ('}', _, _)   => (TokenKind::RBrace,   "}"),
            ('[', _, _)   => (TokenKind::LBracket, "["),
            (']', _, _)   => (TokenKind::RBracket, "]"),
            _ => (TokenKind::Unknown, ""),
        };
        Ok(Token::new(kind, extra.to_string(), sp))
    }
}

fn unescape_char(c: char) -> char {
    match c {
        'n' => '\n', 't' => '\t', 'r' => '\r', '0' => '\0',
        '\\' => '\\', '\'' => '\'', '"' => '"',
        'a' => '\x07', 'b' => '\x08', 'f' => '\x0C', 'v' => '\x0B',
        _ => c,
    }
}

fn keyword_or_ident(s: &str, typedefs: &HashSet<String>, lang: Lang) -> TokenKind {
    // sic's Rust-style primitive aliases are reserved type names only in sic
    // source; in C they are ordinary identifiers (e.g. a local named `isize`).
    if lang == Lang::Sic {
        match s {
            "int8" | "int16" | "int32" | "int64" | "int128" |
            "uint8" | "uint16" | "uint32" | "uint64" | "uint128" |
            "i8" | "i16" | "i32" | "i64" | "i128" |
            "u8" | "u16" | "u32" | "u64" | "u128" |
            "isize" | "usize" => return TokenKind::TypeName,
            _ => {}
        }
    }
    match s {
        "auto"           => TokenKind::Auto,
        "break"          => TokenKind::Break,
        "case"           => TokenKind::Case,
        "char"           => TokenKind::Char,
        "const"          => TokenKind::Const,
        "continue"       => TokenKind::Continue,
        "default"        => TokenKind::Default,
        "do"             => TokenKind::Do,
        "double"         => TokenKind::Double,
        "else"           => TokenKind::Else,
        "enum"           => TokenKind::Enum,
        "extern"         => TokenKind::Extern,
        "float"          => TokenKind::Float,
        "for"            => TokenKind::For,
        "goto"           => TokenKind::Goto,
        "if"             => TokenKind::If,
        "inline"         => TokenKind::Inline,
        "int"            => TokenKind::Int,
        "long"           => TokenKind::Long,
        "register"       => TokenKind::Register,
        "restrict"       => TokenKind::Restrict,
        "return"         => TokenKind::Return,
        "short"          => TokenKind::Short,
        "signed"         => TokenKind::Signed,
        "sizeof"         => TokenKind::Sizeof,
        "static"         => TokenKind::Static,
        "struct"         => TokenKind::Struct,
        "switch"         => TokenKind::Switch,
        "typedef"        => TokenKind::Typedef,
        "union"          => TokenKind::Union,
        "unsigned"       => TokenKind::Unsigned,
        "void"           => TokenKind::Void,
        "volatile"       => TokenKind::Volatile,
        "while"          => TokenKind::While,
        "_Bool"          => TokenKind::Bool,
        "bool"           => TokenKind::Bool,
        "typeof" | "__typeof__" | "__typeof" => TokenKind::Typeof,
        "nullptr"        => TokenKind::Nullptr,
        "_Alignas" | "alignas" => TokenKind::Alignas,
        "_Generic"       => TokenKind::Generic,
        "_Complex"       => TokenKind::Complex,
        "_Atomic"        => TokenKind::Atomic,
        "__builtin_va_list" => TokenKind::TypeName,
        // Extended floating types (GCC `__float128`/`__float80`, C23 `_FloatN`).
        // Resolved to an IR float type in `lower_ast_type`.
        "__float128" | "_Float128" | "_Float128x" | "__float80" | "__ibm128"
        | "_Float16" | "_Float32" | "_Float32x" | "_Float64" | "_Float64x" => TokenKind::TypeName,
        "__attribute__" | "__attribute" => TokenKind::Attribute,
        "__extension__"  => TokenKind::Extension,
        // GNU/Clang double-underscore keyword aliases (both `__kw` and `__kw__`
        // spellings). glibc headers use these once the compiler advertises
        // `__GNUC__`/`__clang__`.
        "__asm__" | "__asm" | "asm" => TokenKind::Asm,
        "__inline__" | "__inline" => TokenKind::Inline,
        "__const__" | "__const" => TokenKind::Const,
        "__volatile__" | "__volatile" => TokenKind::Volatile,
        "__restrict__" | "__restrict" => TokenKind::Restrict,
        "__signed__" | "__signed" => TokenKind::Signed,
        "__builtin_va_start" | "__builtin_c23_va_start"
        | "__builtin_va_end" | "__builtin_va_arg" | "__builtin_va_copy" => TokenKind::Ident,
        _ if typedefs.contains(s) => TokenKind::TypeName,
        _ => TokenKind::Ident,
    }
}
