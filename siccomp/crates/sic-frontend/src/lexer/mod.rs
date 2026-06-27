mod token;
pub use token::{Token, TokenKind, Span};

use std::collections::HashSet;
use crate::{Result, CompileError};

pub struct Lexer {
    src: Vec<char>,
    pos: usize,
    line: u32,
    col: u32,
    /// File name from the most recent line marker.
    file: Option<String>,
    /// Typedef names to distinguish from plain identifiers.
    pub typedefs: HashSet<String>,
}

impl Lexer {
    pub fn new(source: &str, typedefs: HashSet<String>) -> Self {
        Lexer {
            src: source.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
            file: None,
            typedefs,
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

    /// Handle a preprocessor line marker like `# 42 "foo.c" 1`.
    fn handle_line_marker(&mut self) {
        // consume '#'
        self.advance();
        // skip spaces
        while self.pos < self.src.len() && self.src[self.pos] == ' ' { self.advance(); }
        // read digits for line number
        if self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            let mut num = String::new();
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                num.push(self.advance());
            }
            if let Ok(n) = num.parse::<u32>() { self.line = n; self.col = 1; }
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
        // skip rest of line
        while self.pos < self.src.len() && self.src[self.pos] != '\n' { self.advance(); }
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
        let kind = keyword_or_ident(&text, &self.typedefs);
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

        // suffixes: u, l, ll, f, ul, ull, etc. (consume but store in text)
        while self.pos < self.src.len() && matches!(self.src[self.pos], 'u'|'U'|'l'|'L'|'f'|'F') {
            text.push(self.advance());
        }

        let kind = if is_float { TokenKind::FloatLit } else { TokenKind::IntLit };
        Ok(Token::new(kind, text, sp))
    }

    fn scan_string_literal(&mut self, sp: Span) -> Result<Token> {
        self.advance(); // opening "
        let mut s = String::new();
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
                let esc = self.advance();
                s.push(unescape_char(esc));
            } else {
                s.push(c);
            }
        }
        // Adjacent string literal concatenation is handled by the parser.
        Ok(Token::new(TokenKind::StringLit, s, sp))
    }

    fn scan_char_literal(&mut self, sp: Span) -> Result<Token> {
        self.advance(); // opening '
        if self.pos >= self.src.len() {
            return Err(CompileError::at("unterminated char literal", sp.file.clone(), sp.line, sp.col));
        }
        let c = self.advance();
        let ch = if c == '\\' {
            if self.pos >= self.src.len() {
                return Err(CompileError::at("unterminated escape", sp.file.clone(), sp.line, sp.col));
            }
            unescape_char(self.advance())
        } else {
            c
        };
        // closing '
        if self.pos < self.src.len() && self.src[self.pos] == '\'' { self.advance(); }
        Ok(Token::new(TokenKind::CharLit, (ch as u32).to_string(), sp))
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

fn keyword_or_ident(s: &str, typedefs: &HashSet<String>) -> TokenKind {
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
        "_Complex"       => TokenKind::Complex,
        "_Atomic"        => TokenKind::Atomic,
        "__builtin_va_list" => TokenKind::TypeName,
        // sic primitive type aliases
        "int8" | "int16" | "int32" | "int64" | "int128" |
        "uint8" | "uint16" | "uint32" | "uint64" | "uint128" |
        "i8" | "i16" | "i32" | "i64" | "i128" |
        "u8" | "u16" | "u32" | "u64" | "u128" |
        "isize" | "usize" => TokenKind::TypeName,
        "__attribute__"  => TokenKind::Attribute,
        "__extension__"  => TokenKind::Extension,
        "__asm__" | "asm" => TokenKind::Asm,
        "__inline__" | "__inline" => TokenKind::Inline,
        "__const__"      => TokenKind::Const,
        "__volatile__"   => TokenKind::Volatile,
        "__restrict__"   => TokenKind::Restrict,
        "__builtin_va_start" | "__builtin_va_end" | "__builtin_va_arg" => TokenKind::Ident,
        _ if typedefs.contains(s) => TokenKind::TypeName,
        _ => TokenKind::Ident,
    }
}
