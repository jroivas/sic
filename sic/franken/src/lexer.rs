//! The lex stage in SIC: sic/lexer (lexer.sic), through the crate `sic
//! --emit-crate` wrote for it. Its tokens come packed (see `Tokens` there) and
//! become the Rust parser's.

use sic_frontend::lexer::{Span, Token, TokenKind as K};
use sic_frontend::{CompileError, Lang, Result};
use std::rc::Rc;

#[allow(dead_code, unused_imports, clippy::all)]
mod bindings {
    include!(env!("SIC_LEXER_BINDINGS"));
}

/// The token kinds by number, in lexer.sic's order (the test checks it).
const KINDS: [K; 119] = [
    K::IntLit, K::FloatLit, K::StringLit, K::WideStringLit, K::CharLit, K::BoolLit,
    K::Ident, K::TypeName, K::Auto, K::Break, K::Case, K::Char, K::Const, K::Continue,
    K::Default, K::Do, K::Double, K::Else, K::Enum, K::Extern, K::Float, K::For, K::Goto,
    K::If, K::Inline, K::Noreturn, K::StaticAssert, K::Int, K::Long, K::Register,
    K::Restrict, K::Return, K::Short, K::Signed, K::Sizeof, K::Static, K::Struct, K::Switch,
    K::Typedef, K::Union, K::Unsigned, K::Void, K::Volatile, K::While, K::Bool, K::Complex,
    K::Atomic, K::Fallthrough, K::Defer, K::New, K::Del, K::Module, K::Import, K::Match,
    K::Tuple, K::Bitfield, K::FatArrow, K::Dollar, K::Typeof, K::Nullptr, K::Alignas,
    K::Generic, K::Attribute, K::Extension, K::Asm, K::ThreadLocal, K::Plus, K::Minus,
    K::Star, K::Slash, K::Percent, K::PlusPlus, K::MinusMinus, K::PlusAssign,
    K::MinusAssign, K::StarAssign, K::SlashAssign, K::PercentAssign, K::Amp, K::Pipe,
    K::Caret, K::Tilde, K::Bang, K::AmpAmp, K::PipePipe, K::AndAssign, K::OrAssign,
    K::XorAssign, K::Shl, K::Shr, K::ShlAssign, K::ShrAssign, K::RotL, K::RotR, K::Swap,
    K::Eq, K::EqEq, K::BangEq, K::Lt, K::Gt, K::LtEq, K::GtEq, K::Question, K::Colon,
    K::Semi, K::Comma, K::Dot, K::Arrow, K::Ellipsis, K::ColonColon, K::At, K::LParen,
    K::RParen, K::LBrace, K::RBrace, K::LBracket, K::RBracket, K::Eof, K::Unknown,
];

const WORDS: usize = 8;
const F_HIDDEN: u32 = 1 << 16;
const F_TEXT: u32 = 1 << 17;

fn bytes<'a>(p: *mut u8, n: u64) -> &'a [u8] {
    if n == 0 || p.is_null() { &[] } else { unsafe { std::slice::from_raw_parts(p, n as usize) } }
}

/// The names in a list of `name\n` entries.
fn names(b: &[u8]) -> Vec<Rc<str>> {
    // Each ends in '\n', so "" is no names and "\n" one empty one.
    let Some(b) = b.strip_suffix(b"\n") else { return Vec::new() };
    b.split(|c| *c == b'\n').map(|n| Rc::from(String::from_utf8_lossy(n).as_ref())).collect()
}

/// The `lex` stage: `text`'s tokens, and `text` as characters.
pub fn lex(text: &str, lang: Lang, c23: bool) -> Result<(Vec<Token>, Vec<char>)> {
    let lang = match lang { Lang::C => 0, Lang::Sic => 1 };
    let mut t = bindings::lex(text, lang, c23, sic_frontend::target::short_wchar());
    let tokens = convert(&t, text);
    bindings::free(&mut t);
    Ok((tokens?, text.chars().collect()))
}

fn convert(t: &bindings::Tokens, src: &str) -> Result<Vec<Token>> {
    let files = names(bytes(t.files, t.files_size));
    let file = |i: u32| if i == 0 { None } else { Some(files[i as usize - 1].clone()) };
    for name in names(bytes(t.system, t.system_size)) {
        sic_frontend::diag::mark_system_file(&name);
    }
    if !t.error.is_empty() {
        return Err(CompileError::at(t.error.to_string_lossy(), file(t.error_file), t.error_line, t.error_col));
    }
    let n = t.count as usize;
    let data = if n == 0 { &[][..] } else { unsafe { std::slice::from_raw_parts(t.data, n * WORDS) } };
    let texts = bytes(t.text, t.text_size);
    let src = src.as_bytes();
    let mut at = 0;
    let mut tokens = Vec::with_capacity(n);
    for w in data.chunks_exact(WORDS) {
        let head = w[0];
        let text = if head & F_TEXT != 0 {
            let s = &texts[at..at + w[2] as usize];
            at += w[2] as usize;
            s
        } else {
            &src[w[1] as usize..w[2] as usize]
        };
        // As the Rust lexer's: the bytes of a literal need not be UTF-8.
        let text = unsafe { String::from_utf8_unchecked(text.to_vec()) };
        let mut tok = Token::new(KINDS[(head & 255) as usize], text, Span { file: file(w[7]), line: w[5], col: w[6] });
        tok.start = w[3];
        tok.end = w[4];
        tok.pack = (head >> 8) as u8;
        tok.hidden = head & F_HIDDEN != 0;
        tokens.push(tok);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// lexer.sic's kinds are `TokenKind`'s, in the same order.
    #[test]
    fn kinds_match() {
        for (i, k) in KINDS.iter().enumerate() {
            assert_eq!(*k as usize, i, "{:?} is not TokenKind number {}", k, i);
            assert_eq!(bindings::kind_name(i as i32).as_bytes(), format!("{:?}", k).as_bytes());
        }
        assert!(bindings::kind_name(KINDS.len() as i32).is_empty());
    }
}
