//! sic `macro_rules` (sic.md §"Macros"): Rust-style declarative macros, invoked
//! WITHOUT `!`.
//!
//! ```text
//! macro_rules assert {
//!     [$c:expr]            => ( ($c) ? (void)0 : __sic_assert_fail($str($c), $file, $line) );
//!     [$c:expr, $m:expr]   => ( ($c) ? (void)0 : __sic_assert_fail($m, $file, $line) );
//! }
//! assert[x > 0];
//! ```
//!
//! **Bracket decides.** A rule's matcher is written with `(…)`, `[…]` or `{…}`,
//! and `name<bracket>…` is a macro invocation only if the macro has a rule
//! written with that bracket. So a macro with only `[…]` rules leaves `name(…)`
//! an ordinary function call. When the bracket fits but no rule matches, the
//! normal parse is used if a function of that name was declared; otherwise it is
//! an error listing the rules.
//!
//! **Tokens, parsed in place.** Expansion runs in the parser on tokens (after the
//! C preprocessor; SIC sources only): the invocation is replaced by the
//! expansion and parsing continues there. In expression position the expansion
//! is parenthesized, and every `$e:expr` substitution is too, so precedence can
//! never split (`m[a] * 2`, `$e * 2`). A statement-position invocation (followed
//! by `;`, or written with `{…}`) expands to statements, braced unless it is a
//! block item; at file scope it expands to declarations.
//!
//! Matchers: `$name:frag` with `expr`, `ident`, `ty`, `literal`, `block`, `stmt`,
//! `path`, `tt`; repetitions `$(…) sep? op` with `*`, `+`, `?`. Transcribers use
//! `$name`, `$(…) sep? op`, and the built-ins `$str(…)` (the tokens as a string
//! literal), `$file` and `$line` (the invocation's location).
//!
//! **Hygiene (locals).** A local a statement/expression template declares itself
//! (`int tmp = …`) is renamed per expansion (`__sicm3_tmp`), so it can neither
//! capture nor shadow the caller's variables. Names from the invocation
//! (`$x`) are never renamed.
//!
//! **Name reservation.** A variable or parameter may not share a macro's name:
//! `name[…]` must never be ambiguous with indexing. Functions may (see above).

use std::collections::HashMap;
use super::Parser;
use crate::lexer::{Lang, Token, TokenKind, Span};
use crate::{Result, CompileError};

/// Built-in macros of every SIC unit. Lowest priority: a user function,
/// variable or macro of the same name replaces one (existing code keeps its
/// meaning). `assert` is always checked (like Rust's `assert!`, not affected by
/// `NDEBUG`); C's `<assert.h>` `assert(…)` still wins where it is included,
/// since the C preprocessor expands it first. `unreachable` / `unreachable()` /
/// `unreachable(msg)` marks a point control never reaches: reaching it reports
/// the place and aborts (like Rust's `unreachable!`); code after it is unreachable.
const PRELUDE: &str = r#"
macro_rules assert {
    ($c:expr) => ( ($c) ? (void)0 : __sic_assert_fail($str($c), $file, $line, "") );
    ($c:expr, $m:expr) => ( ($c) ? (void)0 : __sic_assert_fail($str($c), $file, $line, $m) );
}
macro_rules unreachable {
    () => ( __sic_unreachable($file, $line, "") );
    ($m:expr) => ( __sic_unreachable($file, $line, $m) );
}
macro_rules __builtin_unreachable {
    () => ( __sic_unreachable($file, $line, "") );
}
"#;

/// Total expansions per unit before a (recursive) macro is reported.
const EXPANSION_LIMIT: usize = 100_000;
/// Nesting depth of expansions within expansions (Rust's default limit).
const RECURSION_LIMIT: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Delim { Paren, Bracket, Brace }

impl Delim {
    fn of_open(k: TokenKind) -> Option<Delim> {
        match k {
            TokenKind::LParen => Some(Delim::Paren),
            TokenKind::LBracket => Some(Delim::Bracket),
            TokenKind::LBrace => Some(Delim::Brace),
            _ => None,
        }
    }
    fn close(self) -> TokenKind {
        match self { Delim::Paren => TokenKind::RParen, Delim::Bracket => TokenKind::RBracket, Delim::Brace => TokenKind::RBrace }
    }
    fn show(self) -> (&'static str, &'static str) {
        match self { Delim::Paren => ("(", ")"), Delim::Bracket => ("[", "]"), Delim::Brace => ("{", "}") }
    }
}

/// A token tree: one token, or a bracketed group (open/close tokens kept).
#[derive(Clone, Debug)]
enum Tt {
    Tok(Token),
    Group(Delim, Token, Vec<Tt>, Token),
}

impl Tt {
    fn flatten_into(&self, out: &mut Vec<Token>) {
        match self {
            Tt::Tok(t) => out.push(t.clone()),
            Tt::Group(_, o, inner, c) => {
                out.push(o.clone());
                for t in inner { t.flatten_into(out); }
                out.push(c.clone());
            }
        }
    }
    fn first_span(&self) -> &Span {
        match self { Tt::Tok(t) => &t.span, Tt::Group(_, o, _, _) => &o.span }
    }
}

fn flatten(tts: &[Tt]) -> Vec<Token> {
    let mut v = Vec::new();
    for t in tts { t.flatten_into(&mut v); }
    v
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Frag { Expr, Ident, Ty, Literal, Block, Stmt, Path, Tt }

impl Frag {
    fn parse(s: &str) -> Option<Frag> {
        Some(match s {
            "expr" => Frag::Expr, "ident" => Frag::Ident, "ty" => Frag::Ty,
            "literal" => Frag::Literal, "block" => Frag::Block, "stmt" => Frag::Stmt,
            "path" => Frag::Path, "tt" => Frag::Tt,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RepOp { Star, Plus, Opt }

/// A matcher element.
#[derive(Clone, Debug)]
enum Pm {
    Tok(Token),
    Group(Delim, Vec<Pm>),
    Var(String, Frag),
    Rep(Vec<Pm>, Option<Token>, RepOp),
}

/// A transcriber element.
#[derive(Clone, Debug)]
enum Tm {
    Tok(Token),
    Group(Token, Vec<Tm>, Token),
    Var(String, Span),
    Rep(Vec<Tm>, Option<Token>, RepOp),
    Str(Vec<Tm>),
    File,
    Line,
}

#[derive(Clone, Debug)]
struct Rule { delim: Delim, pat: Vec<Pm>, body: Vec<Tm>, text: String }

#[derive(Clone, Debug)]
pub(super) struct MacroDef { name: String, rules: Vec<Rule>, span: Span }

/// What a matcher variable bound: one fragment's tokens, or one binding per
/// repetition.
#[derive(Clone, Debug)]
enum Bind { One(Vec<Token>, Frag), Seq(Vec<Bind>) }

type Binds = HashMap<String, Bind>;

/// Where an invocation appears, which decides how its expansion is spliced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum MacroPos { Expr, Stmt { block_item: bool }, Item }

fn err_at(msg: String, sp: &Span) -> CompileError {
    CompileError::at(msg, sp.file.clone(), sp.line, sp.col)
}

fn tok(kind: TokenKind, text: &str, sp: &Span) -> Token {
    Token::new(kind, text.to_string(), sp.clone())
}

fn same_tok(a: &Token, b: &Token) -> bool {
    a.kind == b.kind && a.text == b.text
}

/// Matcher variables bound inside `pats` (any depth).
fn pat_vars(pats: &[Pm], out: &mut Vec<String>) {
    for p in pats {
        match p {
            Pm::Var(n, _) => out.push(n.clone()),
            Pm::Group(_, inner) | Pm::Rep(inner, _, _) => pat_vars(inner, out),
            Pm::Tok(_) => {}
        }
    }
}

/// Transcriber variables used inside `body` (any depth).
fn body_vars(body: &[Tm], out: &mut Vec<String>) {
    for t in body {
        match t {
            Tm::Var(n, _) => out.push(n.clone()),
            Tm::Group(_, inner, _) | Tm::Rep(inner, _, _) | Tm::Str(inner) => body_vars(inner, out),
            _ => {}
        }
    }
}

impl Parser {
    /// Register the built-in [`PRELUDE`] macros (SIC units).
    pub(super) fn load_prelude_macros(&mut self) {
        let Ok(mut toks) = crate::lexer::Lexer::new_lang(PRELUDE, std::collections::HashSet::new(), Lang::Sic).tokenize() else { return };
        for t in &mut toks { t.span.file = Some("<sic prelude>".to_string()); t.start = 0; t.end = 0; }
        let saved = std::mem::replace(&mut self.tokens, toks);
        let saved_pos = std::mem::replace(&mut self.pos, 0);
        while let Ok(true) = self.try_macro_definition() {}
        self.tokens = saved;
        self.pos = saved_pos;
        self.prelude_macros = self.macros.keys().cloned().collect();
    }

    /// A user declaration named like a prelude macro replaces the macro.
    fn shadow_prelude(&mut self, name: &str) {
        if self.prelude_macros.remove(name) { self.macros.remove(name); }
    }

    /// A variable/parameter may not take a macro's name (see the module doc).
    pub(super) fn check_not_macro(&mut self, name: &str, sp: &Span) -> Result<()> {
        self.shadow_prelude(name);
        if let Some(m) = self.macros.get(name).filter(|_| self.lang == Lang::Sic) {
            let at = m.span.file.as_deref().map(|f| format!("{}:{}", f, m.span.line))
                .unwrap_or_else(|| format!("line {}", m.span.line));
            return Err(err_at(format!(
                "`{}` is a macro (defined at {}); a variable or parameter cannot use its name", name, at), sp));
        }
        Ok(())
    }

    /// Record functions declared by `d`, so a macro whose rules do not match can
    /// fall back to calling a like-named function.
    pub(super) fn note_declared_fns(&mut self, d: &crate::ast::Decl) {
        use crate::ast::{Decl, AstType};
        match d {
            Decl::Func { name, .. } => { self.shadow_prelude(name); self.declared_fns.insert(name.clone()); }
            Decl::Var { declarators, .. } => {
                for de in declarators {
                    if matches!(de.ty.ty, AstType::Function { .. }) {
                        self.shadow_prelude(&de.name);
                        self.declared_fns.insert(de.name.clone());
                    }
                }
            }
            _ => {}
        }
    }

    // ── definitions ──────────────────────────────────────────────────────────

    /// At `macro_rules` (SIC): parse and register a definition. True if one was
    /// consumed.
    pub(super) fn try_macro_definition(&mut self) -> Result<bool> {
        if self.lang != Lang::Sic || !self.at(TokenKind::Ident) || self.peek().text != "macro_rules" {
            return Ok(false);
        }
        // `macro_rules` as an ordinary identifier (`macro_rules = 1`) is left alone.
        let next = self.tokens.get(self.pos + 1).map(|t| t.kind);
        if !matches!(next, Some(TokenKind::Ident) | Some(TokenKind::TypeName)) { return Ok(false); }
        let sp = self.span();
        self.advance();
        let name = self.advance().text.clone();
        let body = self.read_tt()?;
        let Tt::Group(Delim::Brace, _, items, _) = body else {
            return Err(err_at(format!("expected `{{` after `macro_rules {}`", name), &sp));
        };
        let mut rules = Vec::new();
        let mut i = 0;
        while i < items.len() {
            let Tt::Group(delim, o, pat, c) = &items[i] else {
                return Err(err_at(format!("macro `{}`: expected a rule matcher `(…)`, `[…]` or `{{…}}`", name), items[i].first_span()));
            };
            let text = {
                let mut v = vec![o.clone()];
                v.extend(flatten(pat));
                v.push(c.clone());
                tokens_text(&v, &self.src_chars)
            };
            i += 1;
            match items.get(i) {
                Some(Tt::Tok(t)) if t.kind == TokenKind::FatArrow => i += 1,
                other => {
                    let at = other.map(|t| t.first_span().clone()).unwrap_or_else(|| sp.clone());
                    return Err(err_at(format!("macro `{}`: expected `=>` after the matcher", name), &at));
                }
            }
            let Some(Tt::Group(_, _, body, _)) = items.get(i) else {
                let at = items.get(i).map(|t| t.first_span().clone()).unwrap_or_else(|| sp.clone());
                return Err(err_at(format!("macro `{}`: expected a bracketed transcriber after `=>`", name), &at));
            };
            let pat = self.parse_matcher(&name, pat)?;
            let mut seen = Vec::new();
            pat_vars(&pat, &mut seen);
            for (k, v) in seen.iter().enumerate() {
                if seen[..k].contains(v) {
                    return Err(err_at(format!("macro `{}`: `${}` is bound twice in one matcher", name, v), &o.span));
                }
            }
            let body = self.parse_transcriber(&name, body)?;
            let mut used = Vec::new();
            body_vars(&body, &mut used);
            for u in &used {
                if !seen.contains(u) {
                    return Err(err_at(format!("macro `{}`: `${}` is not bound by the matcher {}", name, u, text), &o.span));
                }
            }
            rules.push(Rule { delim: *delim, pat, body, text });
            i += 1;
            if let Some(Tt::Tok(t)) = items.get(i) { if t.kind == TokenKind::Semi { i += 1; } }
        }
        if rules.is_empty() {
            return Err(err_at(format!("macro `{}` has no rules", name), &sp));
        }
        self.eat(TokenKind::Semi);
        self.prelude_macros.remove(&name);
        self.macros.insert(name.clone(), MacroDef { name, rules, span: sp });
        Ok(true)
    }

    /// Read one token tree at the cursor.
    fn read_tt(&mut self) -> Result<Tt> {
        let t = self.peek().clone();
        if let Some(d) = Delim::of_open(t.kind) {
            self.advance();
            let mut inner = Vec::new();
            loop {
                if self.at(d.close()) { break; }
                if self.at(TokenKind::Eof) {
                    return Err(err_at(format!("unclosed `{}`", d.show().0), &t.span));
                }
                if matches!(self.peek_kind(), TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace) {
                    let c = self.peek().clone();
                    return Err(err_at(format!("mismatched `{}`: expected `{}`", c.text_or_kind(), d.show().1), &c.span));
                }
                inner.push(self.read_tt()?);
            }
            let c = self.advance().clone();
            return Ok(Tt::Group(d, t, inner, c));
        }
        if t.kind == TokenKind::Eof {
            return Err(err_at("unexpected end of input in a macro".to_string(), &t.span));
        }
        self.advance();
        Ok(Tt::Tok(t))
    }

    fn parse_matcher(&self, mname: &str, tts: &[Tt]) -> Result<Vec<Pm>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < tts.len() {
            match &tts[i] {
                Tt::Tok(t) if t.kind == TokenKind::Dollar => {
                    match tts.get(i + 1) {
                        Some(Tt::Tok(n)) if matches!(n.kind, TokenKind::Ident | TokenKind::TypeName) => {
                            if matches!(n.text.as_str(), "str" | "file" | "line") {
                                return Err(err_at(format!("macro `{}`: `${}` is a built-in; use another name", mname, n.text), &n.span));
                            }
                            let ok = matches!(tts.get(i + 2), Some(Tt::Tok(c)) if c.kind == TokenKind::Colon);
                            let frag = match tts.get(i + 3) {
                                Some(Tt::Tok(f)) if ok => Frag::parse(&f.text),
                                _ => None,
                            };
                            let Some(frag) = frag else {
                                return Err(err_at(format!(
                                    "macro `{}`: `${}` needs a fragment kind: `${}:expr`, `ident`, `ty`, `literal`, `block`, `stmt`, `path` or `tt`",
                                    mname, n.text, n.text), &n.span));
                            };
                            out.push(Pm::Var(n.text.clone(), frag));
                            i += 4;
                        }
                        Some(Tt::Group(Delim::Paren, _, inner, _)) => {
                            let inner = self.parse_matcher(mname, inner)?;
                            let (sep, op, used) = rep_suffix(mname, &tts[i + 2..], &t.span)?;
                            out.push(Pm::Rep(inner, sep, op));
                            i += 2 + used;
                        }
                        _ => return Err(err_at(format!("macro `{}`: `$` must be followed by `name:frag` or `(…)`", mname), &t.span)),
                    }
                }
                Tt::Tok(t) => { out.push(Pm::Tok(t.clone())); i += 1; }
                Tt::Group(d, _, inner, _) => { out.push(Pm::Group(*d, self.parse_matcher(mname, inner)?)); i += 1; }
            }
        }
        Ok(out)
    }

    fn parse_transcriber(&self, mname: &str, tts: &[Tt]) -> Result<Vec<Tm>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < tts.len() {
            match &tts[i] {
                Tt::Tok(t) if t.kind == TokenKind::Dollar => {
                    match tts.get(i + 1) {
                        Some(Tt::Tok(n)) if n.text == "str" && matches!(tts.get(i + 2), Some(Tt::Group(Delim::Paren, ..))) => {
                            let Some(Tt::Group(_, _, inner, _)) = tts.get(i + 2) else { unreachable!() };
                            out.push(Tm::Str(self.parse_transcriber(mname, inner)?));
                            i += 3;
                        }
                        Some(Tt::Tok(n)) if n.text == "file" => { out.push(Tm::File); i += 2; }
                        Some(Tt::Tok(n)) if n.text == "line" => { out.push(Tm::Line); i += 2; }
                        Some(Tt::Tok(n)) if matches!(n.kind, TokenKind::Ident | TokenKind::TypeName) => {
                            out.push(Tm::Var(n.text.clone(), n.span.clone()));
                            i += 2;
                        }
                        Some(Tt::Group(Delim::Paren, _, inner, _)) => {
                            let inner = self.parse_transcriber(mname, inner)?;
                            let (sep, op, used) = rep_suffix(mname, &tts[i + 2..], &t.span)?;
                            out.push(Tm::Rep(inner, sep, op));
                            i += 2 + used;
                        }
                        _ => return Err(err_at(format!("macro `{}`: `$` must be followed by a name, `(…)`, `str(…)`, `file` or `line`", mname), &t.span)),
                    }
                }
                Tt::Tok(t) => { out.push(Tm::Tok(t.clone())); i += 1; }
                Tt::Group(_, o, inner, c) => {
                    out.push(Tm::Group(o.clone(), self.parse_transcriber(mname, inner)?, c.clone()));
                    i += 1;
                }
            }
        }
        Ok(out)
    }

    // ── invocations ──────────────────────────────────────────────────────────

    /// If the cursor is at an invocation of a macro in a bracket it has rules
    /// for, expand it in place (the tokens are replaced; parsing resumes at the
    /// same position) and return true. False: not an invocation, or no rule
    /// matched and a like-named function exists (the caller parses normally).
    pub(super) fn try_expand_macro(&mut self, pos: MacroPos) -> Result<bool> {
        if self.lang != Lang::Sic || self.macro_matching || self.macros.is_empty() { return Ok(false); }
        let t = self.peek();
        if !matches!(t.kind, TokenKind::Ident | TokenKind::TypeName) { return Ok(false); }
        let Some(def) = self.macros.get(&t.text) else { return Ok(false) };
        let Some(delim) = self.tokens.get(self.pos + 1).and_then(|n| Delim::of_open(n.kind)) else { return Ok(false) };
        if !def.rules.iter().any(|r| r.delim == delim) { return Ok(false); }
        let def = def.clone();
        let start = self.pos;
        let call = self.peek().clone();
        self.advance();
        let group = self.read_tt()?;
        let after_group = self.pos;
        let Tt::Group(_, _, args, _) = &group else { unreachable!() };

        // Statement position: a `;` right after (or a `{…}` invocation) makes it a
        // statement macro; otherwise it is an expression inside the statement.
        let pos = match pos {
            MacroPos::Stmt { .. } if delim != Delim::Brace && !self.at(TokenKind::Semi) => MacroPos::Expr,
            p => p,
        };

        let mut matched = None;
        for rule in def.rules.iter().filter(|r| r.delim == delim) {
            let mut b = Binds::new();
            if let Some(n) = self.match_seq(&rule.pat, args, 0, &mut b) {
                if n == args.len() { matched = Some((rule, b)); break; }
            }
        }
        let Some((rule, binds)) = matched else {
            if self.declared_fns.contains(&def.name) {
                self.pos = start;
                return Ok(false);
            }
            let (o, c) = delim.show();
            let got = format!("{}{}{}{}", def.name, o, tokens_text(&flatten(args), &self.src_chars), c);
            let tried: Vec<String> = def.rules.iter().filter(|r| r.delim == delim)
                .map(|r| format!("\n  {} => …", r.text)).collect();
            return Err(err_at(format!("no rule of macro `{}` matches `{}`; rules:{}", def.name, got, tried.join("")), &call.span));
        };

        self.macro_expansions += 1;
        if self.macro_expansions > EXPANSION_LIMIT {
            return Err(err_at(format!("macro expansion limit reached expanding `{}` (does it expand to itself?)", def.name), &call.span));
        }
        let hygiene = pos != MacroPos::Item;
        let declared = if hygiene { self.template_locals(&rule.body) } else { Vec::new() };
        self.macro_counter += 1;
        let ctx = Ctx { call: call.span.clone(), declared, tag: self.macro_counter };
        let mut out = Vec::new();
        self.transcribe(&rule.body, &binds, &ctx, &def.name, &mut out)?;

        let sp = &call.span;
        let spliced: Vec<Token> = match pos {
            MacroPos::Expr => {
                if out.is_empty() {
                    return Err(err_at(format!("macro `{}` expanded to nothing where a value is needed", def.name), sp));
                }
                let mut v = vec![tok(TokenKind::LParen, "(", sp)];
                v.extend(out);
                v.push(tok(TokenKind::RParen, ")", sp));
                v
            }
            MacroPos::Stmt { block_item } => {
                // The trailing `;` (if any) is kept after the expansion. A single-
                // statement context (`if (c) m[x];`) gets the statements braced.
                if block_item { out } else {
                    let mut v = vec![tok(TokenKind::LBrace, "{", sp)];
                    v.extend(out);
                    v.push(tok(TokenKind::Semi, ";", sp));
                    v.push(tok(TokenKind::RBrace, "}", sp));
                    v
                }
            }
            MacroPos::Item => out,
        };
        let (o, c) = delim.show();
        self.last_expansion = format!("`{}{}{}{}` expands to `{}`", def.name, o,
            tokens_text(&flatten(args), &self.src_chars), c, tokens_text(&spliced, &self.src_chars));
        self.tokens.splice(start..after_group, spliced);
        self.pos = start;
        self.last_macro = def.name.clone();
        Ok(true)
    }

    /// Parse what an expansion just put at the cursor with `f`: bounded nesting,
    /// and an error inside names the macro.
    pub(super) fn parse_expanded<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let name = self.last_macro.clone();
        let expansion = self.last_expansion.clone();
        if self.macro_depth >= RECURSION_LIMIT {
            let sp = self.span();
            return Err(err_at(format!("macro recursion limit ({}) reached expanding `{}`", RECURSION_LIMIT, name), &sp));
        }
        self.macro_depth += 1;
        let r = f(self);
        self.macro_depth -= 1;
        r.map_err(|mut e| {
            if !e.message.contains("in expansion of macro") && !e.message.starts_with("macro recursion limit") {
                e.message.push_str(&format!("\n  note: in expansion of macro `{}`: {}", name, expansion));
            }
            e
        })
    }

    // ── matching ─────────────────────────────────────────────────────────────

    /// Match `pats` against `tts[i..]`; the index after the match.
    fn match_seq(&mut self, pats: &[Pm], tts: &[Tt], mut i: usize, b: &mut Binds) -> Option<usize> {
        for p in pats {
            match p {
                Pm::Tok(t) => match tts.get(i) {
                    Some(Tt::Tok(x)) if same_tok(x, t) => i += 1,
                    _ => return None,
                },
                Pm::Group(d, inner) => match tts.get(i) {
                    Some(Tt::Group(d2, _, kids, _)) if d2 == d => {
                        let n = self.match_seq(inner, kids, 0, b)?;
                        if n != kids.len() { return None; }
                        i += 1;
                    }
                    _ => return None,
                },
                Pm::Var(name, frag) => {
                    let n = self.match_frag(*frag, &tts[i.min(tts.len())..])?;
                    b.insert(name.clone(), Bind::One(flatten(&tts[i..i + n]), *frag));
                    i += n;
                }
                Pm::Rep(inner, sep, op) => {
                    let mut iters: Vec<Binds> = Vec::new();
                    loop {
                        let mut j = i;
                        if !iters.is_empty() {
                            if let Some(s) = sep {
                                match tts.get(j) {
                                    Some(Tt::Tok(x)) if same_tok(x, s) => j += 1,
                                    _ => break,
                                }
                            }
                        }
                        let mut ib = Binds::new();
                        match self.match_seq(inner, tts, j, &mut ib) {
                            Some(k) if k > i => { iters.push(ib); i = k; }
                            _ => break,
                        }
                        if *op == RepOp::Opt { break; }
                    }
                    if *op == RepOp::Plus && iters.is_empty() { return None; }
                    let mut names = Vec::new();
                    pat_vars(inner, &mut names);
                    for n in names {
                        let seq = iters.iter().map(|ib| ib.get(&n).cloned().unwrap_or(Bind::Seq(Vec::new()))).collect();
                        b.insert(n, Bind::Seq(seq));
                    }
                }
            }
        }
        Some(i)
    }

    /// How many token trees at the start of `tts` the fragment matches.
    fn match_frag(&mut self, frag: Frag, tts: &[Tt]) -> Option<usize> {
        let first = tts.first()?;
        match frag {
            Frag::Tt => Some(1),
            Frag::Ident => matches!(first, Tt::Tok(t) if matches!(t.kind, TokenKind::Ident | TokenKind::TypeName)).then_some(1),
            Frag::Block => matches!(first, Tt::Group(Delim::Brace, ..)).then_some(1),
            Frag::Literal => {
                let lit = |t: &Tt| matches!(t, Tt::Tok(x) if matches!(x.kind,
                    TokenKind::IntLit | TokenKind::FloatLit | TokenKind::StringLit | TokenKind::WideStringLit
                    | TokenKind::CharLit | TokenKind::BoolLit));
                if lit(first) { return Some(1); }
                let neg = matches!(first, Tt::Tok(x) if x.kind == TokenKind::Minus);
                (neg && tts.get(1).map_or(false, |t| matches!(t, Tt::Tok(x) if matches!(x.kind, TokenKind::IntLit | TokenKind::FloatLit)))).then_some(2)
            }
            Frag::Path => {
                let id = |t: Option<&Tt>| matches!(t, Some(Tt::Tok(x)) if matches!(x.kind, TokenKind::Ident | TokenKind::TypeName));
                if !id(tts.first()) { return None; }
                let mut n = 1;
                while matches!(tts.get(n), Some(Tt::Tok(x)) if x.kind == TokenKind::ColonColon) && id(tts.get(n + 1)) { n += 2; }
                Some(n)
            }
            Frag::Expr | Frag::Ty | Frag::Stmt => self.match_by_parsing(frag, tts),
        }
    }

    /// Match an `expr`/`ty`/`stmt` fragment by running the real parser over the
    /// candidate tokens (speculatively: the token stream is swapped back after).
    fn match_by_parsing(&mut self, frag: Frag, tts: &[Tt]) -> Option<usize> {
        let mut toks = flatten(tts);
        let eof_sp = toks.last().map(|t| t.span.clone()).unwrap_or_default();
        toks.push(Token::new(TokenKind::Eof, String::new(), eof_sp));
        let saved_tokens = std::mem::replace(&mut self.tokens, toks);
        let saved_pos = std::mem::replace(&mut self.pos, 0);
        let saved_matching = std::mem::replace(&mut self.macro_matching, true);
        let saved_locals = self.local_decls.len();
        let ok = match frag {
            Frag::Expr => self.parse_assign_expr().is_ok(),
            Frag::Ty => self.parse_type_name().is_ok(),
            _ => self.parse_stmt().is_ok(),
        };
        let consumed = self.pos;
        self.local_decls.truncate(saved_locals);
        self.macro_matching = saved_matching;
        self.pos = saved_pos;
        self.tokens = saved_tokens;
        if !ok || consumed == 0 { return None; }
        // Map the consumed token count back to whole token trees.
        let mut acc = 0;
        for (k, t) in tts.iter().enumerate() {
            let mut v = Vec::new();
            t.flatten_into(&mut v);
            acc += v.len();
            if acc == consumed { return Some(k + 1); }
            if acc > consumed { return None; }
        }
        None
    }

    // ── transcription ────────────────────────────────────────────────────────

    fn transcribe(&self, body: &[Tm], b: &Binds, ctx: &Ctx, mname: &str, out: &mut Vec<Token>) -> Result<()> {
        for t in body {
            match t {
                Tm::Tok(x) => {
                    let mut x = x.clone();
                    x.span = ctx.call.clone();
                    x.start = 0;
                    x.end = 0;
                    if x.kind == TokenKind::Ident && ctx.declared.contains(&x.text)
                        && !matches!(out.last().map(|p| p.kind), Some(TokenKind::Dot) | Some(TokenKind::Arrow))
                    {
                        x.text = format!("__sicm{}_{}", ctx.tag, x.text);
                    }
                    out.push(x);
                }
                Tm::Group(o, inner, c) => {
                    out.push(tok(o.kind, &o.text, &ctx.call));
                    self.transcribe(inner, b, ctx, mname, out)?;
                    out.push(tok(c.kind, &c.text, &ctx.call));
                }
                Tm::Var(n, sp) => match b.get(n) {
                    Some(Bind::One(toks, frag)) => {
                        let wrap = *frag == Frag::Expr && toks.len() > 1;
                        if wrap { out.push(tok(TokenKind::LParen, "(", &ctx.call)); }
                        out.extend(toks.iter().cloned());
                        if wrap { out.push(tok(TokenKind::RParen, ")", &ctx.call)); }
                    }
                    Some(Bind::Seq(_)) => return Err(err_at(format!(
                        "macro `{}`: `${}` is repeated in the matcher; use it inside `$(…)*`", mname, n), sp)),
                    None => return Err(err_at(format!("macro `{}`: `${}` is not bound", mname, n), sp)),
                },
                Tm::Rep(inner, sep, op) => {
                    let mut vars = Vec::new();
                    body_vars(inner, &mut vars);
                    let mut count: Option<usize> = None;
                    for v in &vars {
                        if let Some(Bind::Seq(s)) = b.get(v) {
                            match count {
                                None => count = Some(s.len()),
                                Some(c) if c != s.len() => return Err(err_at(format!(
                                    "macro `{}`: variables repeated together match different counts ({} and {})", mname, c, s.len()), &ctx.call)),
                                _ => {}
                            }
                        }
                    }
                    let Some(n) = count else {
                        return Err(err_at(format!("macro `{}`: `$(…)` in the transcriber repeats no matcher repetition", mname), &ctx.call));
                    };
                    if *op == RepOp::Opt && n > 1 {
                        return Err(err_at(format!("macro `{}`: `$(…)?` in the transcriber repeats {} times", mname, n), &ctx.call));
                    }
                    if *op == RepOp::Plus && n == 0 {
                        return Err(err_at(format!("macro `{}`: `$(…)+` in the transcriber repeats zero times", mname), &ctx.call));
                    }
                    for k in 0..n {
                        if k > 0 { if let Some(s) = sep { out.push(tok(s.kind, &s.text, &ctx.call)); } }
                        let mut ib = b.clone();
                        for v in &vars {
                            if let Some(Bind::Seq(s)) = b.get(v) { ib.insert(v.clone(), s[k].clone()); }
                        }
                        self.transcribe(inner, &ib, ctx, mname, out)?;
                    }
                }
                Tm::Str(inner) => {
                    let mut v = Vec::new();
                    let plain = Ctx { call: ctx.call.clone(), declared: Vec::new(), tag: ctx.tag };
                    self.transcribe(inner, b, &plain, mname, &mut v)?;
                    // Expression substitutions are parenthesized for parsing; the
                    // text shows them as written.
                    let s = tokens_text_unwrapped(inner, b, &v, &self.src_chars);
                    out.push(tok(TokenKind::StringLit, &s, &ctx.call));
                }
                Tm::File => {
                    let f = ctx.call.file.clone().unwrap_or_else(|| self.source_file.clone());
                    out.push(tok(TokenKind::StringLit, &f, &ctx.call));
                }
                Tm::Line => out.push(tok(TokenKind::IntLit, &ctx.call.line.to_string(), &ctx.call)),
            }
        }
        Ok(())
    }

    /// Locals a template declares itself (a name after a type, followed by `=`,
    /// `;`, `,`, `[`, `)` or `:`): renamed per expansion (hygiene).
    fn template_locals(&self, body: &[Tm]) -> Vec<String> {
        let mut flat: Vec<Option<&Token>> = Vec::new();
        fn walk<'a>(b: &'a [Tm], out: &mut Vec<Option<&'a Token>>) {
            for t in b {
                match t {
                    Tm::Tok(x) => out.push(Some(x)),
                    Tm::Group(o, inner, c) => { out.push(Some(o)); walk(inner, out); out.push(Some(c)); }
                    Tm::Rep(inner, _, _) => walk(inner, out),
                    _ => out.push(None),
                }
            }
        }
        walk(body, &mut flat);
        let typeish = |t: Option<&Token>| match t {
            Some(t) => matches!(t.kind,
                TokenKind::Int | TokenKind::Char | TokenKind::Float | TokenKind::Double | TokenKind::Void
                | TokenKind::Long | TokenKind::Short | TokenKind::Signed | TokenKind::Unsigned
                | TokenKind::Bool | TokenKind::TypeName | TokenKind::Auto | TokenKind::Gt)
                || (t.kind == TokenKind::Ident && self.typedefs.contains(&t.text)),
            None => false,
        };
        let mut out = Vec::new();
        for i in 1..flat.len() {
            let Some(t) = flat[i] else { continue };
            if t.kind != TokenKind::Ident { continue; }
            let next_ok = matches!(flat.get(i + 1).copied().flatten().map(|n| n.kind),
                Some(TokenKind::Eq | TokenKind::Semi | TokenKind::Comma | TokenKind::LBracket
                    | TokenKind::RParen | TokenKind::Colon));
            if !next_ok { continue; }
            // Skip pointer stars back to the type.
            let mut k = i - 1;
            while k > 0 && matches!(flat[k].map(|p| p.kind), Some(TokenKind::Star)) { k -= 1; }
            if typeish(flat[k]) && !out.contains(&t.text) { out.push(t.text.clone()); }
        }
        out
    }
}

struct Ctx { call: Span, declared: Vec<String>, tag: usize }

/// Parse a repetition's `sep? op` suffix; (separator, op, tokens used).
fn rep_suffix(mname: &str, rest: &[Tt], sp: &Span) -> Result<(Option<Token>, RepOp, usize)> {
    let op_of = |t: Option<&Tt>| match t {
        Some(Tt::Tok(x)) => match x.kind {
            TokenKind::Star => Some(RepOp::Star),
            TokenKind::Plus => Some(RepOp::Plus),
            TokenKind::Question => Some(RepOp::Opt),
            _ => None,
        },
        _ => None,
    };
    if let Some(op) = op_of(rest.first()) { return Ok((None, op, 1)); }
    if let (Some(Tt::Tok(s)), Some(op)) = (rest.first(), op_of(rest.get(1))) {
        return Ok((Some(s.clone()), op, 2));
    }
    Err(err_at(format!("macro `{}`: `$(…)` must be followed by `*`, `+` or `?` (optionally after a separator)", mname), sp))
}

/// Source-like text of tokens: the exact source when they are contiguous source
/// tokens, else their texts joined by spaces.
fn tokens_text(toks: &[Token], src: &[char]) -> String {
    if let (Some(f), Some(l)) = (toks.first(), toks.last()) {
        let (s, e) = (f.start as usize, l.end as usize);
        if f.end > 0 && l.end > 0 && s < e && e <= src.len() && toks.iter().all(|t| t.end > 0) {
            return src[s..e].iter().collect();
        }
    }
    let mut out = String::new();
    for (i, t) in toks.iter().enumerate() {
        if i > 0 { out.push(' '); }
        out.push_str(&t.text_or_kind());
    }
    out
}

/// Text for `$str(…)`: a single substituted variable shows its source text.
fn tokens_text_unwrapped(inner: &[Tm], b: &Binds, v: &[Token], src: &[char]) -> String {
    if let [Tm::Var(n, _)] = inner {
        if let Some(Bind::One(toks, _)) = b.get(n) { return tokens_text(toks, src); }
    }
    tokens_text(v, src)
}

trait TokText { fn text_or_kind(&self) -> String; }
impl TokText for Token {
    fn text_or_kind(&self) -> String {
        match self.kind {
            TokenKind::StringLit => format!("\"{}\"", self.text.escape_default()),
            _ if !self.text.is_empty() => self.text.clone(),
            k => format!("{:?}", k),
        }
    }
}
