use std::collections::HashSet;
use crate::ast::*;
use crate::lexer::{Lang, Token, TokenKind, Span};
use crate::{Result, CompileError};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    typedefs: HashSet<String>,
    /// sic generic-enum names (`enum Option<T> {…}`), so `Option<int>` in a type
    /// position parses as an instantiation rather than a `<` comparison.
    generic_enums: HashSet<String>,
    source_file: String,
    lang: Lang,
    /// `vector_size(N)` seen in the most recent `skip_attributes` run (GCC/Clang
    /// SIMD vector typedefs). Applied to the declared type as an N-byte array.
    pending_vector_size: Option<u32>,
    /// `__attribute__((constructor[(prio)]))` seen while parsing the current
    /// declaration's specifiers; the function runs before `main` via `.init_array`.
    pending_constructor: Option<i32>,
    /// `__attribute__((weak))` seen while parsing the current declaration; the
    /// declared symbols get weak linkage so duplicate definitions merge.
    pending_weak: bool,
    /// `__attribute__((cleanup(fn)))` function name seen in the most recent
    /// `skip_attributes`/`skip_decl_tail` run, applied to the next declarator.
    pending_cleanup: Option<String>,
    /// `__thread`/`_Thread_local` seen in the current declaration's specifiers.
    pending_thread_local: bool,
    /// `__attribute__((packed))` seen in the most recent attribute scan — used to
    /// size a `packed` enum's underlying type to the smallest that fits.
    pending_packed: bool,
    /// `__attribute__((__order__))` seen in the most recent attribute scan — sic
    /// opt-out that keeps a struct's declaration field order (no reordering).
    pending_order: bool,
    /// `__attribute__((aligned(N)))` seen in the most recent attribute scan — the
    /// largest N. Applied to the next struct/union member to raise its (and the
    /// aggregate's) alignment (QEMU's `FPReg` union → 16-aligned `CPUX86State`).
    pending_aligned: Option<u32>,
    /// sic `private struct`/`union`/`enum` (sic.md §"Namespace"): set while the
    /// `private` keyword has been consumed and applies to the next aggregate.
    pending_private: bool,
    /// Names declared as variables (params + locals) in the function currently
    /// being parsed. A name here shadows a like-named typedef, so `(name)` is a
    /// parenthesized variable, not a cast — QEMU's `vaddr`/`entry`/… parameters
    /// shadow the `typedef uintptr_t vaddr;` etc.
    func_vars: HashSet<String>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>, source_file: String) -> Self {
        Self::new_lang(tokens, source_file, Lang::C)
    }

    pub fn new_lang(tokens: Vec<Token>, source_file: String, lang: Lang) -> Self {
        let mut typedefs = HashSet::new();
        let mut generic_enums = HashSet::new();
        // sic prelude (sic.md §"Match"): `Option`/`Result` are always available as
        // generic enums, so `Option<int>` parses as an instantiation and the names
        // are usable as types without a user declaration. A user `enum Option<T>`
        // still overrides (its variants win at lowering).
        if lang == Lang::Sic {
            for n in ["Option", "Result", "Iterator"] {
                typedefs.insert(n.to_string());
                generic_enums.insert(n.to_string());
            }
        }
        Parser { tokens, pos: 0, typedefs, generic_enums, source_file, lang, pending_vector_size: None, pending_constructor: None, pending_weak: false, pending_cleanup: None, pending_thread_local: false, pending_packed: false, pending_order: false, pending_aligned: None, pending_private: false, func_vars: HashSet::new() }
    }

    pub fn add_typedef(&mut self, name: &str) {
        self.typedefs.insert(name.to_string());
    }

    pub fn is_typedef(&self, name: &str) -> bool {
        self.typedefs.contains(name)
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn peek_kind(&self) -> TokenKind {
        self.peek().kind
    }

    fn advance(&mut self) -> &Token {
        let t = &self.tokens[self.pos.min(self.tokens.len() - 1)];
        if self.pos < self.tokens.len() - 1 { self.pos += 1; }
        t
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token> {
        let t = self.peek().clone();
        if t.kind == kind {
            self.advance();
            Ok(t)
        } else {
            Err(CompileError::at(
                format!("expected {:?} but got {:?} ('{}')", kind, t.kind, t.text),
                t.span.file.clone(), t.span.line, t.span.col,
            ))
        }
    }

    fn at(&self, kind: TokenKind) -> bool { self.peek_kind() == kind }

    /// Expect a name in an ordinary-identifier position (member/enum/label/goto
    /// name). Besides a plain identifier, this also accepts a built-in type-alias
    /// token (`u64`, `i32`, `usize`, ...): those aliases collide with common C
    /// identifiers, so a program is free to use them as names.
    /// A `match` arm pattern name: an identifier/typedef name (enum variant), or a
    /// built-in type keyword (`int`, `bool`, `float`, `void`, `char`, `struct`, …)
    /// used as a type/kind category in `match (type(x))`. Other type spellings
    /// (`string`, `bigint`, `i32`, `f64`, `uint`, `ptr`, …) already lex as
    /// TypeName/Ident.
    fn parse_match_pattern_name(&mut self) -> Result<String> {
        use TokenKind::*;
        match self.peek().kind {
            Ident | TypeName | Bool | Int | Char | Float | Double | Void
            | Long | Short | Signed | Unsigned | Struct | Union | Enum =>
                Ok(self.advance().text.clone()),
            _ => {
                let t = self.peek().clone();
                Err(CompileError::at(
                    format!("expected a match pattern but got {:?} ('{}')", t.kind, t.text),
                    t.span.file.clone(), t.span.line, t.span.col))
            }
        }
    }

    fn expect_name(&mut self) -> Result<String> {
        if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            Ok(self.advance().text.clone())
        } else {
            let t = self.peek().clone();
            Err(CompileError::at(
                format!("expected identifier but got {:?} ('{}')", t.kind, t.text),
                t.span.file.clone(), t.span.line, t.span.col,
            ))
        }
    }
    fn eat(&mut self, kind: TokenKind) -> bool {
        if self.at(kind) { self.advance(); true } else { false }
    }

    fn span(&self) -> Span { self.peek().span.clone() }

    pub fn parse(&mut self) -> Result<TranslationUnit> {
        // Pre-register __builtin_va_list as a type name
        self.typedefs.insert("__builtin_va_list".to_string());

        let mut decls = Vec::new();
        while !self.at(TokenKind::Eof) {
            // Handle stray semicolons
            if self.eat(TokenKind::Semi) { continue; }
            // Handle GCC __extension__
            if self.at(TokenKind::Extension) { self.advance(); continue; }
            let before = self.pos;
            let d = self.parse_external_decl()?;
            decls.push(d);
            // Never spin: a top-level declaration that consumed no tokens would
            // otherwise loop forever (e.g. an unparseable construct that yields an
            // empty expression-statement). Fail with a diagnostic instead.
            if self.pos == before {
                let t = self.peek().clone();
                return Err(CompileError::at(
                    format!("unexpected token {:?} ('{}') at top level", t.kind, t.text),
                    t.span.file.clone(), t.span.line, t.span.col,
                ));
            }
        }
        Ok(TranslationUnit { decls, source_file: self.source_file.clone() })
    }

    // ─── External declarations ────────────────────────────────────────────────

    fn parse_external_decl(&mut self) -> Result<Decl> {
        let sp = self.span();

        // Reset per-declaration attribute state, then parse a leading
        // `__attribute__((constructor))` (captured by `skip_attributes`).
        self.pending_constructor = None;
        self.pending_weak = false;
        self.pending_thread_local = false;
        self.skip_attributes();

        // __asm__ at top level: skip
        if self.at(TokenKind::Asm) {
            self.parse_asm_skip()?;
            return Ok(Decl::ExprStmt(Expr::new(ExprKind::IntLit(0, false), sp.clone()), sp));
        }

        // sic namespace (sic.md §"Namespace"): `namespace N { decls }`. `namespace`
        // is a contextual keyword (a plain identifier elsewhere).
        if self.lang == Lang::Sic && self.at(TokenKind::Ident) && self.peek().text == "namespace" {
            self.advance(); // `namespace`
            let name = self.expect_name()?;
            self.expect(TokenKind::LBrace)?;
            let mut decls = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                if self.eat(TokenKind::Semi) { continue; }
                let before = self.pos;
                decls.push(self.parse_external_decl()?);
                if self.pos == before {
                    let t = self.peek().clone();
                    return Err(CompileError::at(
                        format!("unexpected token {:?} ('{}') in namespace body", t.kind, t.text),
                        t.span.file.clone(), t.span.line, t.span.col));
                }
            }
            self.expect(TokenKind::RBrace)?;
            self.eat(TokenKind::Semi); // optional trailing `;`
            return Ok(Decl::Namespace { name, decls, span: sp });
        }

        // sic module system (sic.md §"Imports").
        if self.at(TokenKind::Module) {
            self.advance();
            let name = self.expect_name()?;
            self.eat(TokenKind::Semi);
            return Ok(Decl::Module(name, sp));
        }
        if self.at(TokenKind::Import) {
            self.advance();
            let module = self.expect_name()?;
            // Optional `.sym` (selective import) and `as alias` (rename).
            let sym = if self.eat(TokenKind::Dot) { Some(self.expect_name()?) } else { None };
            let alias = if sym.is_some()
                && self.peek_kind() == TokenKind::Ident && self.peek().text == "as"
            {
                self.advance(); // `as`
                Some(self.expect_name()?)
            } else {
                None
            };
            self.eat(TokenKind::Semi);
            return Ok(Decl::Import { module, sym, alias, span: sp });
        }

        // Check for a bare expression statement (SIC mode: top-level expressions).
        // Heuristic: if it starts with something that can't be a declaration specifier,
        // treat it as an expression statement.
        if self.is_expr_start_not_decl() {
            let expr = self.parse_expr()?;
            self.eat(TokenKind::Semi);
            return Ok(Decl::ExprStmt(expr, sp));
        }

        // Parse declaration specifiers
        let (base_ty, storage) = self.parse_decl_specifiers()?;
        let is_inline = base_ty.qualifiers.contains(&TypeQual::Inline);

        // Check for ';' — bare type declaration (struct/enum definition, typedef)
        if self.at(TokenKind::Semi) {
            self.advance();
            if let Some(StorageClass::Typedef) = storage {
                return Ok(Decl::TypeDef { names: vec![], span: sp });
            }
            return Ok(Decl::Var { base_ty, declarators: vec![], weak: self.pending_weak, thread_local: self.pending_thread_local, span: sp });
        }

        // typedef with declarators
        if let Some(StorageClass::Typedef) = storage {
            return self.parse_typedef(base_ty, sp);
        }

        // Try to parse first declarator
        let (name, ty) = self.parse_declarator(base_ty.clone())?;

        // If `(` follows and it's a function — function definition or prototype
        if let AstType::Function { ref params, variadic, ref ret } = ty.ty.clone() {
            let mut params = params.clone();
            let variadic = variadic;
            let ret_ty = *ret.clone();

            self.skip_decl_tail();
            // `__attribute__((constructor))` may appear before the specifiers or
            // after the declarator; take whichever was captured for this function.
            let ctor = self.pending_constructor.take();

            // K&R (old-style) definition: the parameter list held only names,
            // and their declarations follow before the `{` body, e.g.
            //   int main(argc, argv) int argc; char *argv[]; { ... }
            if !self.at(TokenKind::LBrace) && !self.at(TokenKind::Semi)
                && !self.at(TokenKind::Eof) && self.starts_decl_specifier()
            {
                self.parse_kr_param_decls(&mut params)?;
                self.func_vars = params.iter().filter_map(|p| p.name.clone()).collect();
                let body = self.parse_compound_stmt_as_stmts()?;
                self.func_vars.clear();
                return Ok(Decl::Func {
                    name, ret_ty, params, variadic,
                    body: Some(body), storage, inline: is_inline, constructor: ctor, span: sp,
                });
            }

            if self.at(TokenKind::LBrace) {
                // Function definition. Seed the shadow set with the parameter names.
                self.func_vars = params.iter().filter_map(|p| p.name.clone()).collect();
                let body = self.parse_compound_stmt_as_stmts()?;
                self.func_vars.clear();
                return Ok(Decl::Func {
                    name, ret_ty, params, variadic,
                    body: Some(body), storage, inline: is_inline, constructor: ctor, span: sp,
                });
            } else {
                // Prototype
                self.eat(TokenKind::Semi);
                return Ok(Decl::Func {
                    name, ret_ty, params, variadic,
                    body: None, storage, inline: is_inline, constructor: ctor, span: sp,
                });
            }
        }

        // Variable declaration(s)
        let mut declarators = Vec::new();
        // Trailing `__asm__("name")` rename and/or `__attribute__((...))`
        // (including `vector_size`) before the initializer.
        let mut ty = ty;
        self.skip_decl_tail();
        if let Some(n) = self.pending_vector_size.take() { ty = self.apply_vector_size(ty, n); }
        let init = if self.eat(TokenKind::Eq) {
            Some(self.parse_initializer()?)
        } else {
            None
        };
        declarators.push(Declarator { name, ty, init, cleanup: None, span: sp.clone() });

        while self.eat(TokenKind::Comma) {
            self.skip_attributes();
            self.pending_vector_size = None;
            let (n, mut t) = self.parse_declarator(base_ty.clone())?;
            self.skip_decl_tail();
            if let Some(vs) = self.pending_vector_size.take() { t = self.apply_vector_size(t, vs); }
            let init = if self.eat(TokenKind::Eq) { Some(self.parse_initializer()?) } else { None };
            declarators.push(Declarator { name: n, ty: t, init, cleanup: None, span: self.span() });
        }
        self.eat(TokenKind::Semi);

        Ok(Decl::Var { base_ty, declarators, weak: self.pending_weak, thread_local: self.pending_thread_local, span: sp })
    }

    fn is_expr_start_not_decl(&self) -> bool {
        // If the current token cannot start a declaration, it's a top-level expr.
        // sic `tuple <name>` is a declaration (not an expression start); `tuple(`
        // is the pack/unpack expression.
        if self.peek_kind() == TokenKind::Tuple {
            return self.tokens.get(self.pos + 1).map(|t| t.kind) == Some(TokenKind::LParen);
        }
        if matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::TypeName | TokenKind::Typeof | TokenKind::Alignas | TokenKind::ThreadLocal
            | TokenKind::Eof | TokenKind::LBrace
        ) { return false; }
        // Ident that's a typedef name also starts a declaration
        if self.peek_kind() == TokenKind::Ident && self.typedefs.contains(self.peek().text.as_str()) {
            return false;
        }
        // sic `private struct/union/enum` is a declaration (sic.md §"Namespace").
        if self.lang == Lang::Sic && self.peek_kind() == TokenKind::Ident
            && self.peek().text == "private"
            && self.tokens.get(self.pos + 1).map_or(false, |t|
                matches!(t.kind, TokenKind::Struct | TokenKind::Union | TokenKind::Enum)) {
            return false;
        }
        // sic `@T` / `@mut T` reference type at the head of a declaration (e.g. a
        // `@char* f()` return type) starts a declaration, not an expression.
        if self.peek_kind() == TokenKind::At {
            let mut j = self.pos + 1;
            if self.tokens.get(j).map(|t| t.kind) == Some(TokenKind::Ident)
                && self.tokens.get(j).map(|t| t.text.as_str()) == Some("mut")
            {
                j += 1;
            }
            if matches!(self.tokens.get(j).map(|t| t.kind), Some(
                TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
                | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
                | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Struct | TokenKind::Union
                | TokenKind::Enum | TokenKind::Const | TokenKind::TypeName)) {
                return false;
            }
        }
        true
    }

    // ─── Typedef ──────────────────────────────────────────────────────────────

    fn parse_typedef(&mut self, base_ty: QualType, sp: Span) -> Result<Decl> {
        let mut names = Vec::new();
        loop {
            // A trailing `__attribute__((vector_size(N)))` turns the typedef into
            // an N-byte SIMD vector (represented as an array — see apply_vector_size).
            // The attribute may be consumed inside `parse_declarator`, so clear the
            // capture slot first and read it afterward.
            self.pending_vector_size = None;
            self.pending_aligned = None;
            let (name, mut ty) = self.parse_declarator(base_ty.clone())?;
            self.skip_attributes();
            if let Some(n) = self.pending_vector_size.take() {
                ty = self.apply_vector_size(ty, n);
            }
            // `typedef struct {...} Name QEMU_ALIGNED(N)`: the alignment attaches
            // to the aliased struct/union type (QEMU's CPUTLBDescFast etc.).
            if let Some(n) = self.pending_aligned.take() {
                match &mut ty.ty {
                    AstType::Struct(sd) => sd.align = Some(sd.align.unwrap_or(0).max(n)),
                    AstType::Union(ud)  => ud.align = Some(ud.align.unwrap_or(0).max(n)),
                    _ => {}
                }
            }
            self.typedefs.insert(name.clone());
            names.push((name, ty));
            if !self.eat(TokenKind::Comma) { break; }
        }
        self.eat(TokenKind::Semi);
        Ok(Decl::TypeDef { names, span: sp })
    }

    // ─── Declaration specifiers ───────────────────────────────────────────────

    /// Consume a contextual `mut` (only right after `@`), returning whether it
    /// was present. `mut` is not a reserved keyword, so ordinary code may still
    /// use it as an identifier.
    fn eat_contextual_mut(&mut self) -> bool {
        if self.peek_kind() == TokenKind::Ident && self.peek().text == "mut" {
            self.advance();
            true
        } else {
            false
        }
    }

    fn parse_decl_specifiers(&mut self) -> Result<(QualType, Option<StorageClass>)> {
        let mut storage: Option<StorageClass> = None;
        let mut quals: Vec<TypeQual> = Vec::new();
        let mut signed: Option<bool> = None;
        let mut base: Option<AstType> = None;
        let mut long_count = 0u32;

        // sic `@T` / `@mut T` reference type (sic.md §"References"): a leading `@`
        // marks the whole declared type as a scoped reference.
        if self.at(TokenKind::At) {
            self.advance();
            let mutable = self.eat_contextual_mut();
            quals.push(TypeQual::Reference { mutable });
        }

        loop {
            self.skip_attributes();
            match self.peek_kind() {
                // GCC `__extension__` is a transparent prefix on a declaration
                // (used e.g. on `long long` struct members in glibc headers).
                // Skip it; not consuming it here made struct-member parsing spin.
                TokenKind::Extension => { self.advance(); }
                // `__thread`/`_Thread_local`: per-thread storage. Orthogonal to
                // the storage class, so it doesn't set `storage`.
                TokenKind::ThreadLocal => { self.pending_thread_local = true; self.advance(); }
                // Storage classes
                TokenKind::Auto     => { storage = Some(StorageClass::Auto);     self.advance(); }
                TokenKind::Register => { storage = Some(StorageClass::Register); self.advance(); }
                TokenKind::Static   => { storage = Some(StorageClass::Static);   self.advance(); }
                TokenKind::Extern   => { storage = Some(StorageClass::Extern);   self.advance(); }
                TokenKind::Typedef  => { storage = Some(StorageClass::Typedef);  self.advance(); }
                // Qualifiers
                TokenKind::Const    => { quals.push(TypeQual::Const);    self.advance(); }
                TokenKind::Volatile => { quals.push(TypeQual::Volatile); self.advance(); }
                TokenKind::Restrict => { quals.push(TypeQual::Restrict); self.advance(); }
                TokenKind::Atomic   => {
                    self.advance();
                    if self.at(TokenKind::LParen) {
                        // C11 `_Atomic(type-name)` / sic `atomic(T)`: the whole
                        // type sits inside the parens and is marked atomic. This
                        // is how an atomic *pointer* is spelled unambiguously —
                        // `atomic(int*)` (the pointer is atomic), vs `atomic int*`
                        // (pointer to an atomic int).
                        self.advance(); // (
                        let (inner_base, _) = self.parse_decl_specifiers()?;
                        let (_, inner_qt) = self.parse_declarator(inner_base)?;
                        self.expect(TokenKind::RParen)?;
                        base = Some(inner_qt.ty);
                        quals.extend(inner_qt.qualifiers);
                        quals.push(TypeQual::Atomic);
                    } else {
                        quals.push(TypeQual::Atomic);
                    }
                }
                // `_Alignas(N)` / `alignas(N)` / `_Alignas(type)`.
                TokenKind::Alignas  => {
                    self.advance();
                    self.expect(TokenKind::LParen)?;
                    let align = if self.starts_decl_specifier() {
                        // Alignment of a type.
                        let (base, _) = self.parse_decl_specifiers()?;
                        let (_, qt) = self.parse_declarator(base)?;
                        ast_type_alignment(&qt.ty)
                    } else {
                        // Constant alignment expression.
                        let e = self.parse_assign_expr()?;
                        crate::lower::eval_const_expr(&e, &std::collections::HashMap::new())
                            .unwrap_or(0)
                            .max(0) as u32
                    };
                    self.expect(TokenKind::RParen)?;
                    if align > 0 { quals.push(TypeQual::Align(align)); }
                }
                // `inline` function specifier: recorded so definitions can be
                // omitted when unreferenced (GNU inline semantics).
                TokenKind::Inline   => { quals.push(TypeQual::Inline); self.advance(); }
                // signedness
                TokenKind::Signed   => { signed = Some(true);  self.advance(); }
                TokenKind::Unsigned => { signed = Some(false); self.advance(); }
                // Basic types
                TokenKind::Void     => { base = Some(AstType::Void); self.advance(); }
                TokenKind::Char     => { base = Some(AstType::Char { signed }); self.advance(); }
                TokenKind::Short    => { base = Some(AstType::Short { signed: signed.unwrap_or(true) }); self.advance(); }
                TokenKind::Int      => {
                    // `int` is redundant in `short int` / `long int` /
                    // `long long int`: only establish `int` as the base when no
                    // width keyword (short/long) has been seen yet, otherwise it
                    // would clobber `short` back to a 4-byte `int`.
                    if base.is_none() {
                        base = Some(AstType::Int { signed: signed.unwrap_or(true) });
                    }
                    self.advance();
                }
                TokenKind::Long     => {
                    long_count += 1;
                    self.advance();
                    // Don't set base yet — may accumulate 'long long'
                }
                TokenKind::Float    => { base = Some(AstType::Float); self.advance(); }
                TokenKind::Double   => { base = Some(AstType::Double); self.advance(); }
                TokenKind::Bool     => { base = Some(AstType::Bool); self.advance(); }
                TokenKind::Complex  => { base = Some(AstType::Complex); self.advance(); }
                // sic `private struct/union/enum` (sic.md §"Namespace"): withhold
                // the following aggregate type from the module manifest.
                TokenKind::Ident if self.lang == Lang::Sic && self.peek().text == "private"
                    && self.tokens.get(self.pos + 1).map_or(false, |t|
                        matches!(t.kind, TokenKind::Struct | TokenKind::Union | TokenKind::Enum)) => {
                    self.advance();
                    self.pending_private = true;
                }
                TokenKind::Struct   => { base = Some(self.parse_struct_or_union(false)?); }
                TokenKind::Union    => { base = Some(self.parse_struct_or_union(true)?); }
                TokenKind::Enum     => { base = Some(self.parse_enum()?); }
                // sic `tuple` type (sic.md §"Tuples"). `tuple(` is instead the
                // pack/unpack expression, handled in primary-expression parsing.
                TokenKind::Tuple if base.is_none()
                    && self.tokens.get(self.pos + 1).map(|t| t.kind) != Some(TokenKind::LParen) =>
                {
                    base = Some(AstType::Tuple);
                    self.advance();
                }
                // `__int128` is a base integer type that combines with
                // signed/unsigned (`unsigned __int128`, `__signed__ __int128`),
                // unlike ordinary typedef names.
                TokenKind::TypeName if base.is_none()
                    && matches!(self.peek().text.as_str(), "__int128" | "__int128_t" | "__uint128_t") =>
                {
                    let name = self.advance().text.clone();
                    base = Some(AstType::Named(
                        if name == "__uint128_t" || signed == Some(false) { "__uint128_t" } else { "__int128" }
                            .to_string()));
                }
                // sic `fixed` / `fixed<integral,fraction>` (sic.md §"Built-in fixed
                // point"). A `fixed` value is an exact rational; the `<I,F>` are
                // display precision only. Either dimension may be omitted — `fixed<,F>`
                // (open integral, F decimals), `fixed<I,>` / bare `fixed` (default
                // decimals) — marked here as `0` (resolved to the default at display).
                TokenKind::TypeName if base.is_none() && signed.is_none() && long_count == 0
                    && self.lang == Lang::Sic && self.peek().text == "fixed" =>
                {
                    self.advance();
                    let (integral, fraction) = if self.at(TokenKind::Lt) {
                        self.advance();
                        let i = if self.at(TokenKind::Comma) { 0 } else { self.parse_fixed_dim()? };
                        self.expect(TokenKind::Comma)?;
                        let f = if self.at(TokenKind::Gt) { 0 } else { self.parse_fixed_dim()? };
                        self.expect(TokenKind::Gt)?;
                        (i, f)
                    } else {
                        (0, 0)
                    };
                    base = Some(AstType::Fixed { integral, fraction });
                }
                // A type-name (typedef or sic alias like `u32`) is only a type
                // specifier when no other type info has been seen yet. Otherwise
                // it is the declarator name — e.g. `uint32_t u32;` where the
                // second token is a field/variable named `u32`, not a type.
                // sic scope-qualified type `A::B::Name` (sic.md §"Namespace") in a
                // type-specifier position — e.g. a `Buffer::Data *buf` parameter.
                // A namespace's types are hoisted to file scope, so the type is the
                // one named by the last segment.
                TokenKind::Ident | TokenKind::TypeName if base.is_none() && signed.is_none()
                    && long_count == 0 && self.lang == Lang::Sic
                    && self.tokens.get(self.pos + 1).map_or(false, |t| t.kind == TokenKind::ColonColon) => {
                    let mut last = self.advance().text.clone();
                    while self.at(TokenKind::ColonColon) {
                        self.advance();
                        last = self.expect_name()?;
                    }
                    base = Some(self.maybe_generic_type(last)?);
                }
                TokenKind::TypeName if base.is_none() && signed.is_none() && long_count == 0 => {
                    let name = self.advance().text.clone();
                    base = Some(self.maybe_generic_type(name)?);
                }
                TokenKind::Ident if base.is_none() && signed.is_none() && long_count == 0
                    && self.typedefs.contains(self.peek().text.as_str()) => {
                    let name = self.advance().text.clone();
                    base = Some(self.maybe_generic_type(name)?);
                }
                // typeof(type-name) / typeof(expr) — GNU / C23.
                TokenKind::Typeof if base.is_none() => {
                    self.advance();
                    self.expect(TokenKind::LParen)?;
                    if self.starts_decl_specifier() {
                        // typeof(type-name): use the named type directly.
                        let (ty, _) = self.parse_decl_specifiers()?;
                        let (_, ty) = self.parse_declarator(ty)?;
                        base = Some(ty.ty);
                    } else {
                        // typeof(expr): resolved to the operand's type later.
                        let e = self.parse_expr()?;
                        base = Some(AstType::Typeof(Box::new(e)));
                    }
                    self.expect(TokenKind::RParen)?;
                }
                _ => break,
            }
        }

        // Resolve long combinations
        if base.is_none() {
            let s = signed.unwrap_or(true);
            base = Some(match long_count {
                0 if signed.is_some() => AstType::Int { signed: s },
                1 => AstType::Long { signed: s },
                _ => AstType::LongLong { signed: s },
            });
        } else if long_count > 0 {
            if let Some(AstType::Double) = &base {
                base = Some(AstType::LongDouble);
            } else if let Some(AstType::Int { .. }) = &base {
                let s = signed.unwrap_or(true);
                base = Some(if long_count >= 2 { AstType::LongLong { signed: s } }
                            else { AstType::Long { signed: s } });
            } else {
                // long + something else: just use long
                let s = signed.unwrap_or(true);
                base = Some(AstType::Long { signed: s });
            }
        } else if let Some(AstType::Char { .. }) = &base {
            base = Some(AstType::Char { signed });
        } else if let Some(AstType::Short { .. }) = &base {
            base = Some(AstType::Short { signed: signed.unwrap_or(true) });
        } else if let Some(AstType::Int { .. }) = &base {
            base = Some(AstType::Int { signed: signed.unwrap_or(true) });
        }

        let ty = base.unwrap_or(AstType::Int { signed: true });
        let mut qt = QualType::new(ty);
        qt.qualifiers = quals;
        qt.storage = storage.clone();

        Ok((qt, storage))
    }

    // ─── Struct / union / enum ────────────────────────────────────────────────

    /// Parse a `::`-separated scope path whose first segment is `first` (with the
    /// leading `::` still pending). The last segment is the member; the rest join
    /// with `::` as the scope. Two segments = an enum variant (`Option::Some`);
    /// three or more = a nested namespace / module path (`std::Buffer::Create`).
    fn parse_scope_path(&mut self, first: String, sp: crate::lexer::Span) -> Result<Expr> {
        let mut segs = vec![first];
        while self.at(TokenKind::ColonColon) {
            self.advance();
            segs.push(self.expect_name()?);
        }
        let variant = segs.pop().unwrap();
        let enum_name = segs.join("::");
        Ok(Expr::new(ExprKind::EnumVariant { enum_name, variant }, sp))
    }

    fn parse_struct_or_union(&mut self, is_union: bool) -> Result<AstType> {
        let sp = self.span();
        self.advance(); // consume 'struct'/'union'
        // Track packed/`__order__` for THIS struct only (sic reordering opt-out).
        self.pending_packed = false;
        self.pending_order = false;
        // A leading `struct __attribute__((aligned(N))) Tag {...}` raises the whole
        // type's alignment. Capture N here, before member parsing clears the slot.
        self.pending_aligned = None;
        self.skip_attributes();
        let mut type_align = self.pending_aligned.take();

        let name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            Some(self.advance().text.clone())
        } else {
            None
        };
        // Attributes may also sit between the tag and the body:
        // `struct Tag __attribute__((aligned(N))) {...}`.
        self.pending_aligned = None;
        self.skip_attributes();
        type_align = type_align.or(self.pending_aligned.take());

        let mut methods: Vec<StructMethod> = Vec::new();
        let fields = if self.at(TokenKind::LBrace) {
            self.advance();
            let mut fields = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                let before = self.pos;
                // sic member functions (sic.md §"Memory safety"): a constructor
                // `S()`, destructor `~S()`, or method `Ret m(S* self){…}` in the
                // body. C structs never have these.
                if !is_union && self.lang == Lang::Sic {
                    if let Some(m) = self.try_parse_struct_method(name.as_deref())? {
                        methods.push(m);
                        continue;
                    }
                }
                fields.extend(self.parse_struct_field()?);
                self.eat(TokenKind::Semi);
                // Safety: never spin (and allocate unboundedly) if some construct
                // failed to consume any tokens.
                if self.pos == before {
                    return Err(CompileError::at(
                        "unexpected token in struct/union member",
                        self.span().file.clone(), self.span().line, self.span().col,
                    ));
                }
            }
            self.expect(TokenKind::RBrace)?;
            // Trailing `struct T {...} __attribute__((packed/__order__))`.
            self.skip_attributes();
            Some(fields)
        } else {
            None
        };
        let keep_order = self.pending_packed || self.pending_order;

        // sic (C++-style): a `struct`/`union` *definition* also makes its tag usable
        // as a bare type name (`BufferData *p`, not just `struct BufferData *p`), so
        // register it. C keeps tags and typedefs in separate namespaces, so this is
        // sic-only; a body is required (a forward `struct X;` reference does not
        // introduce the bare name).
        if self.lang == Lang::Sic && fields.is_some() {
            if let Some(n) = &name { self.typedefs.insert(n.clone()); }
        }

        let private = std::mem::take(&mut self.pending_private);
        if is_union {
            Ok(AstType::Union(UnionDef { name, fields, align: type_align, private, span: sp }))
        } else {
            Ok(AstType::Struct(StructDef { name, fields, align: type_align, keep_order, methods, private, span: sp }))
        }
    }

    /// sic (sic.md §"Memory safety"): try to parse a struct member function at the
    /// current position — a destructor `~S(){…}`, constructor `S(){…}`, or method
    /// `Ret m(S* self){…}`. Returns `None` (leaving the position untouched) when the
    /// member is an ordinary field, so the caller falls back to `parse_struct_field`.
    fn try_parse_struct_method(&mut self, struct_name: Option<&str>) -> Result<Option<StructMethod>> {
        let sp = self.span();
        // Destructor: `~S() { … }`.
        if self.at(TokenKind::Tilde) {
            self.advance();
            let name = self.expect_name()?;
            let (params, variadic) = self.parse_params()?;
            self.skip_attributes();
            let body = self.parse_compound_stmt_as_stmts()?;
            self.eat(TokenKind::Semi);
            return Ok(Some(StructMethod { kind: MethodKind::Dtor, name, ret_ty: QualType::new(AstType::Void), params, variadic, body, span: sp }));
        }
        let start = self.pos;
        // Constructor: `S( … ) { … }` — a bare struct-name followed by `(`.
        if let Some(sname) = struct_name {
            if (self.at(TokenKind::Ident) || self.at(TokenKind::TypeName)) && self.peek().text == sname {
                let save = self.pos;
                self.advance(); // the name
                if self.at(TokenKind::LParen) {
                    let (params, variadic) = self.parse_params()?;
                    if self.at(TokenKind::LBrace) {
                        self.skip_attributes();
                        let body = self.parse_compound_stmt_as_stmts()?;
                        self.eat(TokenKind::Semi);
                        return Ok(Some(StructMethod { kind: MethodKind::Ctor, name: sname.to_string(), ret_ty: QualType::new(AstType::Void), params, variadic, body, span: sp }));
                    }
                }
                self.pos = save; // not a constructor — rewind
            }
        }
        // Method: `Ret name( … ) { … }`. Parse a full declarator; if it is a
        // function declarator immediately followed by a `{`, it is a method body.
        let parsed = (|| -> Result<Option<StructMethod>> {
            let (base_ty, _) = self.parse_decl_specifiers()?;
            let (name, ty) = self.parse_declarator(base_ty)?;
            if let AstType::Function { params, variadic, ret } = ty.ty {
                if self.at(TokenKind::LBrace) {
                    self.skip_attributes();
                    let body = self.parse_compound_stmt_as_stmts()?;
                    self.eat(TokenKind::Semi);
                    return Ok(Some(StructMethod { kind: MethodKind::Method, name, ret_ty: *ret, params, variadic, body, span: sp.clone() }));
                }
            }
            Ok(None)
        })();
        match parsed {
            Ok(Some(m)) => Ok(Some(m)),
            _ => { self.pos = start; Ok(None) }  // field: rewind for parse_struct_field
        }
    }

    fn parse_struct_field(&mut self) -> Result<Vec<FieldDecl>> {
        let sp = self.span();
        // Clear any `aligned(N)` left over from a preceding declaration (a file-
        // scope `int g __attribute__((aligned(64)))`, a typedef, etc.) so it can't
        // leak onto this member and corrupt an unrelated struct's layout.
        self.pending_aligned = None;
        let (base_ty, _) = self.parse_decl_specifiers()?;
        let mut fields = Vec::new();

        if self.at(TokenKind::Semi) {
            // Anonymous struct/union member
            fields.push(FieldDecl { name: None, ty: base_ty, bit_width: None, align: None, span: sp });
            return Ok(fields);
        }

        loop {
            // Alignment may be attached to the base type (before the declarator,
            // applying to every declarator in the group) or trail an individual
            // member; capture both. `parse_declarator` runs `skip_attributes`
            // for the trailing form.
            let group_align = self.pending_aligned.take();
            let (name, ty) = self.parse_declarator(base_ty.clone())?;
            let bit_width = if self.eat(TokenKind::Colon) {
                Some(Box::new(self.parse_assign_expr()?))
            } else {
                None
            };
            // Trailing field attribute, e.g. `int x __attribute__((aligned(8)));`.
            self.skip_attributes();
            let align = self.pending_aligned.take().or(group_align);
            fields.push(FieldDecl { name: Some(name), ty, bit_width, align, span: sp.clone() });
            if !self.eat(TokenKind::Comma) { break; }
        }
        Ok(fields)
    }

    /// Parse a type-name (abstract declarator), e.g. the `int`/`char*`/`string`
    /// inside a sic enum variant payload `Name<T>` / `Name(T)`.
    /// Parse a `fixed<...>` dimension — a small non-negative integer literal.
    fn parse_fixed_dim(&mut self) -> Result<u32> {
        if self.at(TokenKind::IntLit) {
            let t = self.advance().text.clone();
            let digits = t.trim_end_matches(|c| matches!(c, 'u'|'U'|'l'|'L'));
            return digits.parse::<u32>().map_err(|_| CompileError::at(
                format!("invalid fixed-point precision '{}'", t),
                self.span().file.clone(), self.span().line, self.span().col));
        }
        Err(CompileError::at(
            "expected an integer precision in `fixed<...>`".to_string(),
            self.span().file.clone(), self.span().line, self.span().col))
    }

    fn parse_type_name(&mut self) -> Result<QualType> {
        let (base, _) = self.parse_decl_specifiers()?;
        let (_, ty) = self.parse_declarator(base)?;
        Ok(ty)
    }

    /// After reading a type name, parse a generic-enum instantiation `Name<A, …>`
    /// (sic.md §"Match") — e.g. `Option<int>`. A non-generic name stays `Named`.
    fn maybe_generic_type(&mut self, name: String) -> Result<AstType> {
        if self.lang == Lang::Sic && self.generic_enums.contains(&name) && self.at(TokenKind::Lt) {
            self.advance(); // `<`
            let mut args = Vec::new();
            while !self.at(TokenKind::Gt) && !self.at(TokenKind::Eof) {
                args.push(self.parse_type_name()?);
                if !self.eat(TokenKind::Comma) { break; }
            }
            self.expect(TokenKind::Gt)?;
            return Ok(AstType::Generic { name, args });
        }
        Ok(AstType::Named(name))
    }

    fn parse_enum(&mut self) -> Result<AstType> {
        let sp = self.span();
        self.advance(); // 'enum'
        // `enum __attribute__((packed)) { ... }` — a packed enum uses the smallest
        // integer type that fits its enumerators (1 byte for small values), which
        // affects the size/layout of any struct containing it (QEMU's FloatClass /
        // FloatParts128 in softfloat).
        self.pending_packed = false;
        self.skip_attributes();
        let name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            Some(self.advance().text.clone())
        } else {
            None
        };
        // sic generic enum (sic.md §"Match"): `enum Option<T> { … }` — parse the
        // type-parameter list. Their names are ordinary identifiers usable as types
        // inside the variant payloads.
        let mut type_params = Vec::new();
        if self.lang == Lang::Sic && self.at(TokenKind::Lt) {
            self.advance(); // `<`
            while !self.at(TokenKind::Gt) && !self.at(TokenKind::Eof) {
                let p = self.expect_name()?;
                self.typedefs.insert(p.clone()); // a type-param spells a type
                type_params.push(p);
                if !self.eat(TokenKind::Comma) { break; }
            }
            self.expect(TokenKind::Gt)?;
        }
        self.skip_attributes();
        let variants = if self.at(TokenKind::LBrace) {
            self.advance();
            let mut vs = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                let vsp = self.span();
                let vname = self.expect_name()?;
                // sic tagged-enum payload (sic.md §"Match"): `Name<T>` or `Name(T)`
                // attaches a value type to the variant. C enumerators have neither.
                let payload = if self.lang == Lang::Sic && self.at(TokenKind::Lt) {
                    self.advance();
                    let ty = self.parse_type_name()?;
                    self.expect(TokenKind::Gt)?;
                    Some(ty)
                } else if self.lang == Lang::Sic && self.at(TokenKind::LParen) {
                    self.advance();
                    let ty = self.parse_type_name()?;
                    self.expect(TokenKind::RParen)?;
                    Some(ty)
                } else {
                    None
                };
                // Enumerator attributes (`NAME __attribute__((...)) = val`), e.g.
                // glib's `GLIB_AVAILABLE_ENUMERATOR_IN_*` deprecation markers.
                self.skip_attributes();
                let value = if self.eat(TokenKind::Eq) { Some(Box::new(self.parse_assign_expr()?)) } else { None };
                vs.push(EnumVariant { name: vname, value, payload, span: vsp });
                if !self.eat(TokenKind::Comma) { break; }
            }
            self.expect(TokenKind::RBrace)?;
            Some(vs)
        } else {
            None
        };
        // sic tagged enum (sic.md §"Match"): register the name as a type so it can
        // be used bare (`Option a;`) like Rust, not only as `enum Option a;`.
        if self.lang == Lang::Sic {
            if let (Some(n), Some(_)) = (&name, &variants) {
                // Any named enum's tag is usable as a bare type name (`OpenMode m`,
                // not only `enum OpenMode m`) — tagged and plain C enums alike.
                self.typedefs.insert(n.clone());
                // A generic enum name is remembered so `Option<int>` in a later type
                // position parses as an instantiation rather than a `<` comparison.
                if !type_params.is_empty() {
                    self.generic_enums.insert(n.clone());
                }
            }
        }
        let private = std::mem::take(&mut self.pending_private);
        Ok(AstType::Enum(EnumDef { name, variants, packed: self.pending_packed, type_params, private, span: sp }))
    }

    // ─── Declarators ──────────────────────────────────────────────────────────

    /// With the current token at `(`, decide whether it opens a *grouped
    /// declarator* `( declarator )` rather than a function parameter list.
    /// A grouped declarator's first inner token is `*`, another `(`, or an
    /// identifier that is a declarator name (not a typedef/type). A `(` that is
    /// immediately followed by a type, `)`, or `void` is a function suffix and
    /// is handled by `parse_declarator_suffix` instead.
    fn grouped_declarator_ahead(&self) -> bool {
        let next = &self.tokens[(self.pos + 1).min(self.tokens.len() - 1)];
        match next.kind {
            TokenKind::Star | TokenKind::LParen | TokenKind::LBracket => true,
            TokenKind::Ident => !self.typedefs.contains(next.text.as_str()),
            _ => false,
        }
    }

    /// Parse a declarator, returning (name, fully-qualified type).
    fn parse_declarator(&mut self, base: QualType) -> Result<(String, QualType)> {
        // Collect pointer levels and apply them to the base type immediately (forward order).
        // This ensures T *f(params) produces Function{ret:Pointer(T), params} rather than
        // Pointer(Function{ret:T, params}), matching C's right-left declarator rule where
        // postfix () and [] bind tighter than prefix *.
        let mut new_base = base;
        while self.eat(TokenKind::Star) {
            let mut pq = Vec::new();
            loop {
                match self.peek_kind() {
                    TokenKind::Const    => { pq.push(TypeQual::Const);    self.advance(); }
                    TokenKind::Volatile => { pq.push(TypeQual::Volatile); self.advance(); }
                    TokenKind::Restrict => { pq.push(TypeQual::Restrict); self.advance(); }
                    // `int * __attribute__((...)) p` — pointer attribute.
                    TokenKind::Attribute => { self.skip_attributes(); }
                    _ => break,
                }
            }
            new_base = QualType {
                ty: AstType::Pointer { base: Box::new(new_base), quals: pq },
                qualifiers: vec![],
                storage: None,
            };
        }

        self.skip_attributes();

        // Direct declarator: name, grouped, or abstract
        if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            let name = self.advance().text.clone();
            let ty = self.parse_declarator_suffix(new_base)?;
            return Ok((name, ty));
        } else if self.at(TokenKind::LParen) && self.grouped_declarator_ahead() {
            // Grouped declarator: `( declarator )` followed by array/function
            // suffixes. Handles arbitrary nesting, e.g. a function pointer that
            // returns a function pointer: `void (*(*f)(A))(B)`.
            //
            // The C rule is that the trailing suffixes apply to `new_base`
            // *first*, then the inner declarator wraps that. We parse the inner
            // declarator against a fresh sentinel leaf, then splice the suffixed
            // base into the sentinel's place.
            let sentinel = format!("\0decl{}", self.pos);
            self.advance(); // (
            let sent_qt = QualType::new(AstType::Named(sentinel.clone()));
            let (name, inner_ty) = self.parse_declarator(sent_qt)?;
            self.expect(TokenKind::RParen)?;
            let outer_base = self.parse_declarator_suffix(new_base)?;
            let ty = subst_sentinel(inner_ty, &sentinel, &outer_base);
            return Ok((name, ty));
        }

        // Abstract declarator (no name)
        let ty = self.parse_declarator_suffix(new_base)?;
        Ok((String::new(), ty))
    }

    fn parse_declarator_suffix(&mut self, mut ty: QualType) -> Result<QualType> {
        // Postfix declarator operators bind left-to-right: the *leftmost* suffix
        // is the *outermost* type constructor. E.g. `int a[2][3]` is "array-2 of
        // array-3 of int", so `[2]` must wrap `[3]`. Collect the whole suffix run
        // in source order, then apply it inside-out (last suffix innermost).
        enum Suffix { Array(Option<Box<Expr>>), Func(Vec<Param>, bool) }
        let mut suffixes = Vec::new();
        loop {
            match self.peek_kind() {
                TokenKind::LBracket => {
                    self.advance();
                    // C99 array-parameter qualifiers inside the brackets:
                    // `arr[static N]`, `arr[const]`, `arr[restrict]` (glibc's
                    // `__restrict_arr`), `arr[*]` (unspecified VLA).
                    loop {
                        match self.peek_kind() {
                            TokenKind::Static | TokenKind::Const
                            | TokenKind::Volatile | TokenKind::Restrict => { self.advance(); }
                            _ => break,
                        }
                    }
                    let size = if self.at(TokenKind::RBracket) {
                        None
                    } else if self.at(TokenKind::Star)
                        && self.tokens.get(self.pos + 1).map(|t| t.kind) == Some(TokenKind::RBracket)
                    {
                        self.advance(); // `[*]`
                        None
                    } else {
                        Some(Box::new(self.parse_assign_expr()?))
                    };
                    self.expect(TokenKind::RBracket)?;
                    suffixes.push(Suffix::Array(size));
                }
                TokenKind::LParen => {
                    let (params, variadic) = self.parse_params()?;
                    suffixes.push(Suffix::Func(params, variadic));
                }
                _ => break,
            }
        }
        for suf in suffixes.into_iter().rev() {
            ty = match suf {
                Suffix::Array(size) => QualType::new(AstType::Array { base: Box::new(ty), size }),
                Suffix::Func(params, variadic) => QualType::new(AstType::Function {
                    ret: Box::new(ty), params, variadic,
                }),
            };
        }
        Ok(ty)
    }

    fn parse_params(&mut self) -> Result<(Vec<Param>, bool)> {
        self.expect(TokenKind::LParen)?;
        let mut params = Vec::new();
        let mut variadic = false;

        if self.eat(TokenKind::RParen) { return Ok((params, variadic)); }

        // (void) means no params
        if self.at(TokenKind::Void) {
            // peek ahead — if next is ')' then it's `(void)`
            let save = self.pos;
            self.advance();
            if self.eat(TokenKind::RParen) { return Ok((params, false)); }
            self.pos = save;
        }

        loop {
            if self.at(TokenKind::Ellipsis) {
                self.advance();
                variadic = true;
                break;
            }
            let psp = self.span();
            let (base_ty, _) = self.parse_decl_specifiers()?;
            // Check for abstract declarator (no name)
            let (name, ty) = self.parse_declarator(base_ty)?;
            // Parameter attribute, e.g. `f(const T *cfg __attribute__((unused)))`.
            self.skip_attributes();
            params.push(Param { name: if name.is_empty() { None } else { Some(name) }, ty, span: psp });
            if !self.eat(TokenKind::Comma) { break; }
            if self.at(TokenKind::Ellipsis) { self.advance(); variadic = true; break; }
        }
        self.expect(TokenKind::RParen)?;
        Ok((params, variadic))
    }

    /// True if the current token can begin a declaration specifier (a type
    /// keyword/name, qualifier, or storage class). Used to detect K&R-style
    /// parameter declarations following an old-style function header.
    /// sic RTTI: whether the current token begins a bare type used as a `type`
    /// value (sic.md §"RTTI"). Primitive-type keywords and sic `TypeName` aliases
    /// only — deliberately NOT typedef `Ident`s, so `myTypedef * x` stays a
    /// multiply and existing expressions are unaffected.
    fn at_type_value_start(&self) -> bool {
        if self.lang != Lang::Sic { return false; }
        matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::TypeName)
    }

    fn starts_decl_specifier(&self) -> bool {
        // sic `tuple <name>` starts a declaration; `tuple(` is a pack/unpack expr.
        if self.peek_kind() == TokenKind::Tuple {
            return self.tokens.get(self.pos + 1).map(|t| t.kind) != Some(TokenKind::LParen);
        }
        if matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::Typeof | TokenKind::Alignas | TokenKind::ThreadLocal)
        {
            return true;
        }
        self.typename_starts_decl()
    }

    /// Parse the K&R parameter declaration list that sits between an old-style
    /// function header's `)` and its `{` body, applying the declared types back
    /// onto the (name-only) parameters parsed from the header.
    fn parse_kr_param_decls(&mut self, params: &mut [Param]) -> Result<()> {
        while !self.at(TokenKind::LBrace) && !self.at(TokenKind::Eof)
            && self.starts_decl_specifier()
        {
            let (base_ty, _) = self.parse_decl_specifiers()?;
            loop {
                let (pname, pty) = self.parse_declarator(base_ty.clone())?;
                if !pname.is_empty() {
                    if let Some(p) = params.iter_mut().find(|p| p.name.as_deref() == Some(&pname)) {
                        p.ty = pty;
                    }
                }
                if !self.eat(TokenKind::Comma) { break; }
            }
            self.eat(TokenKind::Semi);
        }
        Ok(())
    }

    // ─── Initializer ──────────────────────────────────────────────────────────

    fn parse_initializer(&mut self) -> Result<Initializer> {
        if self.at(TokenKind::LBrace) {
            self.advance();
            let mut list = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                // Designator chain: any run of `.field` / `[index]`, then `=`.
                // e.g. `.payload.area = ...`, `[3].x = ...`.
                let mut designators = Vec::new();
                loop {
                    if self.at(TokenKind::LBracket) {
                        self.advance();
                        let idx = self.parse_assign_expr()?;
                        if self.eat(TokenKind::Ellipsis) {
                            // GNU range designator `[lo ... hi]`.
                            let hi = self.parse_assign_expr()?;
                            self.expect(TokenKind::RBracket)?;
                            designators.push(Designator::IndexRange(Box::new(idx), Box::new(hi)));
                        } else {
                            self.expect(TokenKind::RBracket)?;
                            designators.push(Designator::Index(Box::new(idx)));
                        }
                    } else if self.at(TokenKind::Dot) {
                        self.advance();
                        let name = self.expect_name()?;
                        designators.push(Designator::Field(name));
                    } else {
                        break;
                    }
                }
                if !designators.is_empty() {
                    self.expect(TokenKind::Eq)?;
                }
                let init = self.parse_initializer()?;
                list.push(InitItem { designators, init });
                if !self.eat(TokenKind::Comma) { break; }
            }
            self.expect(TokenKind::RBrace)?;
            Ok(Initializer::List(list))
        } else {
            Ok(Initializer::Expr(self.parse_assign_expr()?))
        }
    }

    // ─── Statements ───────────────────────────────────────────────────────────

    pub fn parse_stmt(&mut self) -> Result<Stmt> {
        let sp = self.span();
        match self.peek_kind() {
            TokenKind::Semi => { self.advance(); Ok(Stmt::Null(sp)) }
            TokenKind::LBrace => Ok(Stmt::Block(self.parse_compound_stmt_as_stmts()?, sp)),
            TokenKind::If => self.parse_if(),
            TokenKind::While => self.parse_while(),
            TokenKind::Do => self.parse_do_while(),
            TokenKind::For => self.parse_for(),
            TokenKind::Return => self.parse_return(),
            TokenKind::Break => { self.advance(); self.eat(TokenKind::Semi); Ok(Stmt::Break(sp)) }
            TokenKind::Continue => { self.advance(); self.eat(TokenKind::Semi); Ok(Stmt::Continue(sp)) }
            TokenKind::Fallthrough => { self.advance(); self.eat(TokenKind::Semi); Ok(Stmt::Fallthrough(sp)) }
            TokenKind::Defer => {
                self.advance();
                let inner = Box::new(self.parse_stmt()?);
                Ok(Stmt::Defer(inner, sp))
            }
            TokenKind::Del => {
                self.advance();
                let e = self.parse_expr()?;
                self.eat(TokenKind::Semi);
                Ok(Stmt::Delete(e, sp))
            }
            TokenKind::Goto => self.parse_goto(),
            TokenKind::Switch => self.parse_switch(),
            TokenKind::Match => self.parse_match(),
            // sic `unsafe { … }` (sic.md §"Integer overflow") — contextual: only a
            // block-keyword when immediately followed by `{`; else an identifier.
            TokenKind::Ident if self.lang == Lang::Sic && self.peek().text == "unsafe"
                && self.tokens.get(self.pos + 1).map(|t| t.kind) == Some(TokenKind::LBrace) =>
            {
                self.advance();
                let body = self.parse_compound_stmt_as_stmts()?;
                Ok(Stmt::Unsafe(body, sp))
            }
            // label: `ident :`
            TokenKind::Ident | TokenKind::TypeName if self.is_label() => self.parse_label(),
            TokenKind::Case => self.parse_case(),
            TokenKind::Default => self.parse_default(),
            // inline asm — skip
            TokenKind::Asm => { self.parse_asm_skip()?; Ok(Stmt::Null(sp)) }
            // __extension__ — skip
            TokenKind::Extension => { self.advance(); self.parse_stmt() }
            // Statement attribute, e.g. `__attribute__((fallthrough));`.
            TokenKind::Attribute => {
                self.skip_attributes();
                if self.eat(TokenKind::Semi) { Ok(Stmt::Null(sp)) } else { self.parse_stmt() }
            }
            // sic guard `… else <stmt>` (sic.md §"Match"): a bind (`auto x = opt
            // else …`) or boolean (`cond else …`) early-exit. Detected by an `else`
            // at depth 0 before the statement's `;`.
            _ if self.lang == Lang::Sic && self.stmt_has_guard_else() => self.parse_guard(sp),
            _ if self.is_decl_start() => {
                let d = self.parse_local_decl()?;
                Ok(Stmt::Decl(d))
            }
            _ => {
                let e = self.parse_expr()?;
                self.eat(TokenKind::Semi);
                Ok(Stmt::Expr(e, sp))
            }
        }
    }

    /// Whether the statement starting here is a guard — an `else` at bracket depth
    /// 0 before the terminating `;` (sic.md §"Match"). `if`/`while`/blocks are
    /// dispatched earlier, so a depth-0 `else` here can only be a guard.
    fn stmt_has_guard_else(&self) -> bool {
        let mut depth = 0i32;
        let mut i = self.pos;
        while i < self.tokens.len() {
            match self.tokens[i].kind {
                TokenKind::LParen | TokenKind::LBracket | TokenKind::LBrace => depth += 1,
                TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace => {
                    if depth == 0 { return false; }
                    depth -= 1;
                }
                TokenKind::Semi if depth == 0 => return false,
                TokenKind::Else if depth == 0 => return true,
                TokenKind::Eof => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// Parse a guard `… else <stmt>` (sic.md §"Match"): `auto x = expr else …` /
    /// `T x = expr else …` (bind) or `cond else …` (boolean).
    fn parse_guard(&mut self, sp: Span) -> Result<Stmt> {
        let binding;
        let cond;
        if self.is_decl_start() {
            // Bind form: `auto`/type + name + `=` + expr.
            let ty = if self.at(TokenKind::Auto) {
                self.advance();
                None // inferred from the payload
            } else {
                let (base, _) = self.parse_decl_specifiers()?;
                let (name, full) = self.parse_declarator(base)?;
                // We already have the name from the declarator — stash and reuse.
                self.expect(TokenKind::Eq)?;
                let e = self.parse_assign_expr()?;
                self.expect(TokenKind::Else)?;
                let else_body = Box::new(self.parse_stmt()?);
                return Ok(Stmt::Guard { binding: Some((Some(full), name)), cond: e, else_body, span: sp });
            };
            let name = self.expect_name()?;
            self.expect(TokenKind::Eq)?;
            cond = self.parse_assign_expr()?;
            binding = Some((ty, name));
        } else {
            // Boolean form: `cond else …`.
            cond = self.parse_expr()?;
            binding = None;
        }
        self.expect(TokenKind::Else)?;
        let else_body = Box::new(self.parse_stmt()?);
        Ok(Stmt::Guard { binding, cond, else_body, span: sp })
    }

    fn is_label(&self) -> bool {
        if self.pos + 1 >= self.tokens.len() { return false; }
        self.tokens[self.pos + 1].kind == TokenKind::Colon
    }

    fn is_decl_start(&self) -> bool {
        // sic `tuple <name>` is a declaration; `tuple(` is a pack/unpack expression.
        if self.peek_kind() == TokenKind::Tuple {
            return self.tokens.get(self.pos + 1).map(|t| t.kind) != Some(TokenKind::LParen);
        }
        if matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::Typeof | TokenKind::Alignas | TokenKind::ThreadLocal
            // A declaration may lead with attributes, e.g. glib's g_autoptr /
            // QEMU's RCU_READ_LOCK_GUARD: `__attribute__((cleanup(f))) T v = ...`.
            | TokenKind::Attribute)
        {
            return true;
        }
        // sic `@T` / `@mut T` local declaration: a leading `@` followed (past an
        // optional contextual `mut`) by a type token. `@expr;` as a bare statement
        // stays an expression (its next token isn't a type).
        if self.peek_kind() == TokenKind::At {
            let mut j = self.pos + 1;
            if self.tokens.get(j).map(|t| t.kind) == Some(TokenKind::Ident)
                && self.tokens.get(j).map(|t| t.text.as_str()) == Some("mut")
            {
                j += 1;
            }
            return matches!(self.tokens.get(j).map(|t| t.kind), Some(
                TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
                | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
                | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Struct | TokenKind::Union
                | TokenKind::Enum | TokenKind::Const | TokenKind::TypeName));
        }
        if self.qualified_scope_decl() { return true; }
        self.typename_starts_decl()
    }

    /// sic (sic.md §"Namespace"): does the statement begin with a scope-qualified
    /// *type* used in a declaration — `A::B::Name` followed by a declarator (`*`…
    /// then a name)? A `(` after the path means a call (`std::Open(…)`), not a decl.
    fn qualified_scope_decl(&self) -> bool {
        if self.lang != Lang::Sic || self.peek_kind() != TokenKind::Ident { return false; }
        let is_seg = |k: Option<TokenKind>| matches!(k, Some(TokenKind::Ident | TokenKind::TypeName));
        // `Ident (:: Ident)+`
        if self.tokens.get(self.pos + 1).map(|t| t.kind) != Some(TokenKind::ColonColon) { return false; }
        let mut j = self.pos + 1; // at the first `::`
        while self.tokens.get(j).map(|t| t.kind) == Some(TokenKind::ColonColon) {
            if !is_seg(self.tokens.get(j + 1).map(|t| t.kind)) { return false; }
            j += 2;
        }
        // Past the path: skip `*` and pointer qualifiers, then require a name.
        while matches!(self.tokens.get(j).map(|t| t.kind),
            Some(TokenKind::Star | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict)) {
            j += 1;
        }
        is_seg(self.tokens.get(j).map(|t| t.kind))
    }

    /// Whether the current `TypeName`/typedef token begins a declaration rather
    /// than being a variable that shadows the type (see `starts_decl_specifier`).
    fn typename_starts_decl(&self) -> bool {
        let is_typename = self.peek_kind() == TokenKind::TypeName
            || (self.peek_kind() == TokenKind::Ident
                && self.typedefs.contains(self.peek().text.as_str()));
        if !is_typename {
            return false;
        }
        if self.lang == Lang::Sic {
            return true;
        }
        // A following assignment/member operator means the name is being used as
        // a value (`vaddr &= x`, `entry->f`), so it's an expression, not a decl.
        !matches!(self.tokens.get(self.pos + 1).map(|t| t.kind),
            Some(TokenKind::Eq) | Some(TokenKind::PlusAssign) | Some(TokenKind::MinusAssign)
            | Some(TokenKind::StarAssign) | Some(TokenKind::SlashAssign) | Some(TokenKind::PercentAssign)
            | Some(TokenKind::AndAssign) | Some(TokenKind::OrAssign) | Some(TokenKind::XorAssign)
            | Some(TokenKind::ShlAssign) | Some(TokenKind::ShrAssign)
            | Some(TokenKind::Dot) | Some(TokenKind::Arrow))
    }

    fn parse_compound_stmt_as_stmts(&mut self) -> Result<Vec<Stmt>> {
        self.expect(TokenKind::LBrace)?;
        let mut stmts = Vec::new();
        while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
            if self.eat(TokenKind::Semi) { continue; }
            stmts.push(self.parse_stmt()?);
        }
        self.expect(TokenKind::RBrace)?;
        Ok(stmts)
    }

    /// sic forbids a bare assignment as a controlling expression, because
    /// `if (x = y)` is a common typo for `if (x == y)`. An extra pair of
    /// parentheses (`if ((x = y))`) documents the intent and is accepted
    /// (sic.md §"Assignment and equals"). `wrapped` says whether the condition
    /// text began with `(`, i.e. the assignment is parenthesised.
    fn reject_bare_assign_cond(&self, cond: &Expr, wrapped: bool) -> Result<()> {
        if self.lang == Lang::Sic && !wrapped
            && matches!(cond.kind, ExprKind::Assign { .. })
        {
            return Err(CompileError::at(
                "assignment used directly as a condition is ambiguous with `==`; \
                 wrap it in an extra pair of parentheses, e.g. `if ((x = y))`"
                    .to_string(),
                cond.span.file.clone(), cond.span.line, cond.span.col,
            ));
        }
        Ok(())
    }

    fn parse_if(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance(); // 'if'
        self.expect(TokenKind::LParen)?;
        // sic guarded unwrap `if (T v = Enum::VARIANT(inst)) { .. } else { .. }`
        // (sic.md §"Match"): a non-throwing unwrap. Desugars to a `match`.
        if self.lang == Lang::Sic && self.is_decl_start() {
            return self.parse_if_let(sp);
        }
        let wrapped = self.at(TokenKind::LParen);
        let cond = self.parse_expr()?;
        self.reject_bare_assign_cond(&cond, wrapped)?;
        self.expect(TokenKind::RParen)?;
        let then = Box::new(self.parse_stmt()?);
        // Dangling else: an unbraced inner `if` that carries its own `else` is
        // ambiguous to read; require braces (sic.md §"Dangling else").
        if self.lang == Lang::Sic {
            if let Stmt::If { else_: Some(_), .. } = then.as_ref() {
                return Err(CompileError::at(
                    "ambiguous dangling `else`: put braces around the inner `if`"
                        .to_string(),
                    sp.file.clone(), sp.line, sp.col,
                ));
            }
        }
        let else_ = if self.eat(TokenKind::Else) { Some(Box::new(self.parse_stmt()?)) } else { None };
        Ok(Stmt::If { cond, then, else_, span: sp })
    }

    /// sic `if (T name = Enum::VARIANT(inst)) then [else]` — a non-throwing enum
    /// unwrap that binds `name` to the payload in the `then` branch when `inst` is
    /// that variant (sic.md §"Match"). Desugared to an equivalent `match`: the
    /// declared type is syntactic (the payload type is authoritative).
    fn parse_if_let(&mut self, sp: Span) -> Result<Stmt> {
        let (base, _) = self.parse_decl_specifiers()?;
        let (name, _ty) = self.parse_declarator(base)?;
        self.expect(TokenKind::Eq)?;
        let init = self.parse_assign_expr()?;
        self.expect(TokenKind::RParen)?;

        // The initializer must be an enum unwrap `Enum::Variant(value)`.
        let (variant, inst) = match &init.kind {
            ExprKind::Call { func, args }
                if args.len() == 1 && matches!(&func.kind, ExprKind::EnumVariant { .. }) =>
            {
                let ExprKind::EnumVariant { variant, .. } = &func.kind else { unreachable!() };
                (variant.clone(), args[0].clone())
            }
            _ => return Err(CompileError::at(
                "sic `if (T v = ...)` requires an enum unwrap `Enum::Variant(value)`".to_string(),
                sp.file.clone(), sp.line, sp.col)),
        };

        let then = Box::new(self.parse_stmt()?);
        let else_body = if self.eat(TokenKind::Else) {
            Box::new(self.parse_stmt()?)
        } else {
            // No `else`: a non-matching variant is simply skipped (no abort).
            Box::new(Stmt::Null(sp.clone()))
        };
        let arms = vec![
            MatchArm { variant: Some(variant), binding: Some(name), body: then, span: sp.clone() },
            MatchArm { variant: None, binding: None, body: else_body, span: sp.clone() },
        ];
        Ok(Stmt::Match { scrutinee: inst, arms, span: sp })
    }

    fn parse_while(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        self.expect(TokenKind::LParen)?;
        let wrapped = self.at(TokenKind::LParen);
        let cond = self.parse_expr()?;
        self.reject_bare_assign_cond(&cond, wrapped)?;
        self.expect(TokenKind::RParen)?;
        let body = Box::new(self.parse_stmt()?);
        Ok(Stmt::While { cond, body, span: sp })
    }

    fn parse_do_while(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance(); // 'do'
        let body = Box::new(self.parse_stmt()?);
        self.expect(TokenKind::While)?;
        self.expect(TokenKind::LParen)?;
        let wrapped = self.at(TokenKind::LParen);
        let cond = self.parse_expr()?;
        self.reject_bare_assign_cond(&cond, wrapped)?;
        self.expect(TokenKind::RParen)?;
        self.eat(TokenKind::Semi);
        Ok(Stmt::DoWhile { body, cond, span: sp })
    }

    fn parse_for(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance(); // 'for'
        self.expect(TokenKind::LParen)?;

        // sic range-`for` (sic.md §"Iterators"): `for (binding : iterable) body`.
        // Detect the colon form by trial-parsing a binding `T name` and checking for
        // `:`; on any mismatch, rewind to the classic three-clause `for`.
        if self.lang == Lang::Sic && self.is_decl_start() {
            let save = self.pos;
            if let Ok((ty, name)) = (|| -> Result<(QualType, String)> {
                let (base, _) = self.parse_decl_specifiers()?;
                let (name, ty) = self.parse_declarator(base)?;
                Ok((ty, name))
            })() {
                if self.at(TokenKind::Colon) {
                    self.advance(); // ':'
                    let iterable = self.parse_expr()?;
                    self.expect(TokenKind::RParen)?;
                    let body = Box::new(self.parse_stmt()?);
                    return Ok(Stmt::ForEach { ty, name, iterable, body, span: sp });
                }
            }
            self.pos = save;
        }

        let init = if self.at(TokenKind::Semi) {
            self.advance(); None
        } else if self.is_decl_start() {
            let d = self.parse_local_decl()?;
            Some(ForInit::Decl(d))
        } else {
            let e = self.parse_expr()?;
            self.eat(TokenKind::Semi);
            Some(ForInit::Expr(e))
        };

        let cond = if self.at(TokenKind::Semi) {
            None
        } else {
            let wrapped = self.at(TokenKind::LParen);
            let c = self.parse_expr()?;
            self.reject_bare_assign_cond(&c, wrapped)?;
            Some(c)
        };
        self.eat(TokenKind::Semi);

        let post = if self.at(TokenKind::RParen) { None } else { Some(self.parse_expr()?) };
        self.expect(TokenKind::RParen)?;

        let body = Box::new(self.parse_stmt()?);
        Ok(Stmt::For { init, cond, post, body, span: sp })
    }

    fn parse_return(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        let val = if self.at(TokenKind::Semi) { None } else { Some(self.parse_expr()?) };
        self.eat(TokenKind::Semi);
        Ok(Stmt::Return(val, sp))
    }

    fn parse_goto(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        let name = self.expect_name()?;
        self.eat(TokenKind::Semi);
        Ok(Stmt::Goto(name, sp))
    }

    fn parse_switch(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        self.expect(TokenKind::LParen)?;
        let val = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        let body = Box::new(self.parse_stmt()?);
        // sic makes every case terminator mandatory (sic.md §"Switch - case").
        if self.lang == Lang::Sic {
            self.check_switch_terminators(&body)?;
        }
        Ok(Stmt::Switch { val, body, span: sp })
    }

    /// sic `match (e) { Variant(bind): stmt; _: stmt }` (sic.md §"Match"). An arm
    /// is `Pattern : Statement`; the pattern is a variant name with an optional
    /// `(binding)`, or `_` for the wildcard. Arms are not comma-separated.
    fn parse_match(&mut self) -> Result<Stmt> {
        let (scrutinee, arms, sp) = self.parse_match_common()?;
        Ok(Stmt::Match { scrutinee, arms, span: sp })
    }

    /// Parse `match (scrut) { pattern: body; … }` — the shared shape of the
    /// statement and expression forms. Arm bodies are ordinary statements; in an
    /// expression `match` an arm's value is its trailing expression.
    fn parse_match_common(&mut self) -> Result<(Expr, Vec<MatchArm>, crate::lexer::Span)> {
        let sp = self.span();
        self.advance(); // 'match'
        self.expect(TokenKind::LParen)?;
        let scrutinee = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        self.expect(TokenKind::LBrace)?;
        let mut arms = Vec::new();
        while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
            let asp = self.span();
            // A match arm's pattern is either an enum variant name (`Some`) or, for
            // a `match (type(x))`, a type / kind category (`string`, `int`, `float`).
            // Type keywords lex as their own token, so accept them here too.
            let name = self.parse_match_pattern_name()?;
            // `_` is the wildcard (any remaining variant).
            let variant = if name == "_" { None } else { Some(name) };
            let binding = if variant.is_some() && self.eat(TokenKind::LParen) {
                let b = self.expect_name()?;
                self.expect(TokenKind::RParen)?;
                Some(b)
            } else {
                None
            };
            self.expect(TokenKind::Colon)?;
            let body = Box::new(self.parse_stmt()?);
            self.eat(TokenKind::Semi); // optional trailing `;` after a non-block arm
            arms.push(MatchArm { variant, binding, body, span: asp });
        }
        self.expect(TokenKind::RBrace)?;
        Ok((scrutinee, arms, sp))
    }

    /// sic requires every switch case to end explicitly with `break` or
    /// `fallthrough`; implicit fallthrough (or code after a terminator) is a
    /// compile error (sic.md §"Switch - case").
    fn check_switch_terminators(&self, body: &Stmt) -> Result<()> {
        // Flatten the switch body into a stream of case-label boundaries and the
        // plain statements that follow them, expanding nested labels
        // (`case 1: case 2:`) and goto-label bodies so each case's region is
        // a contiguous run of statements.
        enum Item<'a> { Label(&'a Span), Plain(&'a Stmt) }
        fn flatten<'a>(s: &'a Stmt, out: &mut Vec<Item<'a>>) {
            match s {
                Stmt::Case(_, b, sp) | Stmt::CaseRange(_, _, b, sp) | Stmt::Default(b, sp) => {
                    out.push(Item::Label(sp));
                    flatten(b, out);
                }
                Stmt::Label(_, b, _) => flatten(b, out),
                other => out.push(Item::Plain(other)),
            }
        }

        let mut stream = Vec::new();
        match body {
            Stmt::Block(ss, _) => for s in ss { flatten(s, &mut stream); },
            other => flatten(other, &mut stream),
        }

        // Split the stream into per-case regions and validate each one.
        let mut i = 0;
        while i < stream.len() && !matches!(stream[i], Item::Label(_)) { i += 1; }
        while i < stream.len() {
            let label_span = match &stream[i] { Item::Label(sp) => *sp, _ => unreachable!() };
            i += 1;
            let start = i;
            while i < stream.len() && !matches!(stream[i], Item::Label(_)) { i += 1; }
            let region: Vec<&Stmt> = stream[start..i].iter()
                .filter_map(|it| if let Item::Plain(s) = it { Some(*s) } else { None })
                .collect();

            let err = |msg: &str| CompileError::at(
                msg.to_string(), label_span.file.clone(), label_span.line, label_span.col,
            );
            let last = match region.last() {
                None => return Err(err("empty case: end it with `break` or `fallthrough`")),
                Some(s) => *s,
            };
            if !stmt_terminates_case(last) {
                return Err(err("case must end with `break` or `fallthrough`"));
            }
            for s in &region[..region.len() - 1] {
                if matches!(s, Stmt::Break(_) | Stmt::Fallthrough(_)) {
                    return Err(err("no code is allowed after `break` or `fallthrough`"));
                }
            }
        }
        Ok(())
    }

    fn parse_label(&mut self) -> Result<Stmt> {
        let sp = self.span();
        let name = self.advance().text.clone();
        self.advance(); // ':'
        let stmt = Box::new(self.parse_stmt()?);
        Ok(Stmt::Label(name, stmt, sp))
    }

    fn parse_case(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        let val = self.parse_assign_expr()?;
        // GCC case-range extension: `case LOW ... HIGH:`.
        if self.eat(TokenKind::Ellipsis) {
            let high = self.parse_assign_expr()?;
            self.expect(TokenKind::Colon)?;
            let body = Box::new(self.parse_stmt()?);
            return Ok(Stmt::CaseRange(val, high, body, sp));
        }
        self.expect(TokenKind::Colon)?;
        let body = Box::new(self.parse_stmt()?);
        Ok(Stmt::Case(val, body, sp))
    }

    fn parse_default(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        self.expect(TokenKind::Colon)?;
        let body = Box::new(self.parse_stmt()?);
        Ok(Stmt::Default(body, sp))
    }

    fn parse_local_decl(&mut self) -> Result<Decl> {
        let sp = self.span();
        let (base_ty, storage) = self.parse_decl_specifiers()?;

        if let Some(StorageClass::Typedef) = storage {
            return self.parse_typedef(base_ty, sp);
        }

        if self.at(TokenKind::Semi) {
            self.advance();
            return Ok(Decl::Var { base_ty, declarators: vec![], weak: false, thread_local: false, span: sp });
        }

        // `g_autoptr(T)`/`QEMU_LOCK_GUARD` put `__attribute__((cleanup(fn)))` in
        // the leading specifiers; it was captured by `parse_decl_specifiers` and
        // applies to the first declarator.
        let spec_cleanup = self.pending_cleanup.take();
        let mut declarators = Vec::new();
        let mut first = true;
        loop {
            let dsp = self.span();
            self.pending_vector_size = None;
            self.pending_cleanup = None;
            let (name, mut ty) = self.parse_declarator(base_ty.clone())?;
            // Trailing `__asm__`/`__attribute__` before the initializer, e.g.
            // glib g_autoptr / QEMU RCU_READ_LOCK_GUARD cleanup locals.
            self.skip_decl_tail();
            if let Some(n) = self.pending_vector_size.take() { ty = self.apply_vector_size(ty, n); }
            let cleanup = self.pending_cleanup.take()
                .or_else(|| if first { spec_cleanup.clone() } else { None });
            first = false;
            if !name.is_empty() { self.func_vars.insert(name.clone()); }
            let init = if self.eat(TokenKind::Eq) { Some(self.parse_initializer()?) } else { None };
            // sic rejects an empty-bracket array declaration like `char test[];`
            // — the size must come from a bound or an initializer (sic.md
            // §"Empty brackets pointer"). `extern` decls (unknown-bound arrays)
            // and function parameters (parsed elsewhere) are unaffected.
            if self.lang == Lang::Sic && init.is_none()
                && !matches!(storage, Some(StorageClass::Extern))
                && matches!(ty.ty, AstType::Array { size: None, .. })
            {
                return Err(CompileError::at(
                    format!("array `{}` has no size; give it a bound or an initializer", name),
                    dsp.file.clone(), dsp.line, dsp.col,
                ));
            }
            if !name.is_empty() {
                declarators.push(Declarator { name, ty, init, cleanup, span: dsp });
            }
            if !self.eat(TokenKind::Comma) { break; }
        }
        self.eat(TokenKind::Semi);
        Ok(Decl::Var { base_ty, declarators, weak: false, thread_local: false, span: sp })
    }

    // ─── Expressions ──────────────────────────────────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_assign_expr()?;
        while self.at(TokenKind::Comma) {
            self.advance();
            let rhs = self.parse_assign_expr()?;
            e = Expr::new(ExprKind::Comma(Box::new(e), Box::new(rhs)), sp.clone());
        }
        Ok(e)
    }

    fn parse_assign_expr(&mut self) -> Result<Expr> {
        let sp = self.span();
        let lhs = self.parse_ternary()?;

        // SIC swap operator `a <> b` (sic.md §"Swap"): exchange two lvalues.
        // Right-associative like assignment, and only recognised in sic mode.
        if self.peek_kind() == TokenKind::Swap {
            self.advance();
            let rhs = self.parse_assign_expr()?;
            return Ok(Expr::new(ExprKind::Swap { lhs: Box::new(lhs), rhs: Box::new(rhs) }, sp));
        }

        let op = match self.peek_kind() {
            TokenKind::Eq           => { self.advance(); None }
            TokenKind::PlusAssign   => { self.advance(); Some(BinOpKind::Add) }
            TokenKind::MinusAssign  => { self.advance(); Some(BinOpKind::Sub) }
            TokenKind::StarAssign   => { self.advance(); Some(BinOpKind::Mul) }
            TokenKind::SlashAssign  => { self.advance(); Some(BinOpKind::Div) }
            TokenKind::PercentAssign => { self.advance(); Some(BinOpKind::Rem) }
            TokenKind::ShlAssign    => { self.advance(); Some(BinOpKind::Shl) }
            TokenKind::ShrAssign    => { self.advance(); Some(BinOpKind::Shr) }
            TokenKind::AndAssign    => { self.advance(); Some(BinOpKind::BitAnd) }
            TokenKind::OrAssign     => { self.advance(); Some(BinOpKind::BitOr) }
            TokenKind::XorAssign    => { self.advance(); Some(BinOpKind::BitXor) }
            _ => return Ok(lhs),
        };

        let rhs = self.parse_assign_expr()?;
        Ok(Expr::new(ExprKind::Assign { op, lhs: Box::new(lhs), rhs: Box::new(rhs) }, sp))
    }

    fn parse_ternary(&mut self) -> Result<Expr> {
        let sp = self.span();
        let cond = self.parse_logor()?;
        if self.eat(TokenKind::Question) {
            // GNU `a ?: b`: omitted middle operand — the value is the condition.
            if self.eat(TokenKind::Colon) {
                let else_ = self.parse_assign_expr()?;
                return Ok(Expr::new(ExprKind::Elvis {
                    cond: Box::new(cond), else_: Box::new(else_),
                }, sp));
            }
            let then = self.parse_expr()?;
            self.expect(TokenKind::Colon)?;
            let else_ = self.parse_assign_expr()?;
            Ok(Expr::new(ExprKind::Ternary {
                cond: Box::new(cond), then: Box::new(then), else_: Box::new(else_),
            }, sp))
        } else {
            Ok(cond)
        }
    }

    fn parse_logor(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_logand()?;
        while self.at(TokenKind::PipePipe) {
            self.advance();
            let r = self.parse_logand()?;
            e = Expr::new(ExprKind::BinOp { op: BinOpKind::LogOr, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_logand(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_bitor()?;
        while self.at(TokenKind::AmpAmp) {
            self.advance();
            let r = self.parse_bitor()?;
            e = Expr::new(ExprKind::BinOp { op: BinOpKind::LogAnd, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_bitor(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_bitxor()?;
        while self.at(TokenKind::Pipe) {
            self.advance();
            let r = self.parse_bitxor()?;
            e = Expr::new(ExprKind::BinOp { op: BinOpKind::BitOr, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_bitxor(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_bitand()?;
        while self.at(TokenKind::Caret) {
            self.advance();
            let r = self.parse_bitand()?;
            e = Expr::new(ExprKind::BinOp { op: BinOpKind::BitXor, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_bitand(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_equality()?;
        while self.at(TokenKind::Amp) {
            self.advance();
            let r = self.parse_equality()?;
            e = Expr::new(ExprKind::BinOp { op: BinOpKind::BitAnd, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_equality(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_relational()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::EqEq  => BinOpKind::Eq,
                TokenKind::BangEq => BinOpKind::Ne,
                _ => break,
            };
            self.advance();
            let r = self.parse_relational()?;
            e = Expr::new(ExprKind::BinOp { op, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_relational(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_shift()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::Lt   => BinOpKind::Lt,
                TokenKind::Gt   => BinOpKind::Gt,
                TokenKind::LtEq => BinOpKind::Le,
                TokenKind::GtEq => BinOpKind::Ge,
                _ => break,
            };
            self.advance();
            let r = self.parse_shift()?;
            e = Expr::new(ExprKind::BinOp { op, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_shift(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_additive()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::Shl => BinOpKind::Shl,
                TokenKind::Shr => BinOpKind::Shr,
                TokenKind::RotL => BinOpKind::RotL,
                TokenKind::RotR => BinOpKind::RotR,
                _ => break,
            };
            self.advance();
            let r = self.parse_additive()?;
            e = Expr::new(ExprKind::BinOp { op, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_additive(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_multiplicative()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::Plus  => BinOpKind::Add,
                TokenKind::Minus => BinOpKind::Sub,
                _ => break,
            };
            self.advance();
            let r = self.parse_multiplicative()?;
            e = Expr::new(ExprKind::BinOp { op, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr> {
        let sp = self.span();
        let mut e = self.parse_cast()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::Star    => BinOpKind::Mul,
                TokenKind::Slash   => BinOpKind::Div,
                TokenKind::Percent => BinOpKind::Rem,
                _ => break,
            };
            self.advance();
            let r = self.parse_cast()?;
            e = Expr::new(ExprKind::BinOp { op, lhs: Box::new(e), rhs: Box::new(r) }, sp.clone());
        }
        Ok(e)
    }

    fn parse_cast(&mut self) -> Result<Expr> {
        // `(type) expr` or `(type){ init }` (compound literal)
        if self.at(TokenKind::LParen) && self.is_cast() {
            let sp = self.span();
            self.advance(); // (
            self.pending_vector_size = None;
            let (ty, _) = self.parse_decl_specifiers()?;
            let (_, mut ty) = self.parse_declarator(ty)?;
            // `(__attribute__((vector_size(N))) T){...}` — apply a captured vector size.
            if let Some(n) = self.pending_vector_size.take() { ty = self.apply_vector_size(ty, n); }
            self.expect(TokenKind::RParen)?;
            if self.at(TokenKind::LBrace) {
                // Compound literal: (type){ initializer-list }. Reuse the normal
                // brace-initializer parser so designated initializers (`.field =`
                // / `[i] =`) are accepted the same way they are in declarations.
                let init = self.parse_initializer()?;
                let inits = match init {
                    Initializer::List(v) => v,
                    other => vec![InitItem { designators: vec![], init: other }],
                };
                let mut e = Expr::new(ExprKind::CompoundLiteral { ty, init: inits }, sp.clone());
                e = self.parse_postfix_ops(e)?;
                return Ok(e);
            }
            let expr = self.parse_cast()?;
            return Ok(Expr::new(ExprKind::Cast { ty, expr: Box::new(expr) }, sp));
        }
        self.parse_unary()
    }

    fn is_cast(&self) -> bool {
        // Look ahead: `( type-specifier ...`
        if self.pos + 1 >= self.tokens.len() { return false; }
        let tok = &self.tokens[self.pos + 1];
        // Keyword type-specifiers (and a leading `__attribute__`, e.g. the
        // `(__attribute__((vector_size(16))) int){...}` compound literals in
        // <xmmintrin.h>) unambiguously begin a type.
        if matches!(tok.kind,
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Struct | TokenKind::Union
            | TokenKind::Enum | TokenKind::Const | TokenKind::Volatile
            | TokenKind::Typeof | TokenKind::Alignas | TokenKind::Attribute)
        {
            return true;
        }
        let is_typename = tok.kind == TokenKind::TypeName
            || (tok.kind == TokenKind::Ident && self.typedefs.contains(tok.text.as_str()));
        if !is_typename {
            return false;
        }
        // A parameter or local of the same name shadows the typedef, so `(name)`
        // is a parenthesized variable, not a cast (`(vaddr) & MASK` is an AND).
        // Only in C mode: in sic-lang the aliases are reserved and cannot shadow.
        if self.lang == Lang::C && self.func_vars.contains(tok.text.as_str()) {
            return false;
        }
        // A `TypeName` is ambiguous with a variable of the same name. In C this
        // is common — code often shadows a typedef (`vaddr`, `entry`, …) with a
        // local — so treat `(T …)` as a cast only when the type is followed by a
        // token that continues/closes a type-name (`)`, `*`, `[`, `(`, or a
        // qualifier), not a binary operator (`(vaddr | x)` is OR, not a cast).
        // In sic-lang the aliases are reserved types, so stay strict there.
        if self.lang == Lang::Sic {
            return true;
        }
        match self.tokens.get(self.pos + 2) {
            Some(t2) => matches!(t2.kind,
                TokenKind::RParen | TokenKind::Star | TokenKind::LBracket | TokenKind::LParen
                | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict),
            None => true,
        }
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        let sp = self.span();
        match self.peek_kind() {
            TokenKind::PlusPlus => {
                self.advance();
                let e = self.parse_unary()?;
                Ok(Expr::new(ExprKind::PreInc { inc: true, expr: Box::new(e) }, sp))
            }
            TokenKind::MinusMinus => {
                self.advance();
                let e = self.parse_unary()?;
                Ok(Expr::new(ExprKind::PreInc { inc: false, expr: Box::new(e) }, sp))
            }
            TokenKind::Amp => {
                self.advance();
                let e = self.parse_cast()?;
                Ok(Expr::new(ExprKind::Unary { op: UnOpKind::Addr, expr: Box::new(e) }, sp))
            }
            TokenKind::Star => {
                self.advance();
                let e = self.parse_cast()?;
                Ok(Expr::new(ExprKind::Unary { op: UnOpKind::Deref, expr: Box::new(e) }, sp))
            }
            TokenKind::Plus => {
                self.advance();
                // unary plus: no-op, just return inner
                self.parse_cast()
            }
            TokenKind::Minus => {
                self.advance();
                let e = self.parse_cast()?;
                Ok(Expr::new(ExprKind::Unary { op: UnOpKind::Neg, expr: Box::new(e) }, sp))
            }
            TokenKind::Bang => {
                self.advance();
                let e = self.parse_cast()?;
                Ok(Expr::new(ExprKind::Unary { op: UnOpKind::Not, expr: Box::new(e) }, sp))
            }
            TokenKind::Tilde => {
                self.advance();
                let e = self.parse_cast()?;
                Ok(Expr::new(ExprKind::Unary { op: UnOpKind::BitNot, expr: Box::new(e) }, sp))
            }
            // sic `@expr` / `@mut expr` — form a scoped reference (sic.md §"References").
            TokenKind::At => {
                self.advance();
                let mutable = self.eat_contextual_mut();
                let e = self.parse_cast()?;
                Ok(Expr::new(ExprKind::Ref { mutable, expr: Box::new(e) }, sp))
            }
            // sic `new T` / `new T(count)` (sic.md §"Scopes and automatic release").
            // sic `match` as an expression (sic.md §"Match"): `x = match (s) { … }`.
            TokenKind::Match if self.lang == Lang::Sic => {
                let (scrutinee, arms, sp) = self.parse_match_common()?;
                Ok(Expr::new(ExprKind::Match { scrutinee: Box::new(scrutinee), arms }, sp))
            }
            TokenKind::New => {
                self.advance();
                let (mut ty, _storage) = self.parse_decl_specifiers()?;
                // Pointer suffixes (`new char*`); qualifiers after `*` are ignored.
                while self.eat(TokenKind::Star) {
                    while matches!(self.peek_kind(),
                        TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict) {
                        self.advance();
                    }
                    ty = QualType::new(AstType::Pointer { base: Box::new(ty), quals: vec![] });
                }
                // Optional `(…)`: an element count `(n)`, constructor arguments, or
                // empty `()`. Parsed as a comma-separated list; the meaning is
                // resolved at lowering from whether `T` has a constructor.
                let args = if self.eat(TokenKind::LParen) {
                    let mut args = Vec::new();
                    while !self.at(TokenKind::RParen) && !self.at(TokenKind::Eof) {
                        args.push(self.parse_assign_expr()?);
                        if !self.eat(TokenKind::Comma) { break; }
                    }
                    self.expect(TokenKind::RParen)?;
                    args
                } else {
                    Vec::new()
                };
                Ok(Expr::new(ExprKind::New { ty, args }, sp))
            }
            TokenKind::Sizeof => {
                self.advance();
                if self.at(TokenKind::LParen) && self.is_cast() {
                    self.advance();
                    let (ty, _) = self.parse_decl_specifiers()?;
                    let (_, ty) = self.parse_declarator(ty)?;
                    self.expect(TokenKind::RParen)?;
                    Ok(Expr::new(ExprKind::SizeofType(ty), sp))
                } else {
                    let e = self.parse_unary()?;
                    Ok(Expr::new(ExprKind::SizeofExpr(Box::new(e)), sp))
                }
            }
            TokenKind::Generic => {
                // C11 `_Generic(controlling, T1: e1, ..., default: eN)`.
                self.advance();
                self.expect(TokenKind::LParen)?;
                let controlling = Box::new(self.parse_assign_expr()?);
                let mut assocs = Vec::new();
                while self.eat(TokenKind::Comma) {
                    let ty = if self.eat(TokenKind::Default) {
                        None
                    } else {
                        let (base, _) = self.parse_decl_specifiers()?;
                        let (_, qt) = self.parse_declarator(base)?;
                        Some(qt)
                    };
                    self.expect(TokenKind::Colon)?;
                    let e = Box::new(self.parse_assign_expr()?);
                    assocs.push((ty, e));
                }
                self.expect(TokenKind::RParen)?;
                // A `_Generic(...)` selection is a primary expression and can be
                // followed by postfix operators — most importantly a call, as in
                // `_Generic(x, int: f, long: g)(x)` (QEMU's bswap macros).
                let e = Expr::new(ExprKind::Generic { controlling, assocs }, sp);
                self.parse_postfix_ops(e)
            }
            // GCC `__extension__` is a transparent prefix in expression context
            // too (e.g. `__extension__ ({ ... })` statement expressions in glib
            // macros). Skip it and parse the operand.
            TokenKind::Extension => {
                self.advance();
                // Parse at the cast level so `__extension__ (T)(V){...}` (glibc
                // SIMD intrinsic bodies) handles the leading cast / compound literal.
                self.parse_cast()
            }
            _ => self.parse_postfix()
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr> {
        let sp = self.span();

        // Compound literal: (Type){ ... }
        if self.at(TokenKind::LParen) && self.is_cast() {
            // Could be compound literal or cast
            let save = self.pos;
            self.advance(); // (
            if let Ok((ty, _)) = self.parse_decl_specifiers() {
                if let Ok((_, ty)) = self.parse_declarator(ty) {
                    if self.eat(TokenKind::RParen) && self.at(TokenKind::LBrace) {
                        // Compound literal — parse the brace body as an
                        // initializer (handles designators).
                        let init = self.parse_initializer()?;
                        let inits = match init {
                            Initializer::List(v) => v,
                            other => vec![InitItem { designators: vec![], init: other }],
                        };
                        let mut e = Expr::new(ExprKind::CompoundLiteral { ty, init: inits }, sp.clone());
                        e = self.parse_postfix_ops(e)?;
                        return Ok(e);
                    }
                }
            }
            // Not a compound literal — backtrack
            self.pos = save;
        }

        let mut e = self.parse_primary()?;
        e = self.parse_postfix_ops(e)?;
        Ok(e)
    }

    fn parse_postfix_ops(&mut self, mut e: Expr) -> Result<Expr> {
        let sp = self.span();
        loop {
            match self.peek_kind() {
                TokenKind::LBracket => {
                    self.advance();
                    // sic substring slice `base[lo:hi]` with optional bounds
                    // (sic.md §"Built-in string"). A leading `:` means no `lo`.
                    let lo = if self.lang == Lang::Sic && self.at(TokenKind::Colon) {
                        None
                    } else {
                        Some(Box::new(self.parse_expr()?))
                    };
                    if self.lang == Lang::Sic && self.eat(TokenKind::Colon) {
                        let hi = if self.at(TokenKind::RBracket) { None } else { Some(Box::new(self.parse_expr()?)) };
                        self.expect(TokenKind::RBracket)?;
                        e = Expr::new(ExprKind::Slice { base: Box::new(e), lo, hi }, sp.clone());
                    } else {
                        self.expect(TokenKind::RBracket)?;
                        e = Expr::new(ExprKind::Index { base: Box::new(e), index: lo.unwrap() }, sp.clone());
                    }
                }
                TokenKind::LParen => {
                    self.advance();
                    let mut args = Vec::new();
                    while !self.at(TokenKind::RParen) && !self.at(TokenKind::Eof) {
                        args.push(self.parse_assign_expr()?);
                        if !self.eat(TokenKind::Comma) { break; }
                    }
                    self.expect(TokenKind::RParen)?;
                    e = Expr::new(ExprKind::Call { func: Box::new(e), args }, sp.clone());
                }
                // sic none/null-safe access `base?.field` (sic.md §"Match"): if
                // `base` is a present Option/Result or a non-null pointer, the
                // field; else a zero value. Chains (`a?.b?.c`) via zero-propagation
                // and pairs with `?:`. Only `? .` (question immediately before dot).
                TokenKind::Question if self.lang == Lang::Sic
                    && self.tokens.get(self.pos + 1).map(|t| t.kind) == Some(TokenKind::Dot) =>
                {
                    self.advance(); // `?`
                    self.advance(); // `.`
                    let name = self.advance().text.clone();
                    e = Expr::new(ExprKind::OptField { base: Box::new(e), name }, sp.clone());
                }
                TokenKind::Dot => {
                    self.advance();
                    let name = self.advance().text.clone();
                    e = Expr::new(ExprKind::Field { base: Box::new(e), name }, sp.clone());
                }
                TokenKind::Arrow => {
                    self.advance();
                    let name = self.advance().text.clone();
                    e = Expr::new(ExprKind::Arrow { base: Box::new(e), name }, sp.clone());
                }
                TokenKind::PlusPlus => {
                    self.advance();
                    e = Expr::new(ExprKind::PostInc { inc: true, expr: Box::new(e) }, sp.clone());
                }
                TokenKind::MinusMinus => {
                    self.advance();
                    e = Expr::new(ExprKind::PostInc { inc: false, expr: Box::new(e) }, sp.clone());
                }
                _ => break,
            }
        }
        Ok(e)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        let sp = self.span();
        // sic RTTI (sic.md §"RTTI"): a bare type name in value position is its
        // `type` value, so `type(x) == i64` and `switch (type(x)) { case string: }`
        // work. Gated to primitive-type keywords + sic type-name aliases (`i64`,
        // `string`, `fixed<…>`, …) — NOT typedef identifiers — so `foo * bar`
        // (a typedef times a var) is still a multiply, not a pointer type.
        if self.at_type_value_start() {
            let (ty, _) = self.parse_decl_specifiers()?;
            let (_, ty) = self.parse_declarator(ty)?;
            return Ok(Expr::new(ExprKind::TypeIdOf(ty), sp));
        }
        match self.peek_kind() {
            TokenKind::Nullptr => {
                self.advance();
                Ok(Expr::new(ExprKind::Nullptr, sp))
            }
            // sic tuple pack/unpack `tuple(e0, e1, …)` (sic.md §"Tuples").
            TokenKind::Tuple => {
                self.advance();
                self.expect(TokenKind::LParen)?;
                let mut elems = Vec::new();
                while !self.at(TokenKind::RParen) && !self.at(TokenKind::Eof) {
                    elems.push(self.parse_assign_expr()?);
                    if !self.eat(TokenKind::Comma) { break; }
                }
                self.expect(TokenKind::RParen)?;
                Ok(Expr::new(ExprKind::TupleExpr(elems), sp))
            }
            TokenKind::IntLit => {
                let text = self.advance().text.clone();
                // sic `bigint` (sic.md §"Integer sizes"): a plain decimal literal
                // that overflows `u64` becomes a `BigIntLit` carrying its digits,
                // so nothing is lost before it reaches a bigint context.
                if self.lang == Lang::Sic {
                    let digits = text.trim_end_matches(|c| matches!(c, 'u'|'U'|'l'|'L'));
                    let is_plain_decimal = digits.bytes().all(|b| b.is_ascii_digit())
                        && !digits.starts_with('0'); // not hex/oct/binary, not a leading-zero form
                    if is_plain_decimal && digits.parse::<u64>().is_err() {
                        return Ok(Expr::new(ExprKind::BigIntLit(digits.to_string()), sp));
                    }
                }
                let (val, is_u, is_64) = parse_int_literal(&text);
                let kind = if is_u { ExprKind::UIntLit(val as u64, is_64) } else { ExprKind::IntLit(val, is_64) };
                Ok(Expr::new(kind, sp))
            }
            TokenKind::FloatLit => {
                let text = self.advance().text.clone();
                // sic: keep a PLAIN decimal-point literal (no exponent, no hex, no
                // suffix) as its exact text so a `fixed` binding can build it
                // precisely (sic.md §"Built-in fixed point"); it still acts as a
                // `double` in any float context. Suffixed/exponent/hex floats stay
                // ordinary `FloatLit`.
                if self.lang == Lang::Sic {
                    let plain = text.contains('.')
                        && text.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                        && text.bytes().filter(|&b| b == b'.').count() == 1;
                    if plain {
                        return Ok(Expr::new(ExprKind::DecimalLit(text), sp));
                    }
                }
                let body = strip_float_suffix(&text);
                let v = parse_c_float(body);
                Ok(Expr::new(ExprKind::FloatLit(v), sp))
            }
            TokenKind::StringLit => {
                let mut s = self.advance().text.clone();
                // Concatenate adjacent string literals. The token text holds raw
                // C-string bytes and may be invalid UTF-8, so append at the byte
                // level rather than via `&str`.
                while self.at(TokenKind::StringLit) {
                    let next = self.advance().text.as_bytes().to_vec();
                    unsafe { s.as_mut_vec().extend_from_slice(&next); }
                }
                Ok(Expr::new(ExprKind::StringLit(s), sp))
            }
            TokenKind::CharLit => {
                let text = self.advance().text.clone();
                let v: i32 = text.parse().unwrap_or(0);
                Ok(Expr::new(ExprKind::CharLit(v), sp))
            }
            TokenKind::BoolLit => {
                // sic `true`/`false` — lexed as text "1"/"0", typed `bool`.
                let text = self.advance().text.clone();
                Ok(Expr::new(ExprKind::BoolLit(text == "1"), sp))
            }
            TokenKind::Ident => {
                let name = self.advance().text.clone();
                // Handle va builtins
                match name.as_str() {
                    "__builtin_va_start"     => return self.parse_va_builtin_start(sp),
                    "__builtin_c23_va_start" => return self.parse_va_builtin_c23_start(sp),
                    "__builtin_va_arg"       => return self.parse_va_builtin_arg(sp),
                    "__builtin_va_end"       => return self.parse_va_builtin_end(sp),
                    "__builtin_va_copy"      => return self.parse_va_builtin_copy(sp),
                    "__builtin_offsetof"     => return self.parse_offsetof(sp),
                    "__alignof__" | "__alignof" | "_Alignof"
                                             => return self.parse_alignof(sp),
                    "__builtin_choose_expr"  => return self.parse_choose_expr(sp),
                    "__builtin_types_compatible_p"
                                             => return self.parse_types_compatible(sp),
                    // sic RTTI (sic.md §"RTTI"): `typeid(x)` / `type(x)` → a `type`
                    // value. The argument may be a type (`typeid(int)`) or an
                    // expression (`type(x)`), like `sizeof`.
                    "typeid" | "type" if self.lang == Lang::Sic && self.at(TokenKind::LParen) => {
                        self.advance(); // consume `(`
                        let node = if self.starts_decl_specifier() {
                            let (ty, _) = self.parse_decl_specifiers()?;
                            let (_, ty) = self.parse_declarator(ty)?;
                            ExprKind::TypeIdOf(ty)
                        } else {
                            let e = self.parse_assign_expr()?;
                            ExprKind::TypeId(Box::new(e))
                        };
                        self.expect(TokenKind::RParen)?;
                        return Ok(Expr::new(node, sp));
                    }
                    // sic exception-guard blocks (sic.md §"Integer overflow",
                    // §"Errors and exceptions") — contextual: `<kw> { … }` only when
                    // immediately followed by `{`; else an ordinary identifier.
                    "overflow" | "divide_by_zero" | "exception"
                        if self.lang == Lang::Sic && self.at(TokenKind::LBrace) =>
                    {
                        let kind = match name.as_str() {
                            "overflow" => GuardKind::Overflow,
                            "divide_by_zero" => GuardKind::DivZero,
                            _ => GuardKind::Exception,
                        };
                        let body = self.parse_compound_stmt_as_stmts()?;
                        return Ok(Expr::new(ExprKind::Guard { kind, body }, sp));
                    }
                    _ => {}
                }
                // sic scope path `A::B::…::member` (sic.md §"Match", §"Namespace").
                if self.at(TokenKind::ColonColon) {
                    return self.parse_scope_path(name, sp);
                }
                Ok(Expr::new(ExprKind::Ident(name), sp))
            }
            TokenKind::TypeName => {
                // typedef name used as an expression (shouldn't be common, but handle gracefully)
                let name = self.advance().text.clone();
                // sic scope path where the first segment is a type name.
                if self.at(TokenKind::ColonColon) {
                    return self.parse_scope_path(name, sp);
                }
                Ok(Expr::new(ExprKind::Ident(name), sp))
            }
            TokenKind::LParen => {
                self.advance();
                // GCC statement expression: ({ stmts... })
                if self.at(TokenKind::LBrace) {
                    let stmts = self.parse_compound_stmt_as_stmts()?;
                    self.expect(TokenKind::RParen)?;
                    return Ok(Expr::new(ExprKind::StmtExpr(stmts), sp));
                }
                let e = self.parse_expr()?;
                self.expect(TokenKind::RParen)?;
                Ok(e)
            }
            _ => {
                let t = self.peek().clone();
                Err(CompileError::at(
                    format!("unexpected token {:?} '{}' in expression", t.kind, t.text),
                    t.span.file, t.span.line, t.span.col,
                ))
            }
        }
    }

    /// `__builtin_offsetof(type-name, member-designator)` where the designator
    /// is `identifier ( .identifier | [ expr ] )*`.
    /// `__builtin_choose_expr(const_cond, then_expr, else_expr)`.
    fn parse_choose_expr(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let cond = Box::new(self.parse_assign_expr()?);
        self.expect(TokenKind::Comma)?;
        let then = Box::new(self.parse_assign_expr()?);
        self.expect(TokenKind::Comma)?;
        let else_ = Box::new(self.parse_assign_expr()?);
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::ChooseExpr { cond, then, else_ }, sp))
    }

    /// `__builtin_types_compatible_p(type1, type2)`.
    fn parse_types_compatible(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let (b1, _) = self.parse_decl_specifiers()?;
        let (_, t1) = self.parse_declarator(b1)?;
        self.expect(TokenKind::Comma)?;
        let (b2, _) = self.parse_decl_specifiers()?;
        let (_, t2) = self.parse_declarator(b2)?;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::TypesCompatible(t1, t2), sp))
    }

    /// `__alignof__(type)` / `_Alignof(type)` / `__alignof__ expr`. The keyword
    /// has already been consumed.
    fn parse_alignof(&mut self, sp: Span) -> Result<Expr> {
        if self.at(TokenKind::LParen) && self.is_cast() {
            self.advance(); // (
            let (ty, _) = self.parse_decl_specifiers()?;
            let (_, ty) = self.parse_declarator(ty)?;
            self.expect(TokenKind::RParen)?;
            Ok(Expr::new(ExprKind::AlignofType(ty), sp))
        } else {
            let e = self.parse_unary()?;
            Ok(Expr::new(ExprKind::AlignofExpr(Box::new(e)), sp))
        }
    }

    fn parse_offsetof(&mut self, sp: Span) -> Result<Expr> {
        use crate::ast::OffsetDesignator;
        self.expect(TokenKind::LParen)?;
        let (base, _) = self.parse_decl_specifiers()?;
        let (_, ty) = self.parse_declarator(base)?;
        self.expect(TokenKind::Comma)?;
        let mut designators = Vec::new();
        // First member is a bare identifier.
        designators.push(OffsetDesignator::Field(self.expect_name()?));
        loop {
            if self.eat(TokenKind::Dot) {
                designators.push(OffsetDesignator::Field(self.expect_name()?));
            } else if self.eat(TokenKind::LBracket) {
                let idx = self.parse_assign_expr()?;
                self.expect(TokenKind::RBracket)?;
                designators.push(OffsetDesignator::Index(Box::new(idx)));
            } else {
                break;
            }
        }
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::OffsetOf { ty, designators }, sp))
    }

    fn parse_va_builtin_start(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let list = self.parse_assign_expr()?;
        self.expect(TokenKind::Comma)?;
        let last = self.parse_assign_expr()?;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::VaStart { list: Box::new(list), last: Box::new(last) }, sp))
    }

    /// C23 `__builtin_c23_va_start(ap, ...)`: the last named-parameter argument
    /// is optional (and, on this target, unused). Accept `(ap)` or `(ap, ...)`
    /// and discard any trailing arguments.
    fn parse_va_builtin_c23_start(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let list = self.parse_assign_expr()?;
        let mut last: Option<Expr> = None;
        while self.eat(TokenKind::Comma) {
            let e = self.parse_assign_expr()?;
            if last.is_none() { last = Some(e); }
        }
        self.expect(TokenKind::RParen)?;
        let last = last.unwrap_or_else(|| Expr::new(ExprKind::IntLit(0, false), sp.clone()));
        Ok(Expr::new(ExprKind::VaStart { list: Box::new(list), last: Box::new(last) }, sp))
    }

    fn parse_va_builtin_copy(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let dst = self.parse_assign_expr()?;
        self.expect(TokenKind::Comma)?;
        let src = self.parse_assign_expr()?;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::VaCopy { dst: Box::new(dst), src: Box::new(src) }, sp))
    }

    fn parse_va_builtin_arg(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let list = self.parse_assign_expr()?;
        self.expect(TokenKind::Comma)?;
        let (ty, _) = self.parse_decl_specifiers()?;
        let (_, ty) = self.parse_declarator(ty)?;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::VaArg { list: Box::new(list), ty }, sp))
    }

    fn parse_va_builtin_end(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let list = self.parse_assign_expr()?;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::VaEnd { list: Box::new(list) }, sp))
    }

    // ─── GCC extensions ───────────────────────────────────────────────────────

    fn skip_attributes(&mut self) {
        while self.at(TokenKind::Attribute) {
            self.advance();
            if self.at(TokenKind::LParen) {
                self.capture_vector_size();
                self.skip_balanced_parens();
            }
        }
    }

    /// Skip the tail that can follow a declarator before `;`/`=`/`{`/`,`: an
    /// `__asm__("label")` rename (glibc's `__REDIRECT`) and/or trailing
    /// `__attribute__((...))`, in any order. Needed now that `__attribute__` is
    /// no longer stripped by the preprocessor.
    fn skip_decl_tail(&mut self) {
        loop {
            if self.at(TokenKind::Attribute) {
                self.advance();
                if self.at(TokenKind::LParen) {
                    self.capture_vector_size();
                    self.skip_balanced_parens();
                }
            } else if self.at(TokenKind::Asm) {
                self.advance();
                if self.at(TokenKind::LParen) { self.skip_balanced_parens(); }
            } else {
                break;
            }
        }
    }

    /// Peek inside an attribute list (positioned at its opening `(`) for a
    /// `vector_size(N)` / `__vector_size__(N)` attribute and record `N` in
    /// `pending_vector_size`. Non-consuming.
    fn capture_vector_size(&mut self) {
        let mut i = self.pos;
        let mut depth = 0i32;
        while i < self.tokens.len() {
            match self.tokens[i].kind {
                TokenKind::LParen => depth += 1,
                TokenKind::RParen => { depth -= 1; if depth <= 0 { break; } }
                TokenKind::Ident => {
                    let name = self.tokens[i].text.as_str();
                    if name == "vector_size" || name == "__vector_size__" {
                        if matches!(self.tokens.get(i + 1).map(|t| t.kind), Some(TokenKind::LParen))
                            && matches!(self.tokens.get(i + 2).map(|t| t.kind), Some(TokenKind::IntLit))
                        {
                            if let Ok(n) = self.tokens[i + 2].text
                                .trim_end_matches(|c: char| c.is_ascii_alphabetic())
                                .parse::<u32>()
                            {
                                self.pending_vector_size = Some(n);
                            }
                        }
                    } else if name == "cleanup" || name == "__cleanup__" {
                        // `cleanup(fn)`: the following token inside the parens is
                        // the cleanup function's name (possibly parenthesized).
                        let mut j = i + 1;
                        while matches!(self.tokens.get(j).map(|t| t.kind), Some(TokenKind::LParen)) { j += 1; }
                        if let Some(t) = self.tokens.get(j) {
                            if t.kind == TokenKind::Ident {
                                self.pending_cleanup = Some(t.text.clone());
                            }
                        }
                    } else if name == "packed" || name == "__packed__" {
                        self.pending_packed = true;
                    } else if name == "order" || name == "__order__" {
                        self.pending_order = true;
                    } else if name == "aligned" || name == "__aligned__" {
                        // `aligned(EXPR)`: force alignment to the constant EXPR
                        // (e.g. `16`, `sizeof(void*)`, `2 * sizeof(void *)` as in
                        // QEMU_ALIGNED). Bare `aligned` (no argument) requests the
                        // target's max useful alignment; ignore that rare form.
                        if matches!(self.tokens.get(i + 1).map(|t| t.kind), Some(TokenKind::LParen)) {
                            if let Some(rp) = self.matching_rparen(i + 1) {
                                if let Some(n) = self.eval_align_tokens(i + 2, rp) {
                                    self.pending_aligned =
                                        Some(self.pending_aligned.unwrap_or(0).max(n));
                                }
                            }
                        }
                    } else if name == "weak" || name == "__weak__" {
                        self.pending_weak = true;
                    } else if name == "constructor" || name == "__constructor__" {
                        // Optional priority: `constructor(101)`. Default 65535
                        // (GCC's default, run after all prioritized constructors).
                        let prio = if matches!(self.tokens.get(i + 1).map(|t| t.kind), Some(TokenKind::LParen)) {
                            self.tokens.get(i + 2)
                                .and_then(|t| t.text.parse::<i32>().ok())
                                .unwrap_or(65535)
                        } else { 65535 };
                        self.pending_constructor = Some(prio);
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// Index of the `)` matching the `(` at `lparen_idx`, or None.
    fn matching_rparen(&self, lparen_idx: usize) -> Option<usize> {
        let mut depth = 0i32;
        let mut i = lparen_idx;
        while i < self.tokens.len() {
            match self.tokens[i].kind {
                TokenKind::LParen => depth += 1,
                TokenKind::RParen => { depth -= 1; if depth == 0 { return Some(i); } }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// Evaluate the constant expression in an `aligned(...)` argument over the
    /// token range `[lo, hi)`. Handles the forms that appear in alignment
    /// attributes: integer literals, `sizeof(...)` (taken as the 8-byte machine
    /// word — sic targets 64-bit), parentheses, and `<<`, `+`, `*`. Returns None
    /// for anything it doesn't understand (the attribute is then ignored, as
    /// before). Operators are handled at the outermost (depth-0) level, splitting
    /// at the last occurrence for left-associativity; precedence low→high is
    /// `<<`, `+`, `*`.
    fn eval_align_tokens(&self, lo: usize, hi: usize) -> Option<u32> {
        if lo >= hi { return None; }
        // Strip a fully-enclosing paren pair.
        if self.tokens[lo].kind == TokenKind::LParen
            && self.matching_rparen(lo) == Some(hi - 1)
        {
            return self.eval_align_tokens(lo + 1, hi - 1);
        }
        // Scan for a top-level (depth 0) split operator, lowest precedence first.
        for op in [TokenKind::Shl, TokenKind::Plus, TokenKind::Star] {
            let mut depth = 0i32;
            let mut split = None;
            for i in lo..hi {
                match self.tokens[i].kind {
                    TokenKind::LParen => depth += 1,
                    TokenKind::RParen => depth -= 1,
                    k if depth == 0 && k == op => split = Some(i), // last occurrence
                    _ => {}
                }
            }
            if let Some(s) = split {
                let l = self.eval_align_tokens(lo, s)?;
                let r = self.eval_align_tokens(s + 1, hi)?;
                return Some(match op {
                    TokenKind::Shl => l.wrapping_shl(r),
                    TokenKind::Plus => l.wrapping_add(r),
                    _ => l.wrapping_mul(r),
                });
            }
        }
        // Atom: a bare integer literal, or sizeof(...) as the machine word.
        if self.tokens[lo].kind == TokenKind::Sizeof {
            return Some(8);
        }
        if hi - lo == 1 && self.tokens[lo].kind == TokenKind::IntLit {
            return self.tokens[lo].text
                .trim_end_matches(|c: char| c.is_ascii_alphabetic())
                .parse::<u32>()
                .ok();
        }
        None
    }

    /// Wrap `ty` as a `vector_size(n)` vector: an array of `n / sizeof(elem)`
    /// elements (a sized aggregate, so `sizeof`/lane-indexing/`|`/`&` work).
    fn apply_vector_size(&self, ty: QualType, n: u32) -> QualType {
        let elem_sz = ast_type_byte_size(&ty.ty).max(1);
        let lanes = (n / elem_sz).max(1);
        let span = Span::default();
        let base = Box::new(ty);
        QualType::new(AstType::Array {
            base,
            size: Some(Box::new(Expr::new(ExprKind::IntLit(lanes as i64, false), span))),
        })
    }

    fn skip_balanced_parens(&mut self) {
        if !self.at(TokenKind::LParen) { return; }
        self.advance();
        let mut depth = 1usize;
        while depth > 0 && !self.at(TokenKind::Eof) {
            match self.peek_kind() {
                TokenKind::LParen => { depth += 1; self.advance(); }
                TokenKind::RParen => { depth -= 1; self.advance(); }
                _ => { self.advance(); }
            }
        }
    }

    fn parse_asm_skip(&mut self) -> Result<()> {
        self.advance(); // asm / __asm__
        if self.at(TokenKind::Volatile) { self.advance(); }
        if self.at(TokenKind::LParen) { self.skip_balanced_parens(); }
        self.eat(TokenKind::Semi);
        Ok(())
    }
}

// ─── Integer literal parsing ──────────────────────────────────────────────────

/// Parse an integer literal into `(value, is_unsigned, is_64bit)`. `is_unsigned`
/// comes from a `u`/`U` suffix. A literal is 64-bit when it carries an `l`/`L`
/// suffix (on LP64 both `long` and `long long` are 64-bit) or its value doesn't
/// fit in *any* 32-bit type — so a bare `0xFFFFFFFF` (a 32-bit `unsigned int`
/// in C) stays 32-bit.
/// Natural alignment (bytes) of a type, for `_Alignas(type)`. Covers scalars
/// and pointers exactly; aggregates/typedefs fall back to a conservative value.
fn ast_type_alignment(ty: &AstType) -> u32 {
    match ty {
        AstType::Char { .. } | AstType::Bool => 1,
        AstType::Short { .. } => 2,
        AstType::Int { .. } | AstType::Float => 4,
        AstType::Long { .. } | AstType::LongLong { .. }
        | AstType::Double | AstType::Pointer { .. } => 8,
        AstType::LongDouble => 16,
        AstType::Array { base, .. } => ast_type_alignment(&base.ty),
        _ => 8,
    }
}

/// Replace the sentinel leaf type (a `Named` placeholder) inside a declarator
/// type with `repl`. Used to splice a grouped declarator's suffixed base into
/// the position occupied by its inner declarator's placeholder leaf.
fn subst_sentinel(ty: QualType, sentinel: &str, repl: &QualType) -> QualType {
    match ty.ty {
        AstType::Named(ref n) if n == sentinel => repl.clone(),
        AstType::Pointer { base, quals } => QualType {
            ty: AstType::Pointer { base: Box::new(subst_sentinel(*base, sentinel, repl)), quals },
            qualifiers: ty.qualifiers, storage: ty.storage,
        },
        AstType::Function { ret, params, variadic } => QualType {
            ty: AstType::Function { ret: Box::new(subst_sentinel(*ret, sentinel, repl)), params, variadic },
            qualifiers: ty.qualifiers, storage: ty.storage,
        },
        AstType::Array { base, size } => QualType {
            ty: AstType::Array { base: Box::new(subst_sentinel(*base, sentinel, repl)), size },
            qualifiers: ty.qualifiers, storage: ty.storage,
        },
        _ => ty,
    }
}

fn parse_int_literal(text: &str) -> (i64, bool, bool) {
    let s = text.trim_end_matches(|c| matches!(c, 'u'|'U'|'l'|'L'));
    let lower = text.to_lowercase();
    let is_u = lower.contains('u');
    let suffix_l = lower.contains('l');

    let raw: u64 = if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else if s.starts_with("0b") || s.starts_with("0B") {
        // Binary literal (C23 / GNU extension).
        u64::from_str_radix(&s[2..], 2).unwrap_or(0)
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(&s[1..], 8).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    };

    let is_64 = suffix_l || raw > u32::MAX as u64;
    (raw as i64, is_u, is_64)
}

/// Parse a C floating-point literal body (suffix already stripped) into an
/// `f64`. Handles decimal floats via the standard parser and C99 hex floats
/// (`0x1p64`, `0x1.8p-3`) which Rust's `str::parse` rejects.
/// Strip a floating-point literal's suffix, including C23 `_FloatN` widths
/// (`f16`/`f32`/`f64`/`f128`, `bf16`) and the plain `f`/`F`/`l`/`L`.
/// Byte size of a primitive `AstType` (64-bit target), used to size a
/// `vector_size(N)` vector as an array of `N / size` elements. Non-primitive
/// bases default to 1 (byte granularity), which still gives the right total size.
fn ast_type_byte_size(ty: &AstType) -> u32 {
    match ty {
        AstType::Char { .. } | AstType::Bool => 1,
        AstType::Short { .. } => 2,
        AstType::Int { .. } | AstType::Float => 4,
        AstType::Long { .. } | AstType::LongLong { .. } | AstType::Double => 8,
        AstType::Pointer { .. } => 8,
        AstType::Named(n) => match n.as_str() {
            "int8" | "i8" | "uint8" | "u8" => 1,
            "int16" | "i16" | "uint16" | "u16" | "_Float16" | "__bf16" | "__fp16" => 2,
            "int32" | "i32" | "uint32" | "u32" | "_Float32" => 4,
            "int64" | "i64" | "uint64" | "u64" | "isize" | "usize" | "_Float64" => 8,
            "int128" | "i128" | "uint128" | "u128" => 16,
            _ => 1,
        },
        _ => 1,
    }
}

/// Whether a statement transfers control out of its switch case, so that the
/// case does not fall through implicitly. `break`/`fallthrough` are the explicit
/// sic terminators; `return`/`goto`/`continue` also leave the case. A braced
/// block terminates iff its last statement does, and an `if/else` terminates iff
/// both arms do.
fn stmt_terminates_case(s: &Stmt) -> bool {
    match s {
        Stmt::Break(_) | Stmt::Fallthrough(_) | Stmt::Return(..)
        | Stmt::Goto(..) | Stmt::Continue(_) => true,
        Stmt::Block(ss, _) => ss.last().map_or(false, stmt_terminates_case),
        Stmt::If { then, else_: Some(e), .. } => {
            stmt_terminates_case(then) && stmt_terminates_case(e)
        }
        _ => false,
    }
}

fn strip_float_suffix(text: &str) -> &str {
    for suf in ["bf16", "BF16", "f128", "F128", "f64", "F64", "f32", "F32",
                "f16", "F16", "f", "F", "l", "L"] {
        if let Some(b) = text.strip_suffix(suf) {
            return b;
        }
    }
    text
}

fn parse_c_float(body: &str) -> f64 {
    let lower = body.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("0x") {
        // rest = <hexint>[.<hexfrac>]p[+-]<decexp>
        let (mantissa, exp) = match rest.split_once('p') {
            Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
            None => (rest, 0),
        };
        let (int_part, frac_part) = match mantissa.split_once('.') {
            Some((i, f)) => (i, f),
            None => (mantissa, ""),
        };
        let mut value = 0.0f64;
        for c in int_part.chars() {
            if let Some(d) = c.to_digit(16) { value = value * 16.0 + d as f64; }
        }
        let mut scale = 1.0f64 / 16.0;
        for c in frac_part.chars() {
            if let Some(d) = c.to_digit(16) { value += d as f64 * scale; scale /= 16.0; }
        }
        value * 2f64.powi(exp)
    } else {
        body.parse().unwrap_or(0.0)
    }
}
