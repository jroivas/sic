use std::collections::HashSet;
use crate::ast::*;
use crate::lexer::{Lang, Token, TokenKind, Span};
use crate::{Result, CompileError};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    typedefs: HashSet<String>,
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
        Parser { tokens, pos: 0, typedefs: HashSet::new(), source_file, lang, pending_vector_size: None, pending_constructor: None, pending_weak: false, func_vars: HashSet::new() }
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
            let d = self.parse_external_decl()?;
            decls.push(d);
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
        self.skip_attributes();

        // __asm__ at top level: skip
        if self.at(TokenKind::Asm) {
            self.parse_asm_skip()?;
            return Ok(Decl::ExprStmt(Expr::new(ExprKind::IntLit(0, false), sp.clone()), sp));
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
            return Ok(Decl::Var { base_ty, declarators: vec![], weak: self.pending_weak, span: sp });
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
        declarators.push(Declarator { name, ty, init, span: sp.clone() });

        while self.eat(TokenKind::Comma) {
            self.skip_attributes();
            self.pending_vector_size = None;
            let (n, mut t) = self.parse_declarator(base_ty.clone())?;
            self.skip_decl_tail();
            if let Some(vs) = self.pending_vector_size.take() { t = self.apply_vector_size(t, vs); }
            let init = if self.eat(TokenKind::Eq) { Some(self.parse_initializer()?) } else { None };
            declarators.push(Declarator { name: n, ty: t, init, span: self.span() });
        }
        self.eat(TokenKind::Semi);

        Ok(Decl::Var { base_ty, declarators, weak: self.pending_weak, span: sp })
    }

    fn is_expr_start_not_decl(&self) -> bool {
        // If the current token cannot start a declaration, it's a top-level expr.
        if matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::TypeName | TokenKind::Typeof | TokenKind::Alignas | TokenKind::Eof | TokenKind::LBrace
        ) { return false; }
        // Ident that's a typedef name also starts a declaration
        if self.peek_kind() == TokenKind::Ident && self.typedefs.contains(self.peek().text.as_str()) {
            return false;
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
            let (name, mut ty) = self.parse_declarator(base_ty.clone())?;
            self.skip_attributes();
            if let Some(n) = self.pending_vector_size.take() {
                ty = self.apply_vector_size(ty, n);
            }
            self.typedefs.insert(name.clone());
            names.push((name, ty));
            if !self.eat(TokenKind::Comma) { break; }
        }
        self.eat(TokenKind::Semi);
        Ok(Decl::TypeDef { names, span: sp })
    }

    // ─── Declaration specifiers ───────────────────────────────────────────────

    fn parse_decl_specifiers(&mut self) -> Result<(QualType, Option<StorageClass>)> {
        let mut storage: Option<StorageClass> = None;
        let mut quals: Vec<TypeQual> = Vec::new();
        let mut signed: Option<bool> = None;
        let mut base: Option<AstType> = None;
        let mut long_count = 0u32;

        loop {
            self.skip_attributes();
            match self.peek_kind() {
                // GCC `__extension__` is a transparent prefix on a declaration
                // (used e.g. on `long long` struct members in glibc headers).
                // Skip it; not consuming it here made struct-member parsing spin.
                TokenKind::Extension => { self.advance(); }
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
                TokenKind::Atomic   => { quals.push(TypeQual::Atomic);   self.advance(); }
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
                TokenKind::Struct   => { base = Some(self.parse_struct_or_union(false)?); }
                TokenKind::Union    => { base = Some(self.parse_struct_or_union(true)?); }
                TokenKind::Enum     => { base = Some(self.parse_enum()?); }
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
                // A type-name (typedef or sic alias like `u32`) is only a type
                // specifier when no other type info has been seen yet. Otherwise
                // it is the declarator name — e.g. `uint32_t u32;` where the
                // second token is a field/variable named `u32`, not a type.
                TokenKind::TypeName if base.is_none() && signed.is_none() && long_count == 0 => {
                    let name = self.advance().text.clone();
                    base = Some(AstType::Named(name));
                }
                TokenKind::Ident if base.is_none() && signed.is_none() && long_count == 0
                    && self.typedefs.contains(self.peek().text.as_str()) => {
                    let name = self.advance().text.clone();
                    base = Some(AstType::Named(name));
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

    fn parse_struct_or_union(&mut self, is_union: bool) -> Result<AstType> {
        let sp = self.span();
        self.advance(); // consume 'struct'/'union'
        self.skip_attributes();

        let name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            Some(self.advance().text.clone())
        } else {
            None
        };

        let fields = if self.at(TokenKind::LBrace) {
            self.advance();
            let mut fields = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                let before = self.pos;
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
            Some(fields)
        } else {
            None
        };

        if is_union {
            Ok(AstType::Union(UnionDef { name, fields, span: sp }))
        } else {
            Ok(AstType::Struct(StructDef { name, fields, span: sp }))
        }
    }

    fn parse_struct_field(&mut self) -> Result<Vec<FieldDecl>> {
        let sp = self.span();
        let (base_ty, _) = self.parse_decl_specifiers()?;
        let mut fields = Vec::new();

        if self.at(TokenKind::Semi) {
            // Anonymous struct/union member
            fields.push(FieldDecl { name: None, ty: base_ty, bit_width: None, span: sp });
            return Ok(fields);
        }

        loop {
            let (name, ty) = self.parse_declarator(base_ty.clone())?;
            let bit_width = if self.eat(TokenKind::Colon) {
                Some(Box::new(self.parse_assign_expr()?))
            } else {
                None
            };
            // Trailing field attribute, e.g. `int x __attribute__((aligned(8)));`.
            self.skip_attributes();
            fields.push(FieldDecl { name: Some(name), ty, bit_width, span: sp.clone() });
            if !self.eat(TokenKind::Comma) { break; }
        }
        Ok(fields)
    }

    fn parse_enum(&mut self) -> Result<AstType> {
        let sp = self.span();
        self.advance(); // 'enum'
        // `enum __attribute__((packed)) { ... }` — skip attributes before the tag.
        self.skip_attributes();
        let name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            Some(self.advance().text.clone())
        } else {
            None
        };
        self.skip_attributes();
        let variants = if self.at(TokenKind::LBrace) {
            self.advance();
            let mut vs = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                let vsp = self.span();
                let vname = self.expect_name()?;
                // Enumerator attributes (`NAME __attribute__((...)) = val`), e.g.
                // glib's `GLIB_AVAILABLE_ENUMERATOR_IN_*` deprecation markers.
                self.skip_attributes();
                let value = if self.eat(TokenKind::Eq) { Some(Box::new(self.parse_assign_expr()?)) } else { None };
                vs.push(EnumVariant { name: vname, value, span: vsp });
                if !self.eat(TokenKind::Comma) { break; }
            }
            self.expect(TokenKind::RBrace)?;
            Some(vs)
        } else {
            None
        };
        Ok(AstType::Enum(EnumDef { name, variants, span: sp }))
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
    fn starts_decl_specifier(&self) -> bool {
        if matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::Typeof | TokenKind::Alignas)
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
            TokenKind::Goto => self.parse_goto(),
            TokenKind::Switch => self.parse_switch(),
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

    fn is_label(&self) -> bool {
        if self.pos + 1 >= self.tokens.len() { return false; }
        self.tokens[self.pos + 1].kind == TokenKind::Colon
    }

    fn is_decl_start(&self) -> bool {
        if matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::Typeof | TokenKind::Alignas
            // A declaration may lead with attributes, e.g. glib's g_autoptr /
            // QEMU's RCU_READ_LOCK_GUARD: `__attribute__((cleanup(f))) T v = ...`.
            | TokenKind::Attribute)
        {
            return true;
        }
        self.typename_starts_decl()
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

    fn parse_if(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance(); // 'if'
        self.expect(TokenKind::LParen)?;
        let cond = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        let then = Box::new(self.parse_stmt()?);
        let else_ = if self.eat(TokenKind::Else) { Some(Box::new(self.parse_stmt()?)) } else { None };
        Ok(Stmt::If { cond, then, else_, span: sp })
    }

    fn parse_while(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance();
        self.expect(TokenKind::LParen)?;
        let cond = self.parse_expr()?;
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
        let cond = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        self.eat(TokenKind::Semi);
        Ok(Stmt::DoWhile { body, cond, span: sp })
    }

    fn parse_for(&mut self) -> Result<Stmt> {
        let sp = self.span();
        self.advance(); // 'for'
        self.expect(TokenKind::LParen)?;

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

        let cond = if self.at(TokenKind::Semi) { None } else { Some(self.parse_expr()?) };
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
        Ok(Stmt::Switch { val, body, span: sp })
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
            return Ok(Decl::Var { base_ty, declarators: vec![], weak: false, span: sp });
        }

        let mut declarators = Vec::new();
        loop {
            let dsp = self.span();
            self.pending_vector_size = None;
            let (name, mut ty) = self.parse_declarator(base_ty.clone())?;
            // Trailing `__asm__`/`__attribute__` before the initializer, e.g.
            // glib g_autoptr / QEMU RCU_READ_LOCK_GUARD cleanup locals.
            self.skip_decl_tail();
            if let Some(n) = self.pending_vector_size.take() { ty = self.apply_vector_size(ty, n); }
            if !name.is_empty() { self.func_vars.insert(name.clone()); }
            let init = if self.eat(TokenKind::Eq) { Some(self.parse_initializer()?) } else { None };
            if !name.is_empty() {
                declarators.push(Declarator { name, ty, init, span: dsp });
            }
            if !self.eat(TokenKind::Comma) { break; }
        }
        self.eat(TokenKind::Semi);
        Ok(Decl::Var { base_ty, declarators, weak: false, span: sp })
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
                    let idx = self.parse_expr()?;
                    self.expect(TokenKind::RBracket)?;
                    e = Expr::new(ExprKind::Index { base: Box::new(e), index: Box::new(idx) }, sp.clone());
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
        match self.peek_kind() {
            TokenKind::Nullptr => {
                self.advance();
                Ok(Expr::new(ExprKind::Nullptr, sp))
            }
            TokenKind::IntLit => {
                let text = self.advance().text.clone();
                let (val, is_u, is_64) = parse_int_literal(&text);
                let kind = if is_u { ExprKind::UIntLit(val as u64, is_64) } else { ExprKind::IntLit(val, is_64) };
                Ok(Expr::new(kind, sp))
            }
            TokenKind::FloatLit => {
                let text = self.advance().text.clone();
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
                    _ => {}
                }
                Ok(Expr::new(ExprKind::Ident(name), sp))
            }
            TokenKind::TypeName => {
                // typedef name used as an expression (shouldn't be common, but handle gracefully)
                let name = self.advance().text.clone();
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
