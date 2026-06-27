use std::collections::HashSet;
use crate::ast::*;
use crate::lexer::{Lexer, Token, TokenKind, Span};
use crate::{Result, CompileError};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    typedefs: HashSet<String>,
    source_file: String,
}

impl Parser {
    pub fn new(tokens: Vec<Token>, source_file: String) -> Self {
        Parser { tokens, pos: 0, typedefs: HashSet::new(), source_file }
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

        // __attribute__ at top level: skip
        self.skip_attributes();

        // __asm__ at top level: skip
        if self.at(TokenKind::Asm) {
            self.parse_asm_skip()?;
            return Ok(Decl::ExprStmt(Expr::new(ExprKind::IntLit(0), sp.clone()), sp));
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

        // Check for ';' — bare type declaration (struct/enum definition, typedef)
        if self.at(TokenKind::Semi) {
            self.advance();
            if let Some(StorageClass::Typedef) = storage {
                return Ok(Decl::TypeDef { names: vec![], span: sp });
            }
            return Ok(Decl::Var { base_ty, declarators: vec![], span: sp });
        }

        // typedef with declarators
        if let Some(StorageClass::Typedef) = storage {
            return self.parse_typedef(base_ty, sp);
        }

        // Try to parse first declarator
        let (name, ty) = self.parse_declarator(base_ty.clone())?;

        // If `(` follows and it's a function — function definition or prototype
        if let AstType::Function { ref params, variadic, ref ret } = ty.ty.clone() {
            let params = params.clone();
            let variadic = variadic;
            let ret_ty = *ret.clone();

            self.skip_attributes();

            if self.at(TokenKind::LBrace) {
                // Function definition
                let body = self.parse_compound_stmt_as_stmts()?;
                return Ok(Decl::Func {
                    name, ret_ty, params, variadic,
                    body: Some(body), storage, span: sp,
                });
            } else {
                // Prototype
                self.eat(TokenKind::Semi);
                return Ok(Decl::Func {
                    name, ret_ty, params, variadic,
                    body: None, storage, span: sp,
                });
            }
        }

        // Variable declaration(s)
        let mut declarators = Vec::new();
        let init = if self.eat(TokenKind::Eq) {
            Some(self.parse_initializer()?)
        } else {
            None
        };
        declarators.push(Declarator { name, ty, init, span: sp.clone() });

        while self.eat(TokenKind::Comma) {
            self.skip_attributes();
            let (n, t) = self.parse_declarator(base_ty.clone())?;
            let init = if self.eat(TokenKind::Eq) { Some(self.parse_initializer()?) } else { None };
            declarators.push(Declarator { name: n, ty: t, init, span: self.span() });
        }
        self.eat(TokenKind::Semi);

        Ok(Decl::Var { base_ty, declarators, span: sp })
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
            | TokenKind::TypeName | TokenKind::Eof | TokenKind::LBrace
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
            let (name, ty) = self.parse_declarator(base_ty.clone())?;
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
                // inline (ignored)
                TokenKind::Inline   => { self.advance(); }
                // signedness
                TokenKind::Signed   => { signed = Some(true);  self.advance(); }
                TokenKind::Unsigned => { signed = Some(false); self.advance(); }
                // Basic types
                TokenKind::Void     => { base = Some(AstType::Void); self.advance(); }
                TokenKind::Char     => { base = Some(AstType::Char { signed }); self.advance(); }
                TokenKind::Short    => { base = Some(AstType::Short { signed: signed.unwrap_or(true) }); self.advance(); }
                TokenKind::Int      => {
                    base = Some(AstType::Int { signed: signed.unwrap_or(true) });
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
                TokenKind::TypeName => {
                    let name = self.advance().text.clone();
                    base = Some(AstType::Named(name));
                }
                TokenKind::Ident if base.is_none() && self.typedefs.contains(self.peek().text.as_str()) => {
                    let name = self.advance().text.clone();
                    base = Some(AstType::Named(name));
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
                fields.extend(self.parse_struct_field()?);
                self.eat(TokenKind::Semi);
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
            fields.push(FieldDecl { name: Some(name), ty, bit_width, span: sp.clone() });
            if !self.eat(TokenKind::Comma) { break; }
        }
        Ok(fields)
    }

    fn parse_enum(&mut self) -> Result<AstType> {
        let sp = self.span();
        self.advance(); // 'enum'
        let name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            Some(self.advance().text.clone())
        } else {
            None
        };
        let variants = if self.at(TokenKind::LBrace) {
            self.advance();
            let mut vs = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                let vsp = self.span();
                let vname = self.expect(TokenKind::Ident)?.text;
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

    /// Parse a declarator, returning (name, fully-qualified type).
    fn parse_declarator(&mut self, base: QualType) -> Result<(String, QualType)> {
        // Collect pointer levels
        let mut pointers: Vec<Vec<TypeQual>> = Vec::new();
        while self.eat(TokenKind::Star) {
            let mut pq = Vec::new();
            loop {
                match self.peek_kind() {
                    TokenKind::Const    => { pq.push(TypeQual::Const);    self.advance(); }
                    TokenKind::Volatile => { pq.push(TypeQual::Volatile); self.advance(); }
                    TokenKind::Restrict => { pq.push(TypeQual::Restrict); self.advance(); }
                    _ => break,
                }
            }
            pointers.push(pq);
        }

        self.skip_attributes();

        // Direct declarator: name or (abstract)
        let name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
            self.advance().text.clone()
        } else if self.at(TokenKind::LParen) {
            // Grouped declarator: `(*name)(suffix)` or abstract
            self.advance(); // (
            if self.at(TokenKind::Star) {
                // Pointer grouped declarator: (*name)(suffix) or (**name)(suffix)
                // Collect pointer stars from the inner part
                let mut ptr_quals: Vec<Vec<TypeQual>> = Vec::new();
                while self.eat(TokenKind::Star) {
                    let mut pq = Vec::new();
                    loop {
                        match self.peek_kind() {
                            TokenKind::Const    => { pq.push(TypeQual::Const);    self.advance(); }
                            TokenKind::Volatile => { pq.push(TypeQual::Volatile); self.advance(); }
                            TokenKind::Restrict => { pq.push(TypeQual::Restrict); self.advance(); }
                            _ => break,
                        }
                    }
                    ptr_quals.push(pq);
                }
                let inner_name = if self.at(TokenKind::Ident) || self.at(TokenKind::TypeName) {
                    self.advance().text.clone()
                } else {
                    String::new()
                };
                self.expect(TokenKind::RParen)?;
                // Apply suffix to BASE type first, then wrap with collected pointers
                let mut ty = self.parse_declarator_suffix(base)?;
                for pq in ptr_quals.into_iter().rev() {
                    ty = QualType {
                        ty: AstType::Pointer { base: Box::new(ty), quals: pq },
                        qualifiers: vec![],
                        storage: None,
                    };
                }
                return Ok((inner_name, ty));
            } else {
                let (inner_name, inner_ty) = (String::new(), base.clone());
                self.expect(TokenKind::RParen)?;
                let ty = self.parse_declarator_suffix(inner_ty)?;
                return Ok((inner_name, ty));
            }
        } else {
            String::new() // abstract declarator
        };

        // Suffix: `[size]` or `(params)`
        let mut ty = self.parse_declarator_suffix(base)?;

        // Apply pointer levels (innermost first)
        for pq in pointers.into_iter().rev() {
            ty = QualType {
                ty: AstType::Pointer { base: Box::new(ty), quals: pq },
                qualifiers: vec![],
                storage: None,
            };
        }

        Ok((name, ty))
    }

    fn parse_declarator_suffix(&mut self, mut ty: QualType) -> Result<QualType> {
        loop {
            match self.peek_kind() {
                TokenKind::LBracket => {
                    self.advance();
                    let size = if self.at(TokenKind::RBracket) { None }
                               else { Some(Box::new(self.parse_assign_expr()?)) };
                    self.expect(TokenKind::RBracket)?;
                    ty = QualType::new(AstType::Array { base: Box::new(ty), size });
                }
                TokenKind::LParen => {
                    let (params, variadic) = self.parse_params()?;
                    ty = QualType::new(AstType::Function {
                        ret: Box::new(ty), params, variadic,
                    });
                }
                _ => break,
            }
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
            params.push(Param { name: if name.is_empty() { None } else { Some(name) }, ty, span: psp });
            if !self.eat(TokenKind::Comma) { break; }
            if self.at(TokenKind::Ellipsis) { self.advance(); variadic = true; break; }
        }
        self.expect(TokenKind::RParen)?;
        Ok((params, variadic))
    }

    // ─── Initializer ──────────────────────────────────────────────────────────

    fn parse_initializer(&mut self) -> Result<Initializer> {
        if self.at(TokenKind::LBrace) {
            self.advance();
            let mut list = Vec::new();
            while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                // designators: [i] = or .field = (skip for now)
                if self.at(TokenKind::LBracket) {
                    self.advance(); self.parse_assign_expr()?; self.expect(TokenKind::RBracket)?;
                    self.eat(TokenKind::Eq);
                } else if self.at(TokenKind::Dot) {
                    self.advance(); self.advance(); // .field
                    self.eat(TokenKind::Eq);
                }
                list.push(self.parse_initializer()?);
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
        matches!(self.peek_kind(),
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Complex | TokenKind::Atomic
            | TokenKind::Struct | TokenKind::Union | TokenKind::Enum | TokenKind::Typedef
            | TokenKind::Extern | TokenKind::Static | TokenKind::Auto | TokenKind::Register
            | TokenKind::Inline | TokenKind::Const | TokenKind::Volatile | TokenKind::Restrict
            | TokenKind::TypeName
        ) || (self.peek_kind() == TokenKind::Ident && self.typedefs.contains(self.peek().text.as_str()))
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
        let name = self.expect(TokenKind::Ident)?.text;
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
            return Ok(Decl::Var { base_ty, declarators: vec![], span: sp });
        }

        let mut declarators = Vec::new();
        loop {
            let dsp = self.span();
            let (name, ty) = self.parse_declarator(base_ty.clone())?;
            let init = if self.eat(TokenKind::Eq) { Some(self.parse_initializer()?) } else { None };
            if !name.is_empty() {
                declarators.push(Declarator { name, ty, init, span: dsp });
            }
            if !self.eat(TokenKind::Comma) { break; }
        }
        self.eat(TokenKind::Semi);
        Ok(Decl::Var { base_ty, declarators, span: sp })
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
            let (ty, _) = self.parse_decl_specifiers()?;
            let (_, ty) = self.parse_declarator(ty)?;
            self.expect(TokenKind::RParen)?;
            if self.at(TokenKind::LBrace) {
                // Compound literal: (type){ initializer-list }
                self.advance(); // {
                let mut inits = Vec::new();
                while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                    inits.push(self.parse_initializer()?);
                    if !self.eat(TokenKind::Comma) { break; }
                }
                self.expect(TokenKind::RBrace)?;
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
        matches!(tok.kind,
            TokenKind::Void | TokenKind::Char | TokenKind::Short | TokenKind::Int
            | TokenKind::Long | TokenKind::Float | TokenKind::Double | TokenKind::Signed
            | TokenKind::Unsigned | TokenKind::Bool | TokenKind::Struct | TokenKind::Union
            | TokenKind::Enum | TokenKind::TypeName | TokenKind::Const | TokenKind::Volatile
        ) || (tok.kind == TokenKind::Ident && self.typedefs.contains(tok.text.as_str()))
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
                        // Compound literal
                        self.advance(); // {
                        let mut inits = Vec::new();
                        while !self.at(TokenKind::RBrace) && !self.at(TokenKind::Eof) {
                            inits.push(self.parse_initializer()?);
                            if !self.eat(TokenKind::Comma) { break; }
                        }
                        self.expect(TokenKind::RBrace)?;
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
            TokenKind::IntLit => {
                let text = self.advance().text.clone();
                let (val, is_u) = parse_int_literal(&text);
                let kind = if is_u { ExprKind::UIntLit(val as u64) } else { ExprKind::IntLit(val) };
                Ok(Expr::new(kind, sp))
            }
            TokenKind::FloatLit => {
                let text = self.advance().text.clone();
                let v: f64 = text.trim_end_matches(|c| matches!(c, 'f'|'F'|'l'|'L'))
                                 .parse().unwrap_or(0.0);
                Ok(Expr::new(ExprKind::FloatLit(v), sp))
            }
            TokenKind::StringLit => {
                let mut s = self.advance().text.clone();
                // Concatenate adjacent string literals
                while self.at(TokenKind::StringLit) {
                    s.push_str(&self.advance().text);
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
                    "__builtin_va_start" => return self.parse_va_builtin_start(sp),
                    "__builtin_va_arg"   => return self.parse_va_builtin_arg(sp),
                    "__builtin_va_end"   => return self.parse_va_builtin_end(sp),
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

    fn parse_va_builtin_start(&mut self, sp: Span) -> Result<Expr> {
        self.expect(TokenKind::LParen)?;
        let list = self.parse_assign_expr()?;
        self.expect(TokenKind::Comma)?;
        let last = self.parse_assign_expr()?;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::new(ExprKind::VaStart { list: Box::new(list), last: Box::new(last) }, sp))
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
                self.skip_balanced_parens();
            }
        }
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

fn parse_int_literal(text: &str) -> (i64, bool) {
    let s = text.trim_end_matches(|c| matches!(c, 'u'|'U'|'l'|'L'));
    let is_u = text.to_lowercase().contains('u');

    if s.starts_with("0x") || s.starts_with("0X") {
        // Parse as u64 first to handle values like 0xFFFFFFFFFFFFFFFF
        let v = u64::from_str_radix(&s[2..], 16).unwrap_or(0) as i64;
        return (v, is_u);
    }
    if s.len() > 1 && s.starts_with('0') {
        let v = u64::from_str_radix(&s[1..], 8).unwrap_or(0) as i64;
        return (v, is_u);
    }
    // For decimal, allow i64 range; large unsigned values handled by 'u' suffix
    let v: i64 = s.parse::<u64>().unwrap_or(0) as i64;
    (v, is_u)
}
