//! GNU inline assembly as LLVM's own (the LLVM back end, `-m32` included): the
//! template and constraints translated to LLVM's syntax, as clang does, and one
//! `Instr::InlineAsm` in the function. The out-of-line helpers of `asm.rs` are
//! for Cranelift, which has no inline assembly.
use crate::ast::AsmStmt;
use crate::{CompileError, Result};
use super::super::func::FuncCtx;
use sic_ir::AsmArg;
use super::*;

/// A constraint's letters without its modifiers (`=`, `+`, `&`, `%`), and
/// whether it is read-write (`+`) and early-clobber (`&`).
fn split_constraint(c: &str) -> (String, bool, bool) {
    let rw = c.contains('+');
    let early = c.contains('&');
    (c.chars().filter(|ch| !"=+&%".contains(*ch)).collect(), rw, early)
}

/// A constraint that only allows memory (`m`, `o`, `V`, `Q`-less memory forms).
fn memory_only(letters: &str) -> bool {
    !letters.is_empty() && letters.chars().all(|c| matches!(c, 'm' | 'o' | 'V' | '<' | '>'))
}

/// The one-register constraint letters as LLVM names the registers (clang's
/// conversion): `a` is `{ax}`, `Nd` is `N{dx}`, `t` the x87 top `{st}`.
fn llvm_letters(letters: &str) -> String {
    letters.chars().map(|c| match c {
        'a' => "{ax}".to_string(), 'b' => "{bx}".to_string(), 'c' => "{cx}".to_string(),
        'd' => "{dx}".to_string(), 'S' => "{si}".to_string(), 'D' => "{di}".to_string(),
        't' => "{st}".to_string(), 'u' => "{st(1)}".to_string(),
        c => c.to_string(),
    }).collect()
}

/// A register-or-memory output constraint as a register one: an output takes a
/// register when it may (`=rm`, `=g`), as clang does.
fn register_letters(letters: &str) -> String {
    let l: String = letters.chars().filter(|c| !matches!(c, 'm' | 'o' | 'V' | '<' | '>' | 'g' | 'X')).collect();
    if l.is_empty() { "r".to_string() } else { llvm_letters(&l) }
}

/// An input constraint in LLVM's letters (`g` is `imr`).
fn input_letters(letters: &str) -> String {
    llvm_letters(&letters.replace('g', "imr"))
}

/// The local label an `asm goto` template jumps to for its label `k`.
fn goto_stub(k: usize) -> String { format!(".Lsic_goto${{:uid}}_{}", k) }

/// The template in LLVM's syntax: `%N`/`%[name]` (with modifiers, `%k0`) is
/// `${N:k}`, `%%` a `%`, `%=` a unique number, and a `$` is `$$`. An `asm goto`
/// label (`%l[name]`, `%lN` numbered after the operands) is its stub.
fn llvm_template(t: &str, names: &[Option<String>], labels: &[String]) -> std::result::Result<String, String> {
    let mut out = String::new();
    let cs: Vec<char> = t.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c == '$' { out.push_str("$$"); i += 1; continue; }
        if c != '%' { out.push(c); i += 1; continue; }
        i += 1;
        let Some(&n) = cs.get(i) else { out.push('%'); break };
        match n {
            '%' => { out.push('%'); i += 1; continue; }
            '=' => { out.push_str("${:uid}"); i += 1; continue; }
            '{' | '|' | '}' => { out.push('$'); out.push(n); i += 1; continue; }
            _ => {}
        }
        // Modifier letters, then a number or `[name]`.
        let mut mods = String::new();
        while i < cs.len() && cs[i].is_ascii_alphabetic() { mods.push(cs[i]); i += 1; }
        let label = mods == "l";
        let index = if cs.get(i) == Some(&'[') {
            let end = cs[i..].iter().position(|&c| c == ']').ok_or("unterminated `%[`")? + i;
            let name: String = cs[i + 1..end].iter().collect();
            i = end + 1;
            if label {
                labels.iter().position(|l| *l == name).ok_or_else(|| format!("undefined label `{}`", name))?
            } else {
                names.iter().position(|n| n.as_deref() == Some(name.as_str()))
                    .ok_or_else(|| format!("undefined named operand `{}`", name))?
            }
        } else if cs.get(i).map_or(false, |c| c.is_ascii_digit()) {
            let start = i;
            while i < cs.len() && cs[i].is_ascii_digit() { i += 1; }
            let n = cs[start..i].iter().collect::<String>().parse::<usize>().map_err(|e| e.to_string())?;
            if label { n.checked_sub(names.len()).filter(|k| *k < labels.len()).ok_or("an asm goto label number past the labels")? } else { n }
        } else {
            return Err(format!("invalid `%{}` in the template", mods));
        };
        if label { out.push_str(&goto_stub(index)); continue; }
        if mods.is_empty() { out.push_str(&format!("${{{}}}", index)); }
        else { out.push_str(&format!("${{{}:{}}}", index, mods)); }
    }
    Ok(out)
}

impl<'m> FuncCtx<'m> {
    /// The `{reg}` constraint of a local `register T x asm("reg")` operand.
    fn pinned_constraint(&self, e: &Expr) -> Option<String> {
        let ExprKind::Ident(n) = &e.kind else { return None };
        let Some(super::super::func::LookupResult::Local(_, v)) = self.lookup(n) else { return None };
        self.local_reg_vars.get(&v.0).map(|r| format!("{{{}}}", r.trim_start_matches('%')))
    }

    /// An input operand's value (arrays decayed, of its own type). A
    /// `vector_size` value stays a vector, as it does for an SSE register
    /// (`vector_reg`: no C array is one).
    fn asm_input_value(&mut self, e: &Expr, vector_reg: bool) -> Result<(Val, Type)> {
        let t = match self.infer_expr_type(e)? {
            t @ Type::Array { .. } if vector_reg || !self.is_c_array_object(e) => {
                let v = self.lower_aggregate_ptr(e)?;
                return Ok((v, t));
            }
            Type::Array { elem, .. } => Type::Pointer(elem),
            Type::Function(_) => Type::void_ptr(),
            t => t,
        };
        let v = self.lower_expr(e)?;
        if matches!(t, Type::Struct(_) | Type::Union(_)) { return Ok((v, t)); }
        Ok((self.coerce(v, &t)?, t))
    }

    /// The address of an operand for a memory constraint: an lvalue's, else a
    /// temporary holding its value.
    fn asm_memory_operand(&mut self, e: &Expr) -> Result<(Val, Type)> {
        if let Ok(lv) = self.lower_lvalue(e) { return Ok((lv.ptr, lv.ty)); }
        let (v, t) = self.asm_input_value(e, false)?;
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: t.clone(), align: None });
        self.push_instr(Instr::Store { val: v, ptr: Val::Local(slot) });
        Ok((Val::Local(slot), t))
    }

    /// GNU `asm` as LLVM inline assembly (see the module comment).
    pub(crate) fn lower_native_asm(&mut self, a: &AsmStmt) -> Result<()> {
        let at = |m: String| CompileError::at(m, a.span.file.clone(), a.span.line, a.span.col);
        let names: Vec<Option<String>> = a.outputs.iter().chain(&a.inputs).map(|o| o.name.clone()).collect();
        let labels: Vec<String> = a.labels.iter().map(|l| l.split('.').next().unwrap_or(l).to_string()).collect();
        let mut template = llvm_template(&a.template, &names, &labels).map_err(at)?;
        // An instruction naming %ah (`%h0`) has no REX prefix: its other register
        // operands must be ones without (GCC's `Q` for a byte, `R` wider). LLVM
        // took any, and `movb %ah, %r9b` cannot be encoded.
        let high_byte = template.contains(":h}");
        let legacy = |l: String, ty: &Type| -> String {
            if !high_byte || !l.chars().all(|c| matches!(c, 'r' | 'q')) { return l; }
            if ty.size_of(8) == 1 { "Q".to_string() } else { "R".to_string() }
        };
        let mut cons: Vec<String> = Vec::new();
        let mut outputs: Vec<(Val, Type)> = Vec::new();
        let mut args: Vec<AsmArg> = Vec::new();
        // `+` operands: an input tied to the output, after all the others.
        let mut tied: Vec<(String, AsmArg)> = Vec::new();
        // Outputs widened to a wider tied input: (wide slot, its type, the
        // output's place and type), stored back narrowed after the asm.
        let mut widened: Vec<(Val, Type, Val, Type)> = Vec::new();
        for (i, o) in a.outputs.iter().enumerate() {
            let (letters, rw, early) = split_constraint(&o.constraint);
            let lv = self.lower_lvalue(&o.expr)?;
            if lv.bitfield.is_some() { return Err(at("a bit-field is not an asm output".into())); }
            let ty = lv.ty.clone();
            if let Some(flag) = letters.strip_prefix("@cc") {
                // A condition-code output (`=@ccz`).
                cons.push(format!("={{@cc{}}}", flag));
                outputs.push((lv.ptr, ty));
                continue;
            }
            if memory_only(&letters) {
                // `+m`: the asm reads the memory too, an input of the same address.
                cons.push(format!("=*{}", letters));
                if rw { tied.push((format!("*{}", letters), AsmArg { val: lv.ptr.clone(), ty: Type::void_ptr(), elem: Some(ty.clone()) })); }
                args.push(AsmArg { val: lv.ptr, ty: Type::void_ptr(), elem: Some(ty) });
                continue;
            }
            let l = self.pinned_constraint(&o.expr).unwrap_or_else(|| legacy(register_letters(&letters), &ty));
            cons.push(format!("={}{}", if early { "&" } else { "" }, l));
            if rw {
                let cur = self.load_lvalue(&lv)?;
                tied.push((i.to_string(), AsmArg { val: cur, ty: ty.clone(), elem: None }));
            }
            outputs.push((lv.ptr, ty));
        }
        for inp in &a.inputs {
            let (letters, _, _) = split_constraint(&inp.constraint);
            if let Ok(n) = letters.parse::<usize>() {
                // Matching constraint: in output N's place, of its type. A wider
                // input widens the output instead, as clang does (GCC passes the
                // whole input): Linux's put_user ties a 64-bit pointer to an
                // `int` result in `%rcx`, and narrowing it cut the address.
                let (v, t) = self.asm_input_value(&inp.expr, false)?;
                let scalar = |t: &Type| matches!(t, Type::Int { .. } | Type::Bool | Type::Pointer(_));
                let ps = crate::target::ptr_size();
                let ty = match outputs.get(n).map(|(_, o)| o.clone()) {
                    Some(o) if scalar(&o) && scalar(&t) && t.size_of(ps) > o.size_of(ps) => {
                        let slot = self.alloc_val();
                        self.push_instr(Instr::Alloca { dest: slot, ty: t.clone(), align: None });
                        let (place, out_ty) = std::mem::replace(&mut outputs[n], (Val::Local(slot), t.clone()));
                        widened.push((Val::Local(slot), t.clone(), place, out_ty));
                        t
                    }
                    Some(o) => o,
                    None => t,
                };
                let v = self.coerce(v, &ty)?;
                cons.push(letters);
                args.push(AsmArg { val: v, ty, elem: None });
            } else if memory_only(&letters) {
                let (p, t) = self.asm_memory_operand(&inp.expr)?;
                cons.push(format!("*{}", letters));
                args.push(AsmArg { val: p, ty: Type::void_ptr(), elem: Some(t) });
            } else {
                let l = self.pinned_constraint(&inp.expr).unwrap_or_else(|| input_letters(&letters));
                // An immediate operand is the constant it folds to.
                let imm = letters.chars().all(|c| matches!(c, 'i' | 'n' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'e' | 'Z'));
                let (v, t) = match super::super::eval_const_expr(&inp.expr, &self.lowerer.enum_consts) {
                    Ok(c) if imm => {
                        let t = self.infer_expr_type(&inp.expr).unwrap_or_else(|_| Type::i32());
                        let t = if matches!(t, Type::Int { .. }) { t } else { Type::i32() };
                        (self.coerce(Constant::int(c), &t)?, t)
                    }
                    _ => self.asm_input_value(&inp.expr, letters.chars().any(|c| matches!(c, 'x' | 'v' | 'Y')))?,
                };
                cons.push(if self.pinned_constraint(&inp.expr).is_some() { l } else { legacy(l, &t) });
                args.push(AsmArg { val: v, ty: t, elem: None });
            }
        }
        for (c, arg) in tied { cons.push(c); args.push(arg); }
        // `asm goto`: each label's stub stores the label's number + 1 (0: the asm
        // fell through) in a slot, whose address is the last input; the C code
        // then goes to the label.
        let taken = if a.goto {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: Type::i32(), align: None });
            let k = cons.len();
            let end = goto_stub(labels.len());
            template.push_str(&format!("\n\tmovl $$0, (${{{k}}})\n\tjmp {end}"));
            for i in 0..labels.len() {
                template.push_str(&format!("\n{}:\n\tmovl $${}, (${{{k}}})\n\tjmp {end}", goto_stub(i), i + 1));
            }
            template.push_str(&format!("\n{end}:"));
            cons.push("r".to_string());
            args.push(AsmArg { val: Val::Local(slot), ty: Type::void_ptr(), elem: None });
            cons.push("~{memory}".to_string());
            Some(slot)
        } else { None };
        for c in &a.clobbers {
            let c = c.trim_start_matches('%');
            if !c.is_empty() { cons.push(format!("~{{{}}}", c)); }
        }
        // As clang: the direction flag, the x87 status and the flags.
        cons.extend(["~{dirflag}", "~{fpsr}", "~{flags}"].map(String::from));
        let place = format!("{}:{}:{}", a.span.file.as_deref().unwrap_or("<input>"), a.span.line, a.span.col);
        self.push_instr(Instr::InlineAsm { template, constraints: cons.join(","), outputs, args, at: place });
        for (slot, wide, place, out_ty) in widened {
            let w = self.alloc_val();
            self.push_instr(Instr::Load { dest: w, ptr: slot, ty: wide });
            let v = self.coerce(Val::Local(w), &out_ty)?;
            self.push_instr(Instr::Store { val: v, ptr: place });
        }
        if let Some(slot) = taken {
            let r = self.alloc_val();
            self.push_instr(Instr::Load { dest: r, ptr: Val::Local(slot), ty: Type::i32() });
            self.asm_goto_dispatch(a, Val::Local(r))?;
        }
        Ok(())
    }

    /// A compiler barrier (`asm volatile("" ::: "memory")`) in LLVM's form.
    pub(crate) fn native_barrier(&mut self) {
        self.push_instr(Instr::InlineAsm {
            template: String::new(),
            constraints: "~{memory},~{dirflag},~{fpsr},~{flags}".to_string(),
            outputs: Vec::new(), args: Vec::new(), at: String::new(),
        });
    }

    /// The stack pointer's value (`register unsigned long sp asm("rsp")`).
    pub(crate) fn native_stack_pointer(&mut self, ty: &Type) -> Result<Val> {
        let slot = self.alloc_val();
        let pt = Type::Int { bits: self.ptr_size() * 8, signed: false };
        self.push_instr(Instr::Alloca { dest: slot, ty: pt.clone(), align: None });
        self.push_instr(Instr::InlineAsm {
            template: if self.ptr_size() == 4 { "mov %esp, $0" } else { "mov %rsp, $0" }.to_string(),
            constraints: "=r,~{dirflag},~{fpsr},~{flags}".to_string(),
            outputs: vec![(Val::Local(slot), pt.clone())], args: Vec::new(), at: String::new(),
        });
        let v = self.alloc_val();
        self.push_instr(Instr::Load { dest: v, ptr: Val::Local(slot), ty: pt });
        self.coerce(Val::Local(v), ty)
    }
}
