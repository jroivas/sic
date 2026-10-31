//! GNU inline assembly: `asm volatile("rdtsc" : "=a"(lo), "=d"(hi));`.
//!
//! Cranelift has no inline assembly, so a statement runs out of line, in a
//! helper function the call stands for:
//!  - a fixed set of x86-64 templates real code uses (QEMU's host tick counter /
//!    cpuid probe / softfloat 128-bit helpers, glibc `<cpuid.h>`, compiler
//!    barriers, …) maps to tiny exact machine-code helpers
//!    (`sic_ir::asm_helpers`, emitted by the backend);
//!  - any other template becomes a helper in assembler text
//!    (`Module::asm_text_helpers`, assembled by the system assembler): constant
//!    operands are printed into it, and register / memory / flag operands are
//!    loaded from a slot array into the registers their constraints name and
//!    stored back after (`try_lower_operand_asm`).
//! What neither handles (vector-register operands, `asm goto`, …) WARNS at
//! compile time and TRAPS (`ud2`) when executed: it must never silently do
//! nothing — sic used to skip every asm statement, so QEMU's `rdtsc`
//! "returned" 0, the guest's TSC never advanced and Visopsys divided by its
//! zero CPU speed. Inline assembly is C only; SIC rejects it.

use crate::ast::{AsmOperand, AsmStmt};
use crate::Result;
use super::super::func::{FuncCtx, LookupResult};
use super::*;
use sic_ir::asm_helpers::ASM_HELPER_PREFIX;

/// An x86-64 register a constraint letter pins (`a` = rax/eax, …).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reg { A, B, C, D }

/// A constraint with its modifiers (`=`, `+`, `&`, …) stripped.
struct Constraint {
    /// The constraint letters, e.g. `r`, `rm`, `a`, `Nd`, `x`.
    letters: String,
    /// `+`: the operand is read and written.
    rw: bool,
    /// A matching constraint `"0"`: same location as output operand N.
    tied: Option<usize>,
}

fn constraint(c: &str) -> Constraint {
    let letters: String = c.chars().filter(|ch| !"=+&%*?!#".contains(*ch)).collect();
    Constraint { tied: letters.parse().ok(), rw: c.contains('+'), letters }
}

fn reg_letter(letters: &str) -> Option<Reg> {
    letters.chars().find_map(|ch| match ch {
        'a' => Some(Reg::A), 'b' => Some(Reg::B), 'c' => Some(Reg::C), 'd' => Some(Reg::D),
        _ => None,
    })
}

/// The template split into instructions (on `;` and newlines), whitespace
/// collapsed, no blank around commas, and `%%` (a literal `%`) decoded.
fn instructions(t: &str) -> Vec<String> {
    t.split(|c| c == ';' || c == '\n')
        .map(|i| i.split_whitespace().collect::<Vec<_>>().join(" ")
            .replace(", ", ",").replace(" ,", ",").replace("%%", "%"))
        .filter(|i| !i.is_empty())
        .collect()
}

/// Drop instructions that are no-ops on real hardware: `xchg %r,%r` and `rol`
/// rotations of one register that add up to whole turns. This is Valgrind's
/// client-request marker (`rolq $3/$13/$61/$51,%rdi ; xchgq %rbx,%rbx`, from
/// <valgrind/valgrind.h>, run by QEMU's coroutine stack registration): natively
/// it changes no register, so the request yields its tied default value.
/// Rotations that do not cancel are kept (the template is then not recognised).
fn strip_native_nops(insns: Vec<String>) -> Vec<String> {
    let mut turns: std::collections::HashMap<String, u32> = Default::default();
    let mut rest = Vec::new();
    for i in &insns {
        if let Some((mnem, ops)) = i.split_once(' ') {
            if let Some((a, b)) = ops.split_once(',') {
                if matches!(mnem, "xchg" | "xchgq") && a == b && a.starts_with('%') { continue; }
                if mnem == "rolq" && b.starts_with('%') {
                    if let Some(n) = a.strip_prefix('$').and_then(|n| n.parse::<u32>().ok()) {
                        *turns.entry(b.to_string()).or_default() += n;
                        continue;
                    }
                }
            }
        }
        rest.push(i.clone());
    }
    if turns.values().all(|n| n % 64 == 0) { rest } else { insns }
}

/// `%N` / `%bN` / `%kN` / `%qN` / `%wN` → N.
fn operand_ref(s: &str) -> Option<usize> {
    let s = s.strip_prefix('%')?;
    let s = s.strip_prefix(|c: char| "bhkqw".contains(c)).unwrap_or(s);
    s.parse().ok()
}

impl<'m> FuncCtx<'m> {
    /// `e` as a symbol-relative memory operand: a file-scope object at a constant
    /// offset. Not a name a local hides, nor a `static` of this function.
    fn global_operand_text(&self, e: &Expr) -> Option<String> {
        let mut root = e;
        while let ExprKind::Field { base, .. } | ExprKind::Index { base, .. } = &root.kind { root = base; }
        let ExprKind::Ident(n) = &root.kind else { return None };
        if !matches!(self.lookup(n), Some(LookupResult::Global(..))) || self.static_locals.contains_key(n) { return None; }
        let (name, off) = self.lowerer.global_lvalue(e)?;
        Some(if off == 0 { format!("{}(%rip)", name) } else { format!("{}{:+}(%rip)", name, off) })
    }

    pub(crate) fn lower_asm(&mut self, a: &AsmStmt) -> Result<()> {
        // SIC has no inline assembly; it is a C feature here.
        if self.is_sic() {
            let sp = &a.span;
            return Err(crate::CompileError::at(
                "inline assembly is not supported in SIC (only in C sources)".to_string(),
                sp.file.clone(), sp.line, sp.col));
        }
        // An operand naming a global register variable (Linux's
        // ASM_CALL_CONSTRAINT, `"+r"(current_stack_pointer)`, only tells the
        // compiler the asm uses the stack) becomes a temporary holding the
        // register's value; what the asm leaves in it is not written back.
        let substituted = self.substitute_reg_var_operands(a)?;
        let a = substituted.as_ref().unwrap_or(a);
        if !a.goto && self.try_lower_asm(a)? {
            return Ok(());
        }
        if self.try_lower_text_asm(a)? {
            return Ok(());
        }
        if self.try_lower_operand_asm(a)? {
            return Ok(());
        }
        let sp = &a.span;
        crate::diag::warn("unsupported-asm", sp.file.as_deref(), sp.line, sp.col, &format!(
            "unsupported inline assembly \"{}\" (an operand constraint or modifier sic does not handle, such as vector registers, or asm goto); it traps if executed",
            a.template.escape_debug()));
        self.call_asm_helper("trap", &[], vec![], Type::Void)?;
        Ok(())
    }

    /// The global register variable `name` refers to, unless a local shadows
    /// it: (its type, the register).
    pub(crate) fn global_reg_var(&self, name: &str) -> Option<(Type, String)> {
        if matches!(self.lookup(name), Some(LookupResult::Local(..))) { return None; }
        self.lowerer.global_reg_vars.get(name).cloned()
    }

    /// A read of a global register variable: the register's value. Only the
    /// stack pointer is supported (the caller's `%rsp`, by a helper); any other
    /// register holds whatever the surrounding code left there.
    pub(crate) fn read_global_reg(&mut self, name: &str, sp: &crate::lexer::Span) -> Result<Option<Val>> {
        let Some((ty, reg)) = self.global_reg_var(name) else { return Ok(None) };
        if reg != "rsp" && reg != "esp" && reg != "sp" {
            return Err(crate::CompileError::at(
                format!("global register variable `{}` in `{}` is not supported (only the stack pointer)", name, reg),
                sp.file.clone(), sp.line, sp.col));
        }
        let v = self.call_asm_helper("rsp", &[], vec![], Type::u64())?;
        Ok(Some(self.coerce(v, &ty)?))
    }

    /// `a` with each operand that names a global register variable replaced by
    /// a fresh local holding the register's value (None: no such operand).
    fn substitute_reg_var_operands(&mut self, a: &AsmStmt) -> Result<Option<AsmStmt>> {
        let names = |ops: &[AsmOperand]| ops.iter().any(|o| matches!(&o.expr.kind, ExprKind::Ident(n) if self.global_reg_var(n).is_some()));
        if !names(&a.outputs) && !names(&a.inputs) { return Ok(None); }
        let mut out = a.clone();
        for (k, op) in out.outputs.iter_mut().chain(out.inputs.iter_mut()).enumerate() {
            let ExprKind::Ident(n) = &op.expr.kind else { continue };
            let Some((ty, _)) = self.global_reg_var(n) else { continue };
            let n = n.clone();
            let v = self.read_global_reg(&n, &op.expr.span)?.unwrap();
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: ty.clone(), align: None });
            self.push_instr(Instr::Store { val: v, ptr: Val::Local(slot) });
            let tmp = format!("__sic_regvar_{}_{}", n, k);
            self.define_local(tmp.clone(), ty, slot);
            op.expr = Expr::new(ExprKind::Ident(tmp), op.expr.span.clone());
        }
        Ok(Some(out))
    }

    /// A template with no outputs whose inputs are all constants (`"i"`/`"n"`):
    /// its operands are substituted as GCC prints them (`%0` → `$24`, `%c0` →
    /// `24`, `%n0` → `-24`) and the text becomes a helper function, assembled
    /// by the system assembler (`-S` writes it as is). Linux's asm-offsets
    /// `DEFINE()`s are such statements: `.ascii "->SYM %0 …" :: "i"(val)`.
    /// With `asm goto`, the helper returns 0 when the template falls through and
    /// K+1 when it jumps to label K (`%l[name]`), and the caller branches on it.
    /// `false` when the statement is not of this form (nothing emitted).
    fn try_lower_text_asm(&mut self, a: &AsmStmt) -> Result<bool> {
        if !a.outputs.is_empty() { return Ok(false); }
        let mut vals: Vec<(Option<String>, Imm)> = Vec::new();
        let mut strings = Vec::new();
        let mut deferred = Vec::new();
        for op in &a.inputs {
            let c = constraint(&op.constraint);
            if c.letters.is_empty() || !c.letters.chars().all(|ch| ch == 'i' || ch == 'n') { return Ok(false); }
            let Some(v) = self.const_operand(&op.expr, c.letters.contains('i'), true, &mut strings, &mut deferred) else { return Ok(false) };
            vals.push((op.name.clone(), v));
        }
        let labels = self.goto_labels(a);
        let Some(text) = substitute_operands(&a.template, &vals, &labels, a.inputs.len()) else { return Ok(false) };
        let text = format!("{}{}", string_defs(&strings), text);
        // Callee-saved registers the template clobbers are saved around it.
        let saved: Vec<&str> = ["rbx", "rbp", "r12", "r13", "r14", "r15"].into_iter()
            .filter(|r| a.clobbers.iter().any(|c| {
                let c = c.trim_start_matches('%');
                c == *r || (r.starts_with('r') && r.len() == 3 && c == format!("e{}", &r[1..]))
            }))
            .collect();
        let exit = |k: usize, goto: bool| -> String {
            let mut e = String::new();
            for r in saved.iter().rev() { e.push_str(&format!("\tpop %{}\n", r)); }
            if goto { e.push_str(&format!("\tmov ${}, %eax\n", k)); }
            e.push_str("\tret\n");
            e
        };
        let mut body = String::new();
        for r in &saved { body.push_str(&format!("\tpush %{}\n", r)); }
        body.push_str(&text);
        body.push('\n');
        body.push_str(&exit(0, a.goto));
        for (k, (_, l)) in labels.iter().enumerate() {
            body.push_str(&format!("{}:\n", l));
            body.push_str(&exit(k + 1, true));
        }
        let name = self.add_text_helper("text", body, a, 0, &deferred);
        let ret = if a.goto { Type::i32() } else { Type::Void };
        let (params, args) = self.deferred_args(&deferred)?;
        let r = self.call_asm_helper(&name, &params, args, ret)?;
        if a.goto { self.asm_goto_dispatch(a, r)?; }
        Ok(true)
    }

    /// `asm goto`'s labels: (C label as `%l[name]` writes it, the helper's local
    /// label for it). A `__label__` name lost its `.N` suffix in the template.
    fn goto_labels(&self, a: &AsmStmt) -> Vec<(String, String)> {
        a.labels.iter().enumerate().map(|(k, l)| {
            (l.split('.').next().unwrap_or(l).to_string(), format!(".Lsic_g{}_{}", UID, k))
        }).collect()
    }

    /// After an `asm goto` helper returned `r`: 0 continues, K+1 jumps to the
    /// statement's label K.
    fn asm_goto_dispatch(&mut self, a: &AsmStmt, r: Val) -> Result<()> {
        let cont = self.new_block_after_current();
        let mut arms = Vec::new();
        let mut targets = Vec::new();
        for (k, l) in a.labels.iter().enumerate() {
            let bb = self.new_block_after_current();
            arms.push((k as i64 + 1, bb));
            targets.push((bb, l.clone()));
        }
        self.set_terminator(Terminator::Switch { val: r, default: cont, arms });
        for (bb, l) in targets {
            self.switch_to_block(bb);
            self.lower_stmt(&crate::ast::Stmt::Goto(l, a.span.clone()))?;
            if !self.is_terminated() { self.set_terminator(Terminator::Jump(cont)); }
        }
        self.switch_to_block(cont);
        Ok(())
    }

    /// The deferred `"i"` operands (see `const_operand`) as trailing call
    /// arguments: (parameter types, values), each an `i64`.
    fn deferred_args(&mut self, deferred: &[(Expr, bool)]) -> Result<(Vec<Type>, Vec<Val>)> {
        let mut params = Vec::new();
        let mut vals = Vec::new();
        for (e, _) in deferred {
            let v = self.lower_expr(e)?;
            params.push(Type::i64());
            vals.push(v);
        }
        Ok((params, vals))
    }

    /// Register a text helper (deduplicated by its body) and return its name
    /// (without the helper prefix). A body holding deferred-operand
    /// placeholders is unique to this statement: `sic_opt::asm_imm` prints each
    /// call's operands (trailing arguments from `first_imm`) into a copy.
    fn add_text_helper(&mut self, kind: &str, body: String, a: &AsmStmt, first_imm: usize, deferred: &[(Expr, bool)]) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        body.hash(&mut h);
        if !deferred.is_empty() { (self.func_ref().name.as_str(), self.lowerer.module.asm_text_helpers.len()).hash(&mut h); }
        let name = format!("{}_{:016x}", kind, h.finish());
        let sym = format!("{}{}", ASM_HELPER_PREFIX, name);
        if !self.lowerer.module.asm_text_helpers.iter().any(|(n, _)| *n == sym) {
            // The helper's own labels (and `%=`) get its number; a deferred
            // helper's are numbered per specialized copy.
            let body = if deferred.is_empty() {
                body.replace(UID, &self.lowerer.module.asm_text_helpers.len().to_string())
            } else { body };
            if !deferred.is_empty() {
                self.lowerer.module.asm_deferred.push(sic_ir::AsmDeferred {
                    helper: sym.clone(), first_imm, int_only: deferred.iter().map(|(_, n)| *n).collect(),
                    file: a.span.file.clone(), line: a.span.line, col: a.span.col,
                });
            }
            self.lowerer.module.asm_text_helpers.push((sym, body));
        }
        name
    }

    /// A constant operand (`"i"` / `"n"`): an integer constant expression; with
    /// `"i"` also a string literal's address (defined in the helper, appended
    /// to `strings`). With `defer_ok` (no register or memory alternative), any
    /// other expression is deferred (appended to `deferred`, with whether it
    /// must be an integer): optimization may make it a constant or a symbol's
    /// address (`"i"(&sym)`, an inlined `always_inline` parameter), resolved by
    /// `sic_opt::asm_imm`. None for anything else.
    fn const_operand(&mut self, e: &Expr, addr_ok: bool, defer_ok: bool, strings: &mut Vec<(String, String)>,
        deferred: &mut Vec<(Expr, bool)>) -> Option<Imm> {
        if let Some(v) = self.lowerer.eval_const_int(e) { return Some(Imm::Int(v)); }
        match &e.kind {
            ExprKind::StringLit(text) if addr_ok => {
                let label = format!(".Lsic_s{}_{}", UID, strings.len());
                strings.push((label.clone(), text.clone()));
                Some(Imm::Label(label))
            }
            _ if defer_ok => {
                deferred.push((e.clone(), !addr_ok));
                Some(Imm::Arg(deferred.len() - 1))
            }
            _ => None,
        }
    }

    /// Lower a recognised template; `false` = not recognised (nothing emitted).
    fn try_lower_asm(&mut self, a: &AsmStmt) -> Result<bool> {
        let insns = strip_native_nops(instructions(&a.template));
        let ins: Vec<&str> = insns.iter().map(|s| s.as_str()).collect();
        let memory_clobber = a.clobbers.iter().any(|c| c == "memory");
        // Every operand must be understood by the template handled below; a
        // symbolic `%[name]` reference is not supported.
        if a.template.contains("%[") { return Ok(false); }
        match ins.as_slice() {
            // Compiler barrier / value laundering: `asm("" ::: "memory")`,
            // `asm("" : "+r"(x))`, `asm("" : "=r"(x) : "0"(y))`.
            [] => {
                for inp in &a.inputs {
                    let c = constraint(&inp.constraint);
                    if let Some(t) = c.tied {
                        let Some(out) = a.outputs.get(t) else { return Ok(false) };
                        let v = self.lower_expr(&inp.expr)?;
                        let lv = self.lower_lvalue(&out.expr)?;
                        self.store_lvalue(&lv, v)?;
                    } else if !c.letters.contains('m') && !c.letters.contains('x') {
                        self.lower_expr(&inp.expr)?; // evaluated, as GCC does
                    }
                }
                // An opaque call: the compiler may not cache memory across it.
                if memory_clobber { self.call_asm_helper("barrier", &[], vec![], Type::Void)?; }
                Ok(true)
            }
            ["rep", "nop"] | ["rep nop"] | ["pause"] if a.outputs.is_empty() => {
                self.call_asm_helper("pause", &[], vec![], Type::Void)?;
                Ok(true)
            }
            [f @ ("mfence" | "lfence" | "sfence")] if a.outputs.is_empty() => {
                self.call_asm_helper(f, &[], vec![], Type::Void)?;
                Ok(true)
            }
            // rdtsc: EDX:EAX = TSC.
            ["rdtsc"] => {
                let v = self.call_asm_helper("rdtsc", &[], vec![], Type::u64())?;
                self.store_edx_eax(a, v)
            }
            // QEMU target/i386/emulate/x86.h: the 64-bit TSC in RAX.
            ["rdtscp", "shl $32,%rdx", "or %rdx,%rax"] => {
                let v = self.call_asm_helper("rdtscp", &[], vec![], Type::u64())?;
                self.store_regs(a, &[(Reg::A, v)])
            }
            ["xgetbv"] => {
                let Some(c) = self.input_for_reg(a, Reg::C)? else { return Ok(false) };
                let v = self.call_asm_helper("xgetbv", &[Type::u32()], vec![c], Type::u64())?;
                self.store_edx_eax(a, v)
            }
            ["cpuid"] => {
                let Some(leaf) = self.input_for_reg(a, Reg::A)? else { return Ok(false) };
                let sub = self.input_for_reg(a, Reg::C)?.unwrap_or_else(|| Constant::int(0));
                let u32t = Type::u32();
                let arr = Type::Array { elem: Box::new(u32t.clone()), len: 4 };
                let slot = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: slot, ty: arr.clone(), align: None });
                self.call_asm_helper("cpuid", &[u32t.clone(), u32t.clone(), Type::ptr(arr)],
                    vec![leaf, sub, Val::Local(slot)], Type::Void)?;
                let mut regs = Vec::new();
                for (i, r) in [Reg::A, Reg::B, Reg::C, Reg::D].into_iter().enumerate() {
                    let p = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest: p, base: Val::Local(slot), index: Constant::int(i as i64),
                        elem_size: 4, result_ty: Type::ptr(u32t.clone()) });
                    let v = self.alloc_val();
                    self.push_instr(Instr::Load { dest: v, ptr: Val::Local(p), ty: u32t.clone() });
                    regs.push((r, Val::Local(v)));
                }
                self.store_regs(a, &regs)
            }
            // QEMU host-utils.h udiv_qrnnd: `divq %4` — RDX:RAX / d → RAX quotient,
            // RDX remainder (the caller guarantees no overflow, as for the CPU).
            [d] if d.starts_with("div") => {
                let Some((mnem, opnd)) = d.split_once(' ') else { return Ok(false) };
                if mnem != "divq" && mnem != "div" { return Ok(false); }
                let Some(n) = operand_ref(opnd) else { return Ok(false) };
                let Some(divisor) = self.operand_value(a, n)? else { return Ok(false) };
                let (Some(lo), Some(hi)) = (self.input_for_reg(a, Reg::A)?, self.input_for_reg(a, Reg::D)?)
                    else { return Ok(false) };
                let rem = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: rem, ty: Type::u64(), align: None });
                let q = self.call_asm_helper("divq", &[Type::u64(), Type::u64(), Type::u64(), Type::ptr(Type::u64())],
                    vec![lo, hi, divisor, Val::Local(rem)], Type::u64())?;
                let r = self.alloc_val();
                self.push_instr(Instr::Load { dest: r, ptr: Val::Local(rem), ty: Type::u64() });
                self.store_regs(a, &[(Reg::A, q), (Reg::D, Val::Local(r))])
            }
            // softfloat-macros.h shl_double/shr_double:
            // `shld %b2, %1, %0` : "+r"(dst) : "r"(src), "ci"(count).
            [s] if s.starts_with("shld ") || s.starts_with("shrd ") || s.starts_with("shldq ") || s.starts_with("shrdq ") => {
                let (mnem, ops) = s.split_once(' ').unwrap();
                let ops: Vec<&str> = ops.split(',').collect();
                let [cnt, src, dst] = ops.as_slice() else { return Ok(false) };
                let (Some(cnt), Some(src), Some(dst)) = (operand_ref(cnt), operand_ref(src), operand_ref(dst))
                    else { return Ok(false) };
                // The destination is a read-write output.
                let Some(out) = a.outputs.get(dst) else { return Ok(false) };
                if !constraint(&out.constraint).rw { return Ok(false); }
                let (Some(c), Some(sv)) = (self.operand_value(a, cnt)?, self.operand_value(a, src)?) else { return Ok(false) };
                let lv = self.lower_lvalue(&out.expr)?;
                if lv.ty.size_of(self.ptr_size()) != 8 { return Ok(false); }
                let cur = self.load_lvalue(&lv)?;
                let name = if mnem.starts_with("shld") { "shld" } else { "shrd" };
                let res = self.call_asm_helper(name, &[Type::u64(), Type::u64(), Type::u32()], vec![cur, sv, c], Type::u64())?;
                self.store_lvalue(&lv, res)?;
                Ok(true)
            }
            // QEMU host/include/x86_64 atomic128-ldst / load-extract-al16-al8:
            // a 16-byte (atomic when aligned) vector load or store.
            [m] if m.starts_with("vmovdqa ") || m.starts_with("vmovdqu ") => {
                let (mnem, ops) = m.split_once(' ').unwrap();
                let Some((src, dst)) = ops.split_once(',') else { return Ok(false) };
                let (Some(src), Some(dst)) = (operand_ref(src), operand_ref(dst)) else { return Ok(false) };
                let (Some(so), Some(dop)) = (self.asm_operand(a, src), self.asm_operand(a, dst)) else { return Ok(false) };
                let (sc, dc) = (constraint(&so.constraint), constraint(&dop.constraint));
                let aligned = mnem == "vmovdqa";
                let helper = match (sc.letters.as_str(), dc.letters.as_str()) {
                    ("m", "x") => if aligned { "ldqa" } else { "ldqu" },
                    ("x", "m") => if aligned { "stqa" } else { "stqu" },
                    _ => return Ok(false),
                };
                let (slv, dlv) = (self.lower_lvalue(&so.expr)?, self.lower_lvalue(&dop.expr)?);
                if slv.ty.size_of(self.ptr_size()) != 16 || dlv.ty.size_of(self.ptr_size()) != 16 { return Ok(false); }
                let vp = Type::void_ptr();
                self.call_asm_helper(helper, &[vp.clone(), vp], vec![dlv.ptr.clone(), slv.ptr.clone()], Type::Void)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Operand N (outputs first, then inputs).
    fn asm_operand<'a>(&self, a: &'a AsmStmt, n: usize) -> Option<&'a AsmOperand> {
        if n < a.outputs.len() { a.outputs.get(n) } else { a.inputs.get(n - a.outputs.len()) }
    }

    /// The value operand N supplies to the instruction: an input's value, or a
    /// read-write output's current value. `None` for a write-only output.
    fn operand_value(&mut self, a: &AsmStmt, n: usize) -> Result<Option<Val>> {
        if n < a.outputs.len() {
            let out = &a.outputs[n];
            if !constraint(&out.constraint).rw { return Ok(None); }
            let lv = self.lower_lvalue(&out.expr)?;
            return Ok(Some(self.load_lvalue(&lv)?));
        }
        match a.inputs.get(n - a.outputs.len()) {
            Some(inp) => Ok(Some(self.lower_expr(&inp.expr)?)),
            None => Ok(None),
        }
    }

    /// The register an operand constraint pins, following a matching
    /// (`"0"`) constraint to its output.
    fn operand_reg(a: &AsmStmt, op: &AsmOperand) -> Option<Reg> {
        let c = constraint(&op.constraint);
        match c.tied {
            Some(t) => reg_letter(&constraint(&a.outputs.get(t)?.constraint).letters),
            None => reg_letter(&c.letters),
        }
    }

    /// The value loaded into register `r` before the instruction: an input
    /// pinned to it, or a read-write output pinned to it.
    fn input_for_reg(&mut self, a: &AsmStmt, r: Reg) -> Result<Option<Val>> {
        if let Some(inp) = a.inputs.iter().find(|i| Self::operand_reg(a, i) == Some(r)) {
            return Ok(Some(self.lower_expr(&inp.expr)?));
        }
        if let Some(out) = a.outputs.iter().find(|o| Self::operand_reg(a, o) == Some(r) && constraint(&o.constraint).rw) {
            let lv = self.lower_lvalue(&out.expr)?;
            return Ok(Some(self.load_lvalue(&lv)?));
        }
        Ok(None)
    }

    /// Store `EDX:EAX` (given as the 64-bit `v`) into the outputs pinned to
    /// `a` (low half) and `d` (high half). Both instructions zero the upper
    /// halves of RAX/RDX, so a 64-bit output gets the zero-extended half.
    fn store_edx_eax(&mut self, a: &AsmStmt, v: Val) -> Result<bool> {
        let lo = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: lo, op: BinOp::And, lhs: v.clone(), rhs: Constant::int(0xffff_ffff), ty: Type::u64() });
        let hi = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: hi, op: BinOp::LShr, lhs: v, rhs: Constant::int(32), ty: Type::u64() });
        self.store_regs(a, &[(Reg::A, Val::Local(lo)), (Reg::D, Val::Local(hi))])
    }

    /// Store each output from the register its constraint pins. Every output
    /// must be pinned to one of `regs` (else the template is not understood).
    fn store_regs(&mut self, a: &AsmStmt, regs: &[(Reg, Val)]) -> Result<bool> {
        let mut stores = Vec::new();
        for out in &a.outputs {
            let Some(r) = Self::operand_reg(a, out) else { return Ok(false) };
            let Some((_, v)) = regs.iter().find(|(rr, _)| *rr == r) else { return Ok(false) };
            stores.push((out, v.clone()));
        }
        for (out, v) in stores {
            let lv = self.lower_lvalue(&out.expr)?;
            self.store_lvalue(&lv, v)?;
        }
        Ok(true)
    }

    /// A memory fence of GCC memory order `order` (`__ATOMIC_RELAXED` = 0 …
    /// `__ATOMIC_SEQ_CST` = 5). `signal`: only against a signal handler on this
    /// thread (`__atomic_signal_fence`), which never needs a CPU fence.
    ///   relaxed                         → nothing
    ///   consume/acquire/release/acq_rel → compiler barrier (x86-64 TSO already
    ///                                     orders these; gcc emits no instruction)
    ///   seq_cst                         → `fence` (mfence), also a compiler barrier
    pub(crate) fn emit_fence(&mut self, order: i64, signal: bool) -> Result<()> {
        match order & 0xffff { // the upper bits are x86 HLE hints
            0 => {}
            5 if !signal => self.push_instr(Instr::Fence),
            _ => { self.call_asm_helper("barrier", &[], vec![], Type::Void)?; }
        }
        Ok(())
    }

    /// Call helper `__sic_asm_<name>` (declared on first use), coercing the
    /// arguments to `params`.
    pub(crate) fn call_asm_helper(&mut self, name: &str, params: &[Type], args: Vec<Val>, ret: Type) -> Result<Val> {
        let sym = format!("{}{}", ASM_HELPER_PREFIX, name);
        let fref = match self.lowerer.module.func_ref_by_name(&sym) {
            Some(f) => f,
            None => self.lowerer.module.add_extern(ExternFunc {
                name: sym,
                sig: FunctionType { ret: ret.clone(), params: params.to_vec(), variadic: false },
            }),
        };
        let mut vals = Vec::with_capacity(args.len());
        for (v, t) in args.into_iter().zip(params) { vals.push(self.coerce(v, t)?); }
        if matches!(ret, Type::Void) {
            self.push_instr(Instr::Call { dest: None, func: fref, args: vals, ret_ty: ret });
            return Ok(Constant::zero());
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vals, ret_ty: ret.clone() });
        self.val_types.insert(dest.0, ret);
        Ok(Val::Local(dest))
    }
}

/// A `%l[name]` / `%lN` reference at `cs[*i]` (after the modifier): the
/// helper's local label for that `asm goto` label (`nops` operands come first
/// in the numbering).
fn goto_label(cs: &[char], i: &mut usize, labels: &[(String, String)], nops: usize) -> Option<String> {
    match cs.get(*i)? {
        '[' => {
            let end = cs[*i..].iter().position(|&x| x == ']')? + *i;
            let name: String = cs[*i + 1..end].iter().collect();
            *i = end + 1;
            labels.iter().find(|(c, _)| *c == name).map(|(_, l)| l.clone())
        }
        d if d.is_ascii_digit() => {
            let start = *i;
            while *i < cs.len() && cs[*i].is_ascii_digit() { *i += 1; }
            let n: usize = cs[start..*i].iter().collect::<String>().parse().ok()?;
            labels.get(n.checked_sub(nops)?).map(|(_, l)| l.clone())
        }
        _ => None,
    }
}

/// `template` with `%N` / `%[name]` operand references replaced by constants as
/// GCC's AT&T printer writes them: plain `$v`, `%cN`/`%PN` → `v`, `%nN` → `-v`;
/// `%l[label]` → the helper's label for an `asm goto` target; `%%` → `%`,
/// `%=` → a number unique to the statement. `None` for a reference or
/// modifier it cannot print.
fn substitute_operands(template: &str, vals: &[(Option<String>, Imm)], labels: &[(String, String)], nops: usize) -> Option<String> {
    let cs: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] != '%' { out.push(cs[i]); i += 1; continue; }
        i += 1;
        let c = *cs.get(i)?;
        if c == '%' { out.push('%'); i += 1; continue; }
        if c == '=' { out.push_str(UID); i += 1; continue; }
        let modifier = if c.is_ascii_alphabetic() { i += 1; Some(c) } else { None };
        if modifier == Some('l') { out.push_str(&goto_label(&cs, &mut i, labels, nops)?); continue; }
        let n = match cs.get(i)? {
            '[' => {
                let end = cs[i..].iter().position(|&x| x == ']')? + i;
                let name: String = cs[i + 1..end].iter().collect();
                i = end + 1;
                vals.iter().position(|(nm, _)| nm.as_deref() == Some(name.as_str()))?
            }
            d if d.is_ascii_digit() => {
                let start = i;
                while i < cs.len() && cs[i].is_ascii_digit() { i += 1; }
                cs[start..i].iter().collect::<String>().parse().ok()?
            }
            _ => return None,
        };
        out.push_str(&vals.get(n)?.1.print(modifier)?);
    }
    Some(out)
}

/// Brackets a deferred operand's placeholder in a helper body: `<mark>K
/// M<mark>` (operand K, modifier M: `$` none, `c`, `n`, `a`), see
/// `sic_ir::AsmDeferred`.
const MARK: char = '\u{1}';

/// Where a helper body needs a number unique to the helper (its local labels,
/// `%=`): `<mark>U<mark>`, filled in by `add_text_helper` or, for a deferred
/// helper, per specialized copy by `sic_opt::asm_imm`.
const UID: &str = "\u{1}U\u{1}";

/// A constant operand's value.
#[derive(Clone, Debug)]
enum Imm {
    /// An integer (`"i"(24)`, `"i"(sizeof(T))`).
    Int(i64),
    /// A string literal's address: a label the helper defines.
    Label(String),
    /// Deferred operand K (a trailing argument of the helper call), printed as
    /// a placeholder that `sic_opt::asm_imm` fills in after optimization.
    Arg(usize),
}

impl Imm {
    /// The operand as the template prints it: `$v` bare, `v` with `%c` / `%P`,
    /// `-v` with `%n`; an address with `%a` (`label(%rip)` for a symbol).
    fn print(&self, modifier: Option<char>) -> Option<String> {
        Some(match (self, modifier) {
            (Imm::Int(v), None) => format!("${}", v),
            (Imm::Int(v), Some('c' | 'P' | 'a')) => format!("{}", v),
            (Imm::Int(v), Some('n')) => format!("{}", v.wrapping_neg()),
            (Imm::Label(l), None) => format!("${}", l),
            (Imm::Label(l), Some('c' | 'P')) => l.clone(),
            (Imm::Label(l), Some('a')) => format!("{}(%rip)", l),
            (Imm::Arg(k), None) => format!("{m}{}${m}", k, m = MARK),
            (Imm::Arg(k), Some('c' | 'P')) => format!("{m}{}c{m}", k, m = MARK),
            (Imm::Arg(k), Some('n')) => format!("{m}{}n{m}", k, m = MARK),
            (Imm::Arg(k), Some('a')) => format!("{m}{}a{m}", k, m = MARK),
            _ => return None,
        })
    }
}

/// The string literals constant operands point to, each under its label, in
/// the read-only string section.
fn string_defs(strings: &[(String, String)]) -> String {
    let mut out = String::new();
    for (label, text) in strings {
        let esc: String = text.bytes().map(|b| match b {
            b'"' => "\\\"".to_string(), b'\\' => "\\\\".to_string(),
            0x20..=0x7e => (b as char).to_string(), _ => format!("\\{:03o}", b),
        }).collect();
        out.push_str(&format!("\t.pushsection .rodata.str1.1,\"aMS\",@progbits,1\n{}:\n\t.asciz \"{}\"\n\t.popsection\n", label, esc));
    }
    out
}

/// The x86-64 general registers: 64-, 32-, 16-, low 8-bit names and the high
/// 8-bit one (a–d only). Index = position here.
const GPR: [(&str, &str, &str, &str, Option<&str>); 16] = [
    ("rax", "eax", "ax", "al", Some("ah")), ("rbx", "ebx", "bx", "bl", Some("bh")),
    ("rcx", "ecx", "cx", "cl", Some("ch")), ("rdx", "edx", "dx", "dl", Some("dh")),
    ("rsi", "esi", "si", "sil", None), ("rdi", "edi", "di", "dil", None),
    ("rbp", "ebp", "bp", "bpl", None), ("rsp", "esp", "sp", "spl", None),
    ("r8", "r8d", "r8w", "r8b", None), ("r9", "r9d", "r9w", "r9b", None),
    ("r10", "r10d", "r10w", "r10b", None), ("r11", "r11d", "r11w", "r11b", None),
    ("r12", "r12d", "r12w", "r12b", None), ("r13", "r13d", "r13w", "r13b", None),
    ("r14", "r14d", "r14w", "r14b", None), ("r15", "r15d", "r15w", "r15b", None),
];
const RDI: usize = 5;
/// Registers handed to `r`-class operands, caller-saved first (rbp and rsp never).
const POOL: [usize; 14] = [0, 2, 3, 4, 5, 8, 9, 10, 11, 1, 12, 13, 14, 15];

/// The register a clobber names (`"rax"`, `"%eax"`, `"r8d"`, `"al"`, …).
fn clobbered_gpr(c: &str) -> Option<usize> {
    let c = c.trim_start_matches('%');
    GPR.iter().position(|g| c == g.0 || c == g.1 || c == g.2 || c == g.3 || Some(c) == g.4)
}

/// Where an operand lives inside the helper.
#[derive(Clone, Debug)]
enum OpLoc {
    /// In a register (index into `GPR`).
    Reg(usize),
    /// In memory, its address in a register.
    Mem(usize),
    /// In memory at a symbol's constant offset, printed as `sym+8(%rip)`: an
    /// exact instruction form that patching relies on (Linux's paravirt
    /// `call *pv_ops+N(%rip)`, which must be `ff 15 disp32`).
    Sym(String),
    /// A constant.
    Imm(Imm),
    /// A flag output `=@cc<cond>`: `set<cond>` into a register.
    Flag(String, usize),
}

/// One operand: its location, its value's width in bytes, and whether its
/// value (or address) goes into the helper.
struct OpInfo { loc: OpLoc, size: u64, load: bool }

/// The helper for an operand-carrying asm statement: save the callee-saved
/// registers, load each operand from the slot array (`%rdi`), run the
/// template, store the outputs back, restore. `outputs` = (operand, register).
fn operand_helper_body(text: &str, ops: &[OpInfo], outputs: &[(usize, usize)], scratch: usize,
    labels: &[(String, String)], goto: bool) -> String {
    let mut b = String::new();
    for r in ["rbx", "rbp", "r12", "r13", "r14", "r15", "rdi"] { b.push_str(&format!("\tpush %{}\n", r)); }
    // Loads through %rdi, the one into %rdi itself last.
    let mut loads: Vec<(usize, usize)> = Vec::new();
    for (n, op) in ops.iter().enumerate() {
        if !op.load { continue; }
        match op.loc { OpLoc::Reg(r) | OpLoc::Mem(r) => loads.push((n, r)), _ => {} }
    }
    loads.sort_by_key(|&(_, r)| r == RDI);
    for (n, r) in loads { b.push_str(&format!("\tmov {}(%rdi), %{}\n", 8 * n, GPR[r].0)); }
    b.push_str(text);
    b.push('\n');
    // Every exit stores the outputs and restores the registers; with `asm
    // goto` it returns 0 (fall through) or K+1 (label K).
    let exit = |k: usize| -> String {
        let mut e = String::new();
        for op in ops {
            if let OpLoc::Flag(cc, r) = &op.loc {
                e.push_str(&format!("\tset{} %{}\n\tmovzbl %{}, %{}\n", cc, GPR[*r].3, GPR[*r].3, GPR[*r].1));
            }
        }
        e.push_str(&format!("\tmov (%rsp), %{}\n", GPR[scratch].0));
        for &(n, r) in outputs { e.push_str(&format!("\tmov %{}, {}(%{})\n", GPR[r].0, 8 * n, GPR[scratch].0)); }
        e.push_str("\tadd $8, %rsp\n");
        for r in ["r15", "r14", "r13", "r12", "rbp", "rbx"] { e.push_str(&format!("\tpop %{}\n", r)); }
        if goto { e.push_str(&format!("\tmov ${}, %eax\n", k)); }
        e.push_str("\tret\n");
        e
    };
    b.push_str(&exit(0));
    for (k, (_, l)) in labels.iter().enumerate() {
        b.push_str(&format!("{}:\n", l));
        b.push_str(&exit(k + 1));
    }
    b
}

/// The template with operand references printed for their locations, as
/// GCC's AT&T printer does: registers by the operand's width or the modifier
/// (`b` `h` `w` `k` `q`; `V` without `%`), memory as `(%reg)`, constants as
/// `$v` (`c`/`P`: `v`, `n`: `-v`); `z` the size suffix; `%%` and `%=`.
fn print_operands(template: &str, ops: &[OpInfo], names: &[Option<String>], labels: &[(String, String)]) -> Option<String> {
    let cs: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let reg_name = |r: usize, size: u64, m: Option<char>| -> Option<String> {
        let g = GPR[r];
        Some(match m {
            Some('b') => g.3.to_string(), Some('h') => g.4?.to_string(), Some('w') => g.2.to_string(),
            Some('k') => g.1.to_string(), Some('q') => g.0.to_string(),
            _ => match size { 1 => g.3, 2 => g.2, 4 => g.1, _ => g.0 }.to_string(),
        })
    };
    while i < cs.len() {
        if cs[i] != '%' { out.push(cs[i]); i += 1; continue; }
        i += 1;
        let c = *cs.get(i)?;
        if c == '%' { out.push('%'); i += 1; continue; }
        if c == '=' { out.push_str(UID); i += 1; continue; }
        let modifier = if c.is_ascii_alphabetic() { i += 1; Some(c) } else { None };
        if modifier == Some('l') { out.push_str(&goto_label(&cs, &mut i, labels, ops.len())?); continue; }
        let n = match cs.get(i)? {
            '[' => {
                let end = cs[i..].iter().position(|&x| x == ']')? + i;
                let name: String = cs[i + 1..end].iter().collect();
                i = end + 1;
                names.iter().position(|nm| nm.as_deref() == Some(name.as_str()))?
            }
            d if d.is_ascii_digit() => {
                let start = i;
                while i < cs.len() && cs[i].is_ascii_digit() { i += 1; }
                cs[start..i].iter().collect::<String>().parse().ok()?
            }
            _ => return None,
        };
        let op = ops.get(n)?;
        if modifier == Some('z') {
            out.push(match op.size { 1 => 'b', 2 => 'w', 4 => 'l', _ => 'q' });
            continue;
        }
        match (&op.loc, modifier) {
            (OpLoc::Reg(r), Some('V')) => out.push_str(&reg_name(*r, op.size, None)?),
            // `%a` on a register: the address it holds (Linux's vDSO futex
            // unlock: `cmpxchgl %k[zero], %a[lock]` with [lock] "D").
            (OpLoc::Reg(r), Some('a')) => out.push_str(&format!("(%{})", GPR[*r].0)),
            (OpLoc::Reg(r), m @ (None | Some('b' | 'h' | 'w' | 'k' | 'q'))) => { out.push('%'); out.push_str(&reg_name(*r, op.size, m)?); }
            (OpLoc::Mem(r), None | Some('b' | 'h' | 'w' | 'k' | 'q' | 'a')) => out.push_str(&format!("(%{})", GPR[*r].0)),
            (OpLoc::Sym(s), None | Some('b' | 'h' | 'w' | 'k' | 'q' | 'a')) => out.push_str(s),
            (OpLoc::Imm(v), m) => out.push_str(&v.print(m)?),
            _ => return None,
        }
    }
    Some(out)
}

impl FuncCtx<'_> {
    /// A statement with register / memory / flag operands: a helper taking a
    /// slot array (one 8-byte slot per operand, in operand order) that loads
    /// the operands into the registers their constraints ask for, runs the
    /// template, and stores the outputs back (see `operand_helper_body`). The
    /// caller fills the slots (input values, read-write outputs' current
    /// values, memory operands' addresses) and copies the outputs out after.
    /// `false` (nothing emitted) for a constraint it does not handle (vector
    /// and x87 registers, …) or a template it cannot print.
    fn try_lower_operand_asm(&mut self, a: &AsmStmt) -> Result<bool> {
        let ps = self.ptr_size();
        let nout = a.outputs.len();
        let all: Vec<&AsmOperand> = a.outputs.iter().chain(a.inputs.iter()).collect();
        let mut used = [false; 16];
        used[6] = true; used[7] = true; // rbp, rsp
        // Fixed registers of plain outputs (no `+`, no `&`): one input may
        // share each, as `[err] "=a"(err) : "a"(lmask)` in Linux's XSTATE_OP.
        let mut shareable = [false; 16];
        for c in &a.clobbers { if let Some(r) = clobbered_gpr(c) { used[r] = true; } }
        let mut ops: Vec<Option<OpInfo>> = (0..all.len()).map(|_| None).collect();
        // Pass 1: fixed registers, constants, flags; note what needs a pool register.
        let mut want_reg: Vec<(usize, bool)> = Vec::new(); // (operand, memory?)
        let mut strings = Vec::new();
        let mut deferred = Vec::new();
        for (n, op) in all.iter().enumerate() {
            let is_out = n < nout;
            let raw = op.constraint.split(',').next().unwrap_or("");
            let c = constraint(raw);
            let ty = self.infer_expr_type(&op.expr).ok();
            let size = ty.as_ref().map_or(8, |t| t.size_of(ps)).min(8).max(1);
            if let Some(cc) = c.letters.strip_prefix("@cc") {
                if !is_out { return Ok(false); }
                want_reg.push((n, false));
                ops[n] = Some(OpInfo { loc: OpLoc::Flag(cc.to_string(), 0), size, load: false });
                continue;
            }
            if let Some(t) = c.tied {
                if is_out || t >= nout { return Ok(false); }
                continue; // after the outputs are placed
            }
            let letters = c.letters.as_str();
            if letters.chars().any(|ch| "xvYtufykh".contains(ch)) && !letters.chars().any(|ch| "rgqm".contains(ch)) {
                return Ok(false);
            }
            let fixed = letters.chars().find_map(|ch| match ch {
                'a' => Some(0), 'b' => Some(1), 'c' => Some(2), 'd' => Some(3), 'S' => Some(4), 'D' => Some(5), _ => None,
            });
            let imm_ok = letters.chars().any(|ch| "inIJKLMNOPeZEF".contains(ch));
            if !is_out && imm_ok && fixed.is_none() {
                if let Some(v) = self.const_operand(&op.expr, letters.contains('i'),
                    !letters.chars().any(|ch| "rgqmoVXpRlQabcdSD".contains(ch)), &mut strings, &mut deferred) {
                    ops[n] = Some(OpInfo { loc: OpLoc::Imm(v), size, load: false });
                    continue;
                }
                if !letters.chars().any(|ch| "rgqmoVXp".contains(ch)) { return Ok(false); }
            }
            if let Some(r) = fixed {
                if used[r] && !(!is_out && shareable[r]) { return Ok(false); }
                used[r] = true;
                shareable[r] = is_out && !c.rw && !raw.contains('&');
                ops[n] = Some(OpInfo { loc: OpLoc::Reg(r), size, load: !is_out || c.rw });
                continue;
            }
            let mem_only = letters.chars().any(|ch| "moV".contains(ch)) && !letters.chars().any(|ch| "rgqXp".contains(ch));
            if mem_only && !is_out && !c.rw {
                if let Some(text) = self.global_operand_text(&op.expr) {
                    ops[n] = Some(OpInfo { loc: OpLoc::Sym(text), size, load: false });
                    continue;
                }
            }
            if mem_only {
                want_reg.push((n, true));
                ops[n] = Some(OpInfo { loc: OpLoc::Mem(0), size, load: true });
                continue;
            }
            if !letters.chars().any(|ch| "rgqRlXpQ".contains(ch)) { return Ok(false); }
            want_reg.push((n, false));
            ops[n] = Some(OpInfo { loc: OpLoc::Reg(0), size, load: !is_out || c.rw });
        }
        // Pool registers.
        for (n, _) in want_reg {
            let Some(r) = POOL.iter().copied().find(|&r| !used[r]) else { return Ok(false) };
            used[r] = true;
            let info = ops[n].as_mut().unwrap();
            info.loc = match &info.loc {
                OpLoc::Mem(_) => OpLoc::Mem(r),
                OpLoc::Flag(cc, _) => OpLoc::Flag(cc.clone(), r),
                _ => OpLoc::Reg(r),
            };
        }
        // Tied inputs share their output's register.
        for (n, op) in all.iter().enumerate().skip(nout) {
            if let Some(t) = constraint(op.constraint.split(',').next().unwrap_or("")).tied {
                let OpLoc::Reg(r) = ops[t].as_ref().unwrap().loc else { return Ok(false) };
                let size = self.infer_expr_type(&op.expr).ok().map_or(8, |t| t.size_of(ps)).min(8).max(1);
                ops[n] = Some(OpInfo { loc: OpLoc::Reg(r), size, load: true });
            }
        }
        let ops: Vec<OpInfo> = ops.into_iter().map(|o| o.unwrap()).collect();
        // A register to find the slots again after the template: any not
        // holding an output.
        let out_regs: Vec<usize> = ops[..nout].iter().filter_map(|o| match o.loc {
            OpLoc::Reg(r) | OpLoc::Flag(_, r) => Some(r), _ => None }).collect();
        let Some(scratch) = POOL.iter().copied().find(|r| !out_regs.contains(r)) else { return Ok(false) };
        let names: Vec<Option<String>> = all.iter().map(|o| o.name.clone()).collect();
        let labels = self.goto_labels(a);
        let Some(text) = print_operands(&a.template, &ops, &names, &labels) else { return Ok(false) };
        let outputs: Vec<(usize, usize)> = ops[..nout].iter().enumerate().filter_map(|(n, o)| match o.loc {
            OpLoc::Reg(r) | OpLoc::Flag(_, r) => Some((n, r)), _ => None }).collect();
        let body = operand_helper_body(&format!("{}{}", string_defs(&strings), text), &ops, &outputs, scratch, &labels, a.goto);

        // The caller: lvalues once, the slots, the call, the outputs back.
        let i64t = Type::i64();
        let slots = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slots, ty: Type::Array { elem: Box::new(i64t.clone()), len: all.len().max(1) }, align: None });
        let slot_at = |me: &mut Self, n: usize| -> Val {
            let d = me.alloc_val();
            me.push_instr(Instr::PtrOffset { dest: d, base: Val::Local(slots), offset: Constant::int(8 * n as i64) });
            Val::Local(d)
        };
        let mut out_lvs = Vec::new();
        for out in &a.outputs { out_lvs.push(self.lower_lvalue(&out.expr)?); }
        for (n, op) in all.iter().enumerate() {
            let info = &ops[n];
            if !info.load { continue; }
            let v = match info.loc {
                OpLoc::Mem(_) => {
                    if n < nout { out_lvs[n].ptr.clone() } else {
                        match self.lower_lvalue(&op.expr) {
                            Ok(lv) => lv.ptr,
                            Err(_) => {
                                // An rvalue memory operand: a temporary holds it.
                                let ty = self.infer_expr_type(&op.expr)?;
                                let v = self.lower_expr(&op.expr)?;
                                let t = self.alloc_val();
                                self.push_instr(Instr::Alloca { dest: t, ty: ty.clone(), align: None });
                                let v = self.coerce(v, &ty)?;
                                self.push_instr(Instr::Store { val: v, ptr: Val::Local(t) });
                                Val::Local(t)
                            }
                        }
                    }
                }
                _ => {
                    if n < nout { self.load_lvalue(&out_lvs[n])? } else { self.lower_expr(&op.expr)? }
                }
            };
            let v = self.coerce(v, &i64t)?;
            let p = slot_at(self, n);
            self.push_instr(Instr::Store { val: v, ptr: p });
        }
        let name = self.add_text_helper("op", body, a, 1, &deferred);
        let (mut params, dargs) = self.deferred_args(&deferred)?;
        params.insert(0, Type::ptr(i64t.clone()));
        let mut args = vec![Val::Local(slots)];
        args.extend(dargs);
        let ret = if a.goto { Type::i32() } else { Type::Void };
        let r = self.call_asm_helper(&name, &params, args, ret)?;
        for (n, _) in &outputs {
            let p = slot_at(self, *n);
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: p, ty: i64t.clone() });
            let ty = out_lvs[*n].ty.clone();
            let v = self.coerce(Val::Local(d), &ty)?;
            self.store_lvalue(&out_lvs[*n], v)?;
        }
        if a.goto { self.asm_goto_dispatch(a, r)?; }
        Ok(true)
    }
}
