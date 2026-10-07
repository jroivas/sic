//! GNU inline assembly: `asm volatile("rdtsc" : "=a"(lo), "=d"(hi));`.
//!
//! Cranelift has no inline assembly, so a fixed set of x86-64 templates that
//! real code uses (QEMU's host tick counter / cpuid probe / softfloat 128-bit
//! helpers, glibc `<cpuid.h>`, compiler barriers, …) is recognised here and
//! lowered to calls of tiny exact machine-code helpers (`sic_ir::asm_helpers`,
//! emitted by the backend). Anything else WARNS at compile time and TRAPS
//! (`ud2`) when executed: it must never silently do nothing — sic used to skip
//! every asm statement, so QEMU's `rdtsc` "returned" 0, the guest's TSC never
//! advanced and Visopsys divided by its zero CPU speed.

use crate::ast::{AsmOperand, AsmStmt};
use crate::Result;
use super::super::func::FuncCtx;
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
    pub(crate) fn lower_asm(&mut self, a: &AsmStmt) -> Result<()> {
        if !a.goto && self.try_lower_asm(a)? {
            return Ok(());
        }
        let sp = &a.span;
        eprintln!("{}:{}:{}: warning: unsupported inline assembly \"{}\" (sic recognises only a fixed set of x86-64 templates); it traps if executed",
            sp.file.as_deref().unwrap_or("<input>"), sp.line, sp.col, a.template.escape_debug());
        self.call_asm_helper("trap", &[], vec![], Type::Void)?;
        Ok(())
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

    /// Call helper `__sic_asm_<name>` (declared on first use), coercing the
    /// arguments to `params`.
    fn call_asm_helper(&mut self, name: &str, params: &[Type], args: Vec<Val>, ret: Type) -> Result<Val> {
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
