use std::fmt;
use crate::*;

/// Human-readable label for a function reference: `@f<i>` for defined functions,
/// `@fe<i>` for externs (the raw ref carries EXTERN_BIT which is not meaningful
/// to print).
fn func_label(fr: FuncRef) -> String {
    if fr.is_extern() { format!("@fe{}", fr.index()) } else { format!("@f{}", fr.index()) }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Void => write!(f, "void"),
            Type::Bool => write!(f, "i1"),
            Type::Int { bits, signed } => write!(f, "{}{}", if *signed { 'i' } else { 'u' }, bits),
            Type::Float32 => write!(f, "f32"),
            Type::Float64 => write!(f, "f64"),
            Type::Float80 => write!(f, "f80"),
            Type::Pointer(inner) => write!(f, "{}*", inner),
            Type::Array { elem, len } => write!(f, "[{}; {}]", elem, len),
            Type::Struct(s) => {
                if let Some(n) = &s.name { write!(f, "struct.{}", n) }
                else { write!(f, "struct{{..}}") }
            }
            Type::Union(u) => {
                if let Some(n) = &u.name { write!(f, "union.{}", n) }
                else { write!(f, "union{{..}}") }
            }
            Type::Function(ft) => {
                write!(f, "fn(")?;
                for (i, p) in ft.params.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", p)?;
                }
                if ft.variadic { write!(f, ", ...")?; }
                write!(f, ") -> {}", ft.ret)
            }
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Val::Local(id) => write!(f, "%{}", id.0),
            Val::Global(g) => write!(f, "@g{}", g.0),
            Val::Func(fr) => write!(f, "{}", func_label(*fr)),
            Val::Const(c) => write!(f, "{}", c),
        }
    }
}

impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constant::Int(v) => write!(f, "{}", v),
            Constant::UInt(v) => write!(f, "{}", v),
            Constant::Float(v) => write!(f, "{:.6}", v),
            Constant::Bool(b) => write!(f, "{}", b),
            Constant::Null => write!(f, "null"),
            Constant::Undef => write!(f, "undef"),
            Constant::Bytes(b) => write!(f, "\"{}\"", String::from_utf8_lossy(b).escape_default()),
            Constant::Zeroinit => write!(f, "zeroinit"),
            Constant::GlobalAddr(g) => write!(f, "&global{}", g.0),
        }
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOp::Add => "add", BinOp::Sub => "sub", BinOp::Mul => "mul",
            BinOp::SDiv => "sdiv", BinOp::UDiv => "udiv",
            BinOp::SRem => "srem", BinOp::URem => "urem",
            BinOp::FAdd => "fadd", BinOp::FSub => "fsub",
            BinOp::FMul => "fmul", BinOp::FDiv => "fdiv", BinOp::FRem => "frem",
            BinOp::And => "and", BinOp::Or => "or", BinOp::Xor => "xor",
            BinOp::Shl => "shl", BinOp::AShr => "ashr", BinOp::LShr => "lshr",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for CmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CmpOp::IEq => "ieq", CmpOp::INe => "ine",
            CmpOp::ISLt => "islt", CmpOp::ISLe => "isle",
            CmpOp::ISGt => "isgt", CmpOp::ISGe => "isge",
            CmpOp::IULt => "iult", CmpOp::IULe => "iule",
            CmpOp::IUGt => "iugt", CmpOp::IUGe => "iuge",
            CmpOp::FOEq => "foeq", CmpOp::FONe => "fone",
            CmpOp::FOLt => "folt", CmpOp::FOLe => "fole",
            CmpOp::FOGt => "fogt", CmpOp::FOGe => "foge",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instr::Alloca { dest, ty, align } => {
                write!(f, "  %{} = alloca {}", dest.0, ty)?;
                if let Some(a) = align { write!(f, " align {}", a)?; }
                Ok(())
            }
            Instr::Load { dest, ptr, ty } =>
                write!(f, "  %{} = load {} {}", dest.0, ty, ptr),
            Instr::Store { val, ptr } =>
                write!(f, "  store {}, {}", val, ptr),
            Instr::BinOp { dest, op, lhs, rhs, ty } =>
                write!(f, "  %{} = {} {} {}, {}", dest.0, op, ty, lhs, rhs),
            Instr::UnaryOp { dest, op, val, ty } =>
                write!(f, "  %{} = {:?} {} {}", dest.0, op, ty, val),
            Instr::Cast { dest, op, val, to_ty } =>
                write!(f, "  %{} = {:?} {} to {}", dest.0, op, val, to_ty),
            Instr::Cmp { dest, op, lhs, rhs, ty } =>
                write!(f, "  %{} = {} {} {}, {}", dest.0, op, ty, lhs, rhs),
            Instr::Call { dest, func, args, ret_ty } => {
                if let Some(d) = dest { write!(f, "  %{} = ", d.0)?; } else { write!(f, "  ")?; }
                write!(f, "call {} {}(", ret_ty, func_label(*func))?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", a)?;
                }
                write!(f, ")")
            }
            Instr::GetFieldPtr { dest, base, field_idx, struct_name, byte_offset, .. } =>
                write!(f, "  %{} = gfp {}.{} {} +{}", dest.0,
                    struct_name.as_deref().unwrap_or("?"), field_idx, base, byte_offset),
            Instr::GetElemPtr { dest, base, index, elem_size } =>
                write!(f, "  %{} = gep {}, {} *{}", dest.0, base, index, elem_size),
            Instr::PtrOffset { dest, base, offset } =>
                write!(f, "  %{} = ptroff {}, {}", dest.0, base, offset),
            Instr::Select { dest, cond, on_true, on_false, ty } =>
                write!(f, "  %{} = select {} {}, {}, {}", dest.0, ty, cond, on_true, on_false),
            Instr::MemCopy { dst, src, size, align } =>
                write!(f, "  memcopy {}, {}, size={}, align={}", dst, src, size, align),
            Instr::MemSet { dst, val, size, align } =>
                write!(f, "  memset {}, {}, size={}, align={}", dst, val, size, align),
            Instr::BSwap { dest, val, ty } =>
                write!(f, "  %{} = bswap {} {}", dest.0, ty, val),
            Instr::VaStart { list_ptr } => write!(f, "  va_start {}", list_ptr),
            Instr::VaArg { dest, list_ptr, ty } =>
                write!(f, "  %{} = va_arg {} {}", dest.0, ty, list_ptr),
            Instr::VaEnd { list_ptr } => write!(f, "  va_end {}", list_ptr),
            Instr::CallIndirect { dest, fptr, args, ret_ty, .. } => {
                if let Some(d) = dest { write!(f, "  %{} = ", d.0)?; } else { write!(f, "  ")?; }
                write!(f, "call_indirect {} {}(", ret_ty, fptr)?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", a)?;
                }
                write!(f, ")")
            }
            Instr::SrcLine(line) => write!(f, "  .loc {}", line),
            Instr::DbgVar { name, ty, slot, is_param } => write!(
                f, "  .dbgvar {} {} %{}{}", ty, name, slot.0,
                if *is_param { " (param)" } else { "" },
            ),
        }
    }
}

impl fmt::Display for Terminator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Terminator::Ret(None) => write!(f, "  ret void"),
            Terminator::Ret(Some(v)) => write!(f, "  ret {}", v),
            Terminator::Jump(b) => write!(f, "  jump bb{}", b.0),
            Terminator::CondJump { cond, then_bb, else_bb } =>
                write!(f, "  brif {}, bb{}, bb{}", cond, then_bb.0, else_bb.0),
            Terminator::Switch { val, default, arms } => {
                write!(f, "  switch {} default bb{}", val, default.0)?;
                for (v, b) in arms { write!(f, ", {} => bb{}", v, b.0)?; }
                Ok(())
            }
            Terminator::Unreachable => write!(f, "  unreachable"),
        }
    }
}

/// Pretty-print an entire module.
pub fn print_module(module: &Module) -> String {
    let mut out = String::new();
    out.push_str(&format!("; module: {}\n\n", module.name));

    for g in &module.globals {
        out.push_str(&format!("@{} : {} = {:?}\n", g.name, g.ty,
            g.init.as_ref().map(|c| format!("{}", c)).unwrap_or_else(|| "undef".into())));
    }
    if !module.globals.is_empty() { out.push('\n'); }

    for e in &module.externs {
        out.push_str(&format!("extern fn {}(", e.name));
        for (i, p) in e.sig.params.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("{}", p));
        }
        if e.sig.variadic { out.push_str(", ..."); }
        out.push_str(&format!(") -> {}\n", e.sig.ret));
    }
    if !module.externs.is_empty() { out.push('\n'); }

    for func in &module.functions {
        out.push_str(&format!("fn {}(", func.name));
        for (i, p) in func.params.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("{}: {}", p.name, p.ty));
        }
        if func.sig.variadic { out.push_str(", ..."); }
        out.push_str(&format!(") -> {} {{\n", func.sig.ret));

        for bb in &func.blocks {
            if let Some(lbl) = &bb.label {
                out.push_str(&format!("  bb{} ({}):\n", bb.id.0, lbl));
            } else {
                out.push_str(&format!("  bb{}:\n", bb.id.0));
            }
            for instr in &bb.instrs {
                out.push_str(&format!("{}\n", instr));
            }
            out.push_str(&format!("{}\n", bb.terminator));
        }
        out.push_str("}\n\n");
    }

    out
}
