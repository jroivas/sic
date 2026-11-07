//! IR types and C signatures as LLVM sees them.

use crate::Cx;
use crate::enum_attr;
use inkwell::attributes::{Attribute, AttributeLoc};
use inkwell::module::Linkage as LLinkage;
use inkwell::types::{AnyTypeEnum, BasicMetadataTypeEnum, BasicType, BasicTypeEnum, FunctionType as LFunctionType, IntType};
use inkwell::values::FunctionValue;
use inkwell::AddressSpace;
use sic_ir::abi::{classify_param, classify_struct_union, AggClass, Chunk, ParamPass, RegClass};
use sic_ir::{FunctionType, Type};

impl<'ctx> Cx<'ctx, '_> {
    pub fn ptr(&self) -> BasicTypeEnum<'ctx> { self.ctx.ptr_type(AddressSpace::default()).into() }

    /// An integer type of any width; `bits` is not zero.
    pub fn int_type(&self, bits: u32) -> IntType<'ctx> {
        self.ctx.custom_width_int_type(std::num::NonZero::new(bits).expect("integer width")).expect("integer width")
    }

    /// The type of a value of IR type `t`. An aggregate flows as a pointer, and a
    /// `long double` as a `double`: `x86_fp80` is only in memory and at calls.
    pub fn value_type(&self, t: &Type) -> BasicTypeEnum<'ctx> {
        match t {
            Type::Void => self.ctx.i32_type().into(),
            Type::Bool => self.ctx.i8_type().into(),
            Type::Int { bits, .. } => match bits {
                1..=8 => self.ctx.i8_type().into(),
                9..=16 => self.ctx.i16_type().into(),
                17..=32 => self.ctx.i32_type().into(),
                65..=128 => self.ctx.i128_type().into(),
                _ => self.ctx.i64_type().into(),
            },
            Type::Float32 => self.ctx.f32_type().into(),
            Type::Float64 | Type::Float80 => self.ctx.f64_type().into(),
            Type::Pointer(_) | Type::Function(_) | Type::Array { .. } | Type::Struct(_) | Type::Union(_) => self.ptr(),
        }
    }

    /// `value_type`, but a 128-bit SIMD array is a vector.
    pub fn operand_type(&self, t: &Type) -> BasicTypeEnum<'ctx> {
        self.vector_type(t).unwrap_or_else(|| self.value_type(t))
    }

    pub fn vector_type(&self, t: &Type) -> Option<BasicTypeEnum<'ctx>> {
        let (elem, lanes) = t.simd128()?;
        let lanes = lanes as u32;
        Some(match elem {
            Type::Float32 => self.ctx.f32_type().vec_type(lanes).into(),
            Type::Float64 => self.ctx.f64_type().vec_type(lanes).into(),
            Type::Int { bits: 8, .. } => self.ctx.i8_type().vec_type(lanes).into(),
            Type::Int { bits: 16, .. } => self.ctx.i16_type().vec_type(lanes).into(),
            Type::Int { bits: 32, .. } => self.ctx.i32_type().vec_type(lanes).into(),
            Type::Int { bits: 64, .. } => self.ctx.i64_type().vec_type(lanes).into(),
            _ => return None,
        })
    }

    pub fn chunk_type(&self, c: &Chunk) -> BasicTypeEnum<'ctx> {
        match c.class {
            RegClass::Int => self.ctx.i64_type().into(),
            RegClass::Sse if c.bytes <= 4 => self.ctx.f32_type().into(),
            RegClass::Sse => self.ctx.f64_type().into(),
        }
    }

    /// What a function returns at the C ABI, if anything: a small aggregate as its
    /// eightbytes. A MEMORY aggregate has the frontend's hidden pointer instead.
    pub fn return_type(&self, ret: &Type) -> Option<BasicTypeEnum<'ctx>> {
        // `_Complex long double` comes back in `st(0)` and `st(1)`.
        if sic_ir::abi::ret_in_x87_pair(ret, self.opts.ptr_size) {
            let f = self.ctx.x86_f80_type().into();
            return Some(self.ctx.struct_type(&[f, f], false).into());
        }
        match ret {
            Type::Struct(_) | Type::Union(_) => match classify_struct_union(ret, self.opts.ptr_size) {
                AggClass::Regs(chunks) if chunks.len() == 1 => Some(self.chunk_type(&chunks[0])),
                AggClass::Regs(chunks) => {
                    let f: Vec<BasicTypeEnum> = chunks.iter().map(|c| self.chunk_type(c)).collect();
                    Some(self.ctx.struct_type(&f, false).into())
                }
                AggClass::Memory(_) => None,
            },
            Type::Array { .. } | Type::Void => None,
            Type::Float80 => Some(self.ctx.x86_f80_type().into()),
            other => Some(self.value_type(other)),
        }
    }

    /// The LLVM parameters of one IR parameter, with their attributes.
    pub fn param_abi(&self, ty: &Type) -> Vec<(BasicTypeEnum<'ctx>, Vec<Attribute>)> {
        match classify_param(ty, self.opts.ptr_size) {
            ParamPass::Scalar => vec![(self.value_type(ty), self.ext_attr(ty).into_iter().collect())],
            ParamPass::Direct(chunks) => chunks.iter().map(|c| (self.chunk_type(c), Vec::new())).collect(),
            ParamPass::ByValStack(size, align) => vec![(self.ptr(), self.byval_attrs(size, align))],
            ParamPass::X87 => vec![(self.ctx.x86_f80_type().into(), Vec::new())],
        }
    }

    /// A by-value stack block: stack slots (8 bytes, 4 on i386), and what the
    /// type asks beyond that.
    pub fn byval_attrs(&self, size: u32, align: u32) -> Vec<Attribute> {
        let slot = self.opts.ptr_size;
        let block: AnyTypeEnum = self.ctx.i8_type().array_type((size + slot - 1) & !(slot - 1)).into();
        let kind = Attribute::get_named_enum_kind_id("byval");
        vec![self.ctx.create_type_attribute(kind, block), enum_attr(self.ctx, "align", align.max(slot) as u64)]
    }

    /// The hidden result pointer of an aggregate returned in memory is `sret`: the
    /// callee returns it in `rax` (x86-64) or pops it (`ret $4`, i386).
    pub fn sret_attr(&self, ret: &Type) -> Option<Attribute> {
        if !matches!(ret, Type::Struct(_) | Type::Union(_)) || !sic_ir::abi::ret_in_memory(ret, self.opts.ptr_size) {
            return None;
        }
        let block: AnyTypeEnum = self.ctx.i8_type().array_type(ret.size_of(self.opts.ptr_size).max(1) as u32).into();
        Some(self.ctx.create_type_attribute(Attribute::get_named_enum_kind_id("sret"), block))
    }

    /// A narrow integer is extended to 32 bits at the boundary (SysV, gcc).
    pub fn ext_attr(&self, ty: &Type) -> Option<Attribute> {
        match ty {
            Type::Bool => Some(enum_attr(self.ctx, "zeroext", 0)),
            Type::Int { bits, signed } if *bits < 32 => Some(enum_attr(self.ctx, if *signed { "signext" } else { "zeroext" }, 0)),
            _ => None,
        }
    }

    /// The function type of `ret` with these (already ABI-expanded) parameters.
    pub fn fn_type(&self, ret: &Type, params: &[BasicTypeEnum<'ctx>], variadic: bool) -> LFunctionType<'ctx> {
        let meta: Vec<BasicMetadataTypeEnum> = params.iter().map(|t| (*t).into()).collect();
        match self.return_type(ret) {
            Some(t) => t.fn_type(&meta, variadic),
            None => self.ctx.void_type().fn_type(&meta, variadic),
        }
    }
}

pub fn declare<'ctx>(cx: &Cx<'ctx, '_>, name: &str, sig: &FunctionType, linkage: Option<LLinkage>) -> FunctionValue<'ctx> {
    let params: Vec<&Type> = sig.params.iter().filter(|t| !matches!(t, Type::Void)).collect();
    let abi: Vec<_> = params.iter().flat_map(|t| cx.param_abi(t)).collect();
    let tys: Vec<BasicTypeEnum> = abi.iter().map(|(t, _)| *t).collect();
    let lf = cx.module.add_function(name, cx.fn_type(&sig.ret, &tys, sig.variadic), linkage);
    for (i, (_, attrs)) in abi.iter().enumerate() {
        for a in attrs { lf.add_attribute(AttributeLoc::Param(i as u32), *a); }
    }
    if let Some(a) = cx.ext_attr(&sig.ret) { lf.add_attribute(AttributeLoc::Return, a); }
    if let Some(a) = cx.sret_attr(&sig.ret) { lf.add_attribute(AttributeLoc::Param(0), a); }
    lf
}
