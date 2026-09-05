use crate::ast::{self, Expr, ExprKind, BinOpKind, UnOpKind};
use crate::{Result, CompileError};
use sic_ir::*;
use super::func::{FuncCtx, LookupResult};

/// The result of lowering a "location" (lvalue) — a pointer to the storage.
struct LValue {
    ptr: Val,
    ty: Type,    // type of the pointee
    /// Set when the location is a bit-field: (bit offset within the storage unit
    /// pointed to by `ptr`, width in bits, whether the field is signed). Reads
    /// and writes go through masked load/store.
    bitfield: Option<BitField>,
    /// sic `atomic` (sic.md §"Atomics"): the location holds an atomic object, so
    /// reads/stores/RMW go through the atomic IR ops.
    atomic: bool,
}

#[derive(Clone, Copy)]
pub(super) struct BitField {
    pub(super) bit_offset: u32,
    pub(super) width: u32,
    pub(super) signed: bool,
}

impl BitField {
    pub(super) fn new(bit_offset: u32, width: u32, signed: bool) -> Self {
        BitField { bit_offset, width, signed }
    }
}

/// Which AES-NI round intrinsic to emulate.
#[derive(Clone, Copy)]
enum AesMode { Enc, EncLast, Dec, DecLast, Imc }

/// AES forward S-box.
static AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// AES inverse S-box.
static AES_INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

impl LValue {
    fn plain(ptr: Val, ty: Type) -> Self { LValue { ptr, ty, bitfield: None, atomic: false } }
}

impl<'m> FuncCtx<'m> {
    /// Emit a NUL-terminated string as a private global and return a pointer to
    /// its first element (the decayed `char *` value).
    pub fn emit_cstring(&mut self, s: &str) -> Val {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // null terminate
        let name = format!(".str.{}", self.lowerer.module.globals.len());
        let len = bytes.len();
        let g = Global {
            name,
            ty: Type::Array { elem: Box::new(Type::i8()), len },
            init: Some(Constant::Bytes(bytes)),
            linkage: Linkage::Private,
            constant: true,
            thread_local: false,
        };
        let gref = self.lowerer.module.add_global(g);
        let ptr_id = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: ptr_id,
            base: Val::Global(gref),
            index: Constant::zero(),
            elem_size: 1,
            result_ty: Type::char_ptr(),
        });
        Val::Local(ptr_id)
    }

    /// Emit (once per canonical name) a static `__sic_type_info` record and return
    /// a `type` value pointing at it (sic.md §"RTTI"). `name` is the canonical
    /// spelling (`type_name_of`); `kind`/`size` classify the type for formatters.
    pub(super) fn emit_type_info(&mut self, name: &str, kind: u32, size: u32) -> Val {
        use super::types as t;
        let gref = if let Some(&g) = self.lowerer.type_info_globals.get(name) {
            g
        } else {
            // The canonical name string (a private cstring the record points at).
            let mut nb = name.as_bytes().to_vec();
            nb.push(0);
            let name_g = {
                let gn = format!(".str.{}", self.lowerer.module.globals.len());
                let len = nb.len();
                let g = Global {
                    name: gn,
                    ty: Type::Array { elem: Box::new(Type::i8()), len },
                    init: Some(Constant::Bytes(nb)),
                    linkage: Linkage::Private, constant: true, thread_local: false,
                };
                self.lowerer.module.add_global(g)
            };
            // The record: opaque bytes with a pointer reloc for `name`.
            let id = t::type_id_hash(name);
            let mut b = vec![0u8; t::TYPEINFO_REC_SIZE];
            b[t::TYPEINFO_OFF_ID..t::TYPEINFO_OFF_ID + 8].copy_from_slice(&id.to_le_bytes());
            b[t::TYPEINFO_OFF_SIZE..t::TYPEINFO_OFF_SIZE + 4].copy_from_slice(&size.to_le_bytes());
            b[t::TYPEINFO_OFF_KIND..t::TYPEINFO_OFF_KIND + 4].copy_from_slice(&kind.to_le_bytes());
            let rec = Global {
                name: format!(".typeinfo.{}", self.lowerer.module.globals.len()),
                ty: Type::Array { elem: Box::new(Type::i8()), len: t::TYPEINFO_REC_SIZE },
                init: Some(Constant::Aggregate {
                    bytes: b,
                    relocs: vec![(t::TYPEINFO_OFF_NAME, RelocTarget::Global(name_g, 0))],
                }),
                linkage: Linkage::Private, constant: true, thread_local: false,
            };
            let g = self.lowerer.module.add_global(rec);
            self.lowerer.type_info_globals.insert(name.to_string(), g);
            g
        };
        let ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: ptr, base: Val::Global(gref), index: Constant::zero(),
            elem_size: 1, result_ty: t::type_info_type(),
        });
        self.val_types.insert(ptr.0, t::type_info_type());
        Val::Local(ptr)
    }

    /// Load a field from a `type` value's `__sic_type_info` record (sic.md §"RTTI").
    /// `.str`/`.name` → `char*`; `.id` → `u64`; `.size`/`.kind` → `u32`.
    pub(crate) fn emit_type_info_field(&mut self, base: &Expr, name: &str) -> Result<Val> {
        use super::types as t;
        let rec = self.lower_expr(base)?; // pointer to the record
        let (off, fty) = match name {
            "str" | "name" => (t::TYPEINFO_OFF_NAME, Type::char_ptr()),
            "id"           => (t::TYPEINFO_OFF_ID, Type::u64()),
            "size"         => (t::TYPEINFO_OFF_SIZE, Type::u32()),
            _              => (t::TYPEINFO_OFF_KIND, Type::u32()), // "kind"
        };
        let fptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: fptr, base: rec, index: Constant::int(off as i64),
            elem_size: 1, result_ty: Type::Pointer(Box::new(fty.clone())),
        });
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(fptr), ty: fty.clone() });
        self.val_types.insert(dest.0, fty);
        Ok(Val::Local(dest))
    }

    /// Load the `id` (u64) from a `type` value's record (sic.md §"RTTI").
    fn load_type_id(&mut self, e: &Expr) -> Result<Val> {
        use super::types as t;
        let rec = self.lower_expr(e)?;
        let fptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: fptr, base: rec, index: Constant::int(t::TYPEINFO_OFF_ID as i64),
            elem_size: 1, result_ty: Type::Pointer(Box::new(Type::u64())),
        });
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(fptr), ty: Type::u64() });
        self.val_types.insert(dest.0, Type::u64());
        Ok(Val::Local(dest))
    }

    /// Lower `type(a) == type(b)` / `!=` by comparing the records' `id` fields
    /// (sic.md §"RTTI") → an `i32` boolean.
    fn lower_type_compare(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let a = self.load_type_id(lhs)?;
        let b = self.load_type_id(rhs)?;
        self.emit_binop(op, a, b)
    }

    /// Lower a `type` value for a concrete IR type (sic.md §"RTTI").
    pub(super) fn lower_type_value(&mut self, ty: &Type) -> Val {
        let name = self.type_name_of(ty);
        let kind = super::types::type_kind(ty);
        let size = ty.size_of(self.ptr_size()) as u32;
        self.emit_type_info(&name, kind, size)
    }

    /// Box a value into an `any` (sic.md std): `{ ty = typeid(static type); slot =
    /// the value }` — the slot holds a scalar's bits (int zero/sign-extended, float
    /// bit-cast) or a pointer for an aggregate (string/fixed/bigint/…). Returns a
    /// pointer to the `any` struct (aggregate-by-pointer rvalue); an already-`any`
    /// value passes through.
    pub(super) fn box_any(&mut self, e: &Expr) -> Result<Val> {
        let ty = self.infer_expr_type(e).unwrap_or_else(|_| Type::i32());
        if super::types::is_any(&ty) { return self.lower_expr(e); }
        let sp = e.span.clone();
        let tyval = self.lower_type_value(&ty);
        let slot = self.box_slot(e, &ty)?;
        let any_ty = super::types::any_type();
        let p = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: p, ty: any_ty.clone(), align: None });
        self.val_types.insert(p.0, any_ty.clone());
        let ty_lv = self.field_ptr_from(LValue::plain(Val::Local(p), any_ty.clone()), "ty", false, &sp)?;
        self.store_lvalue(&ty_lv, tyval)?;
        let slot_lv = self.field_ptr_from(LValue::plain(Val::Local(p), any_ty.clone()), "slot", false, &sp)?;
        self.store_lvalue(&slot_lv, slot)?;
        Ok(Val::Local(p))
    }

    /// Lower `va[i]` (sic.md std): `data + i*sizeof(any)` — a pointer to the i-th
    /// boxed `any` (the aggregate-by-pointer rvalue).
    fn lower_va_array_index(&mut self, base: &Expr, index: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let any_ty = super::types::any_type();
        let any_sz = any_ty.size_of(self.ptr_size()) as i64;
        let p = self.lower_aggregate_ptr(base)?;
        let data_lv = self.field_ptr_from(LValue::plain(p, super::types::va_array_type(self.ptr_size())), "data", false, sp)?;
        let data = self.load_lvalue(&data_lv)?; // any*
        let iv = self.lower_expr(index)?;
        let iv = self.coerce(iv, &Type::i64())?;
        let elem = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: elem, base: data, index: iv,
            elem_size: any_sz as u64, result_ty: Type::Pointer(Box::new(any_ty.clone())),
        });
        self.val_types.insert(elem.0, any_ty);
        Ok(Val::Local(elem))
    }

    /// Lower `cps[i]` on a `u8char[]` (from `string.utf8`) → a pointer to the i-th
    /// `u8char` (aggregate-by-pointer rvalue).
    fn lower_u8char_arr_index(&mut self, base: &Expr, index: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let u8c = super::types::u8char_type();
        let u8c_sz = u8c.size_of(self.ptr_size()) as i64;
        let p = self.lower_aggregate_ptr(base)?;
        let data_lv = self.field_ptr_from(LValue::plain(p, super::types::u8char_arr_type(self.ptr_size())), "data", false, sp)?;
        let data = self.load_lvalue(&data_lv)?; // u8char*
        let iv = self.lower_expr(index)?;
        let iv = self.coerce(iv, &Type::i64())?;
        let elem = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: elem, base: data, index: iv,
            elem_size: u8c_sz as u64, result_ty: Type::Pointer(Box::new(u8c.clone())),
        });
        self.val_types.insert(elem.0, u8c);
        Ok(Val::Local(elem))
    }

    /// Pack a call's trailing arguments into a `va_array` (sic.md std): box each
    /// into an `any`, lay them out in a stack array, and build the `{ data, len }`
    /// slice. Returns a pointer to the slice value (aggregate-by-pointer).
    fn pack_va_array(&mut self, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let any_ty = super::types::any_type();
        let any_sz = any_ty.size_of(self.ptr_size());
        let any_al = any_ty.align_of(self.ptr_size());
        let n = args.len();
        // A run of `n` boxed `any` values (n == 0 → a 1-elem alloca, len stays 0).
        let arr = self.alloc_val();
        let arr_ty = Type::Array { elem: Box::new(any_ty.clone()), len: n.max(1) };
        self.push_instr(Instr::Alloca { dest: arr, ty: arr_ty, align: None });
        for (i, a) in args.iter().enumerate() {
            let boxed = self.box_any(a)?; // pointer to a fresh `any`
            let slot = self.alloc_val();
            self.push_instr(Instr::GetElemPtr {
                dest: slot, base: Val::Local(arr), index: Constant::int((i * any_sz as usize) as i64),
                elem_size: 1, result_ty: Type::Pointer(Box::new(any_ty.clone())),
            });
            self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: boxed, size: any_sz, align: any_al });
        }
        // Build the { data, len } slice.
        let va_ty = super::types::va_array_type(self.ptr_size());
        let p = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: p, ty: va_ty.clone(), align: None });
        self.val_types.insert(p.0, va_ty.clone());
        let data_lv = self.field_ptr_from(LValue::plain(Val::Local(p), va_ty.clone()), "data", false, sp)?;
        let dptr = self.coerce(Val::Local(arr), &Type::Pointer(Box::new(any_ty)))?;
        self.store_lvalue(&data_lv, dptr)?;
        let len_lv = self.field_ptr_from(LValue::plain(Val::Local(p), va_ty.clone()), "len", false, sp)?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let lenv = self.coerce(Constant::uint(n as u64), &usize_ty)?;
        self.store_lvalue(&len_lv, lenv)?;
        Ok(Val::Local(p))
    }

    /// Pack a call's *named* trailing arguments into a `va_dict` (sic.md §"Named
    /// parameters"): a fresh `dict<string, any>` mapping each argument's name to its
    /// value boxed as `any`. Returns the dict handle.
    fn pack_va_dict(&mut self, named: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let vd_ty = super::types::va_dict_type();
        // No named arguments → pass a null handle (no allocation). The runtime
        // treats a null dict as empty, so a lookup on it just misses.
        if named.is_empty() {
            let z = self.alloc_val();
            self.push_instr(Instr::Cast { dest: z, op: CastOp::BitCast, val: Constant::uint(0), to_ty: vd_ty.clone() });
            self.val_types.insert(z.0, vd_ty);
            return Ok(Val::Local(z));
        }
        let handle = self.lower_dict_new(&vd_ty, sp)?;
        // Free this per-call va_dict at the end of the statement (the callee only
        // borrows it for the duration of the call).
        self.va_dict_temps.push(handle.clone());
        let set = self.dict_runtime_fn("__sic_dict_set");
        for arg in named {
            if let ExprKind::NamedArg { name, value } = &arg.kind {
                // Key: the argument name as a string (kind 2 = string bytes).
                let name_data = self.emit_cstring(name);
                let ka = self.alloc_val();
                self.push_instr(Instr::Cast { dest: ka, op: CastOp::BitCast, val: name_data, to_ty: Type::u64() });
                self.val_types.insert(ka.0, Type::u64());
                let kb = Constant::uint(name.len() as u64);
                // Value: box into (type-info, slot).
                let ety = self.infer_expr_type(value).unwrap_or_else(|_| Type::i32());
                let tyval = self.lower_type_value(&ety);
                let tyw = self.alloc_val();
                self.push_instr(Instr::Cast { dest: tyw, op: CastOp::BitCast, val: tyval, to_ty: Type::u64() });
                self.val_types.insert(tyw.0, Type::u64());
                let slot = self.box_slot(value, &ety)?;
                self.push_instr(Instr::Call {
                    dest: None, func: set,
                    // vowned = 0: the values borrow the caller's temporaries, which
                    // outlive the call the va_dict is consumed in.
                    args: vec![handle.clone(), Constant::int(2), Val::Local(ka), kb, Val::Local(tyw), slot, Constant::int(0)],
                    ret_ty: Type::Void,
                });
            }
        }
        Ok(handle)
    }

    /// The 64-bit `slot` stored in an `any` for a value of type `ty`.
    fn box_slot(&mut self, e: &Expr, ty: &Type) -> Result<Val> {
        // Store the value's address. `fixed`/`bigint`/pointer rvalues are already a
        // pointer-typed value; `string`/tuple/struct rvalues are the STRUCT type but
        // a pointer at the machine level, so take their address via
        // `lower_aggregate_ptr` (a real pointer-typed value) before reinterpreting.
        let is_ptr_val = super::types::is_fixed(ty) || super::types::is_bigint(ty)
            || matches!(ty, Type::Pointer(_));
        let is_aggr = super::types::is_sic_string(ty) || super::types::is_tuple(ty)
            || matches!(ty, Type::Struct(_) | Type::Union(_) | Type::Array { .. });
        if is_ptr_val || is_aggr {
            let v = if is_ptr_val { self.lower_expr(e)? } else { self.lower_aggregate_ptr(e)? };
            let dest = self.alloc_val();
            self.push_instr(Instr::Cast { dest, op: CastOp::BitCast, val: v, to_ty: Type::u64() });
            self.val_types.insert(dest.0, Type::u64());
            return Ok(Val::Local(dest));
        }
        let v = self.lower_expr(e)?;
        if matches!(ty, Type::Float32 | Type::Float64 | Type::Float80) {
            // Reinterpret the float's bits as u64 via a memory round-trip (a
            // float↔int BitCast converts the value here, not the bits).
            let d = self.coerce(v, &Type::Float64)?;
            let mem = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: mem, ty: Type::Float64, align: None });
            self.push_instr(Instr::Store { val: d, ptr: Val::Local(mem) });
            let out = self.alloc_val();
            self.push_instr(Instr::Load { dest: out, ptr: Val::Local(mem), ty: Type::u64() });
            self.val_types.insert(out.0, Type::u64());
            return Ok(Val::Local(out));
        }
        self.coerce(v, &Type::u64()) // int / bool / char → zero/sign-extend
    }

    /// Downcast an `any` value to `target` (sic.md std): read the `slot` and
    /// reinterpret it as the target — a scalar's bits (int truncate, float bit-cast)
    /// or an aggregate pointer (string/fixed/bigint/…). No runtime type check yet.
    fn unbox_any(&mut self, inner: &Expr, target: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let p = self.lower_aggregate_ptr(inner)?;
        let slot_lv = self.field_ptr_from(LValue::plain(p, super::types::any_type()), "slot", false, sp)?;
        let slot = self.load_lvalue(&slot_lv)?; // u64
        self.reinterpret_slot(slot, target)
    }

    /// Reinterpret a 64-bit `slot` (from an `any` box or a dict value) as `target`:
    /// a float's bits (memory round-trip), an aggregate/pointer address (bit-cast,
    /// aggregate-by-pointer rvalue), or a scalar (coerce).
    fn reinterpret_slot(&mut self, slot: Val, target: &Type) -> Result<Val> {
        if matches!(target, Type::Float32 | Type::Float64 | Type::Float80) {
            // Reinterpret the u64 bits as a float via a memory round-trip.
            let mem = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: mem, ty: Type::u64(), align: None });
            self.push_instr(Instr::Store { val: slot, ptr: Val::Local(mem) });
            let dest = self.alloc_val();
            self.push_instr(Instr::Load { dest, ptr: Val::Local(mem), ty: Type::Float64 });
            self.val_types.insert(dest.0, Type::Float64);
            return self.coerce(Val::Local(dest), target);
        }
        // Aggregates / pointers: the slot holds the value's address; reinterpret it
        // as a pointer and label it as the value type (aggregate-by-pointer rvalue).
        if super::types::is_sic_string(target) || super::types::is_fixed(target)
            || super::types::is_bigint(target) || super::types::is_tuple(target)
            || matches!(target, Type::Pointer(_) | Type::Struct(_) | Type::Union(_))
        {
            let dest = self.alloc_val();
            self.push_instr(Instr::Cast { dest, op: CastOp::BitCast, val: slot, to_ty: Type::void_ptr() });
            self.val_types.insert(dest.0, target.clone());
            return Ok(Val::Local(dest));
        }
        // Scalar integer / bool / char.
        self.coerce(slot, target)
    }

    /// Lower `e` with `ty` as the expected/target type (sic.md §"Match") — lets a
    /// generic constructor `Option::Some(5)` / `None` resolve to its monomorph.
    /// Saves/restores the previous hint so nesting is safe.
    pub(super) fn lower_expr_expecting(&mut self, e: &Expr, ty: &Type) -> Result<Val> {
        let prev = self.expected_ty.replace(ty.clone());
        let r = self.lower_expr(e);
        self.expected_ty = prev;
        r
    }

    /// Lower an expression, returning its rvalue.
    pub fn lower_expr(&mut self, expr: &Expr) -> Result<Val> {
        match &expr.kind {
            ExprKind::Generic { controlling, assocs } => {
                let idx = self.select_generic(controlling, assocs)?;
                self.lower_expr(&assocs[idx].1)
            }
            ExprKind::OffsetOf { ty, designators } => {
                self.lower_offsetof(ty, designators)
            }
            // Widen a 64-bit literal to its declared width so its runtime type
            // isn't the default 32-bit (needed for e.g. `1LL << 40`). For a
            // large-magnitude value `val_type` already reports 64-bit, so the
            // coercion is a no-op there and only kicks in for small-valued but
            // suffix-typed literals.
            ExprKind::IntLit(v, is64) => {
                let c = Constant::int(*v);
                if *is64 { self.coerce(c, &Type::i64()) } else { Ok(c) }
            }
            ExprKind::UIntLit(v, is64) => {
                let c = Constant::uint(*v);
                if *is64 { self.coerce(c, &Type::Int { bits: 64, signed: false }) } else { Ok(c) }
            }
            // sic `true`/`false`: a `bool`-typed constant (its `val_type` is `Bool`).
            // Any conversion to int happens later at a use site via `coerce`.
            ExprKind::BoolLit(b) => Ok(Val::Const(Constant::Bool(*b))),
            ExprKind::FloatLit(v) => Ok(Val::Const(Constant::Float(*v))),
            // A plain decimal literal in a non-fixed context is a `double` — parse
            // its exact text to f64. (A `fixed` binding intercepts it earlier and
            // never goes through this float path.)
            ExprKind::DecimalLit(text) => {
                let v: f64 = text.parse().unwrap_or(0.0);
                Ok(Val::Const(Constant::Float(v)))
            }
            // sic RTTI (sic.md §"RTTI"): `typeid(x)` / `type(x)` → a `type` value.
            // The operand is not evaluated — only its static type is used. A bare
            // decimal literal reports its natural `fixed<I,F>` (matching typestr).
            ExprKind::TypeId(inner) => {
                let ty = self.infer_expr_type(inner).unwrap_or(Type::i32());
                // `type(anyval)` is DYNAMIC — read the boxed value's runtime `ty`
                // field (sic.md std) — unlike a statically-typed operand.
                if super::types::is_any(&ty) {
                    let p = self.lower_aggregate_ptr(inner)?;
                    let lv = self.field_ptr_from(LValue::plain(p, super::types::any_type()), "ty", false, &expr.span)?;
                    return self.load_lvalue(&lv);
                }
                let name = self.type_name_string(inner, &ty);
                let kind = super::types::type_kind(&ty);
                let size = ty.size_of(self.ptr_size()) as u32;
                Ok(self.emit_type_info(&name, kind, size))
            }
            ExprKind::TypeIdOf(qty) => {
                let ty = self.lower_type(qty)?;
                Ok(self.lower_type_value(&ty))
            }
            // sic none/null-safe access `base?.field` (sic.md §"Match").
            ExprKind::OptField { base, name } => self.lower_opt_field(base, name, &expr.span),
            // sic exception-guard block (sic.md §"Integer overflow", §"Errors and
            // exceptions"): run `body` with the matching exception caught; yields
            // `0` on clean completion, `1` if the exception fired.
            ExprKind::Guard { kind, body } => self.lower_guard(*kind, body),
            ExprKind::CharLit(v) => Ok(Constant::int(*v as i64)),
            ExprKind::StringLit(s) => {
                let data = self.emit_cstring(s);
                // sic (sic.md §"Strings"): a string literal is a native `string` view
                // over the static bytes — unless a `char*` is wanted (assigned to a
                // `char*`, a `char*` parameter, or C). Then it stays the raw pointer.
                if !self.is_sic() || self.expected_is_char_ptr() {
                    return Ok(data);
                }
                // View: {data, size = compile-time length, rc = NULL (static, never freed)}.
                let size = self.coerce(Constant::int(s.len() as i64),
                    &Type::Int { bits: self.ptr_size() * 8, signed: false })?;
                let rc = self.coerce(Constant::zero(), &self.rc_ptr_ty())?;
                self.make_string_val(data, size, rc)
            }
            ExprKind::Nullptr => Ok(Constant::null()),

            ExprKind::Ident(name) => {
                let atomic = self.is_atomic_name(name);
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, vid)) => {
                        let ty = ty.clone();
                        // Arrays and structs decay to pointer-to-first-element in rvalue context
                        if matches!(ty, Type::Array { .. }) {
                            return Ok(Val::Local(vid));
                        }
                        let dest = self.alloc_val();
                        if atomic {
                            self.push_instr(Instr::AtomicLoad { dest, ptr: Val::Local(vid), ty });
                        } else {
                            self.push_instr(Instr::Load { dest, ptr: Val::Local(vid), ty });
                        }
                        Ok(Val::Local(dest))
                    }
                    Some(LookupResult::Global(ty, gref)) => {
                        let ty = ty.clone();
                        // Arrays decay to pointer in rvalue context
                        if matches!(ty, Type::Array { .. }) {
                            return Ok(Val::Global(gref));
                        }
                        let dest = self.alloc_val();
                        if atomic {
                            self.push_instr(Instr::AtomicLoad { dest, ptr: Val::Global(gref), ty });
                        } else {
                            self.push_instr(Instr::Load { dest, ptr: Val::Global(gref), ty });
                        }
                        Ok(Val::Local(dest))
                    }
                    // A bare tagged-enum variant is its integer discriminant here;
                    // an int→enum-struct `coerce` builds the value when the target
                    // is the enum (e.g. `Test x = BLACK;`), and enum→int reads the
                    // tag (`(int)x`). See `coerce`.
                    Some(LookupResult::EnumConst(v)) => Ok(Constant::int(v)),
                    Some(LookupResult::Func(fref)) => Ok(Val::Func(fref)),
                    None => {
                        // Compiler-provided predefined identifiers that expand to a
                        // string literal naming the enclosing function. Unlike
                        // __FILE__/__LINE__ these are not preprocessor macros, so we
                        // synthesize them here natively.
                        match name.as_str() {
                            "__func__" | "__FUNCTION__" => {
                                let fname = self.func_ref().name.clone();
                                return Ok(self.emit_cstring(&fname));
                            }
                            "__PRETTY_FUNCTION__" => {
                                let pretty = self.pretty_func.clone();
                                return Ok(self.emit_cstring(&pretty));
                            }
                            _ => {}
                        }
                        Err(CompileError::at(
                            format!("undefined name '{}'", name),
                            expr.span.file.clone(), expr.span.line, expr.span.col,
                        ))
                    }
                }
            }

            ExprKind::BinOp { op, lhs, rhs } => self.lower_binop(*op, lhs, rhs),

            ExprKind::Assign { op, lhs, rhs } => self.lower_assign(*op, lhs, rhs),

            ExprKind::Swap { lhs, rhs } => self.lower_swap(lhs, rhs),

            ExprKind::Slice { base, lo, hi } => self.lower_slice(base, lo.as_deref(), hi.as_deref()),

            ExprKind::New { ty, args } => self.lower_new(ty, args),

            ExprKind::Ref { expr, .. } => self.lower_ref(expr),

            ExprKind::Unary { op, expr: inner } => self.lower_unary(*op, inner),

            ExprKind::PreInc { inc, expr: inner } => self.lower_pre_inc(*inc, inner),
            ExprKind::PostInc { inc, expr: inner } => self.lower_post_inc(*inc, inner),

            ExprKind::Ternary { cond, then, else_ } => self.lower_ternary(cond, then, else_),
            ExprKind::Elvis { cond, else_ } => self.lower_elvis(cond, else_),
            ExprKind::Match { scrutinee, arms } => self.lower_match_expr(scrutinee, arms, &expr.span),

            ExprKind::Call { func, args } => self.lower_call(func, args, &expr.span),

            // sic `await expr` (sic.md §"Async").
            ExprKind::Await(inner) => self.lower_await(inner),

            // sic named argument (sic.md §"Named parameters") outside a call's
            // argument list — the call site resolves these, so reaching here means
            // `name = value` was written where a value was expected.
            ExprKind::NamedArg { name, .. } => Err(CompileError::at(
                format!("named argument `{} = …` is only allowed in a function call", name),
                expr.span.file.clone(), expr.span.line, expr.span.col)),

            // sic generic functions (sic.md §"Generics"): `add<int>` outside a call
            // has no single symbol to name — it must be applied.
            ExprKind::GenericRef { name, .. } => Err(CompileError::at(
                format!("generic function `{}` must be called (`{}<…>(…)`)", name, name),
                expr.span.file.clone(), expr.span.line, expr.span.col)),

            // Bare tagged-enum variant used as a value, e.g. `Option::None`
            // (a payload-less constructor). A payload variant needs `(...)`.
            ExprKind::EnumVariant { enum_name, variant } => {
                // sic (sic.md §"Namespace"): `N::member` is a namespace member value.
                if self.is_sic() {
                    if let Some(mangled) = self.lowerer.namespace_members.get(&(enum_name.clone(), variant.clone())).cloned() {
                        return self.lower_expr(&Expr { kind: ExprKind::Ident(mangled), span: expr.span.clone() });
                    }
                }
                self.construct_enum(enum_name, variant, &[], &expr.span)
            }

            // sic tuple pack `tuple(e0, e1, …)` (sic.md §"Tuples"). As an rvalue
            // it builds the tuple; the unpack form (LHS of `=`) is handled in
            // `lower_assign`, so reaching here as a value is always a pack.
            ExprKind::TupleExpr(elems) => self.construct_tuple(elems, &expr.span),

            // sic oversized decimal literal → a fresh `bigint` (sic.md §"Integer
            // sizes"). Reaches here when used as a value directly.
            ExprKind::BigIntLit(_) => self.to_bigint(expr),

            ExprKind::Index { base, index } => {
                // sic `list[i]` read (sic.md §"List").
                if self.is_sic() && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_list(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_list(i))) {
                    return self.lower_list_get(base, index, &expr.span);
                }
                // sic `dict[key]` read (sic.md §"Dict").
                if self.is_sic() && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_dict(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_dict(i))) {
                    return self.lower_dict_get(base, index, &expr.span);
                }
                // sic `va_array` element `args[i]` → a pointer to the i-th `any`
                // (aggregate-by-pointer rvalue), sic.md std.
                if self.is_sic() && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_va_array(&t)) {
                    return self.lower_va_array_index(base, index, &expr.span);
                }
                if self.is_sic() && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_u8char_arr(&t)) {
                    return self.lower_u8char_arr_index(base, index, &expr.span);
                }
                // sic `string[i]` → the byte at index i (`"hello"[1]` → 'e'), with a
                // bounds check (compile-time for a literal + constant index).
                if self.is_sic() && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_sic_string(&t)) {
                    return self.lower_string_index(base, index, &expr.span);
                }
                let lv = self.lower_lvalue_index(base, index)?;
                // An array element that is itself an array decays to a pointer to
                // its first element (`a[i]` in `a[i][j]` yields the row address,
                // not a load of the whole row).
                if matches!(lv.ty, Type::Array { .. }) {
                    return Ok(lv.ptr);
                }
                let dest = self.alloc_val();
                let ty = lv.ty.clone();
                self.push_instr(Instr::Load { dest, ptr: lv.ptr, ty });
                Ok(Val::Local(dest))
            }

            ExprKind::Field { base, name } => {
                // sic RTTI accessors (sic.md §"RTTI"): on a `type` value, `.str` /
                // `.name` give the canonical spelling, `.id` the stable hash, `.size`
                // the byte size, `.kind` the classification. Loaded from the record.
                if self.is_sic() && matches!(name.as_str(), "str" | "name" | "id" | "size" | "kind") {
                    if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_type_info(&t)) {
                        return self.emit_type_info_field(base, name);
                    }
                }
                // sic native-string computed accessors (sic.md §"Built-in string").
                // sic `u8char`: `.size` is the code point's UTF-8 byte length (1..4).
                if self.is_sic() && name == "size"
                    && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_u8char(&t))
                {
                    let cp = self.u8char_cp(base)?;
                    return self.u8char_encoded_len(cp);
                }
                // sic `string.utf8` — decode the string's bytes into a `u8char[]`.
                if self.is_sic() && name == "utf8"
                    && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_sic_string(&t))
                {
                    return self.lower_string_utf8(base);
                }
                // `.size` / `.data` are ordinary struct fields and fall through.
                // `.str` is an alias for `.ptr` (the NUL-terminated C string).
                if self.is_sic() && (name == "ptr" || name == "str" || name == "length") {
                    if let Ok(bt) = self.infer_expr_type(base) {
                        if super::types::is_sic_string(&bt) {
                            return if name == "length" {
                                self.emit_string_length(base)
                            } else {
                                self.emit_string_cptr(base)
                            };
                        }
                    }
                }
                // sic `s.dup` — an owned heap copy of a `string` or a C string
                // (`char*`/`char[]`), so it can outlive a local buffer it came from.
                if self.is_sic() && name == "dup" {
                    if let Ok(bt) = self.infer_expr_type(base) {
                        let is_cstr = super::types::is_sic_string(&bt)
                            || matches!(&bt, Type::Pointer(i) if matches!(i.as_ref(), Type::Int { bits: 8, .. }))
                            || matches!(&bt, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }));
                        if is_cstr {
                            return self.emit_string_dup(base);
                        }
                    }
                }
                // sic array accessors (sic.md §"Arrays and lists"): `.length` is the
                // element count, `.size` the byte size. Both fold from the array
                // type (fixed arrays and concat temporaries alike).
                if self.is_sic() && (name == "length" || name == "size") {
                    if let Ok(Type::Array { elem, len }) = self.infer_expr_type(base) {
                        let n = len as u64;
                        let v = if name == "length" { n } else { n * elem.size_of(self.ptr_size()) };
                        return Ok(self.size_t_val(v));
                    }
                    // sic `va_array` (sic.md std): `.length`/`.size` = its `len` field.
                    if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_va_array(&t)) {
                        let p = self.lower_aggregate_ptr(base)?;
                        let lv = self.field_ptr_from(LValue::plain(p, super::types::va_array_type(self.ptr_size())), "len", false, &expr.span)?;
                        return self.load_lvalue(&lv);
                    }
                    // sic `dict`/`set` (sic.md §"Dict", §"Set"): entry count.
                    if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_dict(&t)
                        || matches!(&t, Type::Pointer(i) if super::types::is_dict(i))) {
                        let d = self.dict_handle(base)?;
                        let f = self.dict_runtime_fn("__sic_dict_len");
                        let r = self.alloc_val();
                        self.push_instr(Instr::Call { dest: Some(r), func: f, args: vec![d], ret_ty: Type::u64() });
                        self.val_types.insert(r.0, Type::u64());
                        return Ok(Val::Local(r));
                    }
                    // sic `list` (sic.md §"List"): element count.
                    if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_list(&t)
                        || matches!(&t, Type::Pointer(i) if super::types::is_list(i))) {
                        let l = self.list_handle(base)?;
                        let f = self.list_runtime_fn("__sic_list_len");
                        let r = self.alloc_val();
                        self.push_instr(Instr::Call { dest: Some(r), func: f, args: vec![l], ret_ty: Type::u64() });
                        self.val_types.insert(r.0, Type::u64());
                        return Ok(Val::Local(r));
                    }
                }
                // sic `enumvalue.str` → a native `"EnumName::Variant"` string
                // (sic.md §"Match"). A bare constant is statically known; an
                // enum-typed variable maps its runtime value to the variant name.
                if self.is_sic() && name == "str" {
                    if let ExprKind::Ident(id) = &base.kind {
                        if let Some(en) = self.enum_locals.get(id).cloned() {
                            let vs = self.lowerer.c_enum_defs.get(&en).cloned().unwrap_or_default();
                            return self.emit_enum_str(base, &en, &vs);
                        }
                        if let Some(en) = self.lowerer.c_enum_variant.get(id).cloned() {
                            return self.enum_str_literal(&format!("{}::{}", en, id));
                        }
                    }
                }
                // sic bigint accessors (sic.md §"Integer sizes"): `.str` is a fresh
                // decimal `char*` (freed at scope exit); `.int` is the value as a
                // fixed 64-bit int (low bits). A cast, by contrast, only
                // reinterprets the pointer — it never converts.
                // sic fixed `.str` — decimal string with the point (sic.md §"Built-in
                // fixed point"). A cast only reinterprets the pointer.
                if self.is_sic() && name == "str" && self.is_fixed_typed(base) {
                    return self.fixed_to_str(base);
                }
                // sic fixed `.int` — the value truncated toward zero to a 64-bit
                // integer (sic.md §"Built-in fixed point").
                if self.is_sic() && name == "int" && self.is_fixed_typed(base) {
                    let (r, _, _) = self.fixed_operand(base)?;
                    return self.emit_bigint_call("__sic_rat_to_i64", vec![r], Type::i64());
                }
                if self.is_sic() && (name == "str" || name == "int") && self.is_bigint_operand(base) {
                    let b = self.to_bigint(base)?;
                    return if name == "int" {
                        self.emit_bigint_call("__sic_bi_to_i64", vec![b], Type::i64())
                    } else {
                        let s = self.emit_bigint_call("__sic_bi_to_str", vec![b], Type::char_ptr())?;
                        let slot = self.alloc_val();
                        self.push_instr(Instr::Alloca { dest: slot, ty: Type::char_ptr(), align: None });
                        self.push_instr(Instr::Store { val: s.clone(), ptr: Val::Local(slot) });
                        self.register_scope_exit(super::func::Cleanup::FreePtr { slot: Val::Local(slot) });
                        Ok(s)
                    };
                }
                let lv = self.lower_lvalue_field(base, name)?;
                // An array member decays to a pointer to its first element.
                if matches!(lv.ty, Type::Array { .. }) {
                    return Ok(lv.ptr);
                }
                self.load_lvalue(&lv)
            }

            ExprKind::Arrow { base, name } => {
                let lv = self.lower_lvalue_arrow(base, name)?;
                if matches!(lv.ty, Type::Array { .. }) {
                    return Ok(lv.ptr);
                }
                self.load_lvalue(&lv)
            }

            ExprKind::Cast { ty, expr: inner } => {
                let target = self.lower_type(ty)?;
                // sic `any` (sic.md std): `(any)x` boxes; `(T)anyval` downcasts
                // (reads the slot back out as T).
                if self.is_sic() && super::types::is_any(&target) {
                    return self.box_any(inner);
                }
                if self.is_sic() && matches!(self.infer_expr_type(inner), Ok(t) if super::types::is_any(&t)) {
                    return self.unbox_any(inner, &target, &expr.span);
                }
                // sic `u8char` (sic.md §"Integer sizes"): `(u8char)i` builds a code
                // point from an integer; `(int)c` / `(u32)c` extracts the code point.
                if self.is_sic() && super::types::is_u8char(&target) {
                    let v = self.lower_expr(inner)?;
                    let cp = self.coerce(v, &Type::Int { bits: 32, signed: false })?;
                    return self.make_u8char(cp);
                }
                if self.is_sic()
                    && matches!(target, Type::Int { .. } | Type::Bool | Type::Float32 | Type::Float64 | Type::Float80)
                    && matches!(self.infer_expr_type(inner), Ok(t) if super::types::is_u8char(&t))
                {
                    let cp = self.u8char_cp(inner)?;
                    return self.coerce(cp, &target);
                }
                // sic: `(int)enum_value` yields the discriminant (sic.md §"Match").
                if self.is_sic() && matches!(target, Type::Int { .. } | Type::Bool) {
                    if let Ok(src_ty) = self.infer_expr_type(inner) {
                        if self.is_tagged_enum_struct(&src_ty) {
                            let ptr = self.lower_aggregate_ptr(inner)?;
                            let tag = self.load_enum_tag(ptr, &src_ty, &expr.span)?;
                            return self.coerce(tag, &target);
                        }
                    }
                }
                // sic `fixed` → numeric cast (sic.md §"Built-in fixed point"): a
                // `fixed` is an exact rational, so `(double)f`/`(int)f` CONVERT the
                // value (unlike a `bigint`, whose cast only reinterprets its pointer).
                // Integer targets truncate toward zero; float targets resolve num/den.
                if self.is_sic() && matches!(self.infer_expr_type(inner), Ok(t) if super::types::is_fixed(&t)) {
                    if matches!(target, Type::Float32 | Type::Float64 | Type::Float80) {
                        let (r, _, _) = self.fixed_operand(inner)?;
                        let d = self.emit_bigint_call("__sic_rat_to_double", vec![r], Type::Float64)?;
                        return self.coerce(d, &target);
                    }
                    if matches!(target, Type::Int { .. } | Type::Bool) {
                        let (r, _, _) = self.fixed_operand(inner)?;
                        let iv = self.emit_bigint_call("__sic_rat_to_i64", vec![r], Type::i64())?;
                        return self.coerce(iv, &target);
                    }
                }
                // A `bigint` is a pointer, so casting it (`(char*)b`, `(long)b`)
                // only reinterprets the pointer — it never converts. Use the
                // explicit `.str` / `.int` accessors to get the decimal string or
                // numeric value (sic.md §"Integer sizes").
                let v = self.lower_expr(inner)?;
                self.coerce(v, &target)
            }

            ExprKind::SizeofType(ty) => {
                let ir_ty = self.lower_type(ty)?;
                let size = ir_ty.size_of(self.ptr_size());
                Ok(self.size_t_val(size))
            }

            ExprKind::SizeofExpr(inner) => {
                // We need the type of the expression without evaluating it.
                // Simplified: just return a placeholder for now.
                let ty = self.infer_expr_type(inner)?;
                let size = ty.size_of(self.ptr_size());
                Ok(self.size_t_val(size))
            }

            ExprKind::ChooseExpr { cond, then, else_ } => {
                // Compile-time selection: only the chosen branch is lowered.
                if self.eval_choose_cond(cond) != 0 { self.lower_expr(then) }
                else { self.lower_expr(else_) }
            }
            ExprKind::TypesCompatible(t1, t2) => {
                let compat = match (self.lower_type(t1), self.lower_type(t2)) {
                    (Ok(a), Ok(b)) => self.types_equal(&a, &b),
                    _ => false,
                };
                Ok(Constant::int(if compat { 1 } else { 0 }))
            }

            ExprKind::AlignofType(ty) => {
                let a = self.lower_type(ty)?.align_of(self.ptr_size());
                Ok(self.size_t_val(a))
            }
            ExprKind::AlignofExpr(inner) => {
                let a = self.infer_expr_type(inner)?.align_of(self.ptr_size());
                Ok(self.size_t_val(a))
            }

            ExprKind::Comma(lhs, rhs) => {
                self.lower_expr(lhs)?;
                self.lower_expr(rhs)
            }

            ExprKind::StmtExpr(stmts) => {
                // GCC statement expression: the value is that of the last
                // statement when it is an expression statement, else void (0).
                self.enter_scope();
                let mut result = Constant::zero();
                let n = stmts.len();
                for (i, stmt) in stmts.iter().enumerate() {
                    if self.is_terminated() { break; }
                    if i + 1 == n {
                        if let ast::Stmt::Expr(e, _) = stmt {
                            result = self.lower_expr(e)?;
                            continue;
                        }
                    }
                    self.lower_stmt(stmt)?;
                }
                self.exit_scope();
                Ok(result)
            }

            ExprKind::CompoundLiteral { ty, init } => {
                let mut ir_ty = self.lower_type(ty)?;
                // An implicit-length array literal `(T[]){ a, b, c }` lowers to
                // `[T; 0]`; size it from the initializer element count so the
                // alloca reserves the full array. Otherwise the element stores
                // overflow a 1-byte slot into neighboring stack storage (QEMU's
                // virtio_pci_types_register `.interfaces = (const InterfaceInfo[])
                // { {..}, {..}, {} }` got clobbered by a later g_strdup_printf).
                if let Type::Array { len, .. } = &mut ir_ty {
                    if *len == 0 { *len = self.lowerer.infer_array_len(init); }
                }
                let vid = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: vid, ty: ir_ty.clone(), align: None });
                // Zero first
                let size = ir_ty.size_of(self.ptr_size());
                if size > 0 {
                    self.push_instr(Instr::MemSet {
                        dst: Val::Local(vid), val: Constant::zero(), size,
                        align: ir_ty.align_of(self.ptr_size()),
                    });
                }
                let ptr = Val::Local(vid);
                // Reuse the full brace-initializer lowering (handles designators,
                // nested aggregates, and cursor positioning).
                let list = crate::ast::Initializer::List(init.clone());
                self.lower_initializer(&list, ptr.clone(), &ir_ty)?;
                // A compound literal decays to a pointer to its temporary.
                Ok(ptr)
            }

            ExprKind::VaStart { list, last } => {
                let _ = last;
                let list_ptr = self.lower_va_list_ptr(list)?;
                self.push_instr(Instr::VaStart { list_ptr });
                Ok(Constant::zero())
            }

            ExprKind::VaArg { list, ty } => {
                let list_ptr = self.lower_va_list_ptr(list)?;
                let ir_ty = self.lower_type(ty)?;
                let dest = self.alloc_val();
                self.push_instr(Instr::VaArg { dest, list_ptr, ty: ir_ty });
                Ok(Val::Local(dest))
            }

            ExprKind::VaEnd { list } => {
                let list_ptr = self.lower_va_list_ptr(list)?;
                self.push_instr(Instr::VaEnd { list_ptr });
                Ok(Constant::zero())
            }

            ExprKind::VaCopy { dst, src } => {
                // va_copy(d, s): duplicate the whole va_list state.
                let dptr = self.lower_va_list_ptr(dst)?;
                let sptr = self.lower_va_list_ptr(src)?;
                let vl = super::types::va_list_type();
                let size = vl.size_of(self.ptr_size());
                let align = vl.align_of(self.ptr_size());
                self.push_instr(Instr::MemCopy { dst: dptr, src: sptr, size, align });
                Ok(Constant::zero())
            }
        }
    }

    fn lower_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        // Short-circuit for logical ops
        if op == BinOpKind::LogAnd || op == BinOpKind::LogOr {
            return self.lower_logical(op == BinOpKind::LogAnd, lhs, rhs);
        }

        // sic strict enum typing (sic.md §"Enums"): a payload-less enum has no
        // arithmetic — `e + 1` must be `(int)e + 1`. Comparisons are allowed.
        self.check_enum_arith(op, lhs, rhs)?;

        // sic array concatenation `a + b` (sic.md §"Arrays and lists"): two array
        // operands joined into a fresh array of the combined length. Checked
        // before the GCC vector path, which in sic would otherwise read `+` as an
        // element-wise op (the two share one IR array type). C is unaffected.
        if self.is_sic() && op == BinOpKind::Add {
            if let (Ok(Type::Array { .. }), Ok(Type::Array { .. })) =
                (self.infer_expr_type(lhs), self.infer_expr_type(rhs))
            {
                return self.lower_array_concat(lhs, rhs);
            }
        }

        // sic `u8char` (sic.md §"Integer sizes"): a code point participates in
        // comparisons/arithmetic through its `cp` value — extract it (u32) from
        // either operand and operate on the integers, so `c == 'A'` etc. are stable
        // (comparing the raw 4-byte struct is not).
        if self.is_sic() {
            let lu = matches!(self.infer_expr_type(lhs), Ok(t) if super::types::is_u8char(&t));
            let ru = matches!(self.infer_expr_type(rhs), Ok(t) if super::types::is_u8char(&t));
            if lu || ru {
                let l = if lu { self.u8char_cp(lhs)? } else { self.lower_expr(lhs)? };
                let r = if ru { self.u8char_cp(rhs)? } else { self.lower_expr(rhs)? };
                return self.emit_binop(op, l, r);
            }
        }

        // GCC vector extension: when both operands are vector (array) types an
        // arithmetic/bitwise/comparison operator is element-wise, not scalar.
        // Regular arrays decay to pointers before this point, so two array
        // operands here means a `vector_size` type.
        if !matches!(op, BinOpKind::LogAnd | BinOpKind::LogOr) {
            if let (Ok(lt @ Type::Array { .. }), Ok(Type::Array { .. })) =
                (self.infer_expr_type(lhs), self.infer_expr_type(rhs))
            {
                return self.lower_vector_binop(op, lhs, rhs, lt);
            }
        }

        // sic string concatenation `a + b` (sic.md §"Built-in string"): build a
        // fresh joined string only when BOTH sides are string-ish — a native
        // `string`, a string literal, or a C string (`char*`/`char[]`). A string
        // literal (now a `string`) plus an integer — `"abc" + 1` — is pointer
        // arithmetic, not concat, so a non-stringy operand disables concat.
        if self.is_sic() && op == BinOpKind::Add {
            let stringish = |this: &mut Self, e: &Expr| -> bool {
                if matches!(&e.kind, ExprKind::StringLit(_)) { return true; }
                match this.infer_expr_type(e) {
                    Ok(t) => super::types::is_sic_string(&t)
                        || matches!(&t, Type::Pointer(i) if matches!(i.as_ref(), Type::Int { bits: 8, .. }))
                        || matches!(&t, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. })),
                    Err(_) => false,
                }
            };
            if stringish(self, lhs) && stringish(self, rhs) {
                return self.lower_string_concat(lhs, rhs);
            }
            // `string + int` is a cheap view offset — `s + n` ≡ `s[n:]` (drop the
            // first n bytes): `"hello" + 1` → "ello", `"hello" + 5` → "". A native
            // `string` or string literal on the left with an integer on the right;
            // a real `char*` keeps C pointer arithmetic. For a literal + constant
            // offset the bounds are checked at compile time (sic.md §"Strings").
            let lhs_is_string = matches!(&lhs.kind, ExprKind::StringLit(_)) || self.is_string_operand(lhs);
            let rhs_is_int = matches!(self.infer_expr_type(rhs),
                Ok(Type::Int { .. }) | Ok(Type::Bool));
            if lhs_is_string && rhs_is_int {
                if let ExprKind::StringLit(s) = &lhs.kind {
                    if let Ok(off) = crate::lower::eval_const_expr(rhs, &self.lowerer.enum_consts) {
                        if off < 0 || off as usize > s.len() {
                            return Err(CompileError::at(
                                format!("offset {} is out of bounds for a string of length {}", off, s.len()),
                                rhs.span.file.clone(), rhs.span.line, rhs.span.col));
                        }
                    }
                }
                // `char*` target ("if char* detected, don't use string") → plain
                // pointer arithmetic on the bytes; otherwise a `string` view.
                if self.expected_is_char_ptr() {
                    return self.lower_string_offset_cptr(lhs, rhs);
                }
                return self.lower_slice(lhs, Some(rhs), None);
            }
        }

        // sic RTTI type comparison `type(x) == i64` (sic.md §"RTTI"): compare the
        // records' `id` fields, so equality is correct even across TUs (records for
        // the same type may have different addresses).
        if self.is_sic() && matches!(op, BinOpKind::Eq | BinOpKind::Ne)
            && (matches!(self.infer_expr_type(lhs), Ok(t) if super::types::is_type_info(&t))
                || matches!(self.infer_expr_type(rhs), Ok(t) if super::types::is_type_info(&t)))
        {
            return self.lower_type_compare(op, lhs, rhs);
        }

        // sic native string comparison `a == b` / `a != b` (sic.md §"Built-in
        // string"): compare bytes directly (no `.str`, no copy). Triggered when a
        // real `string`/slice is on either side; the other side may be a literal.
        if self.is_sic() && matches!(op, BinOpKind::Eq | BinOpKind::Ne)
            && (self.is_string_operand(lhs) || self.is_string_operand(rhs))
        {
            return self.lower_string_compare(op, lhs, rhs);
        }

        // sic `bigint` arithmetic / comparison (sic.md §"Integer sizes"): if either
        // side is a bigint, the op runs through the arbitrary-precision runtime.
        if self.is_sic() && (self.is_bigint_operand(lhs) || self.is_bigint_operand(rhs)) {
            use BinOpKind::*;
            match op {
                Add | Sub | Mul | Div | Rem | BitAnd | BitOr | BitXor | Shl | Shr =>
                    return self.lower_bigint_binop(op, lhs, rhs),
                Eq | Ne | Lt | Le | Gt | Ge => return self.lower_bigint_cmp(op, lhs, rhs),
                _ => {}
            }
        }

        // sic `fixed` arithmetic / comparison (sic.md §"Built-in fixed point"): a
        // fixed operand routes through the EXACT rational ops (num/den, no scale). A
        // bare decimal literal alone stays a `double`; it only becomes fixed when
        // paired with a real `fixed` operand.
        if self.is_sic() {
            let fl = self.is_fixed_typed(lhs);
            let fr = self.is_fixed_typed(rhs);
            if fl || fr {
                use BinOpKind::*;
                match op {
                    Add | Sub | Mul | Div | Rem => return self.lower_fixed_binop(op, lhs, rhs),
                    Eq | Ne | Lt | Le | Gt | Ge => return self.lower_fixed_cmp(op, lhs, rhs),
                    _ => {}
                }
            }
        }

        let l = self.lower_expr(lhs)?;
        let r = self.lower_expr(rhs)?;
        self.emit_binop(op, l, r)
    }

    // ─── bigint (sic.md §"Integer sizes") ──────────────────────────────────────

    /// Emit a call to a bigint runtime function (defined by the prepended
    /// runtime). Returns its result value.
    pub(super) fn emit_bigint_call(&mut self, name: &str, args: Vec<Val>, ret: Type) -> Result<Val> {
        let fref = self.lowerer.module.func_ref_by_name(name).ok_or_else(|| CompileError::new(
            format!("internal: bigint runtime function '{}' not found", name)))?;
        if ret == Type::Void {
            self.push_instr(Instr::Call { dest: None, func: fref, args, ret_ty: Type::Void });
            return Ok(Constant::zero());
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args, ret_ty: ret.clone() });
        self.val_types.insert(dest.0, ret);
        Ok(Val::Local(dest))
    }

    // ─── sic `dict` (sic.md §"Dict") ─────────────────────────────────────────

    /// Widen a scalar value to a 64-bit slot for the dict runtime.
    fn dict_scalar_to_u64(&mut self, v: Val) -> Val {
        let ty = self.val_type(&v);
        let op = match &ty {
            Type::Int { bits: 64, .. } | Type::Pointer(_) if matches!(ty, Type::Pointer(_)) => CastOp::BitCast,
            Type::Int { bits: 64, .. } => return v,
            Type::Int { signed: true, .. } => CastOp::SExt,
            Type::Int { .. } | Type::Bool => CastOp::ZExt,
            Type::Pointer(_) => CastOp::BitCast,
            _ => return v,
        };
        let d = self.alloc_val();
        self.push_instr(Instr::Cast { dest: d, op, val: v, to_ty: Type::u64() });
        self.val_types.insert(d.0, Type::u64());
        Val::Local(d)
    }

    /// Box a dict key expression into the runtime's `(kind, a, b)` tagged form:
    /// kind 1 = integer (`a` = value), 2 = string (`a` = bytes, `b` = length),
    /// 3 = pointer. String keys (sic `string` or `char*`) hash/compare by bytes.
    fn dict_key_box(&mut self, key: &Expr, _sp: &crate::lexer::Span) -> Result<(Val, Val, Val)> {
        let kty = self.infer_expr_type(key)?;
        let zero = Constant::uint(0);
        // A string key (sic `string` or `char*`) hashes/compares by its bytes.
        let is_str = super::types::is_sic_string(&kty)
            || matches!(&kty, Type::Pointer(inner) if matches!(inner.as_ref(), Type::Int { bits: 8, .. }))
            || matches!(&kty, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }));
        if is_str {
            let (data, size) = self.string_operand_parts(key)?;
            let a = self.dict_scalar_to_u64(data);
            let b = self.dict_scalar_to_u64(size);
            Ok((Constant::int(2), a, b))
        } else {
            let kval = self.lower_expr(key)?;
            let kind = if matches!(self.val_type(&kval), Type::Pointer(_)) { 3 } else { 1 };
            let a = self.dict_scalar_to_u64(kval);
            let _ = zero;
            Ok((Constant::int(kind), a, Constant::uint(0)))
        }
    }

    /// Load the `dict` handle from a base value that is either a dict or a pointer to
    /// one (so both `dict d` and `dict *p` work as subscript bases).
    fn dict_handle(&mut self, base: &Expr) -> Result<Val> {
        let v = self.lower_expr(base)?;
        let ty = self.val_type(&v);
        if super::types::is_dict(&ty) {
            Ok(v)
        } else if matches!(&ty, Type::Pointer(inner) if super::types::is_dict(inner)) {
            let d = self.alloc_val();
            let inner = match ty { Type::Pointer(i) => *i, _ => unreachable!() };
            self.push_instr(Instr::Load { dest: d, ptr: v, ty: inner.clone() });
            self.val_types.insert(d.0, inner);
            Ok(Val::Local(d))
        } else {
            Ok(v)
        }
    }

    /// Resolve a `__sic_dict_*` runtime function, declaring it as an extern if it is
    /// not already present. The definition comes from the prepended dict runtime (when
    /// this unit uses `dict`) or from an imported module's object (e.g. `libstd`,
    /// which now uses `va_dict`) — the weak copies dedupe at link.
    fn dict_runtime_fn(&mut self, name: &str) -> FuncRef {
        if let Some(fr) = self.lowerer.module.func_ref_by_name(name) { return fr; }
        let u64t = Type::u64();
        let ptr = Type::void_ptr();
        let u64p = Type::Pointer(Box::new(u64t.clone()));
        let i32t = Type::i32();
        let (params, ret): (Vec<Type>, Type) = match name {
            "__sic_dict_new" => (vec![], ptr.clone()),
            "__sic_dict_set" => (vec![ptr.clone(), i32t.clone(), u64t.clone(), u64t.clone(), u64t.clone(), u64t.clone(), i32t.clone()], Type::Void),
            "__sic_dict_get" => (vec![ptr.clone(), i32t.clone(), u64t.clone(), u64t.clone(), u64p.clone(), u64p], i32t.clone()),
            "__sic_dict_del" => (vec![ptr.clone(), i32t.clone(), u64t.clone(), u64t.clone()], i32t.clone()),
            "__sic_dict_free" => (vec![ptr.clone()], Type::Void),
            "__sic_dict_len" => (vec![ptr], u64t),
            _ => (vec![], Type::Void),
        };
        let sig = super::build_fn_sig(ret, params, false, self.ptr_size());
        self.lowerer.module.add_extern(sic_ir::ExternFunc { name: name.to_string(), sig })
    }

    // ─── sic `async` / `await` (sic.md §"Async") ─────────────────────────────

    /// Resolve a `__sic_task_*` runtime function, declaring it as an extern if absent
    /// (the definition comes from the prepended async runtime).
    fn task_runtime_fn(&mut self, name: &str) -> FuncRef {
        if let Some(fr) = self.lowerer.module.func_ref_by_name(name) { return fr; }
        let u64t = Type::u64();
        let ptr = Type::void_ptr();
        let (params, ret): (Vec<Type>, Type) = match name {
            "__sic_task_new" => (vec![u64t], ptr),
            "__sic_await" => (vec![ptr], u64t),
            _ => (vec![], Type::Void),
        };
        let sig = super::build_fn_sig(ret, params, false, self.ptr_size());
        self.lowerer.module.add_extern(sic_ir::ExternFunc { name: name.to_string(), sig })
    }

    /// Widen an async result value to the 64-bit task slot (inverse of
    /// `reinterpret_slot`): a float's bits via a memory round-trip, a pointer/scalar
    /// by cast/coercion.
    pub(crate) fn async_box_u64(&mut self, v: Val, elem: &Type) -> Result<Val> {
        match elem {
            Type::Float32 | Type::Float64 | Type::Float80 => {
                let d = self.coerce(v, &Type::Float64)?;
                let mem = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: mem, ty: Type::Float64, align: None });
                self.push_instr(Instr::Store { val: d, ptr: Val::Local(mem) });
                let out = self.alloc_val();
                self.push_instr(Instr::Load { dest: out, ptr: Val::Local(mem), ty: Type::u64() });
                self.val_types.insert(out.0, Type::u64());
                Ok(Val::Local(out))
            }
            Type::Pointer(_) => {
                let d = self.alloc_val();
                self.push_instr(Instr::Cast { dest: d, op: CastOp::BitCast, val: v, to_ty: Type::u64() });
                self.val_types.insert(d.0, Type::u64());
                Ok(Val::Local(d))
            }
            _ => self.coerce(v, &Type::u64()),
        }
    }

    /// `__sic_task_new(v)` → a `Task<elem>` holding the async result `v` (already a
    /// 64-bit slot). The synchronous stub runtime makes a ready task.
    pub(crate) fn emit_task_new(&mut self, v: Val, elem: &Type) -> Result<Val> {
        let f = self.task_runtime_fn("__sic_task_new");
        let tt = super::types::task_type(elem);
        let d = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(d), func: f, args: vec![v], ret_ty: tt.clone() });
        self.val_types.insert(d.0, tt);
        Ok(Val::Local(d))
    }

    /// `await task` → `__sic_await(task)` driven to completion, its `T` value.
    fn lower_await(&mut self, inner: &Expr) -> Result<Val> {
        let task = self.lower_expr(inner)?;
        let tt = self.val_type(&task);
        if !super::types::is_task(&tt) {
            return Err(CompileError::at(
                "`await` expects a `Task<T>` (the result of an async call)".to_string(),
                inner.span.file.clone(), inner.span.line, inner.span.col));
        }
        let elem = super::types::task_elem(&tt, self.ptr_size());
        let taskp = self.coerce(task, &Type::void_ptr())?;
        let f = self.task_runtime_fn("__sic_await");
        let raw = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(raw), func: f, args: vec![taskp], ret_ty: Type::u64() });
        self.val_types.insert(raw.0, Type::u64());
        // Unbox the 64-bit slot back to the result type.
        self.reinterpret_slot(Val::Local(raw), &elem)
    }

    // ─── sic `list` (sic.md §"List") ─────────────────────────────────────────

    /// Resolve a `__sic_list_*` runtime function, declaring it as an extern if absent.
    fn list_runtime_fn(&mut self, name: &str) -> FuncRef {
        if let Some(fr) = self.lowerer.module.func_ref_by_name(name) { return fr; }
        let u64t = Type::u64();
        let ptr = Type::void_ptr();
        let u64p = Type::Pointer(Box::new(u64t.clone()));
        let i32t = Type::i32();
        let (params, ret): (Vec<Type>, Type) = match name {
            "__sic_list_new" => (vec![], ptr),
            "__sic_list_push" => (vec![ptr, u64t.clone(), u64t, i32t], Type::Void),
            "__sic_list_get" => (vec![ptr, u64t, u64p.clone(), u64p], i32t.clone()),
            "__sic_list_set" => (vec![ptr, u64t.clone(), u64t.clone(), u64t, i32t], Type::Void),
            "__sic_list_len" => (vec![ptr], u64t),
            "__sic_list_free" => (vec![ptr], Type::Void),
            _ => (vec![], Type::Void),
        };
        let sig = super::build_fn_sig(ret, params, false, self.ptr_size());
        self.lowerer.module.add_extern(sic_ir::ExternFunc { name: name.to_string(), sig })
    }

    /// The element type of a `list` subscript/method base.
    fn list_elem_of(&mut self, base: &Expr) -> Type {
        let t = self.infer_expr_type(base).ok();
        let t = t.map(|t| if let Type::Pointer(i) = &t {
            if super::types::is_list(i) { (**i).clone() } else { t.clone() }
        } else { t }).unwrap_or_else(super::types::any_type);
        super::types::resolve_aggregate(&super::types::list_elem(&t, self.ptr_size()), &self.lowerer.struct_types)
    }

    /// The `list` handle from a base that is a list or a pointer to one.
    fn list_handle(&mut self, base: &Expr) -> Result<Val> {
        let v = self.lower_expr(base)?;
        let ty = self.val_type(&v);
        if super::types::is_list(&ty) { return Ok(v); }
        if let Type::Pointer(inner) = ty {
            if super::types::is_list(&inner) {
                let d = self.alloc_val();
                self.push_instr(Instr::Load { dest: d, ptr: v, ty: (*inner).clone() });
                self.val_types.insert(d.0, *inner);
                return Ok(Val::Local(d));
            }
        }
        Ok(v)
    }

    /// `l.add(x)` / `l.push(x)` — append `x`.
    pub(crate) fn lower_list_push(&mut self, base: &Expr, val: &Expr, _sp: &crate::lexer::Span) -> Result<()> {
        let elem = self.list_elem_of(base);
        let l = self.list_handle(base)?;
        let (vty, vslot, vowned) = self.container_box_value(val, &elem)?;
        let f = self.list_runtime_fn("__sic_list_push");
        self.push_instr(Instr::Call { dest: None, func: f, args: vec![l, vty, vslot, vowned], ret_ty: Type::Void });
        Ok(())
    }

    /// `l[i]` read.
    pub(crate) fn lower_list_get(&mut self, base: &Expr, index: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let elem = self.list_elem_of(base);
        let l = self.list_handle(base)?;
        let iv = self.lower_expr(index)?;
        let iv = self.coerce(iv, &Type::u64())?;
        let ot = self.dict_out_slot();
        let os = self.dict_out_slot();
        let f = self.list_runtime_fn("__sic_list_get");
        let found = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(found), func: f, args: vec![l, iv, ot.clone(), os.clone()], ret_ty: Type::i32() });
        self.container_read_value(ot, os, &elem, Some(Val::Local(found)), sp)
    }

    /// `l[i] = x`.
    pub(crate) fn lower_list_set(&mut self, base: &Expr, index: &Expr, val: &Expr, _sp: &crate::lexer::Span) -> Result<()> {
        let elem = self.list_elem_of(base);
        let l = self.list_handle(base)?;
        let iv = self.lower_expr(index)?;
        let iv = self.coerce(iv, &Type::u64())?;
        let (vty, vslot, vowned) = self.container_box_value(val, &elem)?;
        let f = self.list_runtime_fn("__sic_list_set");
        self.push_instr(Instr::Call { dest: None, func: f, args: vec![l, iv, vty, vslot, vowned], ret_ty: Type::Void });
        Ok(())
    }

    /// Create a fresh empty list handle (`list<T> l;` auto-init).
    pub(crate) fn lower_list_new(&mut self, lty: &Type) -> Result<Val> {
        let f = self.list_runtime_fn("__sic_list_new");
        let d = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(d), func: f, args: vec![], ret_ty: lty.clone() });
        self.val_types.insert(d.0, lty.clone());
        Ok(Val::Local(d))
    }

    /// The `(key, value)` types of a dict subscript base (defaults to any/any).
    fn dict_kv_of(&mut self, base: &Expr) -> (Type, Type) {
        let bt = self.infer_expr_type(base).ok();
        let (k, v) = bt.and_then(|t| {
            let t = if let Type::Pointer(i) = &t {
                if super::types::is_dict(i) { (**i).clone() } else { t.clone() }
            } else { t };
            super::types::dict_kv(&t, self.ptr_size())
        }).unwrap_or_else(|| (super::types::any_type(), super::types::any_type()));
        // A named struct/union value decodes opaque; fill its fields from the table.
        let v = super::types::resolve_aggregate(&v, &self.lowerer.struct_types);
        (k, v)
    }

    /// Allocate a zero-width `u64` out-slot for a runtime out-pointer argument.
    fn dict_out_slot(&mut self) -> Val {
        let id = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: id, ty: Type::u64(), align: None });
        self.val_types.insert(id.0, Type::Pointer(Box::new(Type::u64())));
        Val::Local(id)
    }

    /// `dict[key]` read: `__sic_dict_get` → the value typed as V (or zero if absent).
    /// The stored value is a two-word `(type-info, slot)` box; a scalar V reads the
    /// slot, an `any` V reconstructs the `{ ty, slot }` box.
    pub(crate) fn lower_dict_get(&mut self, base: &Expr, key: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let (_k, v) = self.dict_kv_of(base);
        let d = self.dict_handle(base)?;
        let (kind, a, b) = self.dict_key_box(key, sp)?;
        let ot = self.dict_out_slot();
        let os = self.dict_out_slot();
        let get = self.dict_runtime_fn("__sic_dict_get");
        let found = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(found), func: get, args: vec![d, kind, a, b, ot.clone(), os.clone()], ret_ty: Type::i32() });
        self.container_read_value(ot, os, &v, Some(Val::Local(found)), sp)
    }

    /// An empty `string` value (`{ data: "", size: 0, rc: null }`).
    fn emit_empty_string(&mut self) -> Result<Val> {
        let data = self.emit_cstring("");
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let zero = self.coerce(Constant::int(0), &usize_ty)?;
        let null_rc = self.coerce(Constant::int(0), &Type::Pointer(Box::new(usize_ty)))?;
        self.make_string_val(data, zero, null_rc)
    }

    /// `dict[key] = val`: `__sic_dict_set`. The value is boxed into `(type-info,
    /// slot)`: the `slot` holds a scalar's bits or an aggregate's address (`box_slot`
    /// handles every value type); the `type-info` word is stored only for an
    /// `any`-valued dict (a concrete V reconstructs from its static type).
    pub(crate) fn lower_dict_set(&mut self, base: &Expr, key: &Expr, val: &Expr, sp: &crate::lexer::Span) -> Result<()> {
        let (_k, v) = self.dict_kv_of(base);
        let d = self.dict_handle(base)?;
        let (kind, a, b) = self.dict_key_box(key, sp)?;
        let (vty_word, vslot_word, vowned) = self.container_box_value(val, &v)?;
        let set = self.dict_runtime_fn("__sic_dict_set");
        self.push_instr(Instr::Call { dest: None, func: set, args: vec![d, kind, a, b, vty_word, vslot_word, vowned], ret_ty: Type::Void });
        Ok(())
    }

    /// Box a value for a dict/list container into `(type-info word, slot word, vowned)`.
    /// The slot holds a scalar's bits or an aggregate's address; strings and structs
    /// are deep-copied into one owned heap block (`vowned = 1`, freed on
    /// overwrite/remove/free); the type word is stored only for an `any` element.
    pub(crate) fn container_box_value(&mut self, val: &Expr, v: &Type) -> Result<(Val, Val, Val)> {
        let ety = self.infer_expr_type(val).unwrap_or_else(|_| Type::i32());
        let is_owned_string = super::types::is_sic_string(v) || super::types::is_sic_string(&ety);
        let is_owned_struct = !is_owned_string && !super::types::is_any(v)
            && matches!(v, Type::Struct(_) | Type::Union(_));
        let vslot_word = if is_owned_string {
            let (data, size) = self.string_operand_parts(val)?;
            let owned = self.emit_dict_owned_string(data, size)?;
            let w = self.alloc_val();
            self.push_instr(Instr::Cast { dest: w, op: CastOp::BitCast, val: owned, to_ty: Type::u64() });
            self.val_types.insert(w.0, Type::u64());
            Val::Local(w)
        } else if is_owned_struct {
            let src = self.lower_aggregate_ptr(val)?;
            let sz = self.coerce(Constant::int(v.size_of(self.ptr_size()).max(1) as i64), &Type::i64())?;
            let heap = self.emit_malloc(sz.clone())?;
            self.emit_memcpy(heap.clone(), src, sz)?;
            let w = self.alloc_val();
            self.push_instr(Instr::Cast { dest: w, op: CastOp::BitCast, val: heap, to_ty: Type::u64() });
            self.val_types.insert(w.0, Type::u64());
            Val::Local(w)
        } else {
            self.box_slot(val, &ety)?
        };
        let vty_word = if super::types::is_any(v) {
            let store_ty = if is_owned_string { super::types::sic_string_type(self.ptr_size()) } else { ety.clone() };
            let tyval = self.lower_type_value(&store_ty);
            let tyw = self.alloc_val();
            self.push_instr(Instr::Cast { dest: tyw, op: CastOp::BitCast, val: tyval, to_ty: Type::u64() });
            self.val_types.insert(tyw.0, Type::u64());
            Val::Local(tyw)
        } else {
            Constant::uint(0)
        };
        let vowned = if is_owned_string || is_owned_struct { Constant::int(1) } else { Constant::int(0) };
        Ok((vty_word, vslot_word, vowned))
    }

    /// Reconstruct a container element from its `(type-info, slot)` out-slots: an
    /// `any` element rebuilds the `{ ty, slot }` box; a concrete element reinterprets
    /// the slot. `found` (a bool ValId) guards a missing `string` → empty string.
    pub(crate) fn container_read_value(&mut self, oty: Val, oslot: Val, v: &Type, found: Option<Val>, sp: &crate::lexer::Span) -> Result<Val> {
        let slot = self.alloc_val();
        self.push_instr(Instr::Load { dest: slot, ptr: oslot, ty: Type::u64() });
        self.val_types.insert(slot.0, Type::u64());
        if super::types::is_any(v) {
            let tyw = self.alloc_val();
            self.push_instr(Instr::Load { dest: tyw, ptr: oty, ty: Type::u64() });
            self.val_types.insert(tyw.0, Type::u64());
            let tinfo = super::types::type_info_type();
            let typ = self.alloc_val();
            self.push_instr(Instr::Cast { dest: typ, op: CastOp::BitCast, val: Val::Local(tyw), to_ty: tinfo.clone() });
            self.val_types.insert(typ.0, tinfo);
            let any_ty = super::types::any_type();
            let p = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: p, ty: any_ty.clone(), align: None });
            self.val_types.insert(p.0, any_ty.clone());
            let ty_lv = self.field_ptr_from(LValue::plain(Val::Local(p), any_ty.clone()), "ty", false, sp)?;
            self.store_lvalue(&ty_lv, Val::Local(typ))?;
            let slot_lv = self.field_ptr_from(LValue::plain(Val::Local(p), any_ty), "slot", false, sp)?;
            self.store_lvalue(&slot_lv, Val::Local(slot))?;
            return Ok(Val::Local(p));
        }
        let val = self.reinterpret_slot(Val::Local(slot), v)?;
        if super::types::is_sic_string(v) {
            if let Some(found) = found {
                let empty = self.emit_empty_string()?;
                let sel = self.alloc_val();
                self.push_instr(Instr::Select { dest: sel, cond: found, on_true: val, on_false: empty, ty: Type::void_ptr() });
                self.val_types.insert(sel.0, v.clone());
                return Ok(Val::Local(sel));
            }
        }
        Ok(val)
    }

    /// `del dict[key]`: `__sic_dict_del` (frees the entry's resources).
    pub(crate) fn lower_dict_del(&mut self, base: &Expr, key: &Expr, sp: &crate::lexer::Span) -> Result<()> {
        let d = self.dict_handle(base)?;
        let (kind, a, b) = self.dict_key_box(key, sp)?;
        let del = self.dict_runtime_fn("__sic_dict_del");
        self.push_instr(Instr::Call { dest: None, func: del, args: vec![d, kind, a, b], ret_ty: Type::i32() });
        Ok(())
    }

    /// Create a fresh empty dict handle (`dict d;` auto-init and `new dict<…>`).
    pub(crate) fn lower_dict_new(&mut self, dty: &Type, _sp: &crate::lexer::Span) -> Result<Val> {
        let new = self.dict_runtime_fn("__sic_dict_new");
        let d = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(d), func: new, args: vec![], ret_ty: dty.clone() });
        self.val_types.insert(d.0, dty.clone());
        Ok(Val::Local(d))
    }

    /// Call a bigint runtime function that returns a fresh `bigint` temporary, and
    /// record it for freeing at the end of the current statement (so a value
    /// re-evaluated each loop iteration does not leak). The result stays valid for
    /// the rest of the statement.
    fn call_bigint_new(&mut self, name: &str, args: Vec<Val>) -> Result<Val> {
        let bt = super::types::bigint_type();
        let v = self.emit_bigint_call(name, args, bt)?;
        self.bigint_temps.push(v.clone());
        Ok(v)
    }

    /// Free every `bigint` temporary created during the current statement. Called
    /// at statement boundaries in `lower_stmt`. Straight-line by construction (a
    /// statement's temps are produced in the block reaching its end).
    pub(super) fn flush_bigint_temps(&mut self) {
        // sic `va_dict` (sic.md §"Named parameters"): free each per-call va_dict
        // packed in this statement (the callee only borrowed it for the call).
        if !self.va_dict_temps.is_empty() {
            let vds = std::mem::take(&mut self.va_dict_temps);
            let free = self.dict_runtime_fn("__sic_dict_free");
            for h in vds {
                self.push_instr(Instr::Call { dest: None, func: free, args: vec![h], ret_ty: Type::Void });
            }
        }
        if self.bigint_temps.is_empty() { return; }
        let temps = std::mem::take(&mut self.bigint_temps);
        for t in temps {
            let f = self.temp_free_fn(&t);
            let _ = self.emit_bigint_call(f, vec![t], Type::Void);
        }
    }

    /// The runtime free function for a bigint/fixed temporary: a `fixed` value is
    /// an exact rational (`__sic_rat*`) freed via `__sic_rat_free`; a `bigint` (or
    /// any other) temp is freed via `__sic_bi_free`. Dispatched on the recorded
    /// value type so a mixed temp list frees each correctly.
    fn temp_free_fn(&self, v: &Val) -> &'static str {
        if let Val::Local(id) = v {
            if matches!(self.val_types.get(&id.0), Some(t) if super::types::is_fixed(t)) {
                return "__sic_rat_free";
            }
        }
        "__sic_bi_free"
    }

    /// Free only the bigint/fixed temporaries recorded since `mark` (in the current
    /// block). Used to free a conditionally-evaluated sub-expression's temps (a
    /// `||`/`&&` right operand, a ternary arm) where they are created, since they
    /// don't dominate the statement-end flush.
    pub(super) fn flush_bigint_temps_from(&mut self, mark: usize) {
        if self.bigint_temps.len() <= mark { return; }
        let temps: Vec<Val> = self.bigint_temps.split_off(mark);
        for t in temps {
            let f = self.temp_free_fn(&t);
            let _ = self.emit_bigint_call(f, vec![t], Type::Void);
        }
    }

    /// Evaluate `e` as a `bigint` value for use as a *borrowed operand* (of an
    /// arithmetic/compare op): an existing bigint is used directly (no copy); a
    /// big literal parses via the runtime; any integer is widened to a bigint.
    fn to_bigint(&mut self, e: &Expr) -> Result<Val> {
        if let ExprKind::BigIntLit(digits) = &e.kind {
            let s = self.emit_cstring(digits);
            return self.call_bigint_new("__sic_bi_from_str", vec![s]);
        }
        // An existing bigint value (variable, arith result temp) is borrowed as-is.
        if matches!(self.infer_expr_type(e), Ok(t) if super::types::is_bigint(&t)) {
            return self.lower_expr(e);
        }
        // An integer expression → widen to a temporary bigint.
        let v = self.lower_expr(e)?;
        let i64v = self.coerce(v, &Type::i64())?;
        self.call_bigint_new("__sic_bi_from_i64", vec![i64v])
    }

    /// Evaluate `e` into an OWNED `bigint` block to store into a slot (a `bigint`
    /// local/target — value semantics). The result is a fresh `__sic_bi_clone`
    /// emitted *raw* (no scope-exit free of its own): it is owned solely by the
    /// slot it is stored into, whose `BigintFree` cleanup frees it. `to_bigint`
    /// yields the borrowed source (and registers frees for any temporaries it
    /// materialises), so this never double-frees.
    pub(super) fn eval_bigint_owned(&mut self, e: &Expr) -> Result<Val> {
        let src = self.to_bigint(e)?;
        self.emit_bigint_call("__sic_bi_clone", vec![src], super::types::bigint_type())
    }

    /// Lower a `bigint` arithmetic binary op `+ - *` (sic.md §"Integer sizes"):
    /// coerce each operand to a bigint and call the runtime, yielding a fresh
    /// owned result.
    fn lower_bigint_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        // Shifts take an integer shift count on the right, not a bigint.
        if matches!(op, BinOpKind::Shl | BinOpKind::Shr) {
            let a = self.to_bigint(lhs)?;
            let cnt = self.lower_expr(rhs)?;
            let cnt = self.coerce(cnt, &Type::u32())?;
            let f = if op == BinOpKind::Shl { "__sic_bi_shl" } else { "__sic_bi_shr" };
            return self.call_bigint_new(f, vec![a, cnt]);
        }
        let fname = match op {
            BinOpKind::Add => "__sic_bi_add",
            BinOpKind::Sub => "__sic_bi_sub",
            BinOpKind::Mul => "__sic_bi_mul",
            BinOpKind::Div => "__sic_bi_div",
            BinOpKind::Rem => "__sic_bi_mod",
            BinOpKind::BitAnd => "__sic_bi_and",
            BinOpKind::BitOr  => "__sic_bi_or",
            BinOpKind::BitXor => "__sic_bi_xor",
            _ => return Err(CompileError::new(
                format!("bigint does not support this operator"))),
        };
        let a = self.to_bigint(lhs)?;
        let b = self.to_bigint(rhs)?;
        self.call_bigint_new(fname, vec![a, b])
    }

    /// `to_bigint`, tracking whether the result is an OWNED temp (literal/int) vs a
    /// borrowed variable — so a caller can free it in-block.
    fn to_bigint_owned(&mut self, e: &Expr) -> Result<(Val, bool)> {
        if let ExprKind::BigIntLit(digits) = &e.kind {
            let s = self.emit_cstring(digits);
            let m = self.emit_bigint_call("__sic_bi_from_str", vec![s], super::types::bigint_type())?;
            return Ok((m, true));
        }
        if matches!(self.infer_expr_type(e), Ok(t) if super::types::is_bigint(&t)) {
            return Ok((self.lower_expr(e)?, false));
        }
        let v = self.lower_expr(e)?;
        let i64v = self.coerce(v, &Type::i64())?;
        let m = self.emit_bigint_call("__sic_bi_from_i64", vec![i64v], super::types::bigint_type())?;
        Ok((m, true))
    }

    /// Lower a `bigint` comparison (all six), via `__sic_bi_cmp` → {-1,0,1} then
    /// the relational operator against 0. Yields an `i32`; operand temps are freed
    /// in-block (safe inside `||`/`&&`).
    fn lower_bigint_cmp(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (a, oa) = self.to_bigint_owned(lhs)?;
        let (b, ob) = self.to_bigint_owned(rhs)?;
        let cmp = self.emit_bigint_call("__sic_bi_cmp", vec![a.clone(), b.clone()], Type::i32())?;
        if oa { self.bi_free_now(a)?; }
        if ob { self.bi_free_now(b)?; }
        self.emit_binop(op, cmp, Constant::int(0))
    }

    /// Whether `e` is (statically) a `bigint`-typed operand — used to route `+`,
    /// comparisons, etc. A `BigIntLit` counts; an integer literal does not.
    fn is_bigint_operand(&self, e: &Expr) -> bool {
        if matches!(&e.kind, ExprKind::BigIntLit(_)) { return true; }
        matches!(self.infer_expr_type(e), Ok(t) if super::types::is_bigint(&t))
    }

    // ─── fixed-point (sic.md §"Built-in fixed point") ──────────────────────────
    //
    // A `fixed<I,F>` value is, at runtime, a `bigint` mantissa equal to the real
    // value × 10^F; the scale F (and integral width I) live in the compile-time
    // type. Arithmetic harmonizes scales by rescaling a mantissa (× or ÷ 10^diff,
    // all on bigints — never a float), then reuses the bigint ops. Memory is
    // managed exactly like a bigint.

    /// Whether `e` genuinely has a `fixed` type (a bare decimal literal does NOT —
    /// `3.5 + 2.5` on their own are `double`; they turn fixed only next to a real
    /// `fixed`). Used to *trigger* fixed lowering.
    fn is_fixed_typed(&self, e: &Expr) -> bool {
        matches!(self.infer_expr_type(e), Ok(t) if super::types::is_fixed(&t))
    }

    /// Whether `e` is a fixed *operand* in a fixed context: a `fixed`-typed value
    /// OR a bare decimal literal. Unlike `is_fixed_typed`, a decimal literal counts
    /// — so `1.0 / 3.0` on the RHS of a `fixed` binding is computed as an exact
    /// rational rather than truncated `double` division.
    fn is_fixed_operand(&self, e: &Expr) -> bool {
        matches!(&e.kind, ExprKind::DecimalLit(_)) || self.is_fixed_typed(e)
    }

    /// Whether `e` is a `+ - * / %` arithmetic op whose operands are fixed operands
    /// — evaluated exactly (num/den) when materialized in a fixed context.
    fn is_fixed_binop(&self, e: &Expr) -> bool {
        use BinOpKind::*;
        matches!(&e.kind, ExprKind::BinOp { op: Add | Sub | Mul | Div | Rem, lhs, rhs }
            if self.is_fixed_operand(lhs) || self.is_fixed_operand(rhs))
    }

    /// Split a decimal literal's exact text into `(mantissa_digits, integral,
    /// fraction)` — the digits with the point removed, and the digit counts.
    fn decimal_lit_parts(text: &str) -> (String, u32, u32) {
        let (neg, body) = match text.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, text.trim_start_matches('+')),
        };
        let (int_part, frac_part) = match body.split_once('.') {
            Some((i, f)) => (i, f),
            None => (body, ""),
        };
        let mut mant = String::new();
        if neg { mant.push('-'); }
        mant.push_str(int_part);
        mant.push_str(frac_part);
        let integral = (int_part.len().max(1)) as u32;
        let fraction = frac_part.len() as u32;
        (mant, integral, fraction)
    }

    /// Default display precision (fraction digits) for a `fixed` whose `F` is
    /// unspecified (`fixed`, `fixed<,>`, `fixed<I,>`). ~fits a small-integral value
    /// in 64 bits (sic.md's guidance) and is plenty for most uses.
    const FIXED_DEFAULT_F: u32 = 18;

    /// Emit a rational-runtime call yielding a `fixed` value (a `__sic_rat*`),
    /// tagging its type so memory management frees it via `__sic_rat_free`.
    fn emit_rat_call(&mut self, name: &str, args: Vec<Val>) -> Result<Val> {
        self.emit_bigint_call(name, args, super::types::fixed_type(0, 0))
    }

    /// Free a `fixed` rational temporary immediately (in the current block).
    fn rat_free_now(&mut self, v: Val) -> Result<()> {
        self.emit_bigint_call("__sic_rat_free", vec![v], Type::Void)?;
        Ok(())
    }

    /// Evaluate `e` as a `fixed` rational → `(rat_ptr, integral, fraction, owned)`.
    /// A fixed variable is borrowed (`owned=false`); a decimal literal / integer
    /// builds a fresh owned rational. `integral`/`fraction` are the display digit
    /// widths for `typestr` and `.str`.
    fn fixed_operand_owned(&mut self, e: &Expr) -> Result<(Val, u32, u32, bool)> {
        // A fixed arithmetic binop (incl. bare-literal ops like `1.0/3.0`) is
        // computed exactly here — its result temp is statement-managed, so it is
        // handed back as a "borrowed" (not caller-freed-in-block) operand.
        if self.is_fixed_binop(e) {
            let ExprKind::BinOp { op, lhs, rhs } = &e.kind else { unreachable!() };
            let (i, f) = self.fixed_expr_dims(e).unwrap_or((0, 0));
            let r = self.lower_fixed_binop(*op, lhs, rhs)?;
            return Ok((r, i, f, false));
        }
        if let ExprKind::DecimalLit(text) = &e.kind {
            let (digits, i, f) = Self::decimal_lit_parts(text);
            let s = self.emit_cstring(&digits);
            let scale = self.coerce(Constant::int(f as i64), &Type::i32())?;
            let r = self.emit_rat_call("__sic_rat_from_decimal", vec![s, scale])?;
            return Ok((r, i, f, true));
        }
        let ty = self.infer_expr_type(e).unwrap_or_else(|_| Type::i32());
        if let Some((i, f)) = super::types::fixed_dims(&ty) {
            let r = self.lower_expr(e)?; // borrowed rational pointer
            return Ok((r, i, f, false));
        }
        // An integer → an exact rational with denominator 1.
        let v = self.lower_expr(e)?;
        let i64v = self.coerce(v, &Type::i64())?;
        let r = self.emit_rat_call("__sic_rat_from_i64", vec![i64v])?;
        Ok((r, 19, 0, true))
    }

    /// Like `fixed_operand_owned` but registers an owned temp for statement-end
    /// freeing (used where the operand isn't consumed immediately in-block).
    fn fixed_operand(&mut self, e: &Expr) -> Result<(Val, u32, u32)> {
        let (r, i, f, owned) = self.fixed_operand_owned(e)?;
        if owned { self.bigint_temps.push(r.clone()); }
        Ok((r, i, f))
    }

    /// Lower a fixed `+ - * / %` as EXACT rational arithmetic (sic.md §"Built-in
    /// fixed point") — no scale, no rounding until display. Operand temps are freed
    /// in-block; the fresh result is registered for statement-end freeing.
    fn lower_fixed_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let fname = match op {
            BinOpKind::Add => "__sic_rat_add",
            BinOpKind::Sub => "__sic_rat_sub",
            BinOpKind::Mul => "__sic_rat_mul",
            BinOpKind::Div => "__sic_rat_div",
            BinOpKind::Rem => "__sic_rat_mod",
            _ => return Err(CompileError::new("fixed supports only + - * / % here".to_string())),
        };
        let (a, _, _, oa) = self.fixed_operand_owned(lhs)?;
        let (b, _, _, ob) = self.fixed_operand_owned(rhs)?;
        let r = self.emit_rat_call(fname, vec![a.clone(), b.clone()])?;
        if oa { self.rat_free_now(a)?; }
        if ob { self.rat_free_now(b)?; }
        self.bigint_temps.push(r.clone());
        Ok(r)
    }

    /// Lower a fixed comparison (all six) as an exact rational compare. Operand
    /// temps are freed in-block (so a compare inside `||`/`&&` leaves nothing
    /// behind); the result is a plain `i32`.
    fn lower_fixed_cmp(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (a, _, _, oa) = self.fixed_operand_owned(lhs)?;
        let (b, _, _, ob) = self.fixed_operand_owned(rhs)?;
        let cmp = self.emit_bigint_call("__sic_rat_cmp", vec![a.clone(), b.clone()], Type::i32())?;
        if oa { self.rat_free_now(a)?; }
        if ob { self.rat_free_now(b)?; }
        self.emit_binop(op, cmp, Constant::int(0))
    }

    /// Result `(integral, fraction)` digit widths of a fixed op, for `typestr` and
    /// `.str` display precision (the value itself is an exact rational): `+`/`-`/`%`
    /// take the larger of each; `*` sums them; `/` keeps the larger fraction (a
    /// non-terminating quotient like 1/3 is shown to that many digits, rounded).
    fn fixed_result_dims(op: BinOpKind, a: (u32, u32), b: (u32, u32)) -> (u32, u32) {
        match op {
            BinOpKind::Mul => (a.0 + b.0, a.1 + b.1),
            BinOpKind::Div => (a.0 + b.1, a.1.max(b.1)),
            _ => (a.0.max(b.0), a.1.max(b.1)),
        }
    }

    /// Compile-time `(integral, fraction)` display widths of a fixed expression.
    pub(super) fn fixed_expr_dims(&self, e: &Expr) -> Option<(u32, u32)> {
        if let ExprKind::DecimalLit(text) = &e.kind {
            let (_, i, f) = Self::decimal_lit_parts(text);
            return Some((i, f));
        }
        match &e.kind {
            ExprKind::IntLit(v, _) => return Some((v.unsigned_abs().to_string().len().max(1) as u32, 0)),
            ExprKind::UIntLit(v, _) => return Some((v.to_string().len().max(1) as u32, 0)),
            _ => {}
        }
        match self.infer_expr_type(e) {
            Ok(t) => super::types::fixed_dims(&t).or({
                if matches!(t, Type::Int { .. }) { Some((19, 0)) } else { None }
            }),
            _ => None,
        }
    }

    /// Materialize `e` as an OWNED `fixed` rational for storing into a slot (value
    /// semantics). The rational is exact; the target's `F` is display precision, so
    /// nothing is rounded here. Clones so the binding owns an independent block.
    pub(super) fn eval_fixed_owned(&mut self, e: &Expr, _to_f: u32) -> Result<Val> {
        // A `fixed` target puts the RHS in a fixed numeric context: bare integer
        // literals adopt `fixed`, so `fixed a = 1/3` is the exact rational ⅓
        // rather than integer-divided to 0 (sic.md §"Built-in fixed point").
        let pe = Self::promote_numeric_literals(e);
        let (r, _, _) = self.fixed_operand(&pe)?;
        self.emit_rat_call("__sic_rat_clone", vec![r])
    }

    /// sic numeric-context literal promotion (sic.md §"Built-in fixed point"): in
    /// `T v = <expr>` with a float/double/fixed target, a bare integer literal in
    /// an arithmetic position adopts the target type — so `fixed a = 1/3` is the
    /// exact rational ⅓ and `float b = 1/3` is 0.333…, not integer-divided to 0.
    /// Rewrites `IntLit(_, false)` → `DecimalLit`, descending only through `+ - * /`,
    /// unary `-`, and ternary arms. Suffixed / unsigned literals (`1U`, `1L`),
    /// explicit casts (`(int)1`), calls, and subscripts keep their own type.
    pub(super) fn promote_numeric_literals(e: &Expr) -> Expr {
        use BinOpKind::*;
        let kind = match &e.kind {
            // Only a bare (un-suffixed, 32-bit) integer literal is promoted; the
            // `bool=true` form marks an `L`/`LL`/oversized literal, left as-is.
            ExprKind::IntLit(v, false) => ExprKind::DecimalLit(v.to_string()),
            // An arithmetic op where either operand is explicitly typed (a suffixed
            // literal or a cast) keeps standard C semantics — no operand is promoted
            // — so `1U / 3` and `(int)1 / 3` still integer-divide.
            ExprKind::BinOp { op: op @ (Add | Sub | Mul | Div), lhs, rhs }
                if !Self::is_type_anchored(lhs) && !Self::is_type_anchored(rhs) => ExprKind::BinOp {
                op: *op,
                lhs: Box::new(Self::promote_numeric_literals(lhs)),
                rhs: Box::new(Self::promote_numeric_literals(rhs)),
            },
            ExprKind::Unary { op: UnOpKind::Neg, expr } if !Self::is_type_anchored(expr) =>
                ExprKind::Unary {
                    op: UnOpKind::Neg,
                    expr: Box::new(Self::promote_numeric_literals(expr)),
                },
            ExprKind::Ternary { cond, then, else_ } => ExprKind::Ternary {
                cond: cond.clone(),
                then: Box::new(Self::promote_numeric_literals(then)),
                else_: Box::new(Self::promote_numeric_literals(else_)),
            },
            _ => return e.clone(),
        };
        Expr { kind, span: e.span.clone() }
    }

    /// Whether `e` pins an explicit numeric type that suppresses literal promotion
    /// (sic.md §"Built-in fixed point"): a suffixed / unsigned literal (`1U`, `1L`)
    /// or an explicit cast (`(int)1`). Propagates through arithmetic, so `(1U+2)/3`
    /// stays integer. Bare literals, variables, calls, etc. do not anchor.
    fn is_type_anchored(e: &Expr) -> bool {
        use BinOpKind::*;
        match &e.kind {
            ExprKind::IntLit(_, true) | ExprKind::UIntLit(_, _) => true,
            ExprKind::Cast { .. } => true,
            ExprKind::BinOp { op: Add | Sub | Mul | Div | Rem, lhs, rhs } =>
                Self::is_type_anchored(lhs) || Self::is_type_anchored(rhs),
            ExprKind::Unary { op: UnOpKind::Neg, expr } => Self::is_type_anchored(expr),
            _ => false,
        }
    }

    /// Free a bigint/fixed temporary immediately (in the current block).
    fn bi_free_now(&mut self, m: Val) -> Result<()> {
        self.emit_bigint_call("__sic_bi_free", vec![m], Type::Void)?;
        Ok(())
    }

    /// If `pty` is a bigint or fixed parameter type, set `*pval` to the argument
    /// built as that bignum value and return true. A same-type/scale argument is
    /// passed as-is (the callee borrows it); a literal/int lowered as a scalar is
    /// (re)built here — safe because such mismatched args are pure. Temps are freed
    /// at statement end (after the call).
    fn build_bignum_arg(&mut self, pval: &mut Val, pty: &Type, arg: &Expr) -> Result<bool> {
        if !self.is_sic() { return Ok(false); }
        let at = self.infer_expr_type(arg).unwrap_or_else(|_| Type::i32());
        if super::types::is_bigint(pty) {
            if !super::types::is_bigint(&at) {
                *pval = self.to_bigint(arg)?;
            }
            return Ok(true);
        }
        if super::types::is_fixed(pty) {
            // A `fixed` value is an exact rational (`__sic_rat*`) regardless of its
            // declared `<I,F>` (display-only), so a fixed argument is borrowed as-is;
            // a decimal literal / integer is (re)built into a fresh rational temp.
            if !super::types::is_fixed(&at) {
                let (m, _, _) = self.fixed_operand(arg)?; // registers the owned temp
                *pval = m;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Format a type as its sic source name for `typestr` (sic.md §"Built-in fixed
    /// point"). `expr`/`ty` are the operand and its inferred type; a fixed uses its
    /// declared/inferred `<I,F>`, a bare decimal literal reports its natural fixed
    /// dims, and other types get their canonical sic spelling.
    fn type_name_string(&self, expr: &Expr, ty: &Type) -> String {
        // A bare decimal literal is a fixed of its own digit widths.
        if let ExprKind::DecimalLit(text) = &expr.kind {
            let (_, i, f) = Self::decimal_lit_parts(text);
            return format!("fixed<{},{}>", i, f);
        }
        self.type_name_of(ty)
    }

    /// Canonical sic spelling of a type (no operand context) — used by RTTI
    /// `type(x).str` and `typeid` records (sic.md §"RTTI").
    pub(super) fn type_name_of(&self, ty: &Type) -> String {
        if let Some((i, f)) = super::types::fixed_dims(ty) {
            return format!("fixed<{},{}>", i, f);
        }
        if super::types::is_bigint(ty) { return "bigint".to_string(); }
        if super::types::is_sic_string(ty) { return "string".to_string(); }
        if super::types::is_type_info(ty) { return "type".to_string(); }
        match ty {
            Type::Void => "void".to_string(),
            Type::Bool => "bool".to_string(),
            Type::Int { bits, signed } => format!("{}{}", if *signed { 'i' } else { 'u' }, bits),
            Type::Float32 => "f32".to_string(),
            Type::Float64 => "f64".to_string(),
            Type::Float80 => "f80".to_string(),
            Type::Pointer(inner) => format!("{}*", self.type_name_of(inner)),
            Type::Struct(st) => format!("struct {}", st.name.clone().unwrap_or_default()),
            Type::Union(u) => format!("union {}", u.name.clone().unwrap_or_default()),
            _ => "?".to_string(),
        }
    }

    /// The fixed value's decimal string (`b.str`): resolve the EXACT rational to
    /// its declared display precision `F` (rounded half-away-from-zero) via
    /// `__sic_rat_to_str`. A bare/open `fixed` (F unspecified) uses the default F.
    fn fixed_to_str(&mut self, base: &Expr) -> Result<Val> {
        let f = self.fixed_expr_dims(base).map(|d| d.1).filter(|&f| f > 0)
            .unwrap_or(Self::FIXED_DEFAULT_F);
        let (r, _, _) = self.fixed_operand(base)?;
        let scale = self.coerce(Constant::int(f as i64), &Type::i32())?;
        let s = self.emit_bigint_call("__sic_rat_to_str", vec![r, scale], Type::char_ptr())?;
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: Type::char_ptr(), align: None });
        self.push_instr(Instr::Store { val: s.clone(), ptr: Val::Local(slot) });
        self.register_scope_exit(super::func::Cleanup::FreePtr { slot: Val::Local(slot) });
        Ok(s)
    }

    /// sic tuple pack (sic.md §"Tuples"): allocate a refcounted heap block
    /// (`[ size | refcount=1 | fields ]`), store the elements, and return a
    /// pointer to it — the tuple value. Immutable and shared by pointer; the
    /// temporary registers a scope-exit release so a discarded tuple is freed.
    fn construct_tuple(&mut self, elems: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // Lower every element first, recording each value and its type.
        let mut vals: Vec<(Val, Type)> = Vec::with_capacity(elems.len());
        for e in elems {
            let ety = self.infer_expr_type(e).unwrap_or_else(|_| Type::i32());
            if matches!(ety, Type::Struct(_) | Type::Union(_)) {
                let p = self.lower_aggregate_ptr(e)?;
                vals.push((p, ety));
            } else {
                let v = self.lower_expr(e)?;
                let vt = self.val_type(&v);
                vals.push((v, vt));
            }
        }
        let layout = super::types::tuple_layout(vals.iter().map(|(_, t)| t.clone()).collect());
        // Heap-allocate the block with a refcount header (rc = 1); `data` points
        // at the fields.
        let data = self.emit_rc_alloc(&layout)?;

        for (i, (v, vt)) in vals.into_iter().enumerate() {
            let fld = self.field_ptr_from(LValue::plain(data.clone(), layout.clone()), &i.to_string(), false, sp)?;
            if matches!(vt, Type::Struct(_) | Type::Union(_)) {
                let size = vt.size_of(self.ptr_size());
                let align = vt.align_of(self.ptr_size());
                self.push_instr(Instr::MemCopy { dst: fld.ptr, src: v, size, align });
            } else {
                self.store_lvalue(&fld, v)?;
            }
        }
        // Register a scope-exit release for the freshly-created temporary.
        self.register_tuple_release(data.clone())?;
        Ok(data)
    }

    /// Allocate a refcounted heap block `[ size | refcount=1 | payload ]` sized for
    /// `layout` and return a pointer to the payload, typed `*layout`. Reuses the
    /// fat-pointer header shared with `new`/`del` so `emit_rc_retain`/`release`
    /// apply directly.
    fn emit_rc_alloc(&mut self, layout: &Type) -> Result<Val> {
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let header = (2 * self.ptr_size()) as i64;
        let size = layout.size_of(self.ptr_size()).max(1);
        let total = self.coerce(Constant::uint(size + header as u64), &usize_ty)?;
        let block = self.emit_malloc(total)?; // char*
        // header[0] = payload size ; header[1] (at +ptr_size) = refcount = 1
        let sz = self.coerce(Constant::uint(size), &usize_ty)?;
        self.push_instr(Instr::Store { val: sz, ptr: block.clone() });
        let rc_ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rc_ptr, base: block.clone(), index: Constant::int(self.ptr_size() as i64), elem_size: 1, result_ty: Type::char_ptr() });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: Val::Local(rc_ptr) });
        let ptr_ty = Type::Pointer(Box::new(layout.clone()));
        let data = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: data, base: block, index: Constant::int(header), elem_size: 1, result_ty: ptr_ty.clone() });
        self.val_types.insert(data.0, ptr_ty);
        Ok(Val::Local(data))
    }

    /// Register a scope-exit release for a tuple pointer value (spills it to a
    /// slot so the cleanup can reach it).
    fn register_tuple_release(&mut self, ptr: Val) -> Result<()> {
        let pc = self.coerce(ptr, &Type::char_ptr())?;
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: Type::char_ptr(), align: None });
        self.push_instr(Instr::Store { val: pc, ptr: Val::Local(slot) });
        self.register_scope_exit(super::func::Cleanup::RefRelease { slot: Val::Local(slot) });
        Ok(())
    }

    /// sic tuple field pointer + type (sic.md §"Tuples"): `t[i]` addresses field
    /// `i` of the tuple. `i` must be an in-range constant.
    fn tuple_field_lvalue(&mut self, base: &Expr, index: &Expr, sp: &crate::lexer::Span) -> Result<LValue> {
        let layout = super::types::tuple_layout_of(&self.infer_expr_type(base)?)
            .ok_or_else(|| CompileError::at("not a tuple".to_string(), sp.file.clone(), sp.line, sp.col))?;
        let nfields = match &layout { Type::Struct(st) => st.fields.len(), _ => 0 };
        let idx = self.const_index(index).ok_or_else(|| CompileError::at(
            "a tuple index must be a constant".to_string(), sp.file.clone(), sp.line, sp.col))?;
        if idx < 0 || idx as usize >= nfields {
            return Err(CompileError::at(
                format!("tuple index {} out of range (0..{})", idx, nfields),
                sp.file.clone(), sp.line, sp.col));
        }
        // A tuple value is a pointer to its heap block; index off that pointer.
        let ptr = self.lower_expr(base)?;
        self.field_ptr_from(LValue::plain(ptr, layout), &idx.to_string(), false, sp)
    }

    /// Evaluate an expression that must be a compile-time integer index.
    fn const_index(&self, e: &Expr) -> Option<i64> {
        crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok()
    }

    /// sic tuple unpack `tuple(t0, t1, …) = rhs` (sic.md §"Tuples"): assign each
    /// tuple field into the corresponding target lvalue. Arity and per-element
    /// assignability are checked.
    fn lower_tuple_unpack(&mut self, targets: &[Expr], rhs: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let rty = self.infer_expr_type(rhs)?;
        let layout = super::types::tuple_layout_of(&rty).ok_or_else(|| CompileError::at(
            "tuple unpack requires a tuple on the right-hand side".to_string(),
            sp.file.clone(), sp.line, sp.col))?;
        let fields = match &layout { Type::Struct(st) => st.fields.clone(), _ => vec![] };
        if fields.len() != targets.len() {
            return Err(CompileError::at(
                format!("tuple unpack expects {} values, got {} targets", fields.len(), targets.len()),
                sp.file.clone(), sp.line, sp.col));
        }
        // A tuple value is a pointer to its heap block; read fields off it.
        let src = self.lower_expr(rhs)?;
        for (i, tgt) in targets.iter().enumerate() {
            let dst_lv = self.lower_lvalue(tgt)?;
            let (_, fty) = &fields[i];
            // Type check: the field must be assignable to the target (same type,
            // or a trivial scalar conversion via `coerce`).
            let fld = self.field_ptr_from(LValue::plain(src.clone(), layout.clone()), &i.to_string(), false, sp)?;
            if matches!(fty, Type::Struct(_) | Type::Union(_)) {
                if dst_lv.ty != *fty {
                    return Err(CompileError::at(
                        format!("tuple element {} type mismatch on unpack", i),
                        sp.file.clone(), sp.line, sp.col));
                }
                let size = fty.size_of(self.ptr_size());
                let align = fty.align_of(self.ptr_size());
                self.push_instr(Instr::MemCopy { dst: dst_lv.ptr, src: fld.ptr, size, align });
            } else {
                let v = self.load_lvalue(&fld)?;
                self.store_lvalue(&dst_lv, v)?;
            }
        }
        Ok(src)
    }

    /// Materialize a deferred `tuple t;` local on its first assignment: allocate
    /// a pointer slot, bind it to the RHS tuple pointer, and retain the shared
    /// heap block (released at scope exit).
    fn materialize_deferred_tuple(&mut self, name: &str, rhs: &Expr) -> Result<Val> {
        let ty = self.infer_expr_type(rhs)?;
        if !super::types::is_tuple(&ty) {
            return Err(CompileError::at(
                format!("tuple '{}' must be assigned a tuple value", name),
                rhs.span.file.clone(), rhs.span.line, rhs.span.col));
        }
        let vid = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: vid, ty: ty.clone(), align: None });
        self.define_local(name.to_string(), ty.clone(), vid);
        self.deferred_tuples.remove(name);
        let ptr = self.lower_expr(rhs)?;
        let pc = self.coerce(ptr.clone(), &Type::char_ptr())?;
        self.emit_rc_retain(pc)?;
        self.push_instr(Instr::Store { val: ptr, ptr: Val::Local(vid) });
        self.register_scope_exit(super::func::Cleanup::RefRelease { slot: Val::Local(vid) });
        Ok(Val::Local(vid))
    }

    /// sic array concatenation `a + b` (sic.md §"Arrays and lists"): allocate a
    /// fresh array of the combined length and copy `a`'s then `b`'s elements into
    /// it. Returns a pointer to the temporary (decays like any array value). Both
    /// operands must share an element type.
    fn lower_array_concat(&mut self, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (le, la) = match self.infer_expr_type(lhs)? {
            Type::Array { elem, len } => (*elem, len),
            _ => unreachable!("caller checked array operands"),
        };
        let (re, lb) = match self.infer_expr_type(rhs)? {
            Type::Array { elem, len } => (*elem, len),
            _ => unreachable!(),
        };
        if le != re {
            return Err(CompileError::at(
                "array concatenation requires matching element types".to_string(),
                lhs.span.file.clone(), lhs.span.line, lhs.span.col));
        }
        let elem_size = le.size_of(self.ptr_size());
        let result_ty = Type::Array { elem: Box::new(le.clone()), len: la + lb };
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: result_ty.clone(), align: None });
        self.val_types.insert(slot.0, result_ty.clone());

        // Copy `a` at offset 0, then `b` right after it. Array operands decay to a
        // pointer to their first element.
        let a_ptr = self.lower_aggregate_ptr(lhs)?;
        self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: a_ptr, size: la as u64 * elem_size, align: le.align_of(self.ptr_size()) });
        if lb > 0 {
            let b_ptr = self.lower_aggregate_ptr(rhs)?;
            let dst_b = self.alloc_val();
            let bc = self.coerce(Val::Local(slot), &Type::char_ptr())?;
            self.push_instr(Instr::GetElemPtr { dest: dst_b, base: bc, index: Constant::int(la as i64 * elem_size as i64), elem_size: 1, result_ty: Type::char_ptr() });
            self.push_instr(Instr::MemCopy { dst: Val::Local(dst_b), src: b_ptr, size: lb as u64 * elem_size, align: le.align_of(self.ptr_size()) });
        }
        Ok(Val::Local(slot))
    }

    /// Whether `e` is an actual `string`-typed expression. Used to decide that a
    /// `+` is string concatenation. A bare string literal does NOT count here (so
    /// `"abc" + 1` stays pointer arithmetic); the literal is still accepted as the
    /// *other* operand once concatenation is triggered by a real string.
    pub(crate) fn is_string_operand(&self, e: &Expr) -> bool {
        matches!(self.infer_expr_type(e), Ok(t) if super::types::is_sic_string(&t))
    }

    /// Load a `string`/literal operand of `+` as a `(data, size)` pair (size as
    /// i64). A `string` reads its slice fields; a literal uses a fresh cstring
    /// global and its compile-time byte length.
    fn string_operand_parts(&mut self, e: &Expr) -> Result<(Val, Val)> {
        if let ExprKind::StringLit(s) = &e.kind {
            let data = self.emit_cstring(s);
            return Ok((data, Constant::int(s.len() as i64)));
        }
        let ty = self.infer_expr_type(e)?;
        // A `char*` / `char[]` operand is a NUL-terminated C string: its parts are
        // the pointer and `strlen` (so `str + argv[1]` / `str + buf` work, not only
        // `str + "literal"`).
        let is_cstr = matches!(&ty, Type::Pointer(inner) if matches!(inner.as_ref(), Type::Int { bits: 8, .. }))
            || matches!(&ty, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }));
        if !super::types::is_sic_string(&ty) && is_cstr {
            let v = self.lower_expr(e)?;
            let cp = self.coerce(v, &Type::char_ptr())?;
            let len = self.emit_strlen(cp.clone())?;
            let len = self.coerce(len, &Type::i64())?;
            return Ok((cp, len));
        }
        if !super::types::is_sic_string(&ty) {
            return Err(CompileError::at(
                "operand of string `+` is neither a string nor a string literal".to_string(),
                e.span.file.clone(), e.span.line, e.span.col,
            ));
        }
        let data_lv = self.lower_lvalue_field(e, "data")?;
        let data = self.load_lvalue(&data_lv)?;
        let size_lv = self.lower_lvalue_field(e, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let size = self.coerce(size, &Type::i64())?;
        Ok((data, size))
    }

    /// sic native string comparison `a == b` / `a != b` (sic.md §"Built-in
    /// string"): equal iff the byte lengths match and the bytes are identical —
    /// `size_a == size_b && memcmp(data_a, data_b, size) == 0`. No NUL-termination,
    /// no `.str`, no copy; slices compare their view of the shared buffer. `memcmp`
    /// is called over `min(size_a, size_b)` so it never reads past either buffer
    /// (a length mismatch already makes the result unequal).
    fn lower_string_compare(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (d1, s1) = self.string_operand_parts(lhs)?;
        let (d2, s2) = self.string_operand_parts(rhs)?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let s1u = self.coerce(s1, &usize_ty)?;
        let s2u = self.coerce(s2, &usize_ty)?;

        // min(s1, s2) — the safe memcmp length.
        let lt = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: lt, op: CmpOp::IULt, lhs: s1u.clone(), rhs: s2u.clone(), ty: usize_ty.clone() });
        let minsz = self.alloc_val();
        self.push_instr(Instr::Select { dest: minsz, cond: Val::Local(lt), on_true: s1u.clone(), on_false: s2u.clone(), ty: usize_ty.clone() });

        let voidp = Type::void_ptr();
        let memcmp = self.lowerer.module.func_ref_by_name("memcmp").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "memcmp".to_string(),
                sig: FunctionType { ret: Type::i32(), params: vec![voidp.clone(), voidp.clone(), usize_ty.clone()], variadic: false },
            })
        });
        let d1v = self.coerce(d1, &voidp)?;
        let d2v = self.coerce(d2, &voidp)?;
        let cmp = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(cmp), func: memcmp, args: vec![d1v, d2v, Val::Local(minsz)], ret_ty: Type::i32() });

        let content_eq = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: content_eq, op: CmpOp::IEq, lhs: Val::Local(cmp), rhs: Constant::zero(), ty: Type::i32() });
        let size_eq = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: size_eq, op: CmpOp::IEq, lhs: s1u, rhs: s2u, ty: usize_ty });
        let equal = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: equal, op: BinOp::And, lhs: Val::Local(size_eq), rhs: Val::Local(content_eq), ty: Type::Bool });

        let bool_result = if op == BinOpKind::Ne {
            let ne = self.alloc_val();
            self.push_instr(Instr::UnaryOp { dest: ne, op: UnOp::BoolNot, val: Val::Local(equal), ty: Type::Bool });
            Val::Local(ne)
        } else {
            Val::Local(equal)
        };
        // Comparisons yield i32 0/1 (C convention).
        let ext = self.alloc_val();
        self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: bool_result, to_ty: Type::i32() });
        Ok(Val::Local(ext))
    }

    /// sic `a + b` on strings: allocate an owned refcount block
    /// `[ rc(usize) | data...(total) | NUL ]`, copy both halves, and return the
    /// joined `string` with `rc` = 1. Released (freed) at scope exit.
    /// sic `s.dup` (sic.md §"Strings"): an OWNED heap copy of a string / C string.
    /// Unlike `string s = <char*>` (a non-owning VIEW), the result owns its bytes in
    /// a `[rc=1 | text | NUL]` block — so it can safely outlive a local buffer it
    /// was formatted into (e.g. `char b[32]; snprintf(b,…); return b.dup;`), where
    /// returning the view would dangle.
    /// Build an OWNED string (`[rc=1 | text | NUL]`) copying `size` bytes from
    /// `data`. Returns a descriptor pointer with a real heap `rc`. Does NOT register
    /// a scope-exit release — the caller decides ownership (a temp registers one; a
    /// returned value is moved out).
    pub(crate) fn owned_string_from_parts(&mut self, data: Val, size: Val) -> Result<Val> {
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let word = self.ptr_size() as i64; // sizeof(usize) — the rc cell
        let bufsize = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: bufsize, op: BinOp::Add, lhs: size.clone(), rhs: Constant::int(word + 1), ty: Type::i64() });
        let block = self.emit_malloc(Val::Local(bufsize))?; // char*
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: block.clone() }); // rc = 1
        let dptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: dptr, base: block.clone(), index: Constant::int(word), elem_size: 1, result_ty: Type::char_ptr() });
        self.emit_memcpy(Val::Local(dptr), data, size.clone())?;
        let endp = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: endp, base: Val::Local(dptr), index: size.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        self.push_instr(Instr::MemSet { dst: Val::Local(endp), val: Constant::zero(), size: 1, align: 1 });
        self.make_string_val(Val::Local(dptr), size, block)
    }

    /// Build a `string` in a SINGLE heap block — `[ descriptor | rc | bytes | NUL ]`
    /// — and return the descriptor pointer (which is the block base), so the whole
    /// value is reclaimed by one `free(ptr)`. Used for dict-owned string values.
    fn emit_dict_owned_string(&mut self, data: Val, size: Val) -> Result<Val> {
        let ps = self.ptr_size() as i64;
        let sty = super::types::sic_string_type(self.ptr_size());
        let hdr = sty.size_of(self.ptr_size()) as i64; // 24: the descriptor
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let size_i = self.coerce(size.clone(), &Type::i64())?;
        let total = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: total, op: BinOp::Add, lhs: size_i.clone(), rhs: Constant::int(hdr + ps + 1), ty: Type::i64() });
        let block = self.emit_malloc(Val::Local(total))?; // char*
        // rc cell at block + hdr.
        let rccell = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rccell, base: block.clone(), index: Constant::int(hdr), elem_size: 1, result_ty: Type::Pointer(Box::new(usize_ty.clone())) });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: Val::Local(rccell) });
        // bytes at block + hdr + word; copy `size` bytes and NUL-terminate.
        let bytes = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: bytes, base: block.clone(), index: Constant::int(hdr + ps), elem_size: 1, result_ty: Type::char_ptr() });
        self.emit_memcpy(Val::Local(bytes), data, size.clone())?;
        let endp = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: endp, base: Val::Local(bytes), index: size_i, elem_size: 1, result_ty: Type::char_ptr() });
        self.push_instr(Instr::MemSet { dst: Val::Local(endp), val: Constant::zero(), size: 1, align: 1 });
        // Descriptor at block+0: { data = bytes, size, rc = rccell }.
        let block_str = self.coerce(block.clone(), &Type::Pointer(Box::new(sty.clone())))?;
        if let Some((dptr, dty, _)) = self.member_at(&block_str, &sty, 0) { let v = self.coerce(Val::Local(bytes), &dty)?; self.push_instr(Instr::Store { val: v, ptr: dptr }); }
        if let Some((sptr, sfty, _)) = self.member_at(&block_str, &sty, 1) { let v = self.coerce(size, &sfty)?; self.push_instr(Instr::Store { val: v, ptr: sptr }); }
        if let Some((rptr, rfty, _)) = self.member_at(&block_str, &sty, 2) { let v = self.coerce(Val::Local(rccell), &rfty)?; self.push_instr(Instr::Store { val: v, ptr: rptr }); }
        Ok(block)
    }

    fn emit_string_dup(&mut self, base: &Expr) -> Result<Val> {
        let (data, size) = self.string_operand_parts(base)?;
        let sv = self.owned_string_from_parts(data, size)?;
        self.register_scope_exit(super::func::Cleanup::StringRelease { addr: sv.clone() });
        Ok(sv)
    }

    /// Move a `string` into the sret slot on `return`: if `src` is a copy-on-escape
    /// view of a LOCAL stack buffer (`rc == 1` sentinel), materialize an OWNED copy
    /// (the buffer dies with the frame); otherwise move the descriptor and retain
    /// (a real refcount is shared with the caller; a static/borrowed view is
    /// rc<=0-safe). Contents are copied ONLY for the escaping local-buffer case.
    pub(crate) fn emit_string_return_into(&mut self, sret: &Val, src: &Val) -> Result<()> {
        let sty = super::types::sic_string_type(self.ptr_size());
        let size_bytes = sty.size_of(self.ptr_size());
        let align = sty.align_of(self.ptr_size()) as u64;
        let rcty = self.rc_ptr_ty();
        // rc = src->rc
        let (rcptr, rfty, _) = self.member_at(src, &sty, 2).expect("string has rc field");
        let rc = self.alloc_val();
        self.push_instr(Instr::Load { dest: rc, ptr: rcptr, ty: rfty });
        let sentinel = self.coerce(Constant::int(Self::RC_LOCAL_SENTINEL), &rcty)?;
        let is_sent = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_sent, op: CmpOp::IEq, lhs: Val::Local(rc), rhs: sentinel, ty: rcty });
        let dup_bb = self.new_block_after_current();
        let move_bb = self.new_block_after_current();
        let join = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_sent), then_bb: dup_bb, else_bb: move_bb });
        // dup: owned copy of the local buffer's bytes
        self.switch_to_block(dup_bb);
        let (dptr, dty, _) = self.member_at(src, &sty, 0).unwrap();
        let data = self.alloc_val();
        self.push_instr(Instr::Load { dest: data, ptr: dptr, ty: dty });
        let (sptr, s2ty, _) = self.member_at(src, &sty, 1).unwrap();
        let size = self.alloc_val();
        self.push_instr(Instr::Load { dest: size, ptr: sptr, ty: s2ty });
        let owned = self.owned_string_from_parts(Val::Local(data), Val::Local(size))?;
        self.push_instr(Instr::MemCopy { dst: sret.clone(), src: owned, size: size_bytes, align });
        self.set_terminator(Terminator::Jump(join));
        // move: copy descriptor + retain (noop for a non-owning view)
        self.switch_to_block(move_bb);
        self.push_instr(Instr::MemCopy { dst: sret.clone(), src: src.clone(), size: size_bytes, align });
        self.retain_string_at(sret)?;
        self.set_terminator(Terminator::Jump(join));
        self.switch_to_block(join);
        Ok(())
    }

    fn lower_string_concat(&mut self, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let (d1, s1) = self.string_operand_parts(lhs)?;
        let (d2, s2) = self.string_operand_parts(rhs)?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let word = self.ptr_size() as i64; // sizeof(usize) — the rc cell

        // total = s1 + s2 ; block = malloc(word + total + 1)
        let total = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: total, op: BinOp::Add, lhs: s1.clone(), rhs: s2.clone(), ty: Type::i64() });
        let bufsize = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: bufsize, op: BinOp::Add, lhs: Val::Local(total), rhs: Constant::int(word + 1), ty: Type::i64() });
        let block = self.emit_malloc(Val::Local(bufsize))?; // char*

        // rc cell at block[0] = 1
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: block.clone() });
        // data = block + word
        let data = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: data, base: block.clone(), index: Constant::int(word), elem_size: 1, result_ty: Type::char_ptr() });

        // memcpy(data, d1, s1); memcpy(data + s1, d2, s2); data[total] = 0
        self.emit_memcpy(Val::Local(data), d1, s1.clone())?;
        let mid = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: mid, base: Val::Local(data), index: s1, elem_size: 1, result_ty: Type::char_ptr() });
        self.emit_memcpy(Val::Local(mid), d2, s2)?;
        let endp = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: endp, base: Val::Local(data), index: Val::Local(total), elem_size: 1, result_ty: Type::char_ptr() });
        self.push_instr(Instr::MemSet { dst: Val::Local(endp), val: Constant::zero(), size: 1, align: 1 });

        // rc = block (the refcount cell address). Register the temp for release
        // so an intermediate that is never bound to a variable is still freed.
        let sv = self.make_string_val(Val::Local(data), Val::Local(total), block)?;
        self.register_scope_exit(super::func::Cleanup::StringRelease { addr: sv.clone() });
        Ok(sv)
    }

    pub fn emit_binop(&mut self, op: BinOpKind, l: Val, r: Val) -> Result<Val> {
        let lt = self.val_type(&l);
        let rt = self.val_type(&r);

        // Handle pointer arithmetic: ptr + int, int + ptr, ptr - int
        if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
            match (&lt, &rt) {
                (Type::Pointer(elem), _) if !matches!(rt, Type::Pointer(_)) => {
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => *e.clone(), t => t.clone() };
                    // Resolve an opaque pointee aggregate so the element stride is
                    // its real size, not 0/1 (pointer pointees are stored opaque).
                    let inner = super::types::resolve_aggregate(&inner, &self.lowerer.struct_types);
                    let elem_size = inner.size_of(self.ptr_size()) as i64;
                    let idx = self.coerce(r, &Type::i64())?;
                    let idx = if op == BinOpKind::Sub {
                        let neg = self.alloc_val();
                        self.push_instr(Instr::UnaryOp { dest: neg, op: UnOp::Neg, val: idx, ty: Type::i64() });
                        Val::Local(neg)
                    } else { idx };
                    let dest = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest, base: l, index: idx, elem_size: elem_size.unsigned_abs(), result_ty: Type::Pointer(Box::new(inner.clone())) });
                    self.val_types.insert(dest.0, Type::Pointer(Box::new(inner)));
                    return Ok(Val::Local(dest));
                }
                (_, Type::Pointer(elem)) if op == BinOpKind::Add => {
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => *e.clone(), t => t.clone() };
                    let inner = super::types::resolve_aggregate(&inner, &self.lowerer.struct_types);
                    let elem_size = inner.size_of(self.ptr_size());
                    let idx = self.coerce(l, &Type::i64())?;
                    let dest = self.alloc_val();
                    self.push_instr(Instr::GetElemPtr { dest, base: r, index: idx, elem_size, result_ty: Type::Pointer(Box::new(inner.clone())) });
                    self.val_types.insert(dest.0, Type::Pointer(Box::new(inner)));
                    return Ok(Val::Local(dest));
                }
                (Type::Pointer(elem), Type::Pointer(_)) if op == BinOpKind::Sub => {
                    // ptr - ptr → (ptr - ptr) / elem_size
                    let inner = match elem.as_ref() { Type::Array { elem: e, .. } => (**e).clone(), t => t.clone() };
                    let inner = super::types::resolve_aggregate(&inner, &self.lowerer.struct_types);
                    let elem_size = inner.size_of(self.ptr_size()) as i64;
                    let lp = self.coerce(l, &Type::i64())?;
                    let rp = self.coerce(r, &Type::i64())?;
                    let diff = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: diff, op: BinOp::Sub, lhs: lp, rhs: rp, ty: Type::i64() });
                    if elem_size > 1 {
                        let elem_size_val = Constant::int(elem_size);
                        let quot = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: quot, op: BinOp::SDiv, lhs: Val::Local(diff), rhs: elem_size_val, ty: Type::i64() });
                        return Ok(Val::Local(quot));
                    }
                    return Ok(Val::Local(diff));
                }
                _ => {}
            }
        }

        let common = usual_arith_conv(&lt, &rt);

        let lc = self.coerce(l, &common)?;
        let rc = self.coerce(r, &common)?;

        let is_float = common.is_float();
        let is_signed = common.is_signed();

        let (ir_op, result_ty) = match op {
            BinOpKind::Add => (if is_float { BinOp::FAdd } else { BinOp::Add }, common.clone()),
            BinOpKind::Sub => (if is_float { BinOp::FSub } else { BinOp::Sub }, common.clone()),
            BinOpKind::Mul => (if is_float { BinOp::FMul } else { BinOp::Mul }, common.clone()),
            BinOpKind::Div => {
                let op = if is_float { BinOp::FDiv } else if is_signed { BinOp::SDiv } else { BinOp::UDiv };
                (op, common.clone())
            }
            BinOpKind::Rem => {
                let op = if is_float { BinOp::FRem } else if is_signed { BinOp::SRem } else { BinOp::URem };
                (op, common.clone())
            }
            BinOpKind::BitAnd => (BinOp::And, common.clone()),
            BinOpKind::BitOr  => (BinOp::Or,  common.clone()),
            BinOpKind::BitXor => (BinOp::Xor, common.clone()),
            BinOpKind::Shl    => (BinOp::Shl,  common.clone()),
            BinOpKind::Shr    => (if is_signed { BinOp::AShr } else { BinOp::LShr }, common.clone()),
            BinOpKind::RotL   => (BinOp::Rotl, common.clone()),
            BinOpKind::RotR   => (BinOp::Rotr, common.clone()),
            // Comparisons return i32 (C convention: 0 or 1)
            BinOpKind::Eq | BinOpKind::Ne | BinOpKind::Lt | BinOpKind::Le |
            BinOpKind::Gt | BinOpKind::Ge => {
                let cmp_op = if is_float {
                    match op {
                        BinOpKind::Eq => CmpOp::FOEq, BinOpKind::Ne => CmpOp::FONe,
                        BinOpKind::Lt => CmpOp::FOLt, BinOpKind::Le => CmpOp::FOLe,
                        BinOpKind::Gt => CmpOp::FOGt, BinOpKind::Ge => CmpOp::FOGe,
                        _ => unreachable!()
                    }
                } else if is_signed {
                    match op {
                        BinOpKind::Eq => CmpOp::IEq,  BinOpKind::Ne => CmpOp::INe,
                        BinOpKind::Lt => CmpOp::ISLt, BinOpKind::Le => CmpOp::ISLe,
                        BinOpKind::Gt => CmpOp::ISGt, BinOpKind::Ge => CmpOp::ISGe,
                        _ => unreachable!()
                    }
                } else {
                    // Unsigned ints AND pointers: pointer relational comparisons
                    // are unsigned (addresses like 0xffff... must compare above
                    // real heap/stack addresses, not as a negative number).
                    match op {
                        BinOpKind::Eq => CmpOp::IEq,  BinOpKind::Ne => CmpOp::INe,
                        BinOpKind::Lt => CmpOp::IULt, BinOpKind::Le => CmpOp::IULe,
                        BinOpKind::Gt => CmpOp::IUGt, BinOpKind::Ge => CmpOp::IUGe,
                        _ => unreachable!()
                    }
                };
                let cmp_dest = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: cmp_dest, op: cmp_op, lhs: lc, rhs: rc, ty: common.clone() });
                // Extend bool to i32
                let ext_dest = self.alloc_val();
                self.push_instr(Instr::Cast { dest: ext_dest, op: CastOp::ZExt, val: Val::Local(cmp_dest), to_ty: Type::i32() });
                return Ok(Val::Local(ext_dest));
            }
            BinOpKind::LogAnd | BinOpKind::LogOr => unreachable!(),
        };

        // SIC defines integer `÷0` and `%0` as 0 (sic.md §"Integer overflow"),
        // rather than C's undefined behavior / hardware trap.
        if self.is_sic()
            && matches!(ir_op, BinOp::SDiv | BinOp::UDiv | BinOp::SRem | BinOp::URem)
        {
            // In `unsafe` / a `divide_by_zero` guard, `÷0` is an exception instead
            // (sic.md §"Errors and exceptions"): trap or jump to the guard.
            if self.divzero_active() {
                let is_zero = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::IEq, lhs: rc.clone(), rhs: Constant::zero(), ty: result_ty.clone() });
                let tgt = self.divzero_target();
                self.branch_on_exception(Val::Local(is_zero), tgt);
                // On the fall-through path the divisor is nonzero — divide directly.
                if let Some(v) = self.emit_div_rem_libcall(ir_op, lc.clone(), rc.clone(), &result_ty) {
                    return Ok(v);
                }
                let dest = self.alloc_val();
                self.push_instr(Instr::BinOp { dest, op: ir_op, lhs: lc, rhs: rc, ty: result_ty });
                return Ok(Val::Local(dest));
            }
            return Ok(self.guarded_div_rem(ir_op, lc, rc, result_ty));
        }
        // SIC defines out-of-range shifts (sic.md §"Rotate and shift"): count ≥
        // width → 0 (signed `>>` → sign-fill); count ≤ 0 → value unchanged.
        if self.is_sic() && matches!(ir_op, BinOp::Shl | BinOp::AShr | BinOp::LShr) {
            return Ok(self.guarded_shift(ir_op, lc, rc, result_ty));
        }
        // sic `unsafe` / `overflow` guard: integer `+ - *` traps on overflow
        // (sic.md §"Integer overflow") instead of wrapping. The wrapping result is
        // computed but committed only on the no-overflow path (so a caught op
        // "changes no values").
        if self.is_sic() && matches!(ir_op, BinOp::Add | BinOp::Sub | BinOp::Mul)
            && self.overflow_active()
        {
            let dest = self.alloc_val();
            self.push_instr(Instr::BinOp { dest, op: ir_op, lhs: lc.clone(), rhs: rc.clone(), ty: result_ty.clone() });
            let res = Val::Local(dest);
            let ovf = self.emit_overflow_flag(ir_op, &lc, &rc, &res, &result_ty);
            let tgt = self.overflow_target();
            self.branch_on_exception(ovf, tgt);
            return Ok(res);
        }
        if let Some(v) = self.emit_div_rem_libcall(ir_op, lc.clone(), rc.clone(), &result_ty) {
            return Ok(v);
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::BinOp { dest, op: ir_op, lhs: lc, rhs: rc, ty: result_ty });
        Ok(Val::Local(dest))
    }

    /// SIC integer `÷0`/`%0` → 0. Force the divisor to a nonzero value so the
    /// trapping div/rem never sees 0, then select 0 when the real divisor was 0.
    fn guarded_div_rem(&mut self, op: BinOp, lc: Val, rc: Val, ty: Type) -> Val {
        let is_zero = self.alloc_val();
        self.push_instr(Instr::Cmp {
            dest: is_zero, op: CmpOp::IEq, lhs: rc.clone(), rhs: Constant::int(0), ty: ty.clone(),
        });
        let safe_rhs = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: safe_rhs, cond: Val::Local(is_zero),
            on_true: Constant::int(1), on_false: rc, ty: ty.clone(),
        });
        let q = if let Some(v) =
            self.emit_div_rem_libcall(op, lc.clone(), Val::Local(safe_rhs), &ty)
        {
            v
        } else {
            let d = self.alloc_val();
            self.push_instr(Instr::BinOp {
                dest: d, op, lhs: lc, rhs: Val::Local(safe_rhs), ty: ty.clone(),
            });
            Val::Local(d)
        };
        let result = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: result, cond: Val::Local(is_zero),
            on_true: Constant::int(0), on_false: q, ty,
        });
        Val::Local(result)
    }

    /// SIC out-of-range shift semantics (sic.md §"Rotate and shift"). Cranelift
    /// masks the shift count to the operand width; SIC instead defines count ≥
    /// width → 0 (arithmetic `>>` → sign fill) and count ≤ 0 → value unchanged.
    /// The in-range shift is only *used* for 0<count<width (where masking is a
    /// no-op); the out-of-range cases are picked with `select`.
    fn guarded_shift(&mut self, op: BinOp, lc: Val, rc: Val, ty: Type) -> Val {
        let bits = ty.int_bits().unwrap_or(32) as i64;

        let normal = self.alloc_val();
        self.push_instr(Instr::BinOp {
            dest: normal, op, lhs: lc.clone(), rhs: rc.clone(), ty: ty.clone(),
        });
        // Value when count ≥ width: 0, except signed `>>` fills the sign bit
        // (= arithmetic-shift the value by width-1).
        let overflow_val = if matches!(op, BinOp::AShr) {
            let d = self.alloc_val();
            self.push_instr(Instr::BinOp {
                dest: d, op: BinOp::AShr, lhs: lc.clone(),
                rhs: Constant::int(bits - 1), ty: ty.clone(),
            });
            Val::Local(d)
        } else {
            Constant::int(0)
        };
        // The count is compared as signed: a shift amount is conceptually signed
        // ("zero or negative → unchanged"), and realistic counts are tiny, so a
        // high-bit-set count means "negative", not "> 2 billion".
        let ge_w = self.alloc_val();
        self.push_instr(Instr::Cmp {
            dest: ge_w, op: CmpOp::ISGe, lhs: rc.clone(), rhs: Constant::int(bits), ty: ty.clone(),
        });
        let inner = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: inner, cond: Val::Local(ge_w),
            on_true: overflow_val, on_false: Val::Local(normal), ty: ty.clone(),
        });
        // count ≤ 0 → value unchanged.
        let le0 = self.alloc_val();
        self.push_instr(Instr::Cmp {
            dest: le0, op: CmpOp::ISLe, lhs: rc, rhs: Constant::int(0), ty: ty.clone(),
        });
        let result = self.alloc_val();
        self.push_instr(Instr::Select {
            dest: result, cond: Val::Local(le0),
            on_true: lc, on_false: Val::Local(inner), ty,
        });
        Val::Local(result)
    }

    /// If `op` is an integer divide/remainder on a 128-bit type, emit a call to
    /// the compiler-rt helper (`__divti3`/`__udivti3`/`__modti3`/`__umodti3`) and
    /// return its result — Cranelift's x64 backend can't lower `udiv.i128` etc.
    /// natively. Otherwise return None so the caller emits a plain `BinOp`.
    fn emit_div_rem_libcall(&mut self, op: BinOp, lhs: Val, rhs: Val, ty: &Type) -> Option<Val> {
        if !matches!(ty, Type::Int { bits: 128, .. }) { return None; }
        let name = match op {
            BinOp::SDiv => "__divti3",
            BinOp::UDiv => "__udivti3",
            BinOp::SRem => "__modti3",
            BinOp::URem => "__umodti3",
            _ => return None,
        };
        let fref = self.lowerer.module.func_ref_by_name(name).unwrap_or_else(|| {
            self.lowerer.module.add_extern(sic_ir::ExternFunc {
                name: name.to_string(),
                sig: sic_ir::FunctionType {
                    ret: ty.clone(),
                    params: vec![ty.clone(), ty.clone()],
                    variadic: false,
                },
            })
        });
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![lhs, rhs], ret_ty: ty.clone() });
        Some(Val::Local(dest))
    }

    /// Emit `malloc(n)` and return the result typed as `char*`. Used by the
    /// native-string ops (`.ptr` copy, concat); the block is not freed yet —
    /// reclamation waits on the ownership/refcount milestone.
    fn emit_malloc(&mut self, n: Val) -> Result<Val> {
        let voidp = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("malloc").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "malloc".to_string(),
                sig: FunctionType { ret: voidp.clone(), params: vec![Type::u64()], variadic: false },
            })
        });
        let sz = self.coerce(n, &Type::u64())?;
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![sz], ret_ty: voidp });
        self.val_types.insert(dest.0, Type::char_ptr());
        Ok(Val::Local(dest))
    }

    /// Emit `strlen(s)` → `usize`.
    fn emit_strlen(&mut self, s: Val) -> Result<Val> {
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let fref = self.lowerer.module.func_ref_by_name("strlen").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "strlen".to_string(),
                sig: FunctionType { ret: usize_ty.clone(), params: vec![Type::char_ptr()], variadic: false },
            })
        });
        let s = self.coerce(s, &Type::char_ptr())?;
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![s], ret_ty: usize_ty });
        Ok(Val::Local(dest))
    }

    /// Build a non-owning `string` (rc = NULL) from a `char*` value, computing its
    /// length with `strlen`. Used to pass a C string / literal to a `string`
    /// parameter.
    /// Wrap a C string as a NON-owning `string` view (`rc = NULL`) — safe for
    /// static/borrowed data (a literal, a caller's buffer) that outlives the view.
    pub(crate) fn cstr_to_string(&mut self, data: Val) -> Result<Val> {
        self.cstr_to_string_rc(data, 0)
    }

    /// Wrap a C string as a view with an explicit `rc` sentinel. `rc = 1` marks a
    /// view of a LOCAL stack buffer (`string s = local_char_array;`): it is not
    /// refcounted or freed (sentinel <= 1 in retain/release), but the return path
    /// materializes an owned copy so it never escapes as a dangling pointer.
    pub(crate) fn cstr_to_string_rc(&mut self, data: Val, rc: i64) -> Result<Val> {
        let data = self.coerce(data, &Type::char_ptr())?;
        let len = self.emit_strlen(data.clone())?;
        let rcv = self.coerce(Constant::int(rc), &self.rc_ptr_ty())?;
        self.make_string_val(data, len, rcv)
    }

    /// The sentinel `rc` value for a view of a local stack buffer (copy-on-escape).
    pub(crate) const RC_LOCAL_SENTINEL: i64 = 1;

    /// Whether `e` names a LOCAL stack array (`char b[10]`) — a buffer whose
    /// lifetime ends with this frame, so a `string` view of it must be copied
    /// before it escapes. A `char*`/array PARAMETER decays to a pointer (points at
    /// caller memory) and a global array is static, so neither counts.
    pub(crate) fn is_local_stack_buffer(&self, e: &Expr) -> bool {
        let ExprKind::Ident(name) = &e.kind else { return false };
        let is_local = self.locals.iter().any(|s| s.contains_key(name));
        is_local && matches!(self.infer_expr_type(e), Ok(Type::Array { .. }))
    }

    /// Whether a `string` view built from `e` must be COPIED before it escapes the
    /// current scope — its `char*` points at a buffer that dies at this frame's
    /// exit: a local stack array, or a bigint/fixed `.str` (a heap buffer freed by a
    /// scope-exit cleanup). A literal or a caller's `char*` outlives the frame, so
    /// it stays a zero-copy view.
    pub(crate) fn needs_copy_on_escape(&self, e: &Expr) -> bool {
        if self.is_local_stack_buffer(e) { return true; }
        // `((bigint)x).str` / `f.str` — a fresh heap string auto-freed at scope exit.
        if let ExprKind::Field { base, name } = &e.kind {
            if name == "str" {
                if let Ok(bt) = self.infer_expr_type(base) {
                    return super::types::is_bigint(&bt) || super::types::is_fixed(&bt);
                }
            }
        }
        false
    }

    // ─── enum `.str` helpers (sic.md §"Match") ───────────────────────────────

    /// A native `string` view over the static literal `s` (rc = NULL; safe to
    /// return — the bytes are static).
    pub(crate) fn enum_str_literal(&mut self, s: &str) -> Result<Val> {
        let data = self.emit_cstring(s);
        self.cstr_to_string(data)
    }

    /// `enumvalue.str` for a payload-less enum variable: map its runtime value to
    /// `"EnumName::Variant"`, defaulting to `"EnumName::?"` for an unlisted value.
    pub(crate) fn emit_enum_str(&mut self, base: &Expr, ename: &str, variants: &[(String, i64)]) -> Result<Val> {
        let v = self.lower_expr(base)?;
        let v = self.coerce(v, &Type::i64())?;
        let sty = super::types::sic_string_type(self.ptr_size());
        let size = sty.size_of(self.ptr_size());
        let align = sty.align_of(self.ptr_size()) as u64;
        let result = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result, ty: sty.clone(), align: None });
        self.val_types.insert(result.0, sty);
        // Default fallback, then overwrite if the value matches a variant.
        let deflt = self.enum_str_literal(&format!("{}::?", ename))?;
        self.push_instr(Instr::MemCopy { dst: Val::Local(result), src: deflt, size, align });
        for (name, val) in variants {
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: v.clone(), rhs: Constant::int(*val), ty: Type::i64() });
            let then_bb = self.new_block_after_current();
            let cont_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: Val::Local(eq), then_bb, else_bb: cont_bb });
            self.switch_to_block(then_bb);
            let s = self.enum_str_literal(&format!("{}::{}", ename, name))?;
            self.push_instr(Instr::MemCopy { dst: Val::Local(result), src: s, size, align });
            self.set_terminator(Terminator::Jump(cont_bb));
            self.switch_to_block(cont_bb);
        }
        Ok(Val::Local(result))
    }

    // ─── `u8char` code-point helpers (sic.md §"Integer sizes") ────────────────

    /// The u32 type used for a `u8char`'s `cp` field.
    fn u32_ty() -> Type { Type::Int { bits: 32, signed: false } }

    /// Load the code point (`cp`, u32) out of a `u8char` value.
    pub(crate) fn u8char_cp(&mut self, e: &Expr) -> Result<Val> {
        let p = self.lower_aggregate_ptr(e)?;             // &{ cp }
        let cptr = self.coerce(p, &Type::Pointer(Box::new(Self::u32_ty())))?;
        let cp = self.alloc_val();
        self.push_instr(Instr::Load { dest: cp, ptr: cptr, ty: Self::u32_ty() });
        Ok(Val::Local(cp))
    }

    /// Materialize a `u8char` value (a `{ cp }` struct temp) holding code point `cp`.
    pub(crate) fn make_u8char(&mut self, cp: Val) -> Result<Val> {
        let ty = super::types::u8char_type();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: ty.clone(), align: None });
        self.val_types.insert(slot.0, ty);
        let cp = self.coerce(cp, &Self::u32_ty())?;
        let cptr = self.coerce(Val::Local(slot), &Type::Pointer(Box::new(Self::u32_ty())))?;
        self.push_instr(Instr::Store { val: cp, ptr: cptr });
        Ok(Val::Local(slot))
    }

    /// sic `string.utf8` — decode a string's UTF-8 bytes into a `u8char[]` slice
    /// `{ data, length, size }`. Calls the prepended `__sic_utf8_decode`, then
    /// wraps the result: `length` = code-point count, `size` = the original byte
    /// count (== sum of each code point's `.size`).
    pub(crate) fn lower_string_utf8(&mut self, base: &Expr) -> Result<Val> {
        let (data, size) = self.string_operand_parts(base)?; // data: char*, size: i64
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let u8c_ptr = Type::Pointer(Box::new(super::types::u8char_type()));

        // out_count slot, then decode(data, size, &out_count) -> u32*/u8char*.
        let count_slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: count_slot, ty: usize_ty.clone(), align: None });
        let data_c = self.coerce(data, &Type::char_ptr())?;
        let size_u = self.coerce(size.clone(), &usize_ty)?;
        let count_ptr = self.coerce(Val::Local(count_slot), &Type::Pointer(Box::new(usize_ty.clone())))?;
        let ret_ty = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("__sic_utf8_decode").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "__sic_utf8_decode".to_string(),
                sig: FunctionType {
                    ret: Type::void_ptr(),
                    params: vec![Type::char_ptr(), usize_ty.clone(), Type::Pointer(Box::new(usize_ty.clone()))],
                    variadic: false,
                },
            })
        });
        let decoded = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(decoded), func: fref, args: vec![data_c, size_u, count_ptr], ret_ty });
        let count = self.alloc_val();
        self.push_instr(Instr::Load { dest: count, ptr: Val::Local(count_slot), ty: usize_ty.clone() });
        // The decoded code-point buffer is malloc'd; free it at scope exit.
        let free_slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: free_slot, ty: Type::char_ptr(), align: None });
        let dfree = self.coerce(Val::Local(decoded), &Type::char_ptr())?;
        self.push_instr(Instr::Store { val: dfree, ptr: Val::Local(free_slot) });
        self.register_scope_exit(super::func::Cleanup::FreePtr { slot: Val::Local(free_slot) });

        // Build the { data, length, size } slice.
        let arr_ty = super::types::u8char_arr_type(self.ptr_size());
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: arr_ty.clone(), align: None });
        self.val_types.insert(slot.0, arr_ty.clone());
        let dptr = self.coerce(Val::Local(decoded), &u8c_ptr)?;
        let data_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), arr_ty.clone()), "data", false, &base.span)?;
        self.store_lvalue(&data_lv, dptr)?;
        let len_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), arr_ty.clone()), "length", false, &base.span)?;
        self.store_lvalue(&len_lv, Val::Local(count))?;
        let siz_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), arr_ty.clone()), "size", false, &base.span)?;
        let siz = self.coerce(size, &usize_ty)?;
        self.store_lvalue(&siz_lv, siz)?;
        Ok(Val::Local(slot))
    }

    /// The UTF-8 encoded byte length (1..4) of a code point `cp`, branchless:
    /// `1 + (cp>=0x80) + (cp>=0x800) + (cp>=0x10000)`. Returned as `usize`.
    pub(crate) fn u8char_encoded_len(&mut self, cp: Val) -> Result<Val> {
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let cp = self.coerce(cp, &Self::u32_ty())?;
        let mut acc = self.coerce(Constant::int(1), &usize_ty)?;
        for bound in [0x80i64, 0x800, 0x10000] {
            let ge = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: ge, op: CmpOp::IUGe, lhs: cp.clone(), rhs: Constant::int(bound), ty: Self::u32_ty() });
            let geu = self.coerce(Val::Local(ge), &usize_ty)?;
            let sum = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: sum, op: BinOp::Add, lhs: acc, rhs: geu, ty: usize_ty.clone() });
            acc = Val::Local(sum);
        }
        Ok(acc)
    }

    /// Emit `free(p)`.
    pub(crate) fn emit_free(&mut self, p: Val) -> Result<()> {
        let voidp = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("free").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "free".to_string(),
                sig: FunctionType { ret: Type::Void, params: vec![voidp.clone()], variadic: false },
            })
        });
        let p = self.coerce(p, &voidp)?;
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![p], ret_ty: Type::Void });
        Ok(())
    }

    /// sic `new T` / `new T(count)` (sic.md §"Scopes and automatic release"):
    /// allocate a block with a `{ usize size; usize refcount }` header before the
    /// data, `refcount = 1`, and return the data pointer typed `T*`. `del` frees
    /// via the header; the header also carries the size for future bounds checks.
    pub(crate) fn lower_new(&mut self, ty: &crate::ast::QualType, args: &[Expr]) -> Result<Val> {
        let elem_ty = self.lower_type(ty)?;
        // sic `new dict<K,V>` (sic.md §"Dict"): allocate a fresh hash map, returning
        // the dict handle directly (the handle is itself a heap pointer).
        if self.is_sic() && super::types::is_dict(&elem_ty) {
            let sp = args.first().map(|e| e.span.clone()).unwrap_or_default();
            return self.lower_dict_new(&elem_ty, &sp);
        }
        let elem_size = elem_ty.size_of(self.ptr_size()).max(1);
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let header = (2 * self.ptr_size()) as i64;

        // sic constructor via `new` (sic.md §"Memory safety"): if `T` is a struct
        // with a constructor, `new T(args)` allocates ONE object and runs the
        // constructor on it; otherwise the parens hold an element count.
        let ctor = if self.is_sic() {
            match &elem_ty {
                Type::Struct(st) => st.name.as_ref().and_then(|n| self.lowerer.struct_ctor.get(n).cloned()),
                _ => None,
            }
        } else { None };

        // A struct constructor gets one object; otherwise the first (only) argument
        // is the element count, defaulting to 1.
        let count_val = match (&ctor, args.first()) {
            (Some(_), _) | (None, None) => self.coerce(Constant::int(1), &usize_ty)?,
            (None, Some(e)) => { let v = self.lower_expr(e)?; self.coerce(v, &usize_ty)? }
        };
        let esz = self.coerce(Constant::uint(elem_size), &usize_ty)?;
        let data_size = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: data_size, op: BinOp::Mul, lhs: count_val, rhs: esz, ty: usize_ty.clone() });
        let header_c = self.coerce(Constant::int(header), &usize_ty)?;
        let total = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: total, op: BinOp::Add, lhs: Val::Local(data_size), rhs: header_c, ty: usize_ty.clone() });
        let block = self.emit_malloc(Val::Local(total))?; // char*

        // header[0] = data_size ; header[1] (at +ptr_size) = refcount = 1
        self.push_instr(Instr::Store { val: Val::Local(data_size), ptr: block.clone() });
        let rc_ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rc_ptr, base: block.clone(), index: Constant::int(self.ptr_size() as i64), elem_size: 1, result_ty: Type::char_ptr() });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        self.push_instr(Instr::Store { val: one, ptr: Val::Local(rc_ptr) });

        let ptr_ty = Type::Pointer(Box::new(elem_ty.clone()));
        let data = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: data, base: block, index: Constant::int(header), elem_size: 1, result_ty: ptr_ty.clone() });
        self.val_types.insert(data.0, ptr_ty);

        // Zero the fresh object and run the constructor `__sic_ctor_<S>(data, args…)`.
        if let Some(ctor) = ctor {
            let osz = elem_ty.size_of(self.ptr_size());
            if osz > 0 {
                self.push_instr(Instr::MemSet { dst: Val::Local(data), val: Constant::zero(), size: osz, align: elem_ty.align_of(self.ptr_size()) });
            }
            let fref = self.lowerer.module.func_ref_by_name(&ctor).ok_or_else(|| CompileError::new(
                format!("internal: constructor '{}' not lowered", ctor)))?;
            let params = self.lowerer.module.func_sig(fref).params.clone();
            let mut cargs = vec![Val::Local(data)];
            for (i, a) in args.iter().enumerate() {
                let v = self.lower_expr(a)?;
                let v = match params.get(i + 1) {
                    Some(pt) if !matches!(pt, Type::Struct(_) | Type::Union(_)) => self.coerce(v, pt)?,
                    _ => v,
                };
                cargs.push(v);
            }
            self.push_instr(Instr::Call { dest: None, func: fref, args: cargs, ret_ty: Type::Void });
        }
        Ok(Val::Local(data))
    }

    /// sic `del p;` — decrement the header refcount of a `new`-allocated pointer
    /// and `free` the block when it reaches 0. A NULL pointer is a no-op.
    pub(crate) fn lower_delete(&mut self, e: &Expr) -> Result<()> {
        // sic `del dict[key]` (sic.md §"Dict"): remove the entry and free its
        // resources. (`del wholeDict` is not a delete-entry — falls through.)
        if self.is_sic() {
            if let ExprKind::Index { base, index } = &e.kind {
                if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_dict(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_dict(i))) {
                    return self.lower_dict_del(base, index, &e.span);
                }
            }
        }
        // sic `del s` on a `string`: drop THIS reference (decrement the refcount,
        // freeing the buffer at zero) and invalidate the descriptor in place. Other
        // copies keep their own reference and stay valid until their scope ends.
        // Zeroing also makes the variable's scope-exit release a no-op, so there is
        // no double free; the variable reads as an empty string afterward.
        if self.is_sic() && matches!(self.infer_expr_type(e), Ok(t) if super::types::is_sic_string(&t)) {
            let ptr = self.lower_aggregate_ptr(e)?;
            self.release_string_at(&ptr)?;
            let sty = super::types::sic_string_type(self.ptr_size());
            let size = sty.size_of(self.ptr_size());
            let align = sty.align_of(self.ptr_size());
            self.push_instr(Instr::MemSet { dst: ptr, val: Constant::zero(), size, align });
            return Ok(());
        }
        // sic `del p` on a pointer to a struct with a destructor (sic.md §"Memory
        // safety"): run `~S()` when the block is actually freed (refcount hits 0).
        let dtor = if self.is_sic() {
            match self.infer_expr_type(e) {
                Ok(Type::Pointer(inner)) => match inner.as_ref() {
                    Type::Struct(st) => st.name.as_ref().and_then(|n| self.lowerer.struct_dtor.get(n).cloned()),
                    _ => None,
                },
                _ => None,
            }
        } else { None };
        let p = self.lower_expr(e)?;
        self.emit_rc_release_dtor(p, dtor)
    }

    /// Decrement the fat-pointer header refcount at `p - ptr_size` and `free` the
    /// block (`p - 2*ptr_size`) at 0. NULL is a no-op. Shared by `del` and by a
    /// `@` reference's scope-exit release.
    pub(crate) fn emit_rc_release(&mut self, p: Val) -> Result<()> {
        self.emit_rc_release_dtor(p, None)
    }

    /// As `emit_rc_release`, but if `dtor` is set, call it on the object right
    /// before the block is freed (only when the refcount reaches 0).
    pub(crate) fn emit_rc_release_dtor(&mut self, p: Val, dtor: Option<String>) -> Result<()> {
        let pc = self.coerce(p, &Type::char_ptr())?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };

        let is_null = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: pc.clone(), rhs: Constant::zero(), ty: Type::char_ptr() });
        let body_bb = self.new_block_after_current();
        let free_bb = self.new_block_after_current();
        let done_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done_bb, else_bb: body_bb });

        // body: refcount field is at p - ptr_size (block + ptr_size). Decrement.
        self.switch_to_block(body_bb);
        let rc_ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rc_ptr, base: pc.clone(), index: Constant::int(-(self.ptr_size() as i64)), elem_size: 1, result_ty: Type::char_ptr() });
        let rc = self.alloc_val();
        self.push_instr(Instr::Load { dest: rc, ptr: Val::Local(rc_ptr), ty: usize_ty.clone() });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        let newrc = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newrc, op: BinOp::Sub, lhs: Val::Local(rc), rhs: one, ty: usize_ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(newrc), ptr: Val::Local(rc_ptr) });
        let zero = self.coerce(Constant::int(0), &usize_ty)?;
        let is_zero = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::IEq, lhs: Val::Local(newrc), rhs: zero, ty: usize_ty });
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_zero), then_bb: free_bb, else_bb: done_bb });

        // free: run the destructor (if any) on the object, then free the block at
        // `p - 2*ptr_size`.
        self.switch_to_block(free_bb);
        if let Some(dtor) = dtor {
            self.emit_cleanup_call(pc.clone(), &dtor);
        }
        let block = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: block, base: pc, index: Constant::int(-(2 * self.ptr_size() as i64)), elem_size: 1, result_ty: Type::char_ptr() });
        self.emit_free(Val::Local(block))?;
        self.set_terminator(Terminator::Jump(done_bb));

        self.switch_to_block(done_bb);
        Ok(())
    }

    /// Increment the fat-pointer header refcount at `p - ptr_size`. NULL is a
    /// no-op. Used when a `@` reference retains its referent.
    pub(crate) fn emit_rc_retain(&mut self, p: Val) -> Result<()> {
        let pc = self.coerce(p, &Type::char_ptr())?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let is_null = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_null, op: CmpOp::IEq, lhs: pc.clone(), rhs: Constant::zero(), ty: Type::char_ptr() });
        let body_bb = self.new_block_after_current();
        let done_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_null), then_bb: done_bb, else_bb: body_bb });
        self.switch_to_block(body_bb);
        let rc_ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: rc_ptr, base: pc, index: Constant::int(-(self.ptr_size() as i64)), elem_size: 1, result_ty: Type::char_ptr() });
        let rc = self.alloc_val();
        self.push_instr(Instr::Load { dest: rc, ptr: Val::Local(rc_ptr), ty: usize_ty.clone() });
        let one = self.coerce(Constant::int(1), &usize_ty)?;
        let newrc = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newrc, op: BinOp::Add, lhs: Val::Local(rc), rhs: one, ty: usize_ty });
        self.push_instr(Instr::Store { val: Val::Local(newrc), ptr: Val::Local(rc_ptr) });
        self.set_terminator(Terminator::Jump(done_bb));
        self.switch_to_block(done_bb);
        Ok(())
    }

    /// sic fat-pointer bounds check: abort if `idx * elem_size >= header.size`,
    /// where the header `size` sits at `base - 2*ptr_size` (sic.md §"Scopes and
    /// automatic release"). `base` must point at the allocation start.
    fn emit_bounds_check(&mut self, base: Val, idx: Val, elem_size: u64) -> Result<()> {
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let idx_u = self.coerce(idx, &usize_ty)?;
        let esz = self.coerce(Constant::uint(elem_size), &usize_ty)?;
        let off = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: off, op: BinOp::Mul, lhs: idx_u, rhs: esz, ty: usize_ty.clone() });

        // size = *(usize*)(base - 2*ptr_size)
        let bc = self.coerce(base, &Type::char_ptr())?;
        let szp = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: szp, base: bc, index: Constant::int(-(2 * self.ptr_size() as i64)), elem_size: 1, result_ty: Type::char_ptr() });
        let size = self.alloc_val();
        self.push_instr(Instr::Load { dest: size, ptr: Val::Local(szp), ty: usize_ty.clone() });

        // if off >= size → __sic_bounds_fail()
        let oob = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: oob, op: CmpOp::IUGe, lhs: Val::Local(off), rhs: Val::Local(size), ty: usize_ty });
        let fail_bb = self.new_block_after_current();
        let ok_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(oob), then_bb: fail_bb, else_bb: ok_bb });
        self.switch_to_block(fail_bb);
        let fref = self.lowerer.ensure_bounds_fail_fn();
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
        self.set_terminator(Terminator::Jump(ok_bb)); // abort never returns
        self.switch_to_block(ok_bb);
        Ok(())
    }

    /// sic `@expr` / `@mut expr` (sic.md §"References"): retain the referent's
    /// allocation and register a scope-exit release, so it stays alive for the
    /// enclosing scope. The reference value is the referent pointer.
    fn lower_ref(&mut self, expr: &Expr) -> Result<Val> {
        let p = self.lower_expr(expr)?;
        let pc = self.coerce(p.clone(), &Type::char_ptr())?;
        self.emit_rc_retain(pc.clone())?;
        // Stash the (char*) pointer so the scope-exit release can reach it.
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: Type::char_ptr(), align: None });
        self.push_instr(Instr::Store { val: pc, ptr: Val::Local(slot) });
        self.register_scope_exit(super::func::Cleanup::RefRelease { slot: Val::Local(slot) });
        // The reference's value is the referent pointer, with its own type.
        Ok(p)
    }

    /// Emit `memcpy(dst, src, n)`.
    fn emit_memcpy(&mut self, dst: Val, src: Val, n: Val) -> Result<()> {
        let voidp = Type::void_ptr();
        let fref = self.lowerer.module.func_ref_by_name("memcpy").unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc {
                name: "memcpy".to_string(),
                sig: FunctionType { ret: voidp.clone(), params: vec![voidp.clone(), voidp.clone(), Type::u64()], variadic: false },
            })
        });
        let dstp = self.coerce(dst, &voidp)?;
        let srcp = self.coerce(src, &voidp)?;
        let n = self.coerce(n, &Type::u64())?;
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![dstp, srcp, n], ret_ty: voidp });
        Ok(())
    }

    /// Materialize a `string` slice descriptor `{ data, size, rc }` in a fresh
    /// temp and return the pointer to it (the aggregate-by-pointer convention used
    /// for struct rvalues). `rc` is the refcount cell pointer (NULL for
    /// non-owning strings).
    pub(crate) fn make_string_val(&mut self, data: Val, size: Val, rc: Val) -> Result<Val> {
        let sty = super::types::sic_string_type(self.ptr_size());
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: sty.clone(), align: None });
        let base = Val::Local(slot);
        if let Some((dptr, dty, _)) = self.member_at(&base, &sty, 0) {
            let v = self.coerce(data, &dty)?;
            self.push_instr(Instr::Store { val: v, ptr: dptr });
        }
        if let Some((sptr, sfty, _)) = self.member_at(&base, &sty, 1) {
            let v = self.coerce(size, &sfty)?;
            self.push_instr(Instr::Store { val: v, ptr: sptr });
        }
        if let Some((rptr, rfty, _)) = self.member_at(&base, &sty, 2) {
            let v = self.coerce(rc, &rfty)?;
            self.push_instr(Instr::Store { val: v, ptr: rptr });
        }
        Ok(base)
    }

    /// Whether the current expected/target type is a *pointer* (`char*`, `void*`,
    /// `const char*`, …) — the signal to keep a string literal as a raw C pointer
    /// instead of promoting it to a `string`. A `string` target is a struct, not a
    /// pointer, so it correctly does not match.
    fn expected_is_char_ptr(&self) -> bool {
        matches!(&self.expected_ty, Some(Type::Pointer(_)))
    }

    /// sic `string[i]` (sic.md §"Strings"): the byte at index `i`. A literal base
    /// with a constant index is bounds-checked at compile time; otherwise a runtime
    /// check against the string's `size` traps on out-of-range access.
    fn lower_string_index(&mut self, base: &Expr, index: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        if let ExprKind::StringLit(s) = &base.kind {
            if let Ok(i) = crate::lower::eval_const_expr(index, &self.lowerer.enum_consts) {
                if i < 0 || i as usize >= s.len() {
                    return Err(CompileError::at(
                        format!("index {} is out of bounds for a string of length {}", i, s.len()),
                        sp.file.clone(), sp.line, sp.col));
                }
            }
        }
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;              // char*
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let size = self.coerce(size, &usize_ty)?;
        let idx = self.lower_expr(index)?;
        let idx = self.coerce(idx, &usize_ty)?;
        // Runtime bounds: i >= size (unsigned, so negatives are huge) → trap.
        let oob = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: oob, op: CmpOp::IUGe, lhs: idx.clone(), rhs: size, ty: usize_ty });
        let fail_bb = self.new_block_after_current();
        let ok_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(oob), then_bb: fail_bb, else_bb: ok_bb });
        self.switch_to_block(fail_bb);
        let fref = self.lowerer.ensure_bounds_fail_fn();
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
        self.set_terminator(Terminator::Jump(ok_bb));
        self.switch_to_block(ok_bb);
        // byte = data[i]
        let ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: ptr, base: data, index: idx, elem_size: 1, result_ty: Type::char_ptr() });
        let byte = self.alloc_val();
        self.push_instr(Instr::Load { dest: byte, ptr: Val::Local(ptr), ty: Type::i8() });
        self.val_types.insert(byte.0, Type::i8());
        Ok(Val::Local(byte))
    }

    /// `char*`-context `string + int`: the bytes pointer offset by `int` — plain C
    /// pointer arithmetic (`"abcdef" + 2` → a `char*` at 'c'). For a literal the
    /// pointer is into the static (NUL-terminated) bytes; for a string it is `.data`.
    fn lower_string_offset_cptr(&mut self, base: &Expr, off: &Expr) -> Result<Val> {
        let data = if let ExprKind::StringLit(s) = &base.kind {
            self.emit_cstring(s)
        } else {
            let lv = self.lower_lvalue_field(base, "data")?;
            self.load_lvalue(&lv)?
        };
        let o = self.lower_expr(off)?;
        let o = self.coerce(o, &Type::i64())?;
        let dest = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest, base: data, index: o, elem_size: 1, result_ty: Type::char_ptr() });
        self.val_types.insert(dest.0, Type::char_ptr());
        Ok(Val::Local(dest))
    }

    /// Decay a `string` descriptor value to its `char*` (`data` field) — for passing
    /// a string to a C variadic function (`printf`). A literal/full string's `data`
    /// is NUL-terminated; a bare slice may not be, so prefer `.ptr`/`.str` there.
    fn string_to_cptr_val(&mut self, s: Val) -> Result<Val> {
        let sty = super::types::sic_string_type(self.ptr_size());
        if let Some((dptr, dty, _)) = self.member_at(&s, &sty, 0) {
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: dptr, ty: dty.clone() });
            self.val_types.insert(d.0, dty);
            return Ok(Val::Local(d));
        }
        Ok(s)
    }

    /// Pointer type of the `rc` refcount cell (`usize*`).
    fn rc_ptr_ty(&self) -> Type {
        Type::Pointer(Box::new(Type::Int { bits: self.ptr_size() * 8, signed: false }))
    }

    /// Emit `__sic_str_retain(rc)` — incref the refcount cell (NULL is a no-op).
    fn emit_string_retain(&mut self, rc: Val) {
        let fref = self.lowerer.ensure_str_retain_fn();
        let rcty = self.rc_ptr_ty();
        let rc = self.coerce(rc.clone(), &rcty).unwrap_or(rc);
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![rc], ret_ty: Type::Void });
    }

    /// Emit `__sic_str_release(rc)` — decref and free the block at 0 (NULL no-op).
    pub(crate) fn emit_string_release(&mut self, rc: Val) {
        let fref = self.lowerer.ensure_str_release_fn();
        let rcty = self.rc_ptr_ty();
        let rc = self.coerce(rc.clone(), &rcty).unwrap_or(rc);
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![rc], ret_ty: Type::Void });
    }

    /// Load and release the `rc` of the `string` stored at `base` (a pointer to
    /// the descriptor) — used for scope-exit release and before overwriting.
    pub(crate) fn release_string_at(&mut self, base: &Val) -> Result<()> {
        let sty = super::types::sic_string_type(self.ptr_size());
        if let Some((rptr, rfty, _)) = self.member_at(base, &sty, 2) {
            let rc = self.alloc_val();
            self.push_instr(Instr::Load { dest: rc, ptr: rptr, ty: rfty });
            self.emit_string_release(Val::Local(rc));
        }
        Ok(())
    }

    /// Retain the `rc` of the `string` stored at `base`.
    pub(crate) fn retain_string_at(&mut self, base: &Val) -> Result<()> {
        let sty = super::types::sic_string_type(self.ptr_size());
        if let Some((rptr, rfty, _)) = self.member_at(base, &sty, 2) {
            let rc = self.alloc_val();
            self.push_instr(Instr::Load { dest: rc, ptr: rptr, ty: rfty });
            self.emit_string_retain(Val::Local(rc));
        }
        Ok(())
    }

    /// sic substring slice `s[lo:hi]` (sic.md §"Built-in string"): a half-open,
    /// byte-offset **view** into `s` — no copy. `{ s.data + lo, hi - lo }`.
    /// Omitted bounds default to `lo=0`, `hi=s.size`.
    /// Resolve a possibly-negative slice bound relative to `size`, Python-style
    /// (sic.md §"Built-in string"): a negative `v` counts from the end —
    /// `v < 0 → size + v` (so `-1` is the last byte, `-2` the one before). A
    /// non-negative bound is unchanged. (Bounds are clamped into range afterwards.)
    fn resolve_slice_index(&mut self, v: Val, size: &Val) -> Val {
        let i64t = Type::i64();
        let is_neg = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_neg, op: CmpOp::ISLt, lhs: v.clone(), rhs: Constant::int(0), ty: i64t.clone() });
        let from_end = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: from_end, op: BinOp::Add, lhs: size.clone(), rhs: v.clone(), ty: i64t.clone() });
        let out = self.alloc_val();
        self.push_instr(Instr::Select { dest: out, cond: Val::Local(is_neg), on_true: Val::Local(from_end), on_false: v, ty: i64t });
        Val::Local(out)
    }

    /// Clamp a signed i64 `v` into `[lo, hi]` (assumes `lo ≤ hi`): `max(lo,
    /// min(v, hi))`. Used to keep string-slice bounds in range.
    fn clamp_signed(&mut self, v: Val, lo: Val, hi: Val) -> Val {
        let i64t = Type::i64();
        // t = min(v, hi)
        let lt_hi = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: lt_hi, op: CmpOp::ISLt, lhs: v.clone(), rhs: hi.clone(), ty: i64t.clone() });
        let t = self.alloc_val();
        self.push_instr(Instr::Select { dest: t, cond: Val::Local(lt_hi), on_true: v, on_false: hi, ty: i64t.clone() });
        // r = max(t, lo)
        let gt_lo = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: gt_lo, op: CmpOp::ISGt, lhs: Val::Local(t), rhs: lo.clone(), ty: i64t.clone() });
        let r = self.alloc_val();
        self.push_instr(Instr::Select { dest: r, cond: Val::Local(gt_lo), on_true: Val::Local(t), on_false: lo, ty: i64t });
        Val::Local(r)
    }

    fn lower_slice(&mut self, base: &Expr, lo: Option<&Expr>, hi: Option<&Expr>) -> Result<Val> {
        let bt = self.infer_expr_type(base)?;
        if !super::types::is_sic_string(&bt) {
            return Err(CompileError::at(
                "slice `[a:b]` applies only to a `string`".to_string(),
                base.span.file.clone(), base.span.line, base.span.col,
            ));
        }
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;                 // char*
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let size = self.coerce(size, &Type::i64())?;

        let lo_v = match lo {
            Some(e) => { let v = self.lower_expr(e)?; self.coerce(v, &Type::i64())? }
            None => Constant::int(0),
        };
        let hi_v = match hi {
            Some(e) => { let v = self.lower_expr(e)?; self.coerce(v, &Type::i64())? }
            None => size.clone(),
        };

        // Python-style negative indices count from the end (`-1` = last byte), then
        // clamp to a valid, defined range (sic.md §"Built-in string"): out-of-range
        // or reversed slices (`s[5:3]`, `s[3:20]`) never read past the buffer — they
        // yield a truncated or empty view instead of crashing. After resolving and
        // clamping, `lo ∈ [0, size]`, `hi ∈ [lo, size]`, so `hi - lo ≥ 0`.
        let lo_r = self.resolve_slice_index(lo_v, &size);
        let hi_r = self.resolve_slice_index(hi_v, &size);
        let lo_c = self.clamp_signed(lo_r, Constant::int(0), size.clone());
        let hi_c = self.clamp_signed(hi_r, lo_c.clone(), size.clone());

        // A slice shares the parent's owned buffer: copy its `rc` and retain it,
        // so the parent's storage outlives the view.
        let rc_lv = self.lower_lvalue_field(base, "rc")?;
        let rc = self.load_lvalue(&rc_lv)?;
        self.emit_string_retain(rc.clone());

        // new data = base data + lo
        let new_data = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: new_data, base: data, index: lo_c.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        // new size = hi - lo (≥ 0 after clamping)
        let new_size = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: new_size, op: BinOp::Sub, lhs: hi_c, rhs: lo_c, ty: Type::i64() });
        // The slice temp holds a reference (it retained the parent above);
        // register it for release so it balances even if never bound.
        let sv = self.make_string_val(Val::Local(new_data), Val::Local(new_size), rc)?;
        self.register_scope_exit(super::func::Cleanup::StringRelease { addr: sv.clone() });
        Ok(sv)
    }

    /// sic `s.length`: number of UTF-8 code points in the slice (sic.md
    /// §"Built-in string"). Delegates to a synthesized once-per-module helper
    /// `__sic_str_length(data, size)` — keeping the counting loop in its own
    /// function avoids emitting multiple expression-level loops into one caller
    /// (which the -O0 backend miscompiles) and keeps call sites small.
    fn emit_string_length(&mut self, base: &Expr) -> Result<Val> {
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        let size = self.coerce(size, &usize_ty)?;
        let fref = self.lowerer.ensure_str_length_fn();
        let dest = self.alloc_val();
        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![data, size], ret_ty: usize_ty });
        Ok(Val::Local(dest))
    }

    /// sic `s.ptr`: yield a `const char*` usable as a C string, copying only when
    /// necessary (sic.md §"Built-in string"). If the byte just past the slice
    /// (`data[size]`) is already NUL, the slice is a valid C string and `data` is
    /// returned as-is; otherwise a NUL-terminated `malloc` copy is made.
    fn emit_string_cptr(&mut self, base: &Expr) -> Result<Val> {
        let data_lv = self.lower_lvalue_field(base, "data")?;
        let data = self.load_lvalue(&data_lv)?;                 // char*
        let size_lv = self.lower_lvalue_field(base, "size")?;
        let size = self.load_lvalue(&size_lv)?;
        let size = self.coerce(size, &Type::i64())?;

        // Probe data[size]; in-bounds because backing buffers are NUL-terminated.
        let last = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: last, base: data.clone(), index: size.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        let byte = self.alloc_val();
        self.push_instr(Instr::Load { dest: byte, ptr: Val::Local(last), ty: Type::i8() });
        let is_term = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: is_term, op: CmpOp::IEq, lhs: Val::Local(byte), rhs: Constant::zero(), ty: Type::i8() });

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: Type::char_ptr(), align: None });
        // `owned` holds the malloc'd copy (or NULL when none) so it can be freed
        // at scope exit — the transient C-string must not leak.
        let owned = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: owned, ty: Type::char_ptr(), align: None });
        let nullp = self.coerce(Constant::zero(), &Type::char_ptr())?;
        self.push_instr(Instr::Store { val: nullp, ptr: Val::Local(owned) });

        let copy_bb = self.new_block_after_current();
        let term_bb = self.new_block_after_current();
        let end_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(is_term), then_bb: term_bb, else_bb: copy_bb });

        // Already NUL-terminated: use data directly.
        self.switch_to_block(term_bb);
        self.push_instr(Instr::Store { val: data.clone(), ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(end_bb));

        // Not terminated: malloc(size+1), copy, append NUL.
        self.switch_to_block(copy_bb);
        let n = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: n, op: BinOp::Add, lhs: size.clone(), rhs: Constant::int(1), ty: Type::i64() });
        let buf = self.emit_malloc(Val::Local(n))?;
        self.emit_memcpy(buf.clone(), data.clone(), size.clone())?;
        let bend = self.alloc_val();
        self.push_instr(Instr::GetElemPtr { dest: bend, base: buf.clone(), index: size.clone(), elem_size: 1, result_ty: Type::char_ptr() });
        self.push_instr(Instr::MemSet { dst: Val::Local(bend), val: Constant::zero(), size: 1, align: 1 });
        self.push_instr(Instr::Store { val: buf.clone(), ptr: Val::Local(result_ptr) });
        self.push_instr(Instr::Store { val: buf, ptr: Val::Local(owned) });
        self.set_terminator(Terminator::Jump(end_bb));

        self.switch_to_block(end_bb);
        // Free the copy (if any) when the enclosing scope exits.
        self.register_scope_exit(super::func::Cleanup::FreePtr { slot: Val::Local(owned) });
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: Type::char_ptr() });
        self.val_types.insert(dest.0, Type::char_ptr());
        Ok(Val::Local(dest))
    }

    fn lower_logical(&mut self, is_and: bool, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: Type::i32(), align: None });
        let zero = Constant::zero();
        let one = Constant::int(1);

        let lhs_val = self.lower_expr(lhs)?;
        let lhs_bool = self.to_bool(lhs_val)?;

        let rhs_bb = self.new_block_after_current();
        let end_bb  = self.new_block_after_current();

        if is_and {
            // if lhs is false → result=0, else evaluate rhs
            let false_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: lhs_bool, then_bb: rhs_bb, else_bb: false_bb });

            self.switch_to_block(false_bb);
            self.push_instr(Instr::Store { val: zero.clone(), ptr: Val::Local(result_ptr) });
            self.set_terminator(Terminator::Jump(end_bb));
        } else {
            // if lhs is true → result=1, else evaluate rhs
            let true_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: lhs_bool, then_bb: true_bb, else_bb: rhs_bb });

            self.switch_to_block(true_bb);
            self.push_instr(Instr::Store { val: one.clone(), ptr: Val::Local(result_ptr) });
            self.set_terminator(Terminator::Jump(end_bb));
        }

        self.switch_to_block(rhs_bb);
        // The rhs is only evaluated on one path, so any bigint/fixed temporaries it
        // creates live in this conditional block and must be freed here — the
        // statement-end flush runs from a block they don't dominate.
        let rhs_mark = self.bigint_temps.len();
        let rhs_val = self.lower_expr(rhs)?;
        let rhs_bool = self.to_bool(rhs_val)?;
        self.flush_bigint_temps_from(rhs_mark);
        // Store 0 or 1 based on rhs bool
        let rhs_ext = self.alloc_val();
        self.push_instr(Instr::Cast { dest: rhs_ext, op: CastOp::ZExt, val: rhs_bool, to_ty: Type::i32() });
        self.push_instr(Instr::Store { val: Val::Local(rhs_ext), ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(end_bb));

        self.switch_to_block(end_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: Type::i32() });
        Ok(Val::Local(dest))
    }

    fn lower_assign(&mut self, op: Option<BinOpKind>, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        // sic type safety (sic.md §"Memory safety"): reject a pointer/value aggregate
        // mismatch on a plain assignment, e.g. `f = new File()` into a `File` value.
        if self.is_sic() && op.is_none() {
            if let Ok(dest_ty) = self.infer_expr_type(lhs) {
                self.check_ptr_value_mismatch(&dest_ty, rhs)?;
            }
        }
        // sic strict enum typing (sic.md §"Enums"): a write to a payload-less
        // enum-typed local must carry the same enum (or an explicit cast); a
        // compound assignment `e += …` is enum arithmetic and is rejected outright.
        if self.is_sic() {
            if let ExprKind::Ident(name) = &lhs.kind {
                if let Some(dest) = self.enum_locals.get(name).cloned() {
                    match op {
                        None => self.check_enum_dest(&dest, rhs, "assigned to")?,
                        Some(_) => return Err(CompileError::at(
                            format!("enum `{}` has no arithmetic — compute with `(int){}` and cast back, \
                                     e.g. `{} = (enum {})((int){} + …)`", dest, name, name, dest, name),
                            lhs.span.file.clone(), lhs.span.line, lhs.span.col)),
                    }
                }
            }
        }
        // sic `list[i] = value` (sic.md §"List") / `dict[key] = value` (sic.md §"Dict").
        if op.is_none() && self.is_sic() {
            if let ExprKind::Index { base, index } = &lhs.kind {
                if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_list(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_list(i))) {
                    self.lower_list_set(base, index, rhs, &lhs.span)?;
                    return Ok(Constant::zero());
                }
                if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_dict(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_dict(i))) {
                    self.lower_dict_set(base, index, rhs, &lhs.span)?;
                    return Ok(Constant::zero());
                }
            }
        }
        // sic tuple unpack `tuple(a, b, …) = e` (sic.md §"Tuples"): assign each of
        // the tuple's fields into the corresponding lvalue.
        if op.is_none() {
            if let ExprKind::TupleExpr(targets) = &lhs.kind {
                return self.lower_tuple_unpack(targets, rhs, &lhs.span);
            }
            // sic deferred tuple local `tuple t; … t = tuple(…)`: the first
            // assignment fixes the concrete type and materializes the slot.
            if let ExprKind::Ident(name) = &lhs.kind {
                if self.is_sic() && self.deferred_tuples.contains(name) {
                    return self.materialize_deferred_tuple(name, rhs);
                }
            }
            // sic tuples are immutable after creation (sic.md §"Tuples"): reject
            // writing to a tuple element `t[i] = x`.
            if self.is_sic() {
                if let ExprKind::Index { base, .. } = &lhs.kind {
                    if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_tuple(&t)) {
                        return Err(CompileError::at(
                            "tuples are immutable: cannot assign to a tuple element".to_string(),
                            lhs.span.file.clone(), lhs.span.line, lhs.span.col));
                    }
                }
            }
        }

        let lv = self.lower_lvalue(lhs)?;

        // sic `atomic` (sic.md §"Atomics"): a compound assignment on an atomic
        // lvalue is a single atomic read-modify-write. Plain `a = v` falls through
        // to the normal store path (store_lvalue emits an atomic store). Only
        // `+= -= &= |= ^=` are allowed, and none on an atomic pointer.
        if self.is_sic() && lv.atomic {
            if let Some(bin) = op {
                let aop = match bin {
                    BinOpKind::Add => AtomicOp::Add,
                    BinOpKind::Sub => AtomicOp::Sub,
                    BinOpKind::BitAnd => AtomicOp::And,
                    BinOpKind::BitOr => AtomicOp::Or,
                    BinOpKind::BitXor => AtomicOp::Xor,
                    _ => return Err(CompileError::at(
                        format!("`{}=` is not an atomic operation — atomics allow only \
                                 `= += -= &= |= ^=` (use an explicit `.cas()` loop otherwise)",
                                super::func::op_symbol(bin)),
                        lhs.span.file.clone(), lhs.span.line, lhs.span.col)),
                };
                if matches!(lv.ty, Type::Pointer(_)) {
                    return Err(CompileError::at(
                        "no arithmetic on an atomic pointer — only load, store, `.swap`, `.cas`".to_string(),
                        lhs.span.file.clone(), lhs.span.line, lhs.span.col));
                }
                let rv = self.lower_expr(rhs)?;
                let rv = self.coerce(rv, &lv.ty)?;
                let old = self.alloc_val();
                self.push_instr(Instr::AtomicRmw { dest: old, op: aop, ptr: lv.ptr.clone(), val: rv.clone(), ty: lv.ty.clone() });
                // The expression value of `a op= v` is the new value; recompute it
                // from the atomically-read old value (the atomic effect is done).
                return self.emit_binop(bin, Val::Local(old), rv);
            }
        }

        // sic tuple variable reassignment `u = <tuple>` (sic.md §"Tuples"): rebind
        // the pointer — retain the new shared block, release the old one (a tuple
        // is immutable, but the *variable* may be re-pointed). Retain-before-
        // release keeps a self-assign balanced.
        if self.is_sic() && op.is_none() && super::types::is_tuple(&lv.ty) {
            let newp = self.lower_expr(rhs)?;
            let npc = self.coerce(newp.clone(), &Type::char_ptr())?;
            self.emit_rc_retain(npc)?;
            let old = self.alloc_val();
            self.push_instr(Instr::Load { dest: old, ptr: lv.ptr.clone(), ty: lv.ty.clone() });
            self.emit_rc_release(Val::Local(old))?;
            self.push_instr(Instr::Store { val: newp, ptr: lv.ptr.clone() });
            return Ok(lv.ptr);
        }

        // sic `bigint` (re)assignment `b = <expr>` / `b += <expr>` (sic.md
        // §"Integer sizes"): free the old block, store a freshly-owned one (value
        // semantics). A compound op computes `b <op> rhs` first.
        if self.is_sic() && super::types::is_bigint(&lv.ty) {
            // Compute the new value as a borrowed/temp bigint, then clone it into
            // an owned block for this slot. `b op= rhs` ≡ `b = b op rhs`.
            let computed = match op {
                None => self.to_bigint(rhs)?,
                Some(bin) => self.lower_bigint_binop(bin, lhs, rhs)?,
            };
            let newv = self.emit_bigint_call("__sic_bi_clone", vec![computed], super::types::bigint_type())?;
            // Free the previous block, then store the freshly-owned one (the slot's
            // scope-exit `BigintFree` will free this in turn).
            let old = self.alloc_val();
            self.push_instr(Instr::Load { dest: old, ptr: lv.ptr.clone(), ty: lv.ty.clone() });
            self.emit_bigint_call("__sic_bi_free", vec![Val::Local(old)], Type::Void)?;
            self.push_instr(Instr::Store { val: newv, ptr: lv.ptr.clone() });
            return Ok(lv.ptr);
        }

        // sic `fixed` (re)assignment `f = <expr>` / `f += <expr>` (sic.md §"Built-in
        // fixed point"): value-semantics like bigint. The value is an EXACT rational
        // (`__sic_rat*`); the variable's declared `<I,F>` is display-only, so nothing
        // is rounded or rescaled on store.
        if self.is_sic() && super::types::is_fixed(&lv.ty) {
            let newv = match op {
                None => self.eval_fixed_owned(rhs, 0)?,
                Some(bin) => {
                    // `f op= rhs` ≡ `f = f op rhs`.
                    let m = self.lower_fixed_binop(bin, lhs, rhs)?;
                    self.emit_rat_call("__sic_rat_clone", vec![m])?
                }
            };
            let old = self.alloc_val();
            self.push_instr(Instr::Load { dest: old, ptr: lv.ptr.clone(), ty: lv.ty.clone() });
            self.emit_bigint_call("__sic_rat_free", vec![Val::Local(old)], Type::Void)?;
            self.push_instr(Instr::Store { val: newv, ptr: lv.ptr.clone() });
            return Ok(lv.ptr);
        }

        // sic: `a = None;` — assign a bare (payload-less) variant by building the
        // `{tag,union}` value from its discriminant. A same-enum RHS copies below.
        if self.is_sic() && op.is_none() && self.is_tagged_enum_struct(&lv.ty) {
            let same = matches!(self.infer_expr_type(rhs), Ok(t) if t == lv.ty);
            if !same {
                let tag = self.lower_expr(rhs)?;
                self.build_enum_from_tag(&lv.ptr, &lv.ty, tag, &rhs.span)?;
                return Ok(lv.ptr);
            }
        }

        // Aggregate (struct/union) assignment is a byte copy, not a scalar
        // load/store — the latter would truncate anything wider than a register.
        // For an array-typed lvalue this only applies to a genuine aggregate RHS
        // (a vector produced by an operator/intrinsic); a scalar RHS to an
        // array-typed lvalue is a deref like `*arr = 1` (an array decayed to a
        // sic `string s = <char*>` reassignment (`v = argv[1];`, `v = "lit";`):
        // wrap a C string (char*/char[]/literal) into a non-owning
        // `{data,size,rc=NULL}` descriptor via strlen, rather than byte-copying the
        // pointer as if it were a descriptor. A real `string` RHS falls through to
        // the aggregate copy + retain/release below.
        if self.is_sic() && op.is_none() && super::types::is_sic_string(&lv.ty) {
            let rt = self.infer_expr_type(rhs).unwrap_or_else(|_| Type::i32());
            let is_str = super::types::is_sic_string(&rt)
                || matches!(&rt, Type::Pointer(inner) if super::types::is_sic_string(inner));
            if !is_str {
                let v = self.lower_expr(rhs)?;
                let cp = self.coerce(v, &Type::char_ptr())?;
                let src = self.cstr_to_string(cp)?; // non-owning {data,size,rc=NULL}
                let size = lv.ty.size_of(self.ptr_size());
                let align = lv.ty.align_of(self.ptr_size());
                self.retain_string_at(&src)?;       // rc=NULL → no-op
                self.release_string_at(&lv.ptr)?;   // drop the previous value
                self.push_instr(Instr::MemCopy { dst: lv.ptr.clone(), src, size, align });
                return Ok(lv.ptr);
            }
        }

        // pointer whose element type sic surfaces as the array), a scalar store.
        let aggregate_assign = op.is_none() && match &lv.ty {
            Type::Struct(_) | Type::Union(_) => true,
            Type::Array { .. } => matches!(
                self.infer_expr_type(rhs),
                Ok(Type::Array { .. } | Type::Struct(_) | Type::Union(_))
            ),
            _ => false,
        };
        if aggregate_assign {
            // Copy the whole object, whether the RHS is an lvalue or an aggregate
            // rvalue (e.g. a compound literal `(T){...}`, a struct return, or a
            // vector produced by an element-wise operator/intrinsic).
            let src = self.lower_aggregate_ptr(rhs)?;
            let size = lv.ty.size_of(self.ptr_size());
            let align = lv.ty.align_of(self.ptr_size());
            // sic `string` reassignment: retain the new value, release the old
            // one, then overwrite. Retain-before-release keeps a self-assign /
            // alias balanced.
            if self.is_sic() && super::types::is_sic_string(&lv.ty) {
                self.retain_string_at(&src)?;
                self.release_string_at(&lv.ptr)?;
            }
            self.push_instr(Instr::MemCopy { dst: lv.ptr.clone(), src, size, align });
            return Ok(lv.ptr);
        }

        let rhs_val = self.lower_expr(rhs)?;

        let store_val = if let Some(bin_op) = op {
            // Load current value (bit-field aware), apply op, store result.
            let cur = self.load_lvalue(&lv)?;
            self.emit_binop(bin_op, cur, rhs_val)?
        } else {
            rhs_val
        };

        self.store_lvalue(&lv, store_val)
    }

    /// SIC swap `a <> b` (sic.md §"Swap"): exchange the contents of two lvalues.
    /// Both operands must denote storage of the same size — swap exchanges bytes,
    /// it never converts. Scalars go through a crossed load/store; aggregates are
    /// exchanged byte-wise via a temporary.
    fn lower_swap(&mut self, lhs: &Expr, rhs: &Expr) -> Result<Val> {
        let lv_a = self.lower_lvalue(lhs)?;
        let lv_b = self.lower_lvalue(rhs)?;

        let size = lv_a.ty.size_of(self.ptr_size());
        if size != lv_b.ty.size_of(self.ptr_size()) {
            return Err(CompileError::at(
                "`<>` swap requires both operands to have the same type".to_string(),
                lhs.span.file.clone(), lhs.span.line, lhs.span.col,
            ));
        }

        match &lv_a.ty {
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => {
                // Aggregate swap: exchange the bytes through a temporary buffer.
                let align = lv_a.ty.align_of(self.ptr_size());
                let tmp_slot = self.alloc_val();
                self.push_instr(Instr::Alloca { dest: tmp_slot, ty: lv_a.ty.clone(), align: None });
                let tmp = Val::Local(tmp_slot);
                self.push_instr(Instr::MemCopy { dst: tmp.clone(), src: lv_a.ptr.clone(), size, align });
                self.push_instr(Instr::MemCopy { dst: lv_a.ptr.clone(), src: lv_b.ptr.clone(), size, align });
                self.push_instr(Instr::MemCopy { dst: lv_b.ptr.clone(), src: tmp, size, align });
            }
            _ => {
                // Scalar (including bit-field) swap: load both, store crossed.
                let va = self.load_lvalue(&lv_a)?;
                let vb = self.load_lvalue(&lv_b)?;
                self.store_lvalue(&lv_a, vb)?;
                self.store_lvalue(&lv_b, va)?;
            }
        }
        Ok(Constant::zero())
    }

    fn lower_unary(&mut self, op: UnOpKind, inner: &Expr) -> Result<Val> {
        match op {
            UnOpKind::Addr => {
                // `&func` yields a function pointer — functions aren't lvalues
                // but are addressable, and `&func` is equivalent to `func`.
                if let ExprKind::Ident(name) = &inner.kind {
                    if let Some(LookupResult::Func(fref)) = self.lookup(name) {
                        return Ok(Val::Func(fref));
                    }
                }
                let lv = self.lower_lvalue(inner)?;
                Ok(lv.ptr)
            }
            UnOpKind::Deref => {
                let ptr = self.lower_expr(inner)?;
                // Determine pointee type
                let ptr_ty = self.val_type(&ptr);
                let inner_ty = self.pointee_of(&ptr_ty);
                // Dereferencing a function pointer yields a function designator
                // that immediately decays back to the pointer — emit no load
                // (so `(*fp)(args)` calls `fp` directly rather than a garbage
                // value loaded from the function's code). The same holds for an
                // array: `*(T(*)[N])p` is an array lvalue that decays to its own
                // address (== `p`), so emit no load — else a scalar is read from
                // the first element. QEMU's coroutine trampoline relies on this:
                // `siglongjmp(*(sigjmp_buf *)co->entry_arg, 1)` where sigjmp_buf is
                // `struct __jmp_buf_tag[1]` — a stray load passed the saved rbx as
                // the jmp_buf and crashed __longjmp.
                if matches!(inner_ty, Type::Function(_) | Type::Array { .. }) {
                    return Ok(ptr);
                }
                let dest = self.alloc_val();
                self.push_instr(Instr::Load { dest, ptr, ty: inner_ty });
                Ok(Val::Local(dest))
            }
            UnOpKind::Neg => {
                // sic bigint negation `-a` via the runtime.
                if self.is_sic() && self.is_bigint_operand(inner) {
                    let a = self.to_bigint(inner)?;
                    return self.call_bigint_new("__sic_bi_neg", vec![a]);
                }
                let v = self.lower_expr(inner)?;
                let ty = self.val_type(&v);
                let dest = self.alloc_val();
                let un_op = if ty.is_float() { UnOp::FNeg } else { UnOp::Neg };
                self.push_instr(Instr::UnaryOp { dest, op: un_op, val: v, ty: ty.clone() });
                Ok(Val::Local(dest))
            }
            UnOpKind::Not => {
                let v = self.lower_expr(inner)?;
                let b = self.to_bool(v)?;
                // Flip the bool
                let dest = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest, op: UnOp::BoolNot, val: b, ty: Type::Bool });
                // Extend to i32
                let ext = self.alloc_val();
                self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: Val::Local(dest), to_ty: Type::i32() });
                Ok(Val::Local(ext))
            }
            UnOpKind::BitNot => {
                // sic bigint bitwise-not `~a` (= -a - 1) via the runtime.
                if self.is_sic() && self.is_bigint_operand(inner) {
                    let a = self.to_bigint(inner)?;
                    return self.call_bigint_new("__sic_bi_not", vec![a]);
                }
                let v = self.lower_expr(inner)?;
                let ty = self.val_type(&v);
                let dest = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest, op: UnOp::Not, val: v, ty: ty.clone() });
                Ok(Val::Local(dest))
            }
        }
    }

    /// Read an lvalue's value, extracting a bit-field with shifts/masking.
    fn load_lvalue(&mut self, lv: &LValue) -> Result<Val> {
        if let Some(bf) = lv.bitfield {
            let ty = lv.ty.clone();
            // The extraction shifts operate on the loaded STORAGE unit's width,
            // not the field type's semantic value width. These differ for a
            // `_Bool` bitfield: `int_bits(_Bool)` is 1, but the field is loaded
            // as a byte (8 bits). Using 1 made the shift/mask a no-op, so a
            // `_Bool:1` read its neighbour's bit too (QEMU's decode_insn loops on
            // `while (e->is_decode)` where is_decode is a `_Bool:1` — an infinite
            // loop that stalled guest translation).
            let bits = ty.size_of(self.ptr_size()).max(1) as u32 * 8;
            let raw = self.alloc_val();
            self.push_instr(Instr::Load { dest: raw, ptr: lv.ptr.clone(), ty: ty.clone() });
            // Shift the field to the top, then back down: masks and (for signed
            // fields) sign-extends in one pair of shifts.
            let left = bits.saturating_sub(bf.bit_offset + bf.width);
            let right = bits.saturating_sub(bf.width);
            let hi = if left > 0 {
                let d = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: d, op: BinOp::Shl, lhs: Val::Local(raw), rhs: Constant::int(left as i64), ty: ty.clone() });
                Val::Local(d)
            } else { Val::Local(raw) };
            let op = if bf.signed { BinOp::AShr } else { BinOp::LShr };
            let res = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: res, op, lhs: hi, rhs: Constant::int(right as i64), ty });
            return Ok(Val::Local(res));
        }
        let dest = self.alloc_val();
        if lv.atomic {
            self.push_instr(Instr::AtomicLoad { dest, ptr: lv.ptr.clone(), ty: lv.ty.clone() });
        } else {
            self.push_instr(Instr::Load { dest, ptr: lv.ptr.clone(), ty: lv.ty.clone() });
        }
        Ok(Val::Local(dest))
    }

    /// Store `val` into an lvalue, performing a read-modify-write for bit-fields.
    /// Returns the value actually stored (for use as the assignment's value).
    fn store_lvalue(&mut self, lv: &LValue, val: Val) -> Result<Val> {
        if let Some(bf) = lv.bitfield {
            return self.store_bitfield(&lv.ptr, &lv.ty, bf, val);
        }
        let coerced = self.coerce(val, &lv.ty)?;
        if lv.atomic {
            self.push_instr(Instr::AtomicStore { ptr: lv.ptr.clone(), val: coerced.clone(), ty: lv.ty.clone() });
        } else {
            self.push_instr(Instr::Store { val: coerced.clone(), ptr: lv.ptr.clone() });
        }
        Ok(coerced)
    }

    /// Store `val` into a bit-field via read-modify-write: `*ptr = (*ptr & ~mask)
    /// | ((val & field_mask) << bit_offset)`. Needed both for `s.bf = v` and for
    /// a designated initializer of a bit-field, so adjacent bit-fields sharing
    /// the storage unit are preserved (QEMU's `PhysPageEntry{ .ptr=NIL, .skip=1 }`
    /// where `ptr:26`/`skip:6` share one word).
    pub(super) fn store_bitfield(&mut self, ptr: &Val, ty: &Type, bf: BitField, val: Val) -> Result<Val> {
        let ty = ty.clone();
        let val = self.coerce(val, &ty)?;
        let mask: i64 = if bf.width >= 64 { -1 } else { ((1u64 << bf.width) - 1) as i64 };
        let vm = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: vm, op: BinOp::And, lhs: val.clone(), rhs: Constant::int(mask), ty: ty.clone() });
        let vs = if bf.bit_offset > 0 {
            let d = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: d, op: BinOp::Shl, lhs: Val::Local(vm), rhs: Constant::int(bf.bit_offset as i64), ty: ty.clone() });
            Val::Local(d)
        } else { Val::Local(vm) };
        let raw = self.alloc_val();
        self.push_instr(Instr::Load { dest: raw, ptr: ptr.clone(), ty: ty.clone() });
        let clear_mask = !(mask as u64).wrapping_shl(bf.bit_offset) as i64;
        let cleared = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: cleared, op: BinOp::And, lhs: Val::Local(raw), rhs: Constant::int(clear_mask), ty: ty.clone() });
        let newv = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newv, op: BinOp::Or, lhs: Val::Local(cleared), rhs: vs, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(newv), ptr: ptr.clone() });
        Ok(val)
    }

    fn lower_pre_inc(&mut self, inc: bool, inner: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(inner)?;
        let op = if inc { BinOpKind::Add } else { BinOpKind::Sub };
        // sic atomic `++a`/`--a` (sic.md §"Atomics"): one atomic RMW; yields the
        // new value. Rejected on an atomic pointer (no arithmetic).
        if self.is_sic() && lv.atomic {
            let old = self.atomic_incdec(&lv, inc, &inner.span)?;
            return self.emit_binop(op, Val::Local(old), Constant::int(1));
        }
        let cur = self.load_lvalue(&lv)?;
        let result = self.emit_binop(op, cur, Constant::int(1))?;
        self.store_lvalue(&lv, result)
    }

    fn lower_post_inc(&mut self, inc: bool, inner: &Expr) -> Result<Val> {
        let lv = self.lower_lvalue(inner)?;
        let op = if inc { BinOpKind::Add } else { BinOpKind::Sub };
        // sic atomic `a++`/`a--`: one atomic RMW; yields the old value.
        if self.is_sic() && lv.atomic {
            let old = self.atomic_incdec(&lv, inc, &inner.span)?;
            return Ok(Val::Local(old));
        }
        let old = self.load_lvalue(&lv)?;
        let result = self.emit_binop(op, old.clone(), Constant::int(1))?;
        self.store_lvalue(&lv, result)?;
        Ok(old)
    }

    /// Atomic `++`/`--`: emit a single `AtomicRmw` of ±1, returning the ValId of
    /// the old value. Errors on an atomic pointer (arithmetic is disallowed).
    fn atomic_incdec(&mut self, lv: &LValue, inc: bool, sp: &crate::lexer::Span) -> Result<ValId> {
        if matches!(lv.ty, Type::Pointer(_)) {
            return Err(CompileError::at(
                "no arithmetic on an atomic pointer — only load, store, `.swap`, `.cas`".to_string(),
                sp.file.clone(), sp.line, sp.col));
        }
        let aop = if inc { AtomicOp::Add } else { AtomicOp::Sub };
        let old = self.alloc_val();
        self.push_instr(Instr::AtomicRmw {
            dest: old, op: aop, ptr: lv.ptr.clone(), val: Constant::int(1), ty: lv.ty.clone(),
        });
        Ok(old)
    }

    fn lower_ternary(&mut self, cond: &Expr, then: &Expr, else_: &Expr) -> Result<Val> {
        // Constant-fold a compile-time-constant condition to just the taken arm,
        // like gcc/clang. QEMU's `dup_const`/tcg macros nest
        // `__builtin_constant_p(x) ? <fold> : <runtime>`; sic returns 0 for
        // `__builtin_constant_p`, so the dead `<fold>` arm (which ends in an
        // exhaustiveness `qemu_build_not_reached_always()`) must not be lowered —
        // else it emits a call to that deliberately-undefined symbol.
        if let Ok(v) = crate::lower::eval_const_expr(cond, &self.lowerer.enum_consts) {
            let taken = if v != 0 { then } else { else_ };
            // An aggregate-valued arm flows as a pointer, so return its aggregate
            // pointer rather than a (truncated) scalar load. Matches the runtime
            // path below and the non-folded aggregate case.
            if matches!(self.infer_expr_type(taken), Ok(Type::Struct(_) | Type::Union(_) | Type::Array { .. })) {
                return self.lower_aggregate_ptr(taken);
            }
            return self.lower_expr(taken);
        }
        let cond_val = self.lower_expr(cond)?;
        let cond_bool = self.to_bool(cond_val)?;

        // Result type of `a ? b : c`: prefer a pointer/float/wider branch so the
        // value (and its type — needed for a following `->`, `*`, arithmetic)
        // survives. Both branches are coerced to it.
        let tty = self.infer_expr_type(then).unwrap_or_else(|_| Type::i32());
        let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());

        // Aggregate result (`cond ? struct_a : struct_b`): each arm yields a
        // pointer to a struct/union/array; copy the selected one into a result
        // slot and yield that slot's pointer (how aggregate values flow in the
        // IR). A scalar Store/Load would truncate the aggregate to a register.
        // QEMU's decoder does `*entry = repz ? pause : nop;` (X86OpEntry copy).
        let agg_ty = match (&tty, &ety) {
            (Type::Struct(_) | Type::Union(_) | Type::Array { .. }, _) => Some(tty.clone()),
            (_, Type::Struct(_) | Type::Union(_) | Type::Array { .. }) => Some(ety.clone()),
            _ => None,
        };
        if let Some(aty) = agg_ty {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: aty.clone(), align: None });
            let size = aty.size_of(self.ptr_size());
            let align = aty.align_of(self.ptr_size());
            let then_bb  = self.new_block_after_current();
            let else_bb  = self.new_block_after_current();
            let merge_bb = self.new_block_after_current();
            self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

            self.switch_to_block(then_bb);
            let tp = self.lower_aggregate_ptr(then)?;
            self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: tp, size, align });
            self.set_terminator(Terminator::Jump(merge_bb));

            self.switch_to_block(else_bb);
            let ep = self.lower_aggregate_ptr(else_)?;
            self.push_instr(Instr::MemCopy { dst: Val::Local(slot), src: ep, size, align });
            self.set_terminator(Terminator::Jump(merge_bb));

            self.switch_to_block(merge_bb);
            return Ok(Val::Local(slot));
        }
        let ty = match (&tty, &ety) {
            (Type::Pointer(_), _) | (Type::Void, _) => tty.clone(),
            (_, Type::Pointer(_)) => ety.clone(),
            _ if tty.is_float() => tty.clone(),
            _ if ety.is_float() => ety.clone(),
            _ if ety.size_of(self.ptr_size()) > tty.size_of(self.ptr_size()) => ety.clone(),
            _ => tty.clone(),
        };

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: ty.clone(), align: None });

        let then_bb  = self.new_block_after_current();
        let else_bb  = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();

        self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

        // Each arm is conditionally evaluated: free any bigint/fixed temporaries it
        // creates within its own block (unless the result itself is a bigint/fixed
        // — then the arm's value IS the result and must survive to the merge).
        let free_arm_temps = !(super::types::is_bigint(&ty) || super::types::is_fixed(&ty));

        self.switch_to_block(then_bb);
        let tmark = self.bigint_temps.len();
        let tv = self.lower_expr(then)?;
        let tv = self.coerce(tv, &ty)?;
        if free_arm_temps { self.flush_bigint_temps_from(tmark); }
        self.push_instr(Instr::Store { val: tv, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(else_bb);
        let emark = self.bigint_temps.len();
        let ev = self.lower_expr(else_)?;
        let ev = self.coerce(ev, &ty)?;
        if free_arm_temps { self.flush_bigint_temps_from(emark); }
        self.push_instr(Instr::Store { val: ev, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: ty.clone() });
        Ok(Val::Local(dest))
    }

    /// Lower GNU `a ?: b`. `a` is evaluated exactly once (its SSA value is reused
    /// both as the condition and as the "then" result).
    fn lower_elvis(&mut self, cond: &Expr, else_: &Expr) -> Result<Val> {
        // sic Option/Result unwrap-or-default (sic.md §"Match"): `opt ?: default`
        // yields the payload of the present variant (Some/Ok — the first
        // payload-carrying variant), else `default`. No unwrap, no panic.
        if self.is_sic() {
            if let Ok(t) = self.infer_expr_type(cond) {
                if self.is_tagged_enum_struct(&t) {
                    return self.lower_option_elvis(cond, else_, &t);
                }
            }
        }
        let cond_val = self.lower_expr(cond)?;
        let cty = self.infer_expr_type(cond).unwrap_or_else(|_| Type::i32());
        let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());
        let ty = match (&cty, &ety) {
            (Type::Pointer(_), _) | (Type::Void, _) => cty.clone(),
            (_, Type::Pointer(_)) => ety.clone(),
            _ if cty.is_float() => cty.clone(),
            _ if ety.is_float() => ety.clone(),
            _ if ety.size_of(self.ptr_size()) > cty.size_of(self.ptr_size()) => ety.clone(),
            _ => cty.clone(),
        };
        let cond_bool = self.to_bool(cond_val.clone())?;

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: ty.clone(), align: None });

        let then_bb  = self.new_block_after_current();
        let else_bb  = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();

        self.set_terminator(Terminator::CondJump { cond: cond_bool, then_bb, else_bb });

        self.switch_to_block(then_bb);
        let tv = self.coerce(cond_val, &ty)?;
        self.push_instr(Instr::Store { val: tv, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(else_bb);
        let ev = self.lower_expr(else_)?;
        let ev = self.coerce(ev, &ty)?;
        self.push_instr(Instr::Store { val: ev, ptr: Val::Local(result_ptr) });
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: ty.clone() });
        Ok(Val::Local(dest))
    }

    /// The "present" variant of an Option/Result-like enum for `?:`/`?.`/guard-bind
    /// (sic.md §"Match"): the first payload-carrying variant (`Some`/`Ok`).
    pub(super) fn enum_present_variant(&self, sty: &Type) -> Option<(String, super::TaggedVariant)> {
        let ename = match sty { Type::Struct(st) => st.name.clone()?, _ => return None };
        let info = self.lowerer.enum_defs.get(&ename)?;
        let v = info.variants.iter().find(|v| v.payload.is_some())?.clone();
        Some((ename, v))
    }

    /// Lower `opt ?: default` (sic.md §"Match"): the present variant's payload, or
    /// `default`. The result type is the payload type.
    fn lower_option_elvis(&mut self, cond: &Expr, else_: &Expr, sty: &Type) -> Result<Val> {
        let sp = cond.span.clone();
        let (ename, present) = self.enum_present_variant(sty).ok_or_else(|| CompileError::at(
            format!("`?:` needs an enum with a payload variant (Some/Ok)"),
            sp.file.clone(), sp.line, sp.col))?;
        let _ = ename;
        let pty = present.payload.clone().unwrap();
        let ptr = self.lower_aggregate_ptr(cond)?;
        let tag = self.load_enum_tag(ptr.clone(), sty, &sp)?;
        let present_bool = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: present_bool, op: CmpOp::IEq, lhs: tag, rhs: Constant::int(present.tag), ty: Type::i32() });

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: pty.clone(), align: None });
        let then_bb = self.new_block_after_current();
        let else_bb = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(present_bool), then_bb, else_bb });

        // Present: copy out the payload (borrowed — scalars loaded, aggregates /
        // strings memcopied). The result is transient (used in-statement).
        self.switch_to_block(then_bb);
        let data = self.enum_data_ptr(ptr.clone(), sty, &sp)?;
        if super::types::is_sic_string(&pty) || matches!(pty, Type::Struct(_) | Type::Union(_)) {
            let size = pty.size_of(self.ptr_size());
            let align = pty.align_of(self.ptr_size());
            self.push_instr(Instr::MemCopy { dst: Val::Local(result_ptr), src: data, size, align });
        } else {
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: data, ty: pty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(d), ptr: Val::Local(result_ptr) });
        }
        self.set_terminator(Terminator::Jump(merge_bb));

        // Absent: the default expression. A `string` payload wraps a bare
        // `char*`/literal default into a `{data,size,rc}` descriptor.
        self.switch_to_block(else_bb);
        if super::types::is_sic_string(&pty) {
            let ev = self.lower_expr(else_)?;
            let vt = self.val_type(&ev);
            let is_str = super::types::is_sic_string(&vt)
                || matches!(&vt, Type::Pointer(inner) if super::types::is_sic_string(inner));
            let src = if is_str { ev } else { self.cstr_to_string(ev)? };
            let size = pty.size_of(self.ptr_size());
            let align = pty.align_of(self.ptr_size());
            self.push_instr(Instr::MemCopy { dst: Val::Local(result_ptr), src, size, align });
        } else {
            let ev = self.lower_expr(else_)?;
            let ev = self.coerce(ev, &pty)?;
            self.push_instr(Instr::Store { val: ev, ptr: Val::Local(result_ptr) });
        }
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        // A `string`/aggregate rvalue is the POINTER to its storage (like a compound
        // literal); a scalar is the loaded value.
        if super::types::is_sic_string(&pty) || matches!(pty, Type::Struct(_) | Type::Union(_)) {
            self.val_types.insert(result_ptr.0, pty.clone());
            return Ok(Val::Local(result_ptr));
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: pty.clone() });
        self.val_types.insert(dest.0, pty.clone());
        Ok(Val::Local(dest))
    }

    /// The type of `field` within a struct/union (sic.md §"Match") — for `?.` /
    /// result sizing. Resolves through anonymous members.
    fn opt_field_type(&self, struct_ty: &Type, field: &str) -> Option<Type> {
        resolve_field_access(struct_ty, field, self.ptr_size(), &self.lowerer.struct_types)
            .map(|(_, ty, _)| ty)
    }

    /// Lower none/null-safe access `base?.field` (sic.md §"Match"): if `base` is a
    /// present Option/Result or a non-null pointer, the field; else a zero value of
    /// the field's type. The result type is the field type, so chains
    /// (`a?.b?.c`) propagate the zero and pair with `?:`.
    fn lower_opt_field(&mut self, base: &Expr, field: &str, sp: &crate::lexer::Span) -> Result<Val> {
        let bty = self.infer_expr_type(base)?;
        // (present-flag, pointer to the struct holding the field, that struct's type)
        let (present, struct_ptr, struct_ty) = if let Type::Pointer(pointee) = &bty {
            let bv = self.lower_expr(base)?;
            let nn = self.to_bool(bv.clone())?;
            (nn, bv, (**pointee).clone())
        } else if self.is_tagged_enum_struct(&bty) {
            let (_, pres) = self.enum_present_variant(&bty).ok_or_else(|| CompileError::at(
                "`?.` needs an enum with a payload variant (Some/Ok)".to_string(),
                sp.file.clone(), sp.line, sp.col))?;
            let pty = pres.payload.clone().unwrap();
            let ptr = self.lower_aggregate_ptr(base)?;
            let tag = self.load_enum_tag(ptr.clone(), &bty, sp)?;
            let pb = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: pb, op: CmpOp::IEq, lhs: tag, rhs: Constant::int(pres.tag), ty: Type::i32() });
            let data = self.enum_data_ptr(ptr, &bty, sp)?;
            (Val::Local(pb), data, pty)
        } else {
            return Err(CompileError::at(
                "`?.` requires an Option/Result or a pointer on the left".to_string(),
                sp.file.clone(), sp.line, sp.col));
        };
        let fty = self.opt_field_type(&struct_ty, field).ok_or_else(|| CompileError::at(
            format!("no field '{}' in type", field), sp.file.clone(), sp.line, sp.col))?;

        let result_ptr = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: result_ptr, ty: fty.clone(), align: None });
        let then_bb = self.new_block_after_current();
        let else_bb = self.new_block_after_current();
        let merge_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: present, then_bb, else_bb });

        // Present: load/copy the field into the result slot.
        self.switch_to_block(then_bb);
        let flv = self.field_ptr_from(LValue::plain(struct_ptr, struct_ty), field, false, sp)?;
        if super::types::is_sic_string(&fty) || matches!(fty, Type::Struct(_) | Type::Union(_)) {
            let size = fty.size_of(self.ptr_size());
            let align = fty.align_of(self.ptr_size());
            self.push_instr(Instr::MemCopy { dst: Val::Local(result_ptr), src: flv.ptr, size, align });
        } else {
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: flv.ptr, ty: fty.clone() });
            self.push_instr(Instr::Store { val: Val::Local(d), ptr: Val::Local(result_ptr) });
        }
        self.set_terminator(Terminator::Jump(merge_bb));

        // Absent: a zero value of the field type.
        self.switch_to_block(else_bb);
        if super::types::is_sic_string(&fty) || matches!(fty, Type::Struct(_) | Type::Union(_)) {
            let size = fty.size_of(self.ptr_size());
            self.push_instr(Instr::MemSet { dst: Val::Local(result_ptr), val: Constant::zero(), size, align: fty.align_of(self.ptr_size()) });
        } else {
            let z = self.coerce(Constant::zero(), &fty)?;
            self.push_instr(Instr::Store { val: z, ptr: Val::Local(result_ptr) });
        }
        self.set_terminator(Terminator::Jump(merge_bb));

        self.switch_to_block(merge_bb);
        if super::types::is_sic_string(&fty) || matches!(fty, Type::Struct(_) | Type::Union(_)) {
            self.val_types.insert(result_ptr.0, fty.clone());
            return Ok(Val::Local(result_ptr));
        }
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(result_ptr), ty: fty.clone() });
        self.val_types.insert(dest.0, fty.clone());
        Ok(Val::Local(dest))
    }

    /// Lower a call argument. Struct/union arguments are passed by value using
    /// the pointer ABI: the callee receives a pointer to the value and copies it
    /// into its own local, so passing the argument's address is sufficient.
    fn lower_arg(&mut self, a: &Expr) -> Result<Val> {
        let aty = self.infer_expr_type(a).unwrap_or_else(|_| Type::i32());
        if matches!(aty, Type::Struct(_) | Type::Union(_)) {
            if let Ok(lv) = self.lower_lvalue(a) {
                return Ok(lv.ptr);
            }
            // Non-lvalue aggregate (e.g. a struct returned by value): its rvalue
            // lowering already yields a pointer to the temporary.
            return self.lower_expr(a);
        }
        self.lower_expr(a)
    }

    /// Pointee type of a pointer value (resolving opaque aggregates).
    fn pointee_ty(&self, ptr: &Val) -> Type {
        match self.val_type(ptr) {
            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
            other => other,
        }
    }

    /// `T __atomic_exchange_n(ptr, val)`: old = *ptr; *ptr = val; return old.
    fn lower_atomic_exchange(&mut self, ptr_expr: &Expr, val_expr: &Expr) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = self.pointee_ty(&ptr);
        let old = self.alloc_val();
        self.push_instr(Instr::Load { dest: old, ptr: ptr.clone(), ty: ty.clone() });
        let val = self.lower_expr(val_expr)?;
        let val = self.coerce(val, &ty)?;
        self.push_instr(Instr::Store { val, ptr });
        Ok(Val::Local(old))
    }

    /// `__sync_{val,bool}_compare_and_swap(ptr, oldv, newv)`: if `*ptr == oldv`
    /// set `*ptr = newv`. Returns the prior value (`ret_bool == false`) or whether
    /// the swap happened. Non-atomic (single-thread) emulation.
    fn lower_atomic_cas(&mut self, ptr_expr: &Expr, old_expr: &Expr, new_expr: &Expr, ret_bool: bool) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = self.pointee_ty(&ptr);
        let cur = self.alloc_val();
        self.push_instr(Instr::Load { dest: cur, ptr: ptr.clone(), ty: ty.clone() });
        let oldv = self.lower_expr(old_expr)?; let oldv = self.coerce(oldv, &ty)?;
        let newv = self.lower_expr(new_expr)?; let newv = self.coerce(newv, &ty)?;
        let matched = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: matched, op: CmpOp::IEq, lhs: Val::Local(cur), rhs: oldv, ty: ty.clone() });
        let sel = self.alloc_val();
        self.push_instr(Instr::Select { dest: sel, cond: Val::Local(matched), on_true: newv, on_false: Val::Local(cur), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(sel), ptr });
        if ret_bool {
            let ext = self.alloc_val();
            self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: Val::Local(matched), to_ty: Type::i32() });
            Ok(Val::Local(ext))
        } else {
            Ok(Val::Local(cur))
        }
    }

    /// `bool __atomic_compare_exchange_n(ptr, expected_ptr, desired, ...)`: like
    /// CAS, but on failure writes the current value back through `expected_ptr`.
    fn lower_atomic_compare_exchange(&mut self, ptr_expr: &Expr, exp_ptr_expr: &Expr, des_expr: &Expr) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = self.pointee_ty(&ptr);
        let eptr = self.lower_expr(exp_ptr_expr)?;
        let cur = self.alloc_val();
        self.push_instr(Instr::Load { dest: cur, ptr: ptr.clone(), ty: ty.clone() });
        let expected = self.alloc_val();
        self.push_instr(Instr::Load { dest: expected, ptr: eptr.clone(), ty: ty.clone() });
        let desired = self.lower_expr(des_expr)?; let desired = self.coerce(desired, &ty)?;
        let matched = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: matched, op: CmpOp::IEq, lhs: Val::Local(cur), rhs: Val::Local(expected), ty: ty.clone() });
        // *ptr = matched ? desired : cur
        let sel = self.alloc_val();
        self.push_instr(Instr::Select { dest: sel, cond: Val::Local(matched), on_true: desired, on_false: Val::Local(cur), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(sel), ptr });
        // *expected_ptr = matched ? expected : cur  (write current back on failure)
        let esel = self.alloc_val();
        self.push_instr(Instr::Select { dest: esel, cond: Val::Local(matched), on_true: Val::Local(expected), on_false: Val::Local(cur), ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(esel), ptr: eptr });
        let ext = self.alloc_val();
        self.push_instr(Instr::Cast { dest: ext, op: CastOp::ZExt, val: Val::Local(matched), to_ty: Type::i32() });
        Ok(Val::Local(ext))
    }

    /// Lower a floating-point classification builtin (`isnan`/`isinf`/`isfinite`/
    /// `isnormal`) to an `int` (0/1) using ordered comparisons: `x == x` is false
    /// only for NaN, and `x - x == 0` is true only for finite values.
    fn lower_fp_classify(&mut self, name: &str, arg: &Expr) -> Result<Val> {
        let x = self.lower_expr(arg)?;
        let fty = match self.val_type(&x) {
            t if t.is_float() => t,
            _ => Type::Float64,
        };
        let x = self.coerce(x, &fty)?;
        let zero = Val::Const(Constant::Float(0.0));
        // self_eq = (x == x): 1 unless NaN.
        let self_eq = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: self_eq, op: CmpOp::FOEq, lhs: x.clone(), rhs: x.clone(), ty: fty.clone() });
        // diff = x - x; finite = (diff == 0): 1 only for finite x.
        let diff = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: diff, op: BinOp::FSub, lhs: x.clone(), rhs: x.clone(), ty: fty.clone() });
        let finite = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: finite, op: CmpOp::FOEq, lhs: Val::Local(diff), rhs: zero.clone(), ty: fty.clone() });

        let res = match name {
            "__builtin_isnan" => {
                // !self_eq
                let r = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: r, op: UnOp::BoolNot, val: Val::Local(self_eq), ty: Type::Bool });
                Val::Local(r)
            }
            "__builtin_isfinite" => Val::Local(finite),
            "__builtin_isinf" | "__builtin_isinf_sign" => {
                // self_eq && !finite  (not NaN, not finite → infinite)
                let nfin = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: nfin, op: UnOp::BoolNot, val: Val::Local(finite), ty: Type::Bool });
                let r = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: r, op: BinOp::And, lhs: Val::Local(self_eq), rhs: Val::Local(nfin), ty: Type::Bool });
                Val::Local(r)
            }
            // isnormal ≈ finite && x != 0 (ignores the subnormal boundary).
            _ => {
                let nz = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: nz, op: CmpOp::FONe, lhs: x, rhs: zero, ty: fty });
                let r = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: r, op: BinOp::And, lhs: Val::Local(finite), rhs: Val::Local(nz), ty: Type::Bool });
                Val::Local(r)
            }
        };
        self.coerce(res, &Type::i32())
    }

    /// Lower a floating-point comparison builtin (`isgreater` etc.) — like the
    /// bare operator but without raising an invalid exception on NaN (which sic
    /// does not model anyway), yielding `int` 0/1.
    fn lower_fp_compare(&mut self, name: &str, a: &Expr, b: &Expr) -> Result<Val> {
        let av = self.lower_expr(a)?;
        let bv = self.lower_expr(b)?;
        let fty = match self.val_type(&av) {
            t if t.is_float() => t,
            _ => Type::Float64,
        };
        let av = self.coerce(av, &fty)?;
        let bv = self.coerce(bv, &fty)?;
        if name == "__builtin_isunordered" {
            // NaN in either operand: !(a == a) || !(b == b).
            let ae = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: ae, op: CmpOp::FOEq, lhs: av.clone(), rhs: av, ty: fty.clone() });
            let be = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: be, op: CmpOp::FOEq, lhs: bv.clone(), rhs: bv, ty: fty });
            let both = self.alloc_val();
            self.push_instr(Instr::BinOp { dest: both, op: BinOp::And, lhs: Val::Local(ae), rhs: Val::Local(be), ty: Type::Bool });
            let r = self.alloc_val();
            self.push_instr(Instr::UnaryOp { dest: r, op: UnOp::BoolNot, val: Val::Local(both), ty: Type::Bool });
            return self.coerce(Val::Local(r), &Type::i32());
        }
        let op = match name {
            "__builtin_isgreater" => CmpOp::FOGt,
            "__builtin_isgreaterequal" => CmpOp::FOGe,
            "__builtin_isless" => CmpOp::FOLt,
            "__builtin_islessequal" => CmpOp::FOLe,
            _ /* islessgreater */ => CmpOp::FONe,
        };
        let r = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: r, op, lhs: av, rhs: bv, ty: fty });
        self.coerce(Val::Local(r), &Type::i32())
    }

    /// Whether two IR types are the same for `__builtin_types_compatible_p`
    /// (sic already drops qualifiers; opaque aggregates compare by name).
    fn types_equal(&self, a: &Type, b: &Type) -> bool {
        super::types::resolve_aggregate(a, &self.lowerer.struct_types)
            == super::types::resolve_aggregate(b, &self.lowerer.struct_types)
    }

    /// Evaluate the (constant) controlling condition of a `__builtin_choose_expr`,
    /// understanding `__builtin_types_compatible_p` and the `||`/`&&`/`!` that
    /// glib/QEMU macros build them from. Unknown → 0 (pick the else branch).
    fn eval_choose_cond(&self, e: &Expr) -> i64 {
        match &e.kind {
            ExprKind::TypesCompatible(t1, t2) => {
                match (self.lower_type(t1), self.lower_type(t2)) {
                    (Ok(a), Ok(b)) => if self.types_equal(&a, &b) { 1 } else { 0 },
                    _ => 0,
                }
            }
            ExprKind::ChooseExpr { cond, then, else_ } => {
                if self.eval_choose_cond(cond) != 0 { self.eval_choose_cond(then) }
                else { self.eval_choose_cond(else_) }
            }
            ExprKind::BinOp { op: BinOpKind::LogOr, lhs, rhs } =>
                (self.eval_choose_cond(lhs) != 0 || self.eval_choose_cond(rhs) != 0) as i64,
            ExprKind::BinOp { op: BinOpKind::LogAnd, lhs, rhs } =>
                (self.eval_choose_cond(lhs) != 0 && self.eval_choose_cond(rhs) != 0) as i64,
            ExprKind::Unary { op: UnOpKind::Not, expr } =>
                (self.eval_choose_cond(expr) == 0) as i64,
            // `__builtin_constant_p(E)` is 1 when E folds to a compile-time
            // constant. `__builtin_choose_expr` needs this accurate (unlike the
            // runtime `?:` fold, which conservatively treats it as 0): QEMU's
            // MIN_CONST/MAX_CONST (e.g. `BDRV_REQUEST_MAX_SECTORS` defaults in
            // virtio_blk_properties) do
            //   __builtin_choose_expr(__builtin_constant_p(a) && ..., min, (void)0)
            // — a 0 here selects the `(void)0` arm, which can't be lowered and
            // zeroed the whole property table.
            ExprKind::Call { func, args }
                if matches!(&func.kind, ExprKind::Ident(n) if n == "__builtin_constant_p") =>
            {
                match args.first() {
                    Some(a) if self.lowerer.eval_const_int(a).is_some() => 1,
                    _ => 0,
                }
            }
            _ => crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).unwrap_or(0),
        }
    }

    /// Lower `__builtin_{clz,ctz,popcount,ffs}[l|ll]` on a `bits`-wide operand.
    /// The result is an `int`.
    fn lower_bit_count(&mut self, arg: &Expr, bits: u32, kind: BitOp) -> Result<Val> {
        let ty = Type::Int { bits, signed: false };
        let v = self.lower_expr(arg)?;
        let v = self.coerce(v, &ty)?;
        let result = match kind {
            BitOp::Clz | BitOp::Ctz | BitOp::Popcnt => {
                let op = match kind {
                    BitOp::Clz => UnOp::Clz,
                    BitOp::Ctz => UnOp::Ctz,
                    _ => UnOp::Popcnt,
                };
                let d = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: d, op, val: v, ty: ty.clone() });
                Val::Local(d)
            }
            BitOp::Parity => {
                // parity(x) = popcount(x) & 1
                let pc = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: pc, op: UnOp::Popcnt, val: v, ty: ty.clone() });
                let res = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: res, op: BinOp::And, lhs: Val::Local(pc), rhs: Constant::int(1), ty: ty.clone() });
                Val::Local(res)
            }
            BitOp::Clrsb => {
                // clrsb(x) = clz(x ^ (x >>arith (bits-1))) - 1: leading redundant
                // sign bits. The `x ^ sign` maps the leading sign run to zeros.
                let sign = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: sign, op: BinOp::AShr, lhs: v.clone(), rhs: Constant::int((bits - 1) as i64), ty: ty.clone() });
                let y = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: y, op: BinOp::Xor, lhs: v, rhs: Val::Local(sign), ty: ty.clone() });
                let clz = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: clz, op: UnOp::Clz, val: Val::Local(y), ty: ty.clone() });
                let res = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: res, op: BinOp::Sub, lhs: Val::Local(clz), rhs: Constant::int(1), ty: ty.clone() });
                Val::Local(res)
            }
            BitOp::Ffs => {
                // ffs(x) = x == 0 ? 0 : ctz(x) + 1
                let ctz = self.alloc_val();
                self.push_instr(Instr::UnaryOp { dest: ctz, op: UnOp::Ctz, val: v.clone(), ty: ty.clone() });
                let ctzp1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: ctzp1, op: BinOp::Add, lhs: Val::Local(ctz), rhs: Constant::int(1), ty: ty.clone() });
                let iszero = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: iszero, op: CmpOp::IEq, lhs: v, rhs: Constant::int(0), ty: ty.clone() });
                let sel = self.alloc_val();
                self.push_instr(Instr::Select { dest: sel, cond: Val::Local(iszero), on_true: Constant::int(0), on_false: Val::Local(ctzp1), ty: ty.clone() });
                Val::Local(sel)
            }
        };
        self.coerce(result, &Type::i32())
    }

    /// Lower an atomic read-modify-write as a non-atomic load/op/store, returning
    /// either the old value (`ret_new == false`) or the new value.
    fn lower_atomic_rmw(&mut self, ptr_expr: &Expr, val_expr: &Expr, op: BinOp, ret_new: bool) -> Result<Val> {
        let ptr = self.lower_expr(ptr_expr)?;
        let ty = match self.val_type(&ptr) {
            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
            other => other,
        };
        let old = self.alloc_val();
        self.push_instr(Instr::Load { dest: old, ptr: ptr.clone(), ty: ty.clone() });
        let rhs = self.lower_expr(val_expr)?;
        let rhs = self.coerce(rhs, &ty)?;
        let newv = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: newv, op, lhs: Val::Local(old), rhs, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(newv), ptr });
        Ok(Val::Local(if ret_new { newv } else { old }))
    }

    // ---- SIMD vector intrinsics (scalar-emulated over the byte aggregate) ----

    /// Address of `base + off` bytes (off is a compile-time constant).
    fn vec_at(&mut self, base: &Val, off: i64) -> Val {
        if off == 0 { return base.clone(); }
        let d = self.alloc_val();
        self.push_instr(Instr::PtrOffset { dest: d, base: base.clone(), offset: Constant::int(off) });
        Val::Local(d)
    }

    /// Load a scalar of `ty` at `base + off`.
    fn vec_load(&mut self, base: &Val, off: i64, ty: Type) -> Val {
        let addr = self.vec_at(base, off);
        let d = self.alloc_val();
        self.push_instr(Instr::Load { dest: d, ptr: addr, ty });
        Val::Local(d)
    }

    /// Store `val` at `base + off`.
    fn vec_store(&mut self, base: &Val, off: i64, val: Val) {
        let addr = self.vec_at(base, off);
        self.push_instr(Instr::Store { val, ptr: addr });
    }

    fn vec_bin(&mut self, op: BinOp, lhs: Val, rhs: Val, ty: Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: d, op, lhs, rhs, ty });
        Val::Local(d)
    }

    /// Fresh stack slot holding a vector of type `vty`; returns a pointer to it.
    fn vec_alloca(&mut self, vty: Type) -> Val {
        let d = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: d, ty: vty, align: None });
        Val::Local(d)
    }

    /// Element-wise binary op on two vector (`vector_size`) operands. Operates
    /// lane-by-lane over the vector's element type into a fresh result vector.
    /// Comparisons yield an all-ones (`-1`) / all-zeros lane per GCC semantics.
    fn lower_vector_binop(&mut self, op: BinOpKind, lhs: &Expr, rhs: &Expr, vty: Type) -> Result<Val> {
        let (elem, lanes) = match &vty {
            Type::Array { elem, len } => ((**elem).clone(), *len),
            _ => return Err(CompileError::new("vector binop on non-array type")),
        };
        let signed = matches!(&elem, Type::Int { signed: true, .. });
        // Either an arithmetic/bitwise op, or a comparison predicate.
        let arith = match op {
            BinOpKind::BitOr => Some(BinOp::Or),
            BinOpKind::BitAnd => Some(BinOp::And),
            BinOpKind::BitXor => Some(BinOp::Xor),
            BinOpKind::Add => Some(BinOp::Add),
            BinOpKind::Sub => Some(BinOp::Sub),
            BinOpKind::Mul => Some(BinOp::Mul),
            BinOpKind::Div => Some(if signed { BinOp::SDiv } else { BinOp::UDiv }),
            BinOpKind::Rem => Some(if signed { BinOp::SRem } else { BinOp::URem }),
            BinOpKind::Shl => Some(BinOp::Shl),
            BinOpKind::Shr => Some(if signed { BinOp::AShr } else { BinOp::LShr }),
            _ => None,
        };
        let cmp = match op {
            BinOpKind::Eq => Some(CmpOp::IEq),
            BinOpKind::Ne => Some(CmpOp::INe),
            BinOpKind::Lt => Some(if signed { CmpOp::ISLt } else { CmpOp::IULt }),
            BinOpKind::Le => Some(if signed { CmpOp::ISLe } else { CmpOp::IULe }),
            BinOpKind::Gt => Some(if signed { CmpOp::ISGt } else { CmpOp::IUGt }),
            BinOpKind::Ge => Some(if signed { CmpOp::ISGe } else { CmpOp::IUGe }),
            _ => None,
        };
        if arith.is_none() && cmp.is_none() {
            return Err(CompileError::new(format!("unsupported vector operator {:?}", op)));
        }
        let lp = self.lower_aggregate_ptr(lhs)?;
        let rp = self.lower_aggregate_ptr(rhs)?;
        let rp_out = self.vec_alloca(vty.clone());
        let esz = elem.size_of(self.ptr_size()) as i64;
        for i in 0..lanes {
            let off = i as i64 * esz;
            let x = self.vec_load(&lp, off, elem.clone());
            let y = self.vec_load(&rp, off, elem.clone());
            let v = if let Some(irop) = arith {
                self.vec_bin(irop, x, y, elem.clone())
            } else {
                let c = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: c, op: cmp.unwrap(), lhs: x, rhs: y, ty: elem.clone() });
                let s = self.alloc_val();
                self.push_instr(Instr::Select { dest: s, cond: Val::Local(c), on_true: Constant::int(-1), on_false: Constant::int(0), ty: elem.clone() });
                Val::Local(s)
            };
            self.vec_store(&rp_out, off, v);
        }
        Ok(rp_out)
    }

    /// `__builtin_ia32_pmovmskb128/256`: pack the high bit of each byte into an int.
    fn lower_vec_pmovmskb(&mut self, arg: &Expr, n: usize) -> Result<Val> {
        let vp = self.lower_aggregate_ptr(arg)?;
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut mask = Constant::int(0);
        for i in 0..n {
            let b = self.vec_load(&vp, i as i64, u8t.clone());
            let b32 = self.coerce(b, &i32t)?;
            let sh = self.vec_bin(BinOp::LShr, b32, Constant::int(7), i32t.clone());
            let bit = self.vec_bin(BinOp::And, sh, Constant::int(1), i32t.clone());
            let shifted = self.vec_bin(BinOp::Shl, bit, Constant::int(i as i64), i32t.clone());
            mask = self.vec_bin(BinOp::Or, mask, shifted, i32t.clone());
        }
        Ok(mask)
    }

    /// `__builtin_ia32_pcmpeqb128/256`: per-byte equality → 0xFF/0x00 lanes.
    fn lower_vec_pcmpeqb(&mut self, a: &Expr, b: &Expr, n: usize) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let vty = self.infer_expr_type(a)?;
        let rp = self.vec_alloca(vty);
        let u8t = Type::u8();
        for i in 0..n {
            let x = self.vec_load(&ap, i as i64, u8t.clone());
            let y = self.vec_load(&bp, i as i64, u8t.clone());
            let eq = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: eq, op: CmpOp::IEq, lhs: x, rhs: y, ty: u8t.clone() });
            let val = self.alloc_val();
            self.push_instr(Instr::Select { dest: val, cond: Val::Local(eq), on_true: Constant::int(0xFF), on_false: Constant::int(0), ty: u8t.clone() });
            self.vec_store(&rp, i as i64, Val::Local(val));
        }
        Ok(rp)
    }

    /// `__builtin_ia32_pshufb128`: byte shuffle `r[i] = (b[i]&0x80) ? 0 : a[b[i]&0x0F]`.
    fn lower_vec_pshufb(&mut self, a: &Expr, b: &Expr, n: usize) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let vty = self.infer_expr_type(a)?;
        let rp = self.vec_alloca(vty);
        let u8t = Type::u8();
        let i64t = Type::i64();
        for i in 0..n {
            let idx = self.vec_load(&bp, i as i64, u8t.clone());
            let idx64 = self.coerce(idx, &i64t)?;
            // lo = idx & 0x0F  → offset into `a`
            let lo = self.vec_bin(BinOp::And, idx64.clone(), Constant::int(0x0F), i64t.clone());
            let srcaddr = self.alloc_val();
            self.push_instr(Instr::PtrOffset { dest: srcaddr, base: ap.clone(), offset: lo });
            let src = self.alloc_val();
            self.push_instr(Instr::Load { dest: src, ptr: Val::Local(srcaddr), ty: u8t.clone() });
            // high bit set → zero the lane
            let hib = self.vec_bin(BinOp::And, idx64, Constant::int(0x80), i64t.clone());
            let clr = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: clr, op: CmpOp::INe, lhs: hib, rhs: Constant::int(0), ty: i64t.clone() });
            let val = self.alloc_val();
            self.push_instr(Instr::Select { dest: val, cond: Val::Local(clr), on_true: Constant::int(0), on_false: Val::Local(src), ty: u8t.clone() });
            self.vec_store(&rp, i as i64, Val::Local(val));
        }
        Ok(rp)
    }

    /// `__builtin_ia32_pclmulqdq128`: carry-less multiply of two selected 64-bit
    /// halves → a 128-bit result. `imm` selects which halves (bit0 of a, bit4 of b).
    fn lower_vec_pclmulqdq(&mut self, a: &Expr, b: &Expr, imm: &Expr) -> Result<Val> {
        let ap = self.lower_aggregate_ptr(a)?;
        let bp = self.lower_aggregate_ptr(b)?;
        let immv = crate::lower::eval_const_expr(imm, &self.lowerer.enum_consts).unwrap_or(0);
        let u64t = Type::u64();
        let i128t = Type::Int { bits: 128, signed: false };
        let a_off = if immv & 0x01 != 0 { 8 } else { 0 };
        let b_off = if immv & 0x10 != 0 { 8 } else { 0 };
        let x = self.vec_load(&ap, a_off, u64t.clone());
        let y = self.vec_load(&bp, b_off, u64t.clone());
        let xext = self.coerce(x, &i128t)?;
        let mut res = Constant::int(0);
        for j in 0..64 {
            // bit j of y set?  term = bit ? (xext << j) : 0 ; res ^= term
            let yj = self.vec_bin(BinOp::LShr, y.clone(), Constant::int(j), u64t.clone());
            let ybit = self.vec_bin(BinOp::And, yj, Constant::int(1), u64t.clone());
            let set = self.alloc_val();
            self.push_instr(Instr::Cmp { dest: set, op: CmpOp::INe, lhs: ybit, rhs: Constant::int(0), ty: u64t.clone() });
            let shifted = self.vec_bin(BinOp::Shl, xext.clone(), Constant::int(j), i128t.clone());
            let term = self.alloc_val();
            self.push_instr(Instr::Select { dest: term, cond: Val::Local(set), on_true: shifted, on_false: Constant::int(0), ty: i128t.clone() });
            res = self.vec_bin(BinOp::Xor, res, Val::Local(term), i128t.clone());
        }
        let vty = self.infer_expr_type(a).unwrap_or(Type::Array { elem: Box::new(Type::i64()), len: 2 });
        let rp = self.vec_alloca(vty);
        self.vec_store(&rp, 0, res);
        Ok(rp)
    }

    /// Pointer to the first byte of the (lazily-created) AES S-box / inverse
    /// S-box global constant.
    fn aes_sbox_ptr(&mut self, inverse: bool) -> Val {
        let name = if inverse { ".sic_aes_inv_sbox" } else { ".sic_aes_sbox" };
        let gref = if let Some(i) = self.lowerer.module.globals.iter().position(|g| g.name == name) {
            sic_ir::GlobalRef(i as u32)
        } else {
            let bytes = if inverse { AES_INV_SBOX.to_vec() } else { AES_SBOX.to_vec() };
            self.lowerer.module.add_global(sic_ir::Global {
                name: name.to_string(),
                ty: Type::Array { elem: Box::new(Type::u8()), len: 256 },
                init: Some(Constant::Bytes(bytes)),
                linkage: Linkage::Private,
                constant: true,
                thread_local: false,
            })
        };
        let ptr = self.alloc_val();
        self.push_instr(Instr::GetElemPtr {
            dest: ptr, base: Val::Global(gref), index: Constant::zero(),
            elem_size: 1, result_ty: Type::ptr(Type::u8()),
        });
        Val::Local(ptr)
    }

    /// GF(2^8) `xtime` (multiply by 2 modulo the AES polynomial 0x11B), on a
    /// byte held in an i32.
    fn aes_xtime(&mut self, x: Val) -> Val {
        let i32t = Type::i32();
        let sh = self.vec_bin(BinOp::Shl, x.clone(), Constant::int(1), i32t.clone());
        let hi = self.vec_bin(BinOp::LShr, x, Constant::int(7), i32t.clone());
        let hi1 = self.vec_bin(BinOp::And, hi, Constant::int(1), i32t.clone());
        let red = self.vec_bin(BinOp::Mul, hi1, Constant::int(0x1b), i32t.clone());
        let xored = self.vec_bin(BinOp::Xor, sh, red, i32t.clone());
        self.vec_bin(BinOp::And, xored, Constant::int(0xff), i32t)
    }

    /// GF(2^8) multiply of byte `x` by a compile-time constant `c`.
    fn aes_gmul(&mut self, x: Val, c: u8) -> Val {
        let i32t = Type::i32();
        let mut pow = x;                 // xtime^0(x) = x
        let mut acc: Option<Val> = None;
        let mut cc = c;
        while cc != 0 {
            if cc & 1 != 0 {
                acc = Some(match acc {
                    None => pow.clone(),
                    Some(a) => self.vec_bin(BinOp::Xor, a, pow.clone(), i32t.clone()),
                });
            }
            cc >>= 1;
            if cc != 0 { pow = self.aes_xtime(pow); }
        }
        acc.unwrap_or(Constant::int(0))
    }

    /// SubBytes / InvSubBytes: replace each byte with its S-box image.
    fn aes_sub_bytes(&mut self, s: Vec<Val>, inverse: bool) -> Result<Vec<Val>> {
        let tbl = self.aes_sbox_ptr(inverse);
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut out = Vec::with_capacity(16);
        for b in s {
            let idx = self.coerce(b, &Type::i64())?;
            let addr = self.alloc_val();
            self.push_instr(Instr::PtrOffset { dest: addr, base: tbl.clone(), offset: idx });
            let v = self.alloc_val();
            self.push_instr(Instr::Load { dest: v, ptr: Val::Local(addr), ty: u8t.clone() });
            out.push(self.coerce(Val::Local(v), &i32t)?);
        }
        Ok(out)
    }

    /// MixColumns / InvMixColumns over the four 4-byte columns.
    fn aes_mix_columns(&mut self, s: Vec<Val>, inverse: bool) -> Vec<Val> {
        let m: [[u8; 4]; 4] = if inverse {
            [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
        } else {
            [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        };
        let i32t = Type::i32();
        let mut out: Vec<Val> = vec![Constant::int(0); 16];
        for col in 0..4 {
            let a = [
                s[col * 4].clone(), s[col * 4 + 1].clone(),
                s[col * 4 + 2].clone(), s[col * 4 + 3].clone(),
            ];
            for r in 0..4 {
                let mut acc: Option<Val> = None;
                for j in 0..4 {
                    let term = self.aes_gmul(a[j].clone(), m[r][j]);
                    acc = Some(match acc {
                        None => term,
                        Some(x) => self.vec_bin(BinOp::Xor, x, term, i32t.clone()),
                    });
                }
                out[col * 4 + r] = acc.unwrap();
            }
        }
        out
    }

    /// Emulate an AES-NI round intrinsic over the 16-byte state.
    fn lower_aes(&mut self, state: &Expr, key: Option<&Expr>, mode: AesMode) -> Result<Val> {
        // Byte permutations for (Inv)ShiftRows: out[i] = in[MAP[i]].
        const SHR: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        const INV_SHR: [usize; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

        let sp = self.lower_aggregate_ptr(state)?;
        let u8t = Type::u8();
        let i32t = Type::i32();
        let mut s: Vec<Val> = Vec::with_capacity(16);
        for i in 0..16 {
            let b = self.vec_load(&sp, i as i64, u8t.clone());
            s.push(self.coerce(b, &i32t)?);
        }
        match mode {
            AesMode::Enc | AesMode::EncLast => {
                s = SHR.iter().map(|&j| s[j].clone()).collect();
                s = self.aes_sub_bytes(s, false)?;
                if matches!(mode, AesMode::Enc) { s = self.aes_mix_columns(s, false); }
            }
            AesMode::Dec | AesMode::DecLast => {
                s = INV_SHR.iter().map(|&j| s[j].clone()).collect();
                s = self.aes_sub_bytes(s, true)?;
                if matches!(mode, AesMode::Dec) { s = self.aes_mix_columns(s, true); }
            }
            AesMode::Imc => {
                s = self.aes_mix_columns(s, true);
            }
        }
        if let Some(k) = key {
            let kp = self.lower_aggregate_ptr(k)?;
            for i in 0..16 {
                let kb = self.vec_load(&kp, i as i64, u8t.clone());
                let kb32 = self.coerce(kb, &i32t)?;
                s[i] = self.vec_bin(BinOp::Xor, s[i].clone(), kb32, i32t.clone());
            }
        }
        let vty = self.infer_expr_type(state)
            .unwrap_or(Type::Array { elem: Box::new(Type::i64()), len: 2 });
        let rp = self.vec_alloca(vty);
        for i in 0..16 {
            let b = self.coerce(s[i].clone(), &u8t)?;
            self.vec_store(&rp, i as i64, b);
        }
        Ok(rp)
    }

    /// Pointer to the storage of a struct/union-typed expression. Lvalues yield
    /// their address; aggregate rvalues (compound literals, struct-returning
    /// calls) already lower to a pointer to their temporary.
    pub(crate) fn lower_aggregate_ptr(&mut self, e: &Expr) -> Result<Val> {
        // sic `dict[key]` yields an aggregate-by-pointer (`any`) directly — never an
        // lvalue-index, which would do bogus pointer arithmetic on the handle.
        if self.is_sic() {
            if let ExprKind::Index { base, index } = &e.kind {
                if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_dict(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_dict(i))) {
                    return self.lower_dict_get(base, index, &e.span);
                }
                if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_list(&t)
                    || matches!(&t, Type::Pointer(i) if super::types::is_list(i))) {
                    return self.lower_list_get(base, index, &e.span);
                }
            }
        }
        if let Ok(lv) = self.lower_lvalue(e) {
            Ok(lv.ptr)
        } else {
            self.lower_expr(e)
        }
    }

    /// sic (sic.md §"Match"/§"Namespace"): the discriminant of a plain (payload-less)
    /// C enum variant named `Enum::VARIANT`. `enum_name` may be scope-qualified
    /// (`N::E`, `mod::E`); the enum is its last `::` segment (alias-resolved).
    fn resolve_plain_enum_const(&self, enum_name: &str, variant: &str) -> Option<i64> {
        let ename = enum_name.rsplit("::").next().unwrap_or(enum_name);
        let canon = self.lowerer.c_enum_alias.get(ename).map(|s| s.as_str()).unwrap_or(ename);
        let vs = self.lowerer.c_enum_defs.get(canon)?;
        vs.iter().find(|(n, _)| n == variant).map(|(_, v)| *v)
    }

    /// Construct a sic tagged-enum value (sic.md §"Match"): allocate the
    /// `{ tag; union }` struct on the stack, store the variant's discriminant, and
    /// store the payload (if any). Returns a pointer to the temporary, like a
    /// compound literal, so the surrounding assignment/return copies it.
    fn construct_enum(&mut self, enum_name: &str, variant: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // sic plain (payload-less) C enum: `E::VARIANT` — possibly scope-qualified
        // (`N::E::VARIANT`, `mod::E::VARIANT`) — is the variant's discriminant.
        if self.is_sic() && args.is_empty() {
            if let Some(v) = self.resolve_plain_enum_const(enum_name, variant) {
                return Ok(Constant::int(v));
            }
        }
        // A scope-qualified tagged enum `mod::Enum` / `N::Enum` resolves to its last
        // `::` segment (sic.md §"Namespace").
        let enum_name = if self.is_sic() && !self.lowerer.enum_defs.contains_key(enum_name) {
            enum_name.rsplit("::").next().unwrap_or(enum_name)
        } else { enum_name };
        // A generic constructor (`Option::Some(5)` / `None`) names the template;
        // resolve it to the concrete monomorph via the expected target type.
        let resolved = self.resolve_generic_ctor(enum_name, sp)?;
        let enum_name = resolved.as_deref().unwrap_or(enum_name);
        let info = self.lowerer.enum_defs.get(enum_name).cloned().ok_or_else(|| CompileError::at(
            format!("'{}' is not a tagged enum", enum_name), sp.file.clone(), sp.line, sp.col))?;
        let v = info.variant(variant).cloned().ok_or_else(|| CompileError::at(
            format!("enum '{}' has no variant '{}'", enum_name, variant), sp.file.clone(), sp.line, sp.col))?;

        // A payload arm whose single argument is itself an instance of this enum is
        // an *unwrap* (`Test::CUSTOM(inst)`), not a construction.
        if v.payload.is_some() && args.len() == 1 {
            if let Ok(t) = self.infer_expr_type(&args[0]) {
                if self.is_enum_struct(&t, enum_name) {
                    return self.unwrap_enum(&info, &v, &args[0], sp);
                }
            }
        }

        let struct_ty = info.struct_type.clone();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: struct_ty.clone(), align: None });
        self.val_types.insert(slot.0, struct_ty.clone());
        // Zero the whole value so an unused payload area is deterministic.
        let size = struct_ty.size_of(self.ptr_size());
        self.push_instr(Instr::MemSet {
            dst: Val::Local(slot), val: Constant::zero(), size,
            align: struct_ty.align_of(self.ptr_size()),
        });
        // Store the discriminant into `tag`.
        let tag_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), struct_ty.clone()), "tag", false, sp)?;
        self.store_lvalue(&tag_lv, Constant::int(v.tag))?;

        // Store the payload into the `data` union member (offset 0 of the union).
        match (&v.payload, args.len()) {
            (Some(pty), 1) => {
                let data_lv = self.field_ptr_from(LValue::plain(Val::Local(slot), struct_ty.clone()), "data", false, sp)?;
                let payload_ptr = LValue::plain(data_lv.ptr, pty.clone());
                if self.is_sic() && super::types::is_sic_string(pty) {
                    // A `string` payload: wrap a bare `char*`/literal into a
                    // `{data,size,rc}` slice, then copy it in and retain it.
                    let arg = self.lower_expr(&args[0])?;
                    let vt = self.val_type(&arg);
                    let is_str = super::types::is_sic_string(&vt)
                        || matches!(&vt, Type::Pointer(inner) if super::types::is_sic_string(inner));
                    let src = if is_str { arg } else { self.cstr_to_string(arg)? };
                    let sz = pty.size_of(self.ptr_size());
                    let al = pty.align_of(self.ptr_size());
                    self.retain_string_at(&src)?;
                    self.push_instr(Instr::MemCopy { dst: payload_ptr.ptr, src, size: sz, align: al });
                } else if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                    // Other aggregate payload: copy it in.
                    let src = self.lower_aggregate_ptr(&args[0])?;
                    let sz = pty.size_of(self.ptr_size());
                    let al = pty.align_of(self.ptr_size());
                    self.push_instr(Instr::MemCopy { dst: payload_ptr.ptr, src, size: sz, align: al });
                } else if self.is_sic() && super::types::is_fixed(pty) {
                    // A `fixed` payload is an exact rational (`__sic_rat*`). Evaluate
                    // the arg into a freshly-owned rational (converting a literal/int,
                    // and taking an independent copy of any source) so the enum owns
                    // its payload — a bare `lower_expr` yields a raw float, and a
                    // shared pointer would dangle when the source's `__sic_rat_free`
                    // cleanup runs.
                    let val = self.eval_fixed_owned(&args[0], 0)?;
                    self.push_instr(Instr::Store { val, ptr: payload_ptr.ptr });
                } else if self.is_sic() && super::types::is_bigint(pty) {
                    // A `bigint` payload: same ownership story via `__sic_bi_clone`.
                    let val = self.eval_bigint_owned(&args[0])?;
                    self.push_instr(Instr::Store { val, ptr: payload_ptr.ptr });
                } else {
                    let val = self.lower_expr(&args[0])?;
                    self.store_lvalue(&payload_ptr, val)?;
                }
            }
            (Some(_), n) => return Err(CompileError::at(
                format!("variant '{}::{}' takes 1 value, got {}", enum_name, variant, n),
                sp.file.clone(), sp.line, sp.col)),
            (None, 0) => {}
            (None, n) => return Err(CompileError::at(
                format!("variant '{}::{}' takes no value, got {}", enum_name, variant, n),
                sp.file.clone(), sp.line, sp.col)),
        }
        Ok(Val::Local(slot))
    }

    /// Resolve a generic-enum constructor's template name (`Option`) to its
    /// concrete monomorph (`Option<i32>`) using the expected target type
    /// (sic.md §"Match"). Returns `None` for an already-concrete enum name.
    fn resolve_generic_ctor(&self, enum_name: &str, sp: &crate::lexer::Span) -> Result<Option<String>> {
        // Already a concrete (registered) enum — nothing to resolve.
        if self.lowerer.enum_defs.contains_key(enum_name) { return Ok(None); }
        if !self.lowerer.generic_enum_defs.contains_key(enum_name) { return Ok(None); }
        let prefix = format!("{}<", enum_name);
        if let Some(Type::Struct(st)) = &self.expected_ty {
            if let Some(n) = &st.name {
                if n.starts_with(&prefix) && self.lowerer.enum_defs.contains_key(n) {
                    return Ok(Some(n.clone()));
                }
            }
        }
        Err(CompileError::at(format!(
            "cannot infer type arguments for generic enum `{}` here — annotate the \
             target type (e.g. `{}<int> x = …`)", enum_name, enum_name),
            sp.file.clone(), sp.line, sp.col))
    }

    /// True if `t` is the `{tag,union}` struct of the named tagged enum.
    fn is_enum_struct(&self, t: &Type, enum_name: &str) -> bool {
        matches!(t, Type::Struct(st) if st.name.as_deref() == Some(enum_name))
    }

    /// If `pty` is a tagged-enum struct and the arg `pval` is a bare discriminant
    /// (an integer tag), build the enum value into a temporary and repoint `pval`
    /// at it. Returns whether it handled the argument.
    pub(super) fn build_enum_arg(&mut self, pval: &mut Val, pty: &Type, sp: &crate::lexer::Span) -> Result<bool> {
        if !(self.is_sic() && self.is_tagged_enum_struct(pty)) {
            return Ok(false);
        }
        if !matches!(self.val_type(pval), Type::Int { .. }) {
            // Already a proper enum value (pointer to storage).
            return Ok(false);
        }
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: pty.clone(), align: None });
        self.val_types.insert(slot.0, pty.clone());
        self.build_enum_from_tag(&Val::Local(slot), pty, pval.clone(), sp)?;
        *pval = Val::Local(slot);
        Ok(true)
    }

    /// True if `t` is any tagged-enum representation struct.
    pub(super) fn is_tagged_enum_struct(&self, t: &Type) -> bool {
        matches!(t, Type::Struct(st) if st.name.as_deref()
            .map_or(false, |n| self.lowerer.enum_defs.contains_key(n)))
    }

    /// Build a tagged-enum value in place from a bare discriminant (`Test x =
    /// BLACK;`): zero the storage and store the tag. A payload-less variant only.
    pub(super) fn build_enum_from_tag(&mut self, ptr: &Val, ty: &Type, tag: Val, sp: &crate::lexer::Span) -> Result<()> {
        let size = ty.size_of(self.ptr_size());
        self.push_instr(Instr::MemSet {
            dst: ptr.clone(), val: Constant::zero(), size, align: ty.align_of(self.ptr_size()),
        });
        let tag_lv = self.field_ptr_from(LValue::plain(ptr.clone(), ty.clone()), "tag", false, sp)?;
        self.store_lvalue(&tag_lv, tag)?;
        Ok(())
    }

    /// Load a tagged-enum value's discriminant (`(int)x`). `ptr` addresses the
    /// `{tag,union}` struct.
    pub(super) fn load_enum_tag(&mut self, ptr: Val, struct_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let tag_lv = self.field_ptr_from(LValue::plain(ptr, struct_ty.clone()), "tag", false, sp)?;
        self.load_lvalue(&tag_lv)
    }

    /// Pointer to a tagged-enum value's payload (`data` union member).
    pub(super) fn enum_data_ptr(&mut self, ptr: Val, struct_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let data_lv = self.field_ptr_from(LValue::plain(ptr, struct_ty.clone()), "data", false, sp)?;
        Ok(data_lv.ptr)
    }

    /// Materialize a tagged-enum value of type `enum_ty` from `e` and return a
    /// pointer to it: a same-enum expression yields its own storage; a bare
    /// discriminant (`None`, `BLACK`) is built into a fresh temporary. Used where
    /// an enum value is needed by pointer (return, argument passing).
    pub(super) fn enum_value_ptr(&mut self, e: &Expr, enum_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        // Expose the target enum type so a generic constructor (`return
        // Result::Ok(x)`) resolves its monomorph (sic.md §"Match").
        let prev = self.expected_ty.replace(enum_ty.clone());
        let out = self.enum_value_ptr_impl(e, enum_ty, sp);
        self.expected_ty = prev;
        out
    }

    fn enum_value_ptr_impl(&mut self, e: &Expr, enum_ty: &Type, sp: &crate::lexer::Span) -> Result<Val> {
        let same = matches!(self.infer_expr_type(e), Ok(t) if &t == enum_ty);
        if same {
            self.lower_aggregate_ptr(e)
        } else {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: enum_ty.clone(), align: None });
            self.val_types.insert(slot.0, enum_ty.clone());
            let tag = self.lower_expr(e)?;
            self.build_enum_from_tag(&Val::Local(slot), enum_ty, tag, sp)?;
            Ok(Val::Local(slot))
        }
    }

    /// Unwrap a tagged-enum instance to a variant's payload (sic.md §"Match"):
    /// `Enum::VARIANT(inst)`. Aborts at runtime (`__sic_match_fail`) if `inst` is
    /// not that variant. Returns the payload value (or, for an aggregate payload,
    /// a pointer to it).
    fn unwrap_enum(&mut self, info: &super::TaggedEnum, v: &super::TaggedVariant, inst_expr: &Expr, sp: &crate::lexer::Span) -> Result<Val> {
        let payload_ty = v.payload.clone().ok_or_else(|| CompileError::at(
            format!("variant '{}::{}' carries no value to unwrap", info.name, v.name),
            sp.file.clone(), sp.line, sp.col))?;
        let inst_ptr = self.lower_aggregate_ptr(inst_expr)?;
        let struct_ty = info.struct_type.clone();

        // Runtime guard: if tag != this variant's, abort.
        let tag_lv = self.field_ptr_from(LValue::plain(inst_ptr.clone(), struct_ty.clone()), "tag", false, sp)?;
        let tag = self.load_lvalue(&tag_lv)?;
        let ne = self.alloc_val();
        self.push_instr(Instr::Cmp { dest: ne, op: CmpOp::INe, lhs: tag, rhs: Constant::int(v.tag), ty: Type::i32() });
        let fail_bb = self.new_block_after_current();
        let ok_bb = self.new_block_after_current();
        self.set_terminator(Terminator::CondJump { cond: Val::Local(ne), then_bb: fail_bb, else_bb: ok_bb });
        self.switch_to_block(fail_bb);
        let fref = self.lowerer.ensure_match_fail_fn();
        self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
        self.set_terminator(Terminator::Jump(ok_bb)); // abort never returns
        self.switch_to_block(ok_bb);

        // Read the payload out of the `data` union member.
        let data_lv = self.field_ptr_from(LValue::plain(inst_ptr, struct_ty), "data", false, sp)?;
        if matches!(payload_ty, Type::Struct(_) | Type::Union(_)) {
            Ok(data_lv.ptr) // aggregate payload decays to a pointer
        } else {
            let d = self.alloc_val();
            self.push_instr(Instr::Load { dest: d, ptr: data_lv.ptr, ty: payload_ty.clone() });
            self.val_types.insert(d.0, payload_ty);
            Ok(Val::Local(d))
        }
    }

    /// Resolve a namespaced module call `module.sym` to a mangled extern FuncRef,
    /// creating the extern on first use. Errors if the module has no such export.
    fn resolve_module_call(&mut self, module: &str, sym: &str, sp: &crate::lexer::Span) -> Result<FuncRef> {
        let (symbol, ty) = self.lowerer.imported_modules
            .get(module)
            .and_then(|m| m.get(sym))
            .cloned()
            .ok_or_else(|| CompileError::at(
                format!("module '{}' has no exported symbol '{}'", module, sym),
                sp.file.clone(), sp.line, sp.col,
            ))?;
        self.module_extern(&symbol, &ty, sp)
    }

    /// Resolve a selectively/renamed-imported bare name to its mangled extern.
    fn resolve_module_call_bare(&mut self, name: &str, sp: &crate::lexer::Span) -> Result<FuncRef> {
        let (symbol, ty) = self.lowerer.imported_syms.get(name).cloned()
            .expect("caller checked imported_syms");
        self.module_extern(&symbol, &ty, sp)
    }

    /// Get-or-create the extern for an imported function symbol.
    fn module_extern(&mut self, symbol: &str, ty: &Type, sp: &crate::lexer::Span) -> Result<FuncRef> {
        let mut ft = match ty {
            Type::Function(ft) => (**ft).clone(),
            _ => return Err(CompileError::at(
                format!("imported symbol '{}' is not a function", symbol),
                sp.file.clone(), sp.line, sp.col,
            )),
        };
        // A struct/union return uses the sret ABI: the callee's real IR signature has
        // a hidden pointer as param 0 (the frontend prepends it for local functions).
        // The stored export type is user-facing (no sret), so prepend it here so the
        // extern's cranelift signature matches the definition across objects.
        if super::ret_is_sret(&ft.ret, self.ptr_size()) {
            ft.params.insert(0, Type::Pointer(Box::new(ft.ret.clone())));
        }
        Ok(self.lowerer.module.func_ref_by_name(symbol).unwrap_or_else(|| {
            self.lowerer.module.add_extern(ExternFunc { name: symbol.to_string(), sig: ft })
        }))
    }

    /// sic atomic pseudo-methods (sic.md §"Atomics") on an atomic lvalue `base`:
    ///   `base.swap(v)`      → atomic exchange, yields the previous value
    ///   `base.cas(exp, des)`→ compare-and-swap, yields `bool` success
    fn lower_atomic_method(&mut self, base: &Expr, name: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        let lv = self.lower_lvalue(base)?;
        let ty = lv.ty.clone();
        match name {
            "swap" => {
                if args.len() != 1 {
                    return Err(CompileError::at(
                        "`.swap` takes one argument: the value to store".to_string(),
                        sp.file.clone(), sp.line, sp.col));
                }
                let v = self.lower_expr(&args[0])?;
                let v = self.coerce(v, &ty)?;
                let old = self.alloc_val();
                self.push_instr(Instr::AtomicRmw { dest: old, op: AtomicOp::Xchg, ptr: lv.ptr.clone(), val: v, ty });
                Ok(Val::Local(old))
            }
            "cas" => {
                if args.len() != 2 {
                    return Err(CompileError::at(
                        "`.cas` takes two arguments: `.cas(expected, desired)`".to_string(),
                        sp.file.clone(), sp.line, sp.col));
                }
                let exp = self.lower_expr(&args[0])?;
                let exp = self.coerce(exp, &ty)?;
                let des = self.lower_expr(&args[1])?;
                let des = self.coerce(des, &ty)?;
                let old = self.alloc_val();
                self.push_instr(Instr::AtomicCas {
                    dest: old, ptr: lv.ptr.clone(), expected: exp.clone(), desired: des, ty: ty.clone(),
                });
                // Success ⇔ the observed old value equals `expected`.
                let ok = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: ok, op: CmpOp::IEq, lhs: Val::Local(old), rhs: exp, ty });
                Ok(Val::Local(ok))
            }
            _ => unreachable!("atomic method dispatch"),
        }
    }

    fn lower_call(&mut self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // sic named parameters (sic.md §"Named parameters"): if any argument is
        // `name = value`, map every argument to the callee's parameters — reordering,
        // filling, and (for a variadic) dropping unmatched names to the tail — then
        // re-enter with a purely positional list.
        if args.iter().any(|a| matches!(a.kind, ExprKind::NamedArg { .. })) {
            // If the callee has a `va_dict` parameter, the named arguments are kept
            // (not flattened) and packed into it during argument lowering below.
            if !self.callee_has_va_dict(func_expr) {
                let reordered = self.resolve_named_args(func_expr, args, sp)?;
                return self.lower_call(func_expr, &reordered, sp);
            }
        }

        // sic generic call with explicit type arguments (turbofish), `add<int>(…)`
        // (sic.md §"Generics"): monomorphize with the written types (no inference).
        if let ExprKind::GenericRef { name, type_args } = &func_expr.kind {
            return self.lower_generic_call_explicit(name, type_args, args, sp);
        }
        // sic tagged-enum constructor `Enum::Variant(args)` (sic.md §"Match").
        // (Unwrap `Enum::VARIANT(inst)` is handled inside `construct_enum`.)
        if let ExprKind::EnumVariant { enum_name, variant } = &func_expr.kind {
            // sic (sic.md §"Namespace"): `Module::sym(args)` is the canonical scope
            // form of a module call — resolve it like `module.sym(args)`.
            if self.is_sic() && self.lowerer.imported_modules.contains_key(enum_name) {
                let callee = Expr { kind: ExprKind::Field {
                    base: Box::new(Expr { kind: ExprKind::Ident(enum_name.clone()), span: sp.clone() }),
                    name: variant.clone(),
                }, span: sp.clone() };
                return self.lower_call(&callee, args, sp);
            }
            // sic nested module member `mod::A::B::sym(args)` (sic.md §"Namespace"):
            // the module exports namespace members mangled `A__B__sym`. But a
            // qualified *enum* path `mod::Enum::Variant(x)` is a construct/unwrap, not
            // a member call — let it fall through to `construct_enum`.
            if self.is_sic() {
                let leaf = enum_name.rsplit("::").next().unwrap_or(enum_name);
                let is_enum = self.lowerer.enum_defs.contains_key(leaf)
                    || self.resolve_plain_enum_const(enum_name, variant).is_some();
                if let Some((module, rest)) = enum_name.split_once("::") {
                    if !is_enum && self.lowerer.imported_modules.contains_key(module) {
                        let export = format!("{}__{}", rest.replace("::", "__"), variant);
                        let callee = Expr { kind: ExprKind::Field {
                            base: Box::new(Expr { kind: ExprKind::Ident(module.to_string()), span: sp.clone() }),
                            name: export,
                        }, span: sp.clone() };
                        return self.lower_call(&callee, args, sp);
                    }
                }
            }
            // sic (sic.md §"Namespace"): `N::member(args)` calls a namespace member.
            if self.is_sic() {
                if let Some(mangled) = self.lowerer.namespace_members.get(&(enum_name.clone(), variant.clone())).cloned() {
                    let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
                    return self.lower_call(&callee, args, sp);
                }
            }
            return self.construct_enum(enum_name, variant, args, sp);
        }
        // Bare variant constructor `Variant(args)` (`Ok(5)`), resolved from the
        // owning enum unless a real function/variable of that name shadows it.
        if let ExprKind::Ident(name) = &func_expr.kind {
            if self.is_sic() && self.lowerer.variant_enum.contains_key(name)
                && !matches!(self.lookup(name),
                    Some(LookupResult::Func(_)) | Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)))
            {
                let en = self.lowerer.variant_enum.get(name).cloned().unwrap();
                return self.construct_enum(&en, name, args, sp);
            }
        }

        // sic generic functions (sic.md §"Generics"): a call to a `name<T,…>`
        // template — infer the type arguments from the argument types, monomorphize,
        // and dispatch to the concrete instance. A real local/global of that name
        // shadows the template.
        if let ExprKind::Ident(name) = &func_expr.kind {
            if self.is_sic() && self.lowerer.generic_fn_defs.contains_key(name)
                && !matches!(self.lookup(name),
                    Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)))
            {
                return self.lower_generic_call(name, args, sp);
            }
        }

        // sic `set` methods (sic.md §"Set"): `s.add(x)`, `s.contains(x)` / `s.has(x)`,
        // `s.remove(x)` — thin sugar over the underlying `dict<T, bool>`.
        if self.is_sic() {
            if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func_expr.kind {
                if matches!(name.as_str(), "add" | "contains" | "has" | "remove")
                    && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_set(&t)
                        || matches!(&t, Type::Pointer(i) if super::types::is_set(i)))
                {
                    let key = args.first().ok_or_else(|| CompileError::at(
                        format!("`.{}` takes one element argument", name),
                        sp.file.clone(), sp.line, sp.col))?;
                    return match name.as_str() {
                        "add" => {
                            let t = Expr::new(ExprKind::BoolLit(true), sp.clone());
                            self.lower_dict_set(base, key, &t, sp)?;
                            Ok(Constant::zero())
                        }
                        "remove" => { self.lower_dict_del(base, key, sp)?; Ok(Constant::zero()) }
                        _ => self.lower_dict_get(base, key, sp), // contains / has → bool
                    };
                }
            }
        }

        // sic `list` methods (sic.md §"List"): `l.add(x)` / `l.push(x)` /
        // `l.append(x)` append an element.
        if self.is_sic() {
            if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func_expr.kind {
                if matches!(name.as_str(), "add" | "push" | "append")
                    && matches!(self.infer_expr_type(base), Ok(t) if super::types::is_list(&t)
                        || matches!(&t, Type::Pointer(i) if super::types::is_list(i)))
                {
                    let v = args.first().ok_or_else(|| CompileError::at(
                        format!("`.{}` takes one element argument", name),
                        sp.file.clone(), sp.line, sp.col))?;
                    self.lower_list_push(base, v, sp)?;
                    return Ok(Constant::zero());
                }
            }
        }

        // sic atomic methods (sic.md §"Atomics"): `a.swap(v)` and `a.cas(e, d)`,
        // allowed only on an atomic lvalue (never on an ordinary value).
        if self.is_sic() {
            let recv = match &func_expr.kind {
                ExprKind::Field { base, name } | ExprKind::Arrow { base, name }
                    if name == "cas" || name == "swap" => Some((base.as_ref(), name.as_str())),
                _ => None,
            };
            if let Some((base, name)) = recv {
                if matches!(&base.kind, ExprKind::Ident(n) if self.is_atomic_name(n)) {
                    return self.lower_atomic_method(base, name, args, sp);
                }
                // `.cas`/`.swap` on a non-atomic is an error (they only exist on atomics).
                if matches!(&base.kind, ExprKind::Ident(_)) {
                    return Err(CompileError::at(
                        format!("`.{}` is only available on an `atomic` value", name),
                        sp.file.clone(), sp.line, sp.col));
                }
            }
        }

        // sic struct method call (sic.md §"Memory safety" / §"Iterators"):
        // `obj.method(args)` / `p->method(args)` desugars to the hoisted free
        // function `__sic_m_<Struct>_<method>(self, args)`, with `self` the receiver
        // as a pointer (`&obj` for a value receiver, the pointer itself otherwise).
        // Recursing through `lower_call` reuses arg coercion + the sret ABI (the
        // method may return an aggregate such as `Iterator<T>`).
        if self.is_sic() && !self.lowerer.struct_methods.is_empty() {
            let recv = match &func_expr.kind {
                ExprKind::Field { base, name } | ExprKind::Arrow { base, name } =>
                    Some((base.as_ref(), name.clone())),
                _ => None,
            };
            if let Some((base, mname)) = recv {
                let (sname, recv_is_ptr) = match self.infer_expr_type(base).ok() {
                    Some(Type::Struct(st)) => (st.name, false),
                    Some(Type::Pointer(inner)) => match *inner {
                        Type::Struct(st) => (st.name, true),
                        _ => (None, false),
                    },
                    _ => (None, false),
                };
                if let Some(mangled) = sname
                    .and_then(|s| self.lowerer.struct_methods.get(&(s, mname)).cloned())
                {
                    let self_arg = if recv_is_ptr {
                        base.clone()
                    } else {
                        Expr { kind: ExprKind::Unary { op: crate::ast::UnOpKind::Addr, expr: Box::new(base.clone()) }, span: base.span.clone() }
                    };
                    let mut new_args = Vec::with_capacity(args.len() + 1);
                    new_args.push(self_arg);
                    new_args.extend_from_slice(args);
                    let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
                    return self.lower_call(&callee, &new_args, sp);
                }
            }
        }

        // A `_Generic(...)` selection used as the callee resolves to the chosen
        // association's expression, which may itself be a builtin name (e.g.
        // QEMU's `bswaps` macro: `_Generic(x, uint16_t: __builtin_bswap16, ...)(x)`).
        if let ExprKind::Generic { controlling, assocs } = &func_expr.kind {
            let idx = self.select_generic(controlling, assocs)?;
            return self.lower_call(&assocs[idx].1, args, sp);
        }

        // Handle __builtin_bswap* before evaluating args
        if let ExprKind::Ident(name) = &func_expr.kind {
            let bits: Option<u32> = match name.as_str() {
                "__builtin_bswap16" => Some(16),
                "__builtin_bswap32" => Some(32),
                "__builtin_bswap64" => Some(64),
                _ => None,
            };
            if let Some(bits) = bits {
                if let Some(arg) = args.first() {
                    let v = self.lower_expr(arg)?;
                    let ty = Type::Int { bits, signed: false };
                    let dest = self.alloc_val();
                    self.push_instr(Instr::BSwap { dest, val: v, ty });
                    return Ok(Val::Local(dest));
                }
            }

            // Overflow-checked arithmetic builtins:
            //   bool __builtin_{add,mul}_overflow(a, b, *res)
            // Compute `a op b`, store the wrapped result through `*res`, and
            // return whether the mathematical result overflowed the result type.
            let ovf_op = match name.as_str() {
                "__builtin_add_overflow" => Some(BinOp::Add),
                "__builtin_sub_overflow" => Some(BinOp::Sub),
                "__builtin_mul_overflow" => Some(BinOp::Mul),
                _ => None,
            };
            if let (Some(op), [a_expr, b_expr, res_expr]) = (ovf_op, args) {
                return self.lower_overflow_builtin(op, a_expr, b_expr, res_expr);
            }

            // Multiprecision add/subtract with carry:
            //   T __builtin_{add,sub}c[l|ll](T a, T b, T carryin, T *carryout)
            // Returns `a ± b ± carryin` (wrapped) and stores the outgoing
            // carry/borrow (0 or 1) through `*carryout`.
            let carry_sub = match name.as_str() {
                "__builtin_addc" | "__builtin_addcl" | "__builtin_addcll" => Some(false),
                "__builtin_subc" | "__builtin_subcl" | "__builtin_subcll" => Some(true),
                _ => None,
            };
            if let (Some(is_sub), [a_expr, b_expr, cin_expr, cout_expr]) = (carry_sub, args) {
                return self.lower_carry_builtin(is_sub, a_expr, b_expr, cin_expr, cout_expr);
            }

            // Atomic builtins. We lower these to plain (non-atomic) load/store
            // and treat fences as no-ops. This is functionally correct for
            // single-threaded execution and the relaxed-ordering uses sqlite
            // makes; it is not a true multi-threaded atomic implementation.
            match name.as_str() {
                // T __atomic_load_n(const T *ptr, int memorder)
                "__atomic_load_n" => {
                    if let Some(ptr_expr) = args.first() {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => *t,
                            _ => Type::i32(),
                        };
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Load { dest, ptr, ty });
                        return Ok(Val::Local(dest));
                    }
                }
                // void __atomic_load(const T *ptr, T *ret, int memorder): *ret = *ptr.
                "__atomic_load" => {
                    if let [ptr_expr, ret_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ret = self.lower_expr(ret_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        let size = ty.size_of(self.ptr_size());
                        let align = ty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: ret, src: ptr, size, align });
                        return Ok(Constant::zero());
                    }
                }
                // void __atomic_store(T *ptr, T *val, int memorder): *ptr = *val.
                "__atomic_store" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let val = self.lower_expr(val_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => super::types::resolve_aggregate(&t, &self.lowerer.struct_types),
                            _ => Type::i32(),
                        };
                        let size = ty.size_of(self.ptr_size());
                        let align = ty.align_of(self.ptr_size());
                        self.push_instr(Instr::MemCopy { dst: ptr, src: val, size, align });
                        return Ok(Constant::zero());
                    }
                }
                // void __atomic_store_n(T *ptr, T val, int memorder)
                "__atomic_store_n" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let val = self.lower_expr(val_expr)?;
                        let ty = match self.val_type(&ptr) {
                            Type::Pointer(t) => *t,
                            _ => self.val_type(&val),
                        };
                        let cv = self.coerce(val, &ty)?;
                        self.push_instr(Instr::Store { val: cv, ptr });
                        return Ok(Constant::zero());
                    }
                }
                // x86 scalar bit-scan intrinsics (from <ia32intrin.h>):
                //   bsr = index of the most-significant set bit = (bits-1) - clz
                //   bsf = index of the least-significant set bit = ctz
                "__builtin_ia32_bsrsi" | "__builtin_ia32_bsrdi"
                | "__builtin_ia32_bsfsi" | "__builtin_ia32_bsfdi" => {
                    if let Some(arg) = args.first() {
                        let bits = if name.ends_with("di") { 64 } else { 32 };
                        if name.contains("bsf") {
                            return self.lower_bit_count(arg, bits, BitOp::Ctz);
                        }
                        // bsr: (bits-1) - clz
                        let clz = self.lower_bit_count(arg, bits, BitOp::Clz)?;
                        let res = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: res, op: BinOp::Sub, lhs: Constant::int((bits - 1) as i64), rhs: clz, ty: Type::i32() });
                        return Ok(Val::Local(res));
                    }
                }
                // x86 SIMD vector intrinsics — scalar-emulated over the byte/lane
                // aggregate that a `vector_size` type lowers to.
                "__builtin_ia32_pmovmskb128" | "__builtin_ia32_pmovmskb256" => {
                    if let [v] = args {
                        let n = if name.ends_with("256") { 32 } else { 16 };
                        return self.lower_vec_pmovmskb(v, n);
                    }
                }
                "__builtin_ia32_pcmpeqb128" | "__builtin_ia32_pcmpeqb256" => {
                    if let [a, b] = args {
                        let n = if name.ends_with("256") { 32 } else { 16 };
                        return self.lower_vec_pcmpeqb(a, b, n);
                    }
                }
                "__builtin_ia32_pshufb128" => {
                    if let [a, b] = args { return self.lower_vec_pshufb(a, b, 16); }
                }
                "__builtin_ia32_pclmulqdq128" => {
                    if let [a, b, imm] = args { return self.lower_vec_pclmulqdq(a, b, imm); }
                }
                // AES-NI round intrinsics (from <wmmintrin.h>, used by QEMU's
                // host/crypto/aes-round.h). Each is a full AES round emulated with
                // the S-box tables + GF(2^8) MixColumns.
                "__builtin_ia32_aesenc128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::Enc); }
                }
                "__builtin_ia32_aesenclast128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::EncLast); }
                }
                "__builtin_ia32_aesdec128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::Dec); }
                }
                "__builtin_ia32_aesdeclast128" => {
                    if let [s, k] = args { return self.lower_aes(s, Some(k), AesMode::DecLast); }
                }
                "__builtin_ia32_aesimc128" => {
                    if let [s] = args { return self.lower_aes(s, None, AesMode::Imc); }
                }
                // `alloca(n)` / `__builtin_alloca(n)`: sic has no dynamic stack
                // allocation (cranelift stack slots are static-size). Emulate with
                // `malloc` so the code links and yields correct storage. NOTE:
                // this leaks (the block is not freed on function return); adequate
                // for bounded uses, but a proper dynamic stack alloca is a TODO.
                "__builtin_alloca" | "alloca" | "__builtin_alloca_with_align" => {
                    if let [size_expr, ..] = args {
                        let voidp = Type::void_ptr();
                        let fref = match self.lowerer.module.func_ref_by_name("malloc") {
                            Some(f) => f,
                            None => self.lowerer.module.add_extern(ExternFunc {
                                name: "malloc".to_string(),
                                sig: FunctionType { ret: voidp.clone(), params: vec![Type::u64()], variadic: false },
                            }),
                        };
                        let sz = self.lower_expr(size_expr)?;
                        let sz = self.coerce(sz, &Type::u64())?;
                        let dest = self.alloc_val();
                        self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: vec![sz], ret_ty: voidp.clone() });
                        self.val_types.insert(dest.0, voidp);
                        return Ok(Val::Local(dest));
                    }
                }
                // void __sync_synchronize(void) — full memory barrier; no-op here.
                "__sync_synchronize" => return Ok(Constant::zero()),
                // Atomic read-modify-write builtins. sic has no real atomics, so
                // these lower to a plain load / op / store (correct for a single
                // thread, which is enough to compile and run the code).
                //   __atomic_fetch_OP(ptr, val, order)  -> returns OLD value
                //   __atomic_OP_fetch(ptr, val, order)  -> returns NEW value
                //   __sync_fetch_and_OP(ptr, val)       -> returns OLD value
                //   __sync_OP_and_fetch(ptr, val)       -> returns NEW value
                n if atomic_rmw_op(n).is_some() => {
                    let (op, ret_new) = atomic_rmw_op(n).unwrap();
                    if let [ptr_expr, val_expr, ..] = args {
                        return self.lower_atomic_rmw(ptr_expr, val_expr, op, ret_new);
                    }
                }
                // Fences / barriers: no-ops for a single thread.
                "__atomic_thread_fence" | "__atomic_signal_fence" => return Ok(Constant::zero()),
                // T __atomic_exchange_n(ptr, val, order) / __sync_lock_test_and_set(ptr, val)
                "__atomic_exchange_n" | "__sync_lock_test_and_set" => {
                    if let [ptr_expr, val_expr, ..] = args {
                        return self.lower_atomic_exchange(ptr_expr, val_expr);
                    }
                }
                // void __sync_lock_release(ptr): *ptr = 0
                "__sync_lock_release" => {
                    if let [ptr_expr, ..] = args {
                        let ptr = self.lower_expr(ptr_expr)?;
                        let ty = self.pointee_ty(&ptr);
                        let z = self.coerce(Constant::zero(), &ty)?;
                        self.push_instr(Instr::Store { val: z, ptr });
                        return Ok(Constant::zero());
                    }
                }
                // Compare-and-swap. GCC exposes both the type-generic form and the
                // width-suffixed `_1/_2/_4/_8/_16` forms (QEMU's atomic128 host
                // path uses `_16` for 128-bit CAS). `lower_atomic_cas` is width-
                // agnostic (it works off the pointee type, incl. i128).
                n if sync_builtin_base(n) == "__sync_val_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, false); }
                }
                n if sync_builtin_base(n) == "__sync_bool_compare_and_swap" => {
                    if let [p, o, d, ..] = args { return self.lower_atomic_cas(p, o, d, true); }
                }
                "__atomic_compare_exchange_n" | "__atomic_compare_exchange" => {
                    if let [p, eptr, d, ..] = args { return self.lower_atomic_compare_exchange(p, eptr, d); }
                }
                // Branch-prediction hints: the value is just the first argument.
                "__builtin_expect" | "__builtin_expect_with_probability" => {
                    if let Some(e) = args.first() { return self.lower_expr(e); }
                }
                // Optimizer hints with no runtime effect for us.
                "__builtin_prefetch" | "__builtin_unreachable"
                | "__builtin_assume_aligned" => {
                    // `assume_aligned(p, ...)` returns its pointer; the rest are void.
                    if name.as_str() == "__builtin_assume_aligned" {
                        if let Some(e) = args.first() { return self.lower_expr(e); }
                    }
                    return Ok(Constant::zero());
                }
                "__builtin_constant_p" => return Ok(Constant::int(0)),
                // sic does no object-size analysis; return the "size unknown"
                // sentinel so any _FORTIFY / size check falls through to the plain
                // path: type 0/1 -> (size_t)-1, type 2/3 -> 0.
                "__builtin_object_size" | "__builtin_dynamic_object_size" => {
                    let ty = args.get(1)
                        .and_then(|e| crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok())
                        .unwrap_or(0);
                    let v: u64 = if ty & 2 != 0 { 0 } else { u64::MAX };
                    return self.coerce(Constant::uint(v), &Type::Int { bits: 64, signed: false });
                }
                // `__builtin_return_address(0)` = the current function's return
                // address. Critical for QEMU's GETPC(): a faulting helper uses it
                // to restart the TB at the right guest PC. Level 0 maps to
                // Cranelift's get_return_address; deeper levels (stack walking) and
                // frame/CFA queries fall back to null (diagnostics degrade).
                "__builtin_return_address" => {
                    let level0 = args.first()
                        .and_then(|e| crate::lower::eval_const_expr(e, &self.lowerer.enum_consts).ok())
                        .map(|v| v == 0)
                        .unwrap_or(true);
                    if level0 {
                        let d = self.alloc_val();
                        self.push_instr(Instr::ReturnAddress { dest: d });
                        self.val_types.insert(d.0, Type::void_ptr());
                        return Ok(Val::Local(d));
                    }
                    return Ok(Constant::zero());
                }
                "__builtin_frame_address" | "__builtin_dwarf_cfa"
                    => return Ok(Constant::zero()),
                // These identity/no-op address adjusters return their argument.
                "__builtin_extract_return_addr" | "__builtin_frob_return_addr" => {
                    if let Some(e) = args.first() { return self.lower_expr(e); }
                    return Ok(Constant::zero());
                }
                // Floating-point classification / comparison builtins.
                "__builtin_isnan" | "__builtin_isinf" | "__builtin_isinf_sign"
                | "__builtin_isfinite" | "__builtin_isnormal" => {
                    if let Some(arg) = args.first() {
                        return self.lower_fp_classify(name, arg);
                    }
                }
                "__builtin_isgreater" | "__builtin_isgreaterequal" | "__builtin_isless"
                | "__builtin_islessequal" | "__builtin_islessgreater" | "__builtin_isunordered" => {
                    if let [a, b, ..] = args {
                        return self.lower_fp_compare(name, a, b);
                    }
                }
                // __builtin_fpclassify(NAN, INF, NORMAL, SUBNORMAL, ZERO, x):
                // pick the category constant matching x. Subnormals are treated
                // as normal (sic doesn't distinguish the boundary).
                "__builtin_fpclassify" => {
                    if let [nan_v, inf_v, normal_v, _subnormal_v, zero_v, x] = args {
                        let is_nan = self.lower_fp_classify("__builtin_isnan", x)?;
                        let is_inf = self.lower_fp_classify("__builtin_isinf", x)?;
                        let xv = self.lower_expr(x)?;
                        let fty = match self.val_type(&xv) { t if t.is_float() => t, _ => Type::Float64 };
                        let xv = self.coerce(xv, &fty)?;
                        let is_zero = self.alloc_val();
                        self.push_instr(Instr::Cmp { dest: is_zero, op: CmpOp::FOEq, lhs: xv, rhs: Val::Const(Constant::Float(0.0)), ty: fty });
                        // result = isnan ? NAN : isinf ? INF : iszero ? ZERO : NORMAL
                        let nan_v = self.lower_expr(nan_v)?;
                        let inf_v = self.lower_expr(inf_v)?;
                        let normal_v = self.lower_expr(normal_v)?;
                        let zero_v = self.lower_expr(zero_v)?;
                        let ity = Type::i32();
                        let (nan_v, inf_v, normal_v, zero_v) = (
                            self.coerce(nan_v, &ity)?, self.coerce(inf_v, &ity)?,
                            self.coerce(normal_v, &ity)?, self.coerce(zero_v, &ity)?);
                        let is_nan = self.coerce(is_nan, &Type::Bool)?;
                        let is_inf = self.coerce(is_inf, &Type::Bool)?;
                        let sel_zn = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel_zn, cond: Val::Local(is_zero), on_true: zero_v, on_false: normal_v, ty: ity.clone() });
                        let sel_inf = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel_inf, cond: is_inf, on_true: inf_v, on_false: Val::Local(sel_zn), ty: ity.clone() });
                        let sel = self.alloc_val();
                        self.push_instr(Instr::Select { dest: sel, cond: is_nan, on_true: nan_v, on_false: Val::Local(sel_inf), ty: ity });
                        return Ok(Val::Local(sel));
                    }
                }
                // Infinity / huge-value constants.
                "__builtin_inf" | "__builtin_inff" | "__builtin_infl"
                | "__builtin_huge_val" | "__builtin_huge_valf" | "__builtin_huge_vall" =>
                    return Ok(Val::Const(Constant::Float(f64::INFINITY))),
                "__builtin_nan" | "__builtin_nanf" | "__builtin_nanl" =>
                    return Ok(Val::Const(Constant::Float(f64::NAN))),
                // signbit(x): nonzero iff the sign bit is set. Type-pun the float
                // through a stack slot and test the top bit (correct for -0.0).
                "__builtin_signbit" | "__builtin_signbitf" | "__builtin_signbitl" => {
                    if let Some(arg) = args.first() {
                        let v = self.lower_expr(arg)?;
                        let fty = self.val_type(&v);
                        let (fty, ity, shift) = match fty {
                            Type::Float32 => (Type::Float32, Type::Int { bits: 32, signed: false }, 31),
                            _ => (Type::Float64, Type::Int { bits: 64, signed: false }, 63),
                        };
                        let v = self.coerce(v, &fty)?;
                        let slot = self.alloc_val();
                        self.push_instr(Instr::Alloca { dest: slot, ty: ity.clone(), align: None });
                        self.push_instr(Instr::Store { val: v, ptr: Val::Local(slot) });
                        let iv = self.alloc_val();
                        self.push_instr(Instr::Load { dest: iv, ptr: Val::Local(slot), ty: ity.clone() });
                        let sh = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: sh, op: BinOp::LShr, lhs: Val::Local(iv), rhs: Constant::int(shift), ty: ity.clone() });
                        let masked = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: masked, op: BinOp::And, lhs: Val::Local(sh), rhs: Constant::int(1), ty: ity });
                        return self.coerce(Val::Local(masked), &Type::i32());
                    }
                }
                // Bit-count builtins: clz/ctz/popcount/ffs (32- and 64-bit).
                n if builtin_bit_op(n).is_some() => {
                    let (kind, bits) = builtin_bit_op(n).unwrap();
                    if let Some(arg) = args.first() {
                        return self.lower_bit_count(arg, bits, kind);
                    }
                }
                // Static assertions: accepted, not evaluated (compile-time only).
                "_Static_assert" | "static_assert" => return Ok(Constant::zero()),
                // Type-compat query: conservatively false (only affects _Generic-
                // style dispatch we don't otherwise need).
                "__builtin_types_compatible_p" => return Ok(Constant::int(0)),
                _ => {}
            }
        }

        // Evaluate arguments. Expose each parameter's type as the expected type so a
        // generic-enum constructor argument (`f(Option::Some(5))`) infers its
        // monomorph (sic.md §"Match").
        let param_types: Vec<Type> = self.callee_param_types(func_expr);
        // sic va_array / va_dict (sic.md std, §"Named parameters"): a trailing
        // `va_array` collects the positional trailing arguments (boxed into `any`);
        // a trailing `va_dict` collects the named (`name = value`) ones. The fixed
        // parameters are everything before the first such collector.
        let va_array_idx = if self.is_sic() { param_types.iter().position(super::types::is_va_array) } else { None };
        let va_dict_idx = if self.is_sic() { param_types.iter().position(super::types::is_va_dict) } else { None };
        let va_fixed = match (va_array_idx, va_dict_idx) {
            (Some(a), Some(d)) => Some(a.min(d)),
            (Some(a), None) => Some(a),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        // sic strict enum typing (sic.md §"Enums"): the callee's payload-less-enum
        // parameters reject a plain `int` or a different enum argument without a cast.
        let callee_name: Option<String> = match &func_expr.kind {
            ExprKind::Ident(n) => Some(n.clone()),
            _ => None,
        };
        let mut arg_vals = Vec::new();
        for (i, a) in args.iter().enumerate() {
            if let Some(fixed) = va_fixed {
                if i >= fixed { break; } // trailing args handled below
            }
            if self.is_sic() {
                if let Some(fname) = &callee_name {
                    if let Some(dest) = self.lowerer.c_enum_param.get(&(fname.clone(), i)).cloned() {
                        self.check_enum_dest(&dest, a, "passed as")?;
                    }
                }
                // Reject a pointer/value aggregate mismatch on an argument, e.g.
                // passing a `File` value where the parameter is `File*` (sic.md
                // §"Memory safety").
                if let Some(pt) = param_types.get(i) {
                    self.check_ptr_value_mismatch(pt, a)?;
                }
            }
            let prev = self.expected_ty.take();
            if let Some(pt) = param_types.get(i) { self.expected_ty = Some(pt.clone()); }
            let mut v = self.lower_arg(a)?;
            self.expected_ty = prev;
            // sic (sic.md §"Strings"): a `string` reaching a C variadic (`printf("%s",
            // s)`) decays to its `char*` — printf reads a pointer, not a descriptor.
            // sic's own `va_array` (fixed params + boxing) is handled below, not here.
            let is_c_vararg = self.is_sic() && va_fixed.is_none() && i >= param_types.len();
            if is_c_vararg
                && matches!(self.infer_expr_type(a), Ok(t) if super::types::is_sic_string(&t))
            {
                v = self.string_to_cptr_val(v)?;
            }
            arg_vals.push(v);
        }
        if let Some(fixed) = va_fixed {
            let trailing = &args[fixed.min(args.len())..];
            // Classify trailing args: a named one feeds the va_dict; a plain one that
            // is itself a va_array / va_dict is *forwarded* to that slot (like
            // `f(*args, **kw)`); anything else is a plain positional → va_array.
            let mut fwd_va_array: Option<Expr> = None;
            let mut fwd_va_dict: Option<Expr> = None;
            let mut plain: Vec<Expr> = Vec::new();
            let mut named: Vec<Expr> = Vec::new();
            for a in trailing {
                if matches!(a.kind, ExprKind::NamedArg { .. }) { named.push(a.clone()); continue; }
                let t = self.infer_expr_type(a).ok();
                if va_array_idx.is_some() && fwd_va_array.is_none()
                    && matches!(&t, Some(t) if super::types::is_va_array(t)) {
                    fwd_va_array = Some(a.clone());
                } else if va_dict_idx.is_some() && fwd_va_dict.is_none()
                    && matches!(&t, Some(t) if super::types::is_va_dict(t)) {
                    fwd_va_dict = Some(a.clone());
                } else {
                    plain.push(a.clone());
                }
            }
            // Emit the collectors in signature order.
            let mut packed: Vec<(usize, Val)> = Vec::new();
            if let Some(ai) = va_array_idx {
                let va = match fwd_va_array {
                    Some(e) => self.lower_aggregate_ptr(&e)?,
                    None => self.pack_va_array(&plain, sp)?,
                };
                packed.push((ai, va));
            }
            if let Some(di) = va_dict_idx {
                let vd = match fwd_va_dict {
                    // A `va_dict` is a handle (pointer); forward its value, not its
                    // address (unlike the struct-valued `va_array`).
                    Some(e) => self.lower_expr(&e)?,
                    None => self.pack_va_dict(&named, sp)?,
                };
                packed.push((di, vd));
            }
            packed.sort_by_key(|(i, _)| *i);
            for (_, v) in packed { arg_vals.push(v); }
        }

        // sic namespaced module call `x.f(...)`: resolve `x.f` to the imported
        // module's mangled extern; feeds the shared direct-call emission below.
        let module_fref: Option<FuncRef> = match &func_expr.kind {
            ExprKind::Field { base, name } => match &base.kind {
                ExprKind::Ident(module) if self.lowerer.imported_modules.contains_key(module) => {
                    Some(self.resolve_module_call(module, name, sp)?)
                }
                _ => None,
            },
            _ => None,
        };

        // Resolve function reference
        let fref = if let Some(fr) = module_fref { fr } else {
        match &func_expr.kind {
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Func(fr)) => fr,
                    Some(LookupResult::Local(..)) | Some(LookupResult::Global(..)) => {
                        // local/global function pointer variable: fall through to indirect call
                        let fptr = self.lower_expr(func_expr)?;
                        let fptr_ty = self.val_type(&fptr);
                        let func_ty = match &fptr_ty {
                            Type::Pointer(inner) => match inner.as_ref() {
                                Type::Function(ft) => *ft.clone(),
                                _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                            },
                            // A function-typed parameter does not decay to a
                            // pointer type in sic's IR; accept it directly.
                            Type::Function(ft) => *ft.clone(),
                            _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                        };
                        let ret_ty = func_ty.ret.clone();
                        if super::ret_is_sret(&ret_ty, self.ptr_size()) {
                            return self.lower_indirect_sret(fptr, func_ty, arg_vals);
                        }
                        let is_void = ret_ty == Type::Void;
                        let dest = if !is_void { Some(self.alloc_val()) } else { None };
                        self.push_instr(Instr::CallIndirect {
                            dest,
                            fptr,
                            args: arg_vals,
                            ret_ty: ret_ty.clone(),
                            func_ty: Box::new(func_ty),
                        });
                        return Ok(if let Some(d) = dest { Val::Local(d) } else { Constant::zero() });
                    }
                    _ => {
                        // sic selective/renamed import (`import x.f;` / `... as g;`):
                        // a bare call `f()`/`g()` resolves to the module's extern.
                        if self.lowerer.imported_syms.contains_key(name) {
                            self.resolve_module_call_bare(name, sp)?
                        } else
                        // Many `__builtin_<fn>` calls (memcpy, memmove, strlen, …)
                        // are just the libc function; retry resolution with the
                        // prefix stripped.
                        if let Some(libc) = name.strip_prefix("__builtin_") {
                            if let Some(LookupResult::Func(fr)) = self.lookup(libc) {
                                fr
                            } else {
                                return Err(CompileError::at(
                                    format!("unknown function '{}'", name),
                                    sp.file.clone(), sp.line, sp.col,
                                ));
                            }
                        } else {
                            return Err(CompileError::at(
                                format!("unknown function '{}'", name),
                                sp.file.clone(), sp.line, sp.col,
                            ));
                        }
                    }
                }
            }
            _ => {
                // Indirect call through function pointer expression
                let fptr = self.lower_expr(func_expr)?;
                let fptr_ty = self.val_type(&fptr);
                let func_ty = match &fptr_ty {
                    Type::Pointer(inner) => match inner.as_ref() {
                        Type::Function(ft) => *ft.clone(),
                        _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                    },
                    Type::Function(ft) => *ft.clone(),
                    _ => sic_ir::FunctionType { ret: Type::i32(), params: vec![], variadic: true },
                };
                let ret_ty = func_ty.ret.clone();
                if super::ret_is_sret(&ret_ty, self.ptr_size()) {
                    return self.lower_indirect_sret(fptr, func_ty, arg_vals);
                }
                // Coerce fixed args to their param types and apply the default
                // argument promotions to any `...` args (same as the direct path).
                for (i, pval) in arg_vals.iter_mut().enumerate() {
                    if let Some(pty) = func_ty.params.get(i) {
                        if matches!(pty, Type::Struct(_) | Type::Union(_)) { continue; }
                        let c = self.coerce(pval.clone(), pty)?;
                        *pval = c;
                    } else if func_ty.variadic {
                        let p = self.promote_vararg(pval.clone())?;
                        *pval = p;
                    }
                }
                let is_void = ret_ty == Type::Void;
                let dest = if !is_void { Some(self.alloc_val()) } else { None };
                self.push_instr(Instr::CallIndirect {
                    dest,
                    fptr,
                    args: arg_vals,
                    ret_ty: ret_ty.clone(),
                    func_ty: Box::new(func_ty),
                });
                return Ok(if let Some(d) = dest { Val::Local(d) } else { Constant::zero() });
            }
        }
        };

        let ret_ty = self.lowerer.module.func_sig(fref).ret.clone();
        let is_void = ret_ty == Type::Void;

        // Aggregate return (sret ABI): allocate the result slot, pass its pointer
        // as the hidden first argument, and yield that pointer as the call value.
        if super::ret_is_sret(&ret_ty, self.ptr_size()) {
            let slot = self.alloc_val();
            self.push_instr(Instr::Alloca { dest: slot, ty: ret_ty.clone(), align: None });
            let slot = Val::Local(slot);
            // Coerce user args against the user-facing parameter types (`param_types`
            // already has any hidden sret pointer stripped, so index directly by `i`
            // — the raw sig's sret offset differs between direct and module calls).
            let param_tys = param_types.clone();
            for (i, pval) in arg_vals.iter_mut().enumerate() {
                if let Some(pty) = param_tys.get(i) {
                    if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                        if self.build_enum_arg(pval, pty, sp)? { continue; }
                        if self.is_sic() && super::types::is_sic_string(pty) {
                            let vt = self.val_type(pval);
                            let already = matches!(&vt, Type::Pointer(inner) if super::types::is_sic_string(inner));
                            if !already {
                                *pval = self.cstr_to_string(pval.clone())?;
                            }
                        }
                        continue;
                    }
                    let coerced = self.coerce(pval.clone(), pty)?;
                    *pval = coerced;
                }
            }
            let mut args = Vec::with_capacity(arg_vals.len() + 1);
            args.push(slot.clone());
            args.extend(arg_vals);
            self.push_instr(Instr::Call { dest: None, func: fref, args, ret_ty: ret_ty.clone() });
            // A returned `string` temp holds a reference — release it at scope
            // exit (a binding retains it; an unused result is freed here).
            if self.is_sic() && super::types::is_sic_string(&ret_ty) {
                self.register_scope_exit(super::func::Cleanup::StringRelease { addr: slot.clone() });
            }
            return Ok(slot);
        }

        // Coerce arguments to expected param types
        let param_tys: Vec<Type> = self.lowerer.module.func_sig(fref).params.clone();
        let is_variadic = self.lowerer.module.func_sig(fref).variadic;
        for (i, pval) in arg_vals.iter_mut().enumerate() {
            if let Some(pty) = param_tys.get(i) {
                // A packed `va_array` / `va_dict` collector is already a finished
                // pointer value and has no matching `args[i]` — never coerce it.
                if super::types::is_va_array(pty) || super::types::is_va_dict(pty) {
                    continue;
                }
                // Struct/union args are already lowered to a pointer to the value
                // (by-value ABI); leave them as-is.
                if matches!(pty, Type::Struct(_) | Type::Union(_)) {
                    // sic: a bare (payload-less) variant discriminant passed to an
                    // enum parameter is materialized into the enum value here.
                    if self.build_enum_arg(pval, pty, sp)? { continue; }
                    // A `char*`/string-literal passed to a `string` parameter must
                    // be wrapped in a (non-owning) descriptor; a real string arg is
                    // already a descriptor pointer.
                    if self.is_sic() && super::types::is_sic_string(pty) {
                        let vt = self.val_type(pval);
                        let already = matches!(&vt, Type::Pointer(inner) if super::types::is_sic_string(inner));
                        if !already {
                            *pval = self.cstr_to_string(pval.clone())?;
                        }
                    }
                    continue;
                }
                // sic bigint/fixed parameter: build the argument as the right
                // bignum value (a decimal/int literal lowered as a scalar must be
                // reconstructed; a matching-scale value is passed as-is). Args are
                // borrows (the callee doesn't free them).
                if self.build_bignum_arg(pval, pty, &args[i])? { continue; }
                let coerced = self.coerce(pval.clone(), pty)?;
                *pval = coerced;
            } else if is_variadic {
                // Arguments in the `...` part undergo the default argument
                // promotions (char/short→int, float→double). Without this a
                // small integer passed on the stack leaves its slot's high bits
                // uninitialized — libc printf's `%02x` of a `uint8_t` MAC byte
                // then read garbage (QEMU's default NIC MAC came out malformed).
                let p = self.promote_vararg(pval.clone())?;
                *pval = p;
            }
        }

        // x86-64 SysV: a variadic extern (libc) call carrying a float argument
        // needs `AL` set to the vector-arg count, which Cranelift never emits. Note
        // the callee so the backend routes it through an `AL`-setting trampoline.
        if is_variadic && fref.is_extern() {
            let has_float = arg_vals.iter().any(|v| self.val_type(v).is_float());
            if has_float {
                let name = self.lowerer.module.externs[fref.index()].name.clone();
                self.lowerer.float_vararg_externs.insert(name);
            }
        }

        if is_void {
            self.push_instr(Instr::Call { dest: None, func: fref, args: arg_vals, ret_ty });
            Ok(Constant::zero())
        } else {
            let returns_tuple = self.is_sic() && super::types::is_tuple(&ret_ty);
            let returns_bignum = self.is_sic()
                && (super::types::is_bigint(&ret_ty) || super::types::is_fixed(&ret_ty));
            let dest = self.alloc_val();
            self.push_instr(Instr::Call { dest: Some(dest), func: fref, args: arg_vals, ret_ty });
            // sic tuple-returning call: the result carries a reference (retained by
            // the callee before return); release it at scope exit.
            if returns_tuple {
                self.register_tuple_release(Val::Local(dest))?;
            }
            // sic bigint/fixed-returning call: the callee returned an owned clone;
            // free it at statement end (value semantics, like any bigint temp).
            if returns_bignum {
                self.bigint_temps.push(Val::Local(dest));
            }
            Ok(Val::Local(dest))
        }
    }

    /// sic named parameters (sic.md §"Named parameters"): map a call's arguments
    /// (which include one or more `name = value`) onto the callee's parameters,
    /// returning a purely positional argument list. Errors on an unknown/duplicate
    /// name, a missing mandatory argument, a positional argument after a named one,
    /// or a callee whose parameters aren't known by name.
    fn resolve_named_args(&self, func_expr: &Expr, args: &[Expr], sp: &crate::lexer::Span) -> Result<Vec<Expr>> {
        let (param_names, variadic) = self.callee_param_info(func_expr).ok_or_else(|| {
            CompileError::at(
                "named arguments are only supported when the called function is known by name".to_string(),
                sp.file.clone(), sp.line, sp.col)
        })?;
        super::reorder_named_args(args, &param_names, variadic, sp)
    }

    /// The callee's IR parameter types (user-facing: any hidden sret pointer
    /// stripped). Empty when the callee isn't a statically-known function.
    fn callee_param_types(&self, func_expr: &Expr) -> Vec<Type> {
        match &func_expr.kind {
            ExprKind::Ident(name) => match self.lookup(name) {
                Some(LookupResult::Func(fr)) => {
                    let sig = self.lowerer.module.func_sig(fr);
                    let mut ps = sig.params.clone();
                    if super::ret_is_sret(&sig.ret, self.ptr_size()) && !ps.is_empty() {
                        ps.remove(0);
                    }
                    ps
                }
                _ => Vec::new(),
            },
            // Namespaced module call `mod.fn(...)` / `mod::fn(...)`: parameter types
            // come from the imported module's registered export signature.
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name } => match &base.kind {
                ExprKind::Ident(m) => self.lowerer.imported_modules.get(m)
                    .and_then(|ex| ex.get(name))
                    .and_then(|(_, t)| match t { Type::Function(ft) => Some(ft.params.clone()), _ => None })
                    .unwrap_or_default(),
                _ => Vec::new(),
            },
            ExprKind::EnumVariant { enum_name, variant } => self.lowerer.imported_modules.get(enum_name)
                .and_then(|ex| ex.get(variant))
                .and_then(|(_, t)| match t { Type::Function(ft) => Some(ft.params.clone()), _ => None })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Whether the callee declares a `va_dict` parameter (the named-varargs sink).
    fn callee_has_va_dict(&self, func_expr: &Expr) -> bool {
        self.callee_param_types(func_expr).iter().any(super::types::is_va_dict)
    }

    /// The callee's fixed parameter names and variadic flag, for named-argument
    /// binding. `None` when the callee isn't a statically-known function. An unknown
    /// parameter name (imported prototype) is returned as an empty string.
    fn callee_param_info(&self, func_expr: &Expr) -> Option<(Vec<String>, bool)> {
        match &func_expr.kind {
            ExprKind::Ident(name) | ExprKind::GenericRef { name, .. } => {
                if let Some(crate::ast::Decl::Func { params, variadic, .. }) =
                    self.lowerer.generic_fn_defs.get(name)
                {
                    return Some((params.iter().map(|p| p.name.clone().unwrap_or_default()).collect(), *variadic));
                }
                self.lowerer.fn_param_names.get(name).cloned()
            }
            // Module member call `mod.fn(...)` or `mod::fn(...)`: names aren't carried
            // in the manifest, but the exported signature gives the fixed arity +
            // variadic flag — enough for the variadic name-drop case
            // (`std.Print("{}", x=…)` / `std::Print(...)`).
            ExprKind::Field { base, name } | ExprKind::Arrow { base, name } => {
                if let ExprKind::Ident(m) = &base.kind {
                    return self.module_export_param_info(m, name);
                }
                None
            }
            ExprKind::EnumVariant { enum_name, variant } => {
                self.module_export_param_info(enum_name, variant)
            }
            _ => None,
        }
    }

    /// Fixed arity + variadic flag of an imported module export `module::name`, from
    /// its exported function signature (parameter names aren't carried in a manifest,
    /// so they come back empty — enough for the variadic name-drop case).
    fn module_export_param_info(&self, module: &str, name: &str) -> Option<(Vec<String>, bool)> {
        if let Some((_, Type::Function(ft))) =
            self.lowerer.imported_modules.get(module).and_then(|e| e.get(name))
        {
            // A sic `va_array` trailing parameter (`std::Print(string, va_array)`) is
            // the Python-style varargs sink: treat it as variadic and exclude it from
            // the fixed parameters, so extra (named or positional) args drop to the
            // tail that the call site packs into the va_array.
            if let Some(last) = ft.params.last() {
                if super::types::is_va_array(last) {
                    return Some((vec![String::new(); ft.params.len() - 1], true));
                }
            }
            return Some((vec![String::new(); ft.params.len()], ft.variadic));
        }
        None
    }

    /// sic generic functions (sic.md §"Generics"): infer the type arguments of a
    /// `name<T,…>` call from its argument types, monomorphize the template, and
    /// re-dispatch as an ordinary call to the concrete instance. Each instantiation
    /// is fully, strongly type-checked by the normal lowerer.
    fn lower_generic_call(&mut self, name: &str, args: &[Expr], sp: &crate::lexer::Span) -> Result<Val> {
        // The template's type parameters and its declared parameter type patterns.
        let (type_params, param_tys): (Vec<String>, Vec<crate::ast::AstType>) = {
            match self.lowerer.generic_fn_defs.get(name) {
                Some(crate::ast::Decl::Func { type_params, params, .. }) =>
                    (type_params.clone(), params.iter().map(|p| p.ty.ty.clone()).collect()),
                _ => return Err(CompileError::at(
                    format!("`{}` is not a generic function", name),
                    sp.file.clone(), sp.line, sp.col)),
            }
        };
        let params_set: std::collections::HashSet<String> = type_params.iter().cloned().collect();

        // Infer each type parameter from the corresponding argument's type.
        let mut subst: std::collections::HashMap<String, Type> = std::collections::HashMap::new();
        for (i, pat) in param_tys.iter().enumerate() {
            if let Some(arg) = args.get(i) {
                let at = self.infer_expr_type(arg)?;
                super::unify_type(pat, &at, &params_set, &mut subst)
                    .map_err(|e| CompileError::at(e.to_string(), sp.file.clone(), sp.line, sp.col))?;
            }
        }

        // Every type parameter must be solved (no explicit `name<…>()` form yet).
        let mut ordered = Vec::with_capacity(type_params.len());
        for tp in &type_params {
            match subst.get(tp) {
                Some(t) => ordered.push(t.clone()),
                None => return Err(CompileError::at(format!(
                    "cannot infer type parameter `{}` of generic function `{}` from the arguments",
                    tp, name), sp.file.clone(), sp.line, sp.col)),
            }
        }

        let mangled = self.lowerer.instantiate_generic_fn(name, &ordered)
            .map_err(|e| CompileError::at(e.to_string(), sp.file.clone(), sp.line, sp.col))?;

        // Dispatch as an ordinary direct call to the concrete monomorph.
        let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
        self.lower_call(&callee, args, sp)
    }

    /// sic generic functions (sic.md §"Generics"): a call with explicit type
    /// arguments, `add<int>(1, 2)`. The written types supply the monomorphization
    /// directly (used when a type parameter can't be inferred, e.g. it appears only
    /// in the return type). Arity must match the template's type-parameter list.
    fn lower_generic_call_explicit(
        &mut self, name: &str, type_args: &[crate::ast::QualType], args: &[Expr], sp: &crate::lexer::Span,
    ) -> Result<Val> {
        let n_params = match self.lowerer.generic_fn_defs.get(name) {
            Some(crate::ast::Decl::Func { type_params, .. }) => type_params.len(),
            _ => return Err(CompileError::at(
                format!("`{}` is not a generic function", name), sp.file.clone(), sp.line, sp.col)),
        };
        if type_args.len() != n_params {
            return Err(CompileError::at(format!(
                "generic function `{}` expects {} type argument(s), got {}",
                name, n_params, type_args.len()), sp.file.clone(), sp.line, sp.col));
        }
        let mut ordered = Vec::with_capacity(type_args.len());
        for ta in type_args {
            ordered.push(super::lower_type(ta, &self.lowerer.struct_types, self.ptr_size())?);
        }
        let mangled = self.lowerer.instantiate_generic_fn(name, &ordered)
            .map_err(|e| CompileError::at(e.to_string(), sp.file.clone(), sp.line, sp.col))?;
        let callee = Expr { kind: ExprKind::Ident(mangled), span: sp.clone() };
        self.lower_call(&callee, args, sp)
    }

    /// Lower an indirect call to an aggregate-returning function (sret ABI):
    /// allocate the result slot, pass its pointer as the hidden first argument,
    /// and yield that pointer. `func_ty.params[0]` is the sret pointer parameter.
    fn lower_indirect_sret(&mut self, fptr: Val, func_ty: sic_ir::FunctionType, arg_vals: Vec<Val>) -> Result<Val> {
        let ret_ty = func_ty.ret.clone();
        let slot = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: slot, ty: ret_ty.clone(), align: None });
        let slot = Val::Local(slot);
        // Coerce user args against params[1..] (params[0] is the sret pointer).
        let mut coerced = Vec::with_capacity(arg_vals.len() + 1);
        coerced.push(slot.clone());
        for (i, a) in arg_vals.into_iter().enumerate() {
            match func_ty.params.get(i + 1) {
                Some(pty) if !matches!(pty, Type::Struct(_) | Type::Union(_)) => {
                    coerced.push(self.coerce(a, pty)?);
                }
                _ => coerced.push(a),
            }
        }
        self.push_instr(Instr::CallIndirect {
            dest: None,
            fptr,
            args: coerced,
            ret_ty,
            func_ty: Box::new(func_ty),
        });
        Ok(slot)
    }

    /// Lower `__builtin_{add,mul}_overflow(a, b, *res)`: compute `a op b` in the
    /// result type, store the wrapped value through `*res`, and return an i1
    /// indicating whether the true result overflowed that type.
    fn lower_overflow_builtin(
        &mut self,
        op: BinOp,
        a_expr: &Expr,
        b_expr: &Expr,
        res_expr: &Expr,
    ) -> Result<Val> {
        let a = self.lower_expr(a_expr)?;
        let b = self.lower_expr(b_expr)?;
        let res_ptr = self.lower_expr(res_expr)?;

        // The result type is whatever `*res` points at.
        let ty = match self.val_type(&res_ptr) {
            Type::Pointer(inner) => *inner,
            _ => self.val_type(&a),
        };

        // Coerce operands to the result type so the arithmetic is well-typed.
        let a = self.coerce(a, &ty)?;
        let b = self.coerce(b, &ty)?;

        // result = a op b (wrapping), stored through *res.
        let result = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: result, op, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        let result = Val::Local(result);
        self.push_instr(Instr::Store { val: result.clone(), ptr: res_ptr });

        Ok(self.emit_overflow_flag(op, &a, &b, &result, &ty))
    }

    /// Compute the overflow flag (a `Bool` value) for a wrapping integer
    /// `result = a op b` (op ∈ {Add, Sub, Mul}). Shared by `__builtin_*_overflow`
    /// and sic's `unsafe`/`overflow` trapping arithmetic (sic.md §"Integer
    /// overflow").
    pub(super) fn emit_overflow_flag(&mut self, op: BinOp, a: &Val, b: &Val, result: &Val, ty: &Type) -> Val {
        let signed = matches!(ty, Type::Int { signed: true, .. });
        let zero = Constant::zero();
        let ovf = self.alloc_val();
        match op {
            BinOp::Add if signed => {
                // Overflow iff a and b share a sign that differs from the sum:
                // ((a ^ sum) & (b ^ sum)) < 0.
                let t1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t1, op: BinOp::Xor, lhs: a.clone(), rhs: result.clone(), ty: ty.clone() });
                let t2 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t2, op: BinOp::Xor, lhs: b.clone(), rhs: result.clone(), ty: ty.clone() });
                let t3 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t3, op: BinOp::And, lhs: Val::Local(t1), rhs: Val::Local(t2), ty: ty.clone() });
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::ISLt, lhs: Val::Local(t3), rhs: zero, ty: ty.clone() });
            }
            BinOp::Add => {
                // Unsigned add overflows iff the sum wrapped below an operand.
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::IULt, lhs: result.clone(), rhs: a.clone(), ty: ty.clone() });
            }
            BinOp::Sub if signed => {
                // Signed sub overflows iff the operands differ in sign and the
                // result's sign differs from the minuend: ((a^b) & (a^diff)) < 0.
                let t1 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t1, op: BinOp::Xor, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
                let t2 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t2, op: BinOp::Xor, lhs: a.clone(), rhs: result.clone(), ty: ty.clone() });
                let t3 = self.alloc_val();
                self.push_instr(Instr::BinOp { dest: t3, op: BinOp::And, lhs: Val::Local(t1), rhs: Val::Local(t2), ty: ty.clone() });
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::ISLt, lhs: Val::Local(t3), rhs: zero, ty: ty.clone() });
            }
            BinOp::Sub => {
                // Unsigned sub overflows (borrows) iff a < b.
                self.push_instr(Instr::Cmp { dest: ovf, op: CmpOp::IULt, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
            }
            _ => {
                // Multiply: overflow iff a != 0 and result / a != b.
                let a_nz = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: a_nz, op: CmpOp::INe, lhs: a.clone(), rhs: zero, ty: ty.clone() });
                let div = if signed { BinOp::SDiv } else { BinOp::UDiv };
                // 128-bit divide needs a libcall (see emit_div_rem_libcall).
                let quot_val = if let Some(v) = self.emit_div_rem_libcall(div, result.clone(), a.clone(), ty) {
                    v
                } else {
                    let quot = self.alloc_val();
                    self.push_instr(Instr::BinOp { dest: quot, op: div, lhs: result.clone(), rhs: a.clone(), ty: ty.clone() });
                    Val::Local(quot)
                };
                let mism = self.alloc_val();
                self.push_instr(Instr::Cmp { dest: mism, op: CmpOp::INe, lhs: quot_val, rhs: b.clone(), ty: ty.clone() });
                // ovf = a_nz ? mism : false
                self.push_instr(Instr::Select {
                    dest: ovf,
                    cond: Val::Local(a_nz),
                    on_true: Val::Local(mism),
                    on_false: Val::Const(Constant::Bool(false)),
                    ty: Type::Bool,
                });
            }
        }
        Val::Local(ovf)
    }

    /// Lower an exception-guard block `overflow`/`divide_by_zero`/`exception`
    /// `{ body }` (sic.md §"Integer overflow", §"Errors and exceptions"). The body
    /// runs with the matching exception caught; a caught exception jumps to a fail
    /// block (skipping the rest of the body, committing nothing) and the expression
    /// yields `1`, otherwise `0`.
    fn lower_guard(&mut self, kind: crate::ast::GuardKind, body: &[crate::ast::Stmt]) -> Result<Val> {
        // Result slot defaults to 0 (success).
        let res = self.alloc_val();
        self.push_instr(Instr::Alloca { dest: res, ty: Type::i32(), align: None });
        self.push_instr(Instr::Store { val: Constant::zero(), ptr: Val::Local(res) });

        let fail_bb = self.new_block_after_current();
        let end_bb = self.new_block_after_current();

        self.guard_stack.push(super::func::GuardFrame { kind, fail_bb });
        self.enter_scope();
        for s in body {
            if self.is_terminated() { break; }
            self.lower_stmt(s)?;
        }
        self.exit_scope();
        self.guard_stack.pop();

        // Success path: leave result 0, jump to the end.
        if !self.is_terminated() {
            self.set_terminator(Terminator::Jump(end_bb));
        }
        // Fail path: a caught exception lands here — set result to 1.
        self.switch_to_block(fail_bb);
        self.push_instr(Instr::Store { val: Constant::int(1), ptr: Val::Local(res) });
        self.set_terminator(Terminator::Jump(end_bb));

        self.switch_to_block(end_bb);
        let dest = self.alloc_val();
        self.push_instr(Instr::Load { dest, ptr: Val::Local(res), ty: Type::i32() });
        Ok(Val::Local(dest))
    }

    /// Branch to the exception target when `cond` is true (a caught exception), or
    /// (if there is no active guard) call `__sic_trap`. The offending operation's
    /// commit lives on the fall-through path, so a caught/trapped op is not
    /// committed. Continues on the no-exception path.
    fn branch_on_exception(&mut self, cond: Val, target: Option<super::BlockId>) {
        match target {
            Some(fail) => {
                let ok_bb = self.new_block_after_current();
                self.set_terminator(Terminator::CondJump { cond, then_bb: fail, else_bb: ok_bb });
                self.switch_to_block(ok_bb);
            }
            None => {
                let trap_bb = self.new_block_after_current();
                let ok_bb = self.new_block_after_current();
                self.set_terminator(Terminator::CondJump { cond, then_bb: trap_bb, else_bb: ok_bb });
                self.switch_to_block(trap_bb);
                let fref = self.lowerer.ensure_trap_fn();
                self.push_instr(Instr::Call { dest: None, func: fref, args: vec![], ret_ty: Type::Void });
                self.set_terminator(Terminator::Jump(ok_bb)); // abort never returns
                self.switch_to_block(ok_bb);
            }
        }
    }

    /// Lower `__builtin_{add,sub}c[l|ll](a, b, carryin, *carryout)`: wide
    /// add/subtract with carry. Returns the wrapped result and stores the
    /// outgoing carry (0/1) through `*carryout`.
    fn lower_carry_builtin(
        &mut self, is_sub: bool,
        a_expr: &Expr, b_expr: &Expr, cin_expr: &Expr, cout_expr: &Expr,
    ) -> Result<Val> {
        let a = self.lower_expr(a_expr)?;
        let b = self.lower_expr(b_expr)?;
        let cin = self.lower_expr(cin_expr)?;
        let cout_ptr = self.lower_expr(cout_expr)?;

        let ty = match self.val_type(&cout_ptr) {
            Type::Pointer(inner) => *inner,
            _ => self.val_type(&a),
        };
        let a = self.coerce(a, &ty)?;
        let b = self.coerce(b, &ty)?;
        let cin = self.coerce(cin, &ty)?;

        let op = if is_sub { BinOp::Sub } else { BinOp::Add };
        // First combine a and b, tracking carry/borrow, then fold in carryin.
        let s1 = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: s1, op, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        let s1 = Val::Local(s1);
        // carry1: add → s1 < a; sub (borrow) → a < b.
        let c1 = self.alloc_val();
        if is_sub {
            self.push_instr(Instr::Cmp { dest: c1, op: CmpOp::IULt, lhs: a.clone(), rhs: b.clone(), ty: ty.clone() });
        } else {
            self.push_instr(Instr::Cmp { dest: c1, op: CmpOp::IULt, lhs: s1.clone(), rhs: a.clone(), ty: ty.clone() });
        }
        let s2 = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: s2, op, lhs: s1.clone(), rhs: cin.clone(), ty: ty.clone() });
        let s2 = Val::Local(s2);
        // carry2: add → s2 < s1; sub (borrow) → s1 < cin.
        let c2 = self.alloc_val();
        if is_sub {
            self.push_instr(Instr::Cmp { dest: c2, op: CmpOp::IULt, lhs: s1.clone(), rhs: cin.clone(), ty: ty.clone() });
        } else {
            self.push_instr(Instr::Cmp { dest: c2, op: CmpOp::IULt, lhs: s2.clone(), rhs: s1.clone(), ty: ty.clone() });
        }
        // carryout = (c1 | c2), extended to the result type.
        let c1i = self.coerce(Val::Local(c1), &ty)?;
        let c2i = self.coerce(Val::Local(c2), &ty)?;
        let cout = self.alloc_val();
        self.push_instr(Instr::BinOp { dest: cout, op: BinOp::Or, lhs: c1i, rhs: c2i, ty: ty.clone() });
        self.push_instr(Instr::Store { val: Val::Local(cout), ptr: cout_ptr });

        Ok(s2)
    }

    // ─── LValue lowering ─────────────────────────────────────────────────────

    /// Extract a pointer's pointee type, resolving an opaque pointee aggregate
    /// to its full definition. Pointees are stored opaque (see `lower_ast_type`);
    /// dereferencing needs the real layout for loads/stores/copies.
    /// Apply the C default argument promotions to a value passed in the `...`
    /// part of a variadic call: integer types narrower than `int` widen to `int`
    /// (preserving value per the source's signedness), and `float` widens to
    /// `double`. Anything already `int`-width or wider is unchanged.
    fn promote_vararg(&mut self, v: Val) -> Result<Val> {
        match self.val_type(&v) {
            Type::Bool => self.coerce(v, &Type::i32()),
            Type::Int { bits, .. } if bits < 32 => self.coerce(v, &Type::i32()),
            Type::Float32 => self.coerce(v, &Type::Float64),
            _ => Ok(v),
        }
    }

    /// Materialize a `size_t`-typed constant (the result type of `sizeof`,
    /// `_Alignof`, `offsetof`). A bare integer constant defaults to i32 when its
    /// value fits, so `sizeof(long) * n` would compute at 32 bits; forcing the
    /// pointer-width unsigned type keeps such products 64-bit (QEMU's ROUND_UP
    /// masks a 64-bit pointer with `-(sizeof(...)*n)` — a 32-bit result truncated
    /// the TB code buffer address and faulted during code generation).
    fn size_t_val(&mut self, v: u64) -> Val {
        let dest = self.alloc_val();
        let ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
        self.push_instr(Instr::Cast { dest, op: CastOp::ZExt, val: Constant::uint(v), to_ty: ty });
        Val::Local(dest)
    }

    fn pointee_of(&self, ptr_ty: &Type) -> Type {
        match ptr_ty {
            Type::Pointer(t) => super::types::resolve_aggregate(t, &self.lowerer.struct_types),
            _ => Type::i32(),
        }
    }

    fn lower_lvalue(&mut self, expr: &Expr) -> Result<LValue> {
        match &expr.kind {
            // sic (sic.md §"Namespace"): `N::member` as an lvalue is the member's
            // mangled global.
            ExprKind::EnumVariant { enum_name, variant }
                if self.is_sic()
                    && self.lowerer.namespace_members.contains_key(&(enum_name.clone(), variant.clone())) =>
            {
                let mangled = self.lowerer.namespace_members[&(enum_name.clone(), variant.clone())].clone();
                self.lower_lvalue(&Expr { kind: ExprKind::Ident(mangled), span: expr.span.clone() })
            }
            ExprKind::Ident(name) => {
                let atomic = self.is_atomic_name(name);
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, vid)) => {
                        let ty = ty.clone();
                        Ok(LValue { atomic, ..LValue::plain(Val::Local(vid), ty) })
                    }
                    Some(LookupResult::Global(ty, gref)) => {
                        let ty = ty.clone();
                        Ok(LValue { atomic, ..LValue::plain(Val::Global(gref), ty) })
                    }
                    _ => Err(CompileError::at(
                        format!("'{}' is not an lvalue", name),
                        expr.span.file.clone(), expr.span.line, expr.span.col,
                    ))
                }
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let ptr = self.lower_expr(inner)?;
                let ptr_ty = self.val_type(&ptr);
                // `*x`: if `x` is an array it decays to a pointer to its element, so
                // the deref yields the element (`*arr` == `arr[0]`); if `x` is a
                // pointer-to-array it yields the whole array. The C type of `x`
                // disambiguates (both are `Pointer(Array)` in the IR).
                let inner_ty = match self.infer_expr_type(inner) {
                    Ok(Type::Array { elem, .. }) => {
                        super::types::resolve_aggregate(&elem, &self.lowerer.struct_types)
                    }
                    Ok(Type::Pointer(t)) => {
                        super::types::resolve_aggregate(&t, &self.lowerer.struct_types)
                    }
                    _ => self.pointee_of(&ptr_ty),
                };
                Ok(LValue::plain(ptr, inner_ty))
            }
            ExprKind::Index { base, index } => self.lower_lvalue_index(base, index),
            ExprKind::Field { base, name } => self.lower_lvalue_field(base, name),
            ExprKind::Arrow { base, name }  => self.lower_lvalue_arrow(base, name),
            ExprKind::CompoundLiteral { ty, .. } => {
                // A compound literal is an lvalue: materialize the temporary and
                // use its address (its rvalue lowering already yields that pointer).
                let ir_ty = self.lower_type(ty)?;
                let ptr = self.lower_expr(expr)?;
                Ok(LValue::plain(ptr, ir_ty))
            }
            _ => {
                // Not a simple lvalue.
                Err(CompileError::at(
                    "expression is not an lvalue",
                    expr.span.file.clone(), expr.span.line, expr.span.col,
                ))
            }
        }
    }

    fn lower_lvalue_index(&mut self, base: &Expr, index: &Expr) -> Result<LValue> {
        // sic tuple element access `t[const]` (sic.md §"Tuples").
        if self.is_sic() {
            if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_tuple(&t)) {
                return self.tuple_field_lvalue(base, index, &base.span);
            }
            // sic `va_array` element `va[i]` (sic.md std): a pointer to the i-th
            // boxed `any` (also the lvalue used by `lower_aggregate_ptr`).
            if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_va_array(&t)) {
                let elem = self.lower_va_array_index(base, index, &base.span)?;
                return Ok(LValue::plain(elem, super::types::any_type()));
            }
            // sic `u8char[]` element `cps[i]` (from `string.utf8`).
            if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_u8char_arr(&t)) {
                let elem = self.lower_u8char_arr_index(base, index, &base.span)?;
                return Ok(LValue::plain(elem, super::types::u8char_type()));
            }
            // sic `dict[key]` whose value is an aggregate (`string`, a struct, `any`):
            // the dict-get result is a pointer to the value, usable as a (read)
            // lvalue so `d[k].field` works. (A write `d[k] = v` is intercepted in
            // `lower_assign`, so this read-lvalue is never used for assignment.)
            if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_dict(&t)
                || matches!(&t, Type::Pointer(i) if super::types::is_dict(i)))
            {
                let (_k, v) = self.dict_kv_of(base);
                if matches!(v, Type::Struct(_) | Type::Union(_)) {
                    let ptr = self.lower_dict_get(base, index, &base.span)?;
                    return Ok(LValue::plain(ptr, v));
                }
            }
            // sic `list[i]` whose element is an aggregate — a read-lvalue for
            // `l[i].field` (sic.md §"List").
            if matches!(self.infer_expr_type(base), Ok(t) if super::types::is_list(&t)
                || matches!(&t, Type::Pointer(i) if super::types::is_list(i)))
            {
                let v = self.list_elem_of(base);
                if matches!(v, Type::Struct(_) | Type::Union(_)) {
                    let ptr = self.lower_list_get(base, index, &base.span)?;
                    return Ok(LValue::plain(ptr, v));
                }
            }
        }
        let base_val = self.lower_expr(base)?;
        let idx_val = self.lower_expr(index)?;
        let idx_i64 = self.coerce(idx_val, &Type::i64())?;

        let base_ty = self.val_type(&base_val);

        // sic fat-pointer bounds check: for `name[i]` where `name` is a
        // never-moved `new`/`@` pointer, verify `i*elem_size < header.size`.
        if self.is_sic() {
            if let ExprKind::Ident(name) = &base.kind {
                if self.fat_locals.contains(name) {
                    let elem = match &base_ty {
                        Type::Pointer(t) => super::types::resolve_aggregate(t, &self.lowerer.struct_types),
                        _ => Type::i32(),
                    };
                    let esz = elem.size_of(self.ptr_size()).max(1);
                    self.emit_bounds_check(base_val.clone(), idx_i64.clone(), esz)?;
                }
            }
        }

        // `Pointer(Array[T;N])` is ambiguous in the IR: it is both the address of
        // an array *variable* `T v[N]` (where `v[i]` is a `T`) and the value of a
        // pointer-to-array `T (*e)[N]` (where `e[i]` is the whole `T[N]`). The C
        // type of `base` disambiguates: an array-typed base indexes to its element,
        // a pointer-typed base dereferences one level.
        let logical = self.infer_expr_type(base).ok();
        let elem_ty = match &base_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { .. } if matches!(logical, Some(Type::Pointer(_))) => {
                    // pointer-to-array: one index yields the whole array element
                    super::types::resolve_aggregate(t, &self.lowerer.struct_types)
                }
                Type::Array { elem, .. } => *elem.clone(),
                other => super::types::resolve_aggregate(other, &self.lowerer.struct_types),
            },
            Type::Array { elem, .. } => *elem.clone(),
            _ => Type::i32(),
        };

        let elem_size = elem_ty.size_of(self.ptr_size());
        let dest = self.alloc_val();
        let result_ty = Type::Pointer(Box::new(elem_ty.clone()));
        self.push_instr(Instr::GetElemPtr { dest, base: base_val, index: idx_i64, elem_size, result_ty });
        Ok(LValue::plain(Val::Local(dest), elem_ty))
    }

    fn lower_lvalue_field(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base is normally a struct lvalue; but it can also be a struct *rvalue*
        // (e.g. `f().field` where `f` returns a struct by value), whose address is
        // the materialized temporary.
        let lv = match self.lower_lvalue(base) {
            Ok(lv) => lv,
            Err(_) => {
                let ptr = self.lower_aggregate_ptr(base)?;
                let ty = self.infer_expr_type(base)?;
                LValue::plain(ptr, ty)
            }
        };
        self.field_ptr_from(lv, name, false, &base.span)
    }

    fn lower_lvalue_arrow(&mut self, base: &Expr, name: &str) -> Result<LValue> {
        // base is a pointer to struct — or an array, which decays to a pointer
        // to its first element (`arr->field` ≡ `arr[0].field`).
        let ptr = self.lower_expr(base)?;
        let ptr_ty = self.val_type(&ptr);
        let struct_ty = match &ptr_ty {
            Type::Pointer(t) => match t.as_ref() {
                Type::Array { elem, .. } => (**elem).clone(),
                _ => (**t).clone(),
            },
            Type::Array { elem, .. } => (**elem).clone(),
            _ => return Err(CompileError::at(
                format!("-> applied to non-pointer (field '{}')", name),
                base.span.file.clone(), base.span.line, base.span.col)),
        };
        let lv = LValue::plain(ptr, struct_ty);
        self.field_ptr_from(lv, name, true, &base.span)
    }

    fn field_ptr_from(&mut self, lv: LValue, field_name: &str, via_ptr: bool, sp: &crate::lexer::Span) -> Result<LValue> {
        let struct_ty = if via_ptr {
            match &lv.ty {
                Type::Pointer(t) => *t.clone(),
                other => other.clone(),
            }
        } else {
            lv.ty.clone()
        };

        // Resolve the member — including through anonymous struct/union members —
        // to a cumulative byte offset, type, and (if any) bit-field descriptor.
        let (byte_offset, field_ty, bitfield) =
            resolve_field_access(&struct_ty, field_name, self.ptr_size(), &self.lowerer.struct_types)
                .ok_or_else(|| CompileError::at(
                    format!("no field '{}' in type", field_name),
                    sp.file.clone(), sp.line, sp.col,
                ))?;

        let base_ptr = lv.ptr;
        let dest = self.alloc_val();
        let result_ty = Type::Pointer(Box::new(field_ty.clone()));
        self.push_instr(Instr::GetFieldPtr {
            dest, base: base_ptr, field_idx: 0, struct_name: None, byte_offset, result_ty,
        });
        Ok(LValue { ptr: Val::Local(dest), ty: field_ty, bitfield, atomic: false })
    }

    // ─── Type inference ───────────────────────────────────────────────────────

    /// Resolve a `_Generic` selection to the index of the matching association.
    /// The controlling expression's type undergoes lvalue conversion (array /
    /// function decay); it is compared against each association's lowered type,
    /// falling back to the `default` association. Matching is done on the IR
    /// `Type`, which is qualifier-insensitive — adequate because only the
    /// selected branch is ever lowered.
    fn select_generic(&self, controlling: &Expr, assocs: &[(Option<crate::ast::QualType>, Box<Expr>)]) -> Result<usize> {
        fn decay(t: Type) -> Type {
            match t {
                Type::Array { elem, .. } => Type::Pointer(elem),
                Type::Function(_) => Type::void_ptr(),
                other => other,
            }
        }
        let ctrl_ty = decay(self.infer_expr_type(controlling)?);
        let mut default_idx = None;
        for (i, (aty, _)) in assocs.iter().enumerate() {
            match aty {
                None => default_idx = Some(i),
                Some(qt) => {
                    if generic_type_eq(&decay(self.lower_type(qt)?), &ctrl_ty) {
                        return Ok(i);
                    }
                }
            }
        }
        let sp = &controlling.span;
        default_idx.ok_or_else(|| CompileError::at(
            "no matching association in _Generic selection",
            sp.file.clone(), sp.line, sp.col,
        ))
    }

    /// Compute the byte offset of a member designator within a type, for
    /// `__builtin_offsetof`. Walks `.field` (struct/union) and `[index]` (array)
    /// steps, summing struct field offsets and array element strides.
    /// Lower `offsetof(T, ...designators...)` to a `size_t` value. A constant
    /// index folds into the constant offset; a NON-constant array index (a GCC
    /// extension, e.g. `offsetof(CPU, segs[i].base)`) makes offsetof a runtime
    /// value `const_offset + index * elem_size`. QEMU registers its per-segment
    /// TCG globals in a loop with exactly this form; treating the index as 0
    /// pointed every segment base at segs[0], breaking CS-relative addressing.
    fn lower_offsetof(&mut self, ty: &crate::ast::QualType, designators: &[crate::ast::OffsetDesignator]) -> Result<Val> {
        use crate::ast::OffsetDesignator;
        let mut cur = self.lower_type(ty)?;
        let mut const_off: u64 = 0;
        let mut runtime: Option<Val> = None; // accumulated runtime byte offset
        for d in designators {
            match d {
                OffsetDesignator::Field(name) => {
                    let resolved = super::types::resolve_aggregate(&cur, &self.lowerer.struct_types);
                    let (off, fty, _) = resolve_field_access(&resolved, name, self.ptr_size(), &self.lowerer.struct_types)
                        .ok_or_else(|| CompileError::new(format!("no field '{}' in offsetof", name)))?;
                    const_off += off;
                    cur = fty;
                }
                OffsetDesignator::Index(e) => {
                    let elem = match &cur {
                        Type::Array { elem, .. } => *elem.clone(),
                        Type::Pointer(t) => *t.clone(),
                        other => other.clone(),
                    };
                    let esz = elem.size_of(self.ptr_size());
                    if let Ok(i) = super::eval_const_expr(e, &self.lowerer.enum_consts) {
                        const_off += (i as u64).wrapping_mul(esz);
                    } else {
                        // Runtime index: emit `index * elem_size` and add it.
                        let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
                        let iv = self.lower_expr(e)?;
                        let iv = self.coerce(iv, &usize_ty)?;
                        let term = self.alloc_val();
                        self.push_instr(Instr::BinOp { dest: term, op: BinOp::Mul, lhs: iv, rhs: Constant::uint(esz), ty: usize_ty.clone() });
                        runtime = Some(match runtime {
                            None => Val::Local(term),
                            Some(acc) => {
                                let s = self.alloc_val();
                                self.push_instr(Instr::BinOp { dest: s, op: BinOp::Add, lhs: acc, rhs: Val::Local(term), ty: usize_ty.clone() });
                                Val::Local(s)
                            }
                        });
                    }
                    cur = elem;
                }
            }
        }
        match runtime {
            None => self.coerce(Constant::uint(const_off), &Type::u64()),
            Some(rt) => {
                let usize_ty = Type::Int { bits: self.ptr_size() * 8, signed: false };
                let dest = self.alloc_val();
                self.push_instr(Instr::BinOp { dest, op: BinOp::Add, lhs: rt, rhs: Constant::uint(const_off), ty: usize_ty });
                Ok(Val::Local(dest))
            }
        }
    }

    pub fn infer_expr_type(&self, expr: &Expr) -> Result<Type> {
        match &expr.kind {
            ExprKind::Generic { controlling, assocs } => {
                let idx = self.select_generic(controlling, assocs)?;
                self.infer_expr_type(&assocs[idx].1)
            }
            ExprKind::OffsetOf { .. } => Ok(Type::u64()),
            ExprKind::CharLit(_) => Ok(Type::i32()),
            // sic `true`/`false` is `bool` (so `any b = true` boxes with BOOL kind).
            ExprKind::BoolLit(_) => Ok(Type::Bool),
            ExprKind::IntLit(_, is64) => Ok(if *is64 { Type::i64() } else { Type::i32() }),
            ExprKind::UIntLit(_, is64) => Ok(if *is64 { Type::Int { bits: 64, signed: false } } else { Type::u32() }),
            ExprKind::BigIntLit(_) => Ok(super::types::bigint_type()),
            // A bare decimal literal defaults to `double`; in a fixed context it is
            // intercepted before inference is consulted.
            ExprKind::DecimalLit(_) => Ok(Type::Float64),
            ExprKind::TypeId(_) | ExprKind::TypeIdOf(_) => Ok(super::types::type_info_type()),
            // A guard block yields an `int` status (0 clean / 1 caught).
            ExprKind::Guard { .. } => Ok(Type::i32()),
            ExprKind::FloatLit(_) => Ok(Type::Float64),
            // sic (sic.md §"Strings"): a string literal is a native `string` (a view
            // over the static bytes) by default; it decays to `char*` only where a
            // `char*` is expected. C keeps it a `char*`.
            ExprKind::StringLit(_) => Ok(if self.is_sic() {
                super::types::sic_string_type(self.ptr_size())
            } else {
                Type::char_ptr()
            }),
            ExprKind::Nullptr => Ok(Type::void_ptr()),
            ExprKind::Ident(name) => {
                match self.lookup(name) {
                    Some(LookupResult::Local(ty, _)) => Ok(ty.clone()),
                    Some(LookupResult::Global(ty, _)) => Ok(ty.clone()),
                    Some(LookupResult::EnumConst(_)) => Ok(Type::i32()),
                    Some(LookupResult::Func(_)) => Ok(Type::void_ptr()),
                    None => Ok(Type::i32()),
                }
            }
            ExprKind::Cast { ty, .. } => self.lower_type(ty),
            ExprKind::ChooseExpr { cond, then, else_ } => {
                if self.eval_choose_cond(cond) != 0 { self.infer_expr_type(then) }
                else { self.infer_expr_type(else_) }
            }
            ExprKind::TypesCompatible(..) => Ok(Type::i32()),
            ExprKind::SizeofType(_) | ExprKind::SizeofExpr(_)
            | ExprKind::AlignofType(_) | ExprKind::AlignofExpr(_) => Ok(Type::u64()),
            // sic bigint `-a` / `~a` keep the bigint type.
            ExprKind::Unary { op: UnOpKind::Neg | UnOpKind::BitNot, expr: inner }
                if self.is_sic() && self.is_bigint_operand(inner) =>
            {
                Ok(super::types::bigint_type())
            }
            ExprKind::Unary { op: UnOpKind::Addr, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                Ok(Type::Pointer(Box::new(inner_ty)))
            }
            ExprKind::Unary { op: UnOpKind::Deref, expr: inner } => {
                let inner_ty = self.infer_expr_type(inner)?;
                Ok(match inner_ty {
                    Type::Pointer(t) => self.pointee_of(&Type::Pointer(t)),
                    // An array decays to a pointer to its element, so `*arr` is
                    // the element type — `sizeof(*arr)` must be the element size,
                    // not the default i32 (QEMU's `qsort(cmds, .., sizeof(*cmds), ..)`
                    // over a `static HMPCommand cmds[]` gave size 4 → memory
                    // corruption during the sort).
                    Type::Array { elem, .. } => super::types::resolve_aggregate(&elem, &self.lowerer.struct_types),
                    _ => Type::i32(),
                })
            }
            ExprKind::Field { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                // sic native-string computed accessors: `.ptr` (and its alias
                // `.str`) is a `char*`, `.length` is a `usize` (sic.md §"Built-in
                // string").
                if self.is_sic() && super::types::is_sic_string(&base_ty) {
                    if name == "ptr" || name == "str" { return Ok(Type::char_ptr()); }
                    if name == "length" { return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false }); }
                    if name == "dup" { return Ok(super::types::sic_string_type(self.ptr_size())); }
                    if name == "utf8" { return Ok(super::types::u8char_arr_type(self.ptr_size())); }
                }
                // sic `u8char.size` is a `usize` (UTF-8 encoded length).
                if self.is_sic() && name == "size" && super::types::is_u8char(&base_ty) {
                    return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false });
                }
                // sic `enumvalue.str` is a native `string`.
                if self.is_sic() && name == "str" {
                    if let ExprKind::Ident(id) = &base.kind {
                        if self.enum_locals.contains_key(id)
                            || self.lowerer.c_enum_variant.contains_key(id) {
                            return Ok(super::types::sic_string_type(self.ptr_size()));
                        }
                    }
                }
                // `s.dup` on a C string (`char*`/`char[]`) is an owned `string`.
                if self.is_sic() && name == "dup"
                    && (matches!(&base_ty, Type::Pointer(i) if matches!(i.as_ref(), Type::Int { bits: 8, .. }))
                        || matches!(&base_ty, Type::Array { elem, .. } if matches!(elem.as_ref(), Type::Int { bits: 8, .. }))) {
                    return Ok(super::types::sic_string_type(self.ptr_size()));
                }
                // sic array / va_array `.length` / `.size` are `usize`.
                if self.is_sic() && (matches!(base_ty, Type::Array { .. }) || super::types::is_va_array(&base_ty))
                    && (name == "length" || name == "size") {
                    return Ok(Type::Int { bits: self.ptr_size() * 8, signed: false });
                }
                // sic bigint `.str` is a `char*`, `.int` an `i64` (sic.md §"Integer sizes").
                if self.is_sic() && super::types::is_bigint(&base_ty) {
                    if name == "str" { return Ok(Type::char_ptr()); }
                    if name == "int" { return Ok(Type::i64()); }
                }
                // sic fixed `.str` is a `char*` (sic.md §"Built-in fixed point").
                if self.is_sic() && super::types::is_fixed(&base_ty) && name == "str" {
                    return Ok(Type::char_ptr());
                }
                if let Some((_, fty, _)) = resolve_field_access(&base_ty, name, self.ptr_size(), &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            ExprKind::Arrow { base, name } => {
                let base_ty = self.infer_expr_type(base)?;
                let struct_ty = match base_ty {
                    Type::Pointer(t) => *t,
                    other => other,
                };
                if let Some((_, fty, _)) = resolve_field_access(&struct_ty, name, self.ptr_size(), &self.lowerer.struct_types) {
                    Ok(fty)
                } else {
                    Ok(Type::i32())
                }
            }
            // `base?.field` (sic.md §"Match") has the field's type — the zero value
            // on the absent path shares it.
            ExprKind::OptField { base, name } => {
                let bty = self.infer_expr_type(base)?;
                let struct_ty = match &bty {
                    Type::Pointer(p) => (**p).clone(),
                    t if self.is_tagged_enum_struct(t) =>
                        self.enum_present_variant(t).and_then(|(_, v)| v.payload).unwrap_or_else(|| Type::i32()),
                    other => other.clone(),
                };
                Ok(self.opt_field_type(&struct_ty, name).unwrap_or_else(|| Type::i32()))
            }
            ExprKind::Index { base, index } => {
                let bt = self.infer_expr_type(base)?;
                // sic `dict[key]` yields the value type V (sic.md §"Dict").
                if self.is_sic() {
                    let dt = if super::types::is_dict(&bt) {
                        Some(bt.clone())
                    } else if let Type::Pointer(i) = &bt {
                        if super::types::is_dict(i) { Some((**i).clone()) } else { None }
                    } else { None };
                    if let Some(dt) = dt {
                        if let Some((_, v)) = super::types::dict_kv(&dt, self.ptr_size()) {
                            return Ok(v);
                        }
                    }
                    // sic `list[i]` yields the element type T (sic.md §"List").
                    let lt = if super::types::is_list(&bt) { Some(bt.clone()) }
                        else if let Type::Pointer(i) = &bt {
                            if super::types::is_list(i) { Some((**i).clone()) } else { None }
                        } else { None };
                    if let Some(lt) = lt {
                        return Ok(super::types::list_elem(&lt, self.ptr_size()));
                    }
                }
                // sic `va_array` element `va[i]` is an `any` (sic.md std).
                if self.is_sic() && super::types::is_va_array(&bt) {
                    return Ok(super::types::any_type());
                }
                // sic `u8char[]` element `cps[i]` is a `u8char`.
                if self.is_sic() && super::types::is_u8char_arr(&bt) {
                    return Ok(super::types::u8char_type());
                }
                // sic `string[i]` is the byte (a `char`).
                if self.is_sic() && super::types::is_sic_string(&bt) {
                    return Ok(Type::i8());
                }
                // sic tuple element `t[const]` has the field's type (deref the
                // tuple pointer to its layout struct).
                if self.is_sic() {
                    if let Some(Type::Struct(st)) = super::types::tuple_layout_of(&bt) {
                        if let Some(i) = self.const_index(index) {
                            if let Some((_, fty)) = st.fields.get(i as usize) {
                                return Ok(fty.clone());
                            }
                        }
                    }
                }
                let elem = match bt {
                    Type::Pointer(t) => match *t {
                        Type::Array { elem, .. } => *elem,
                        other => other,
                    },
                    Type::Array { elem, .. } => *elem,
                    _ => Type::i32(),
                };
                // The element of a pointer-to-opaque-aggregate (e.g. `p->aCol[0]`
                // where `aCol` is `Column*`) must be resolved to its full
                // definition, or `sizeof` sees an empty struct and returns 0.
                Ok(super::types::resolve_aggregate(&elem, &self.lowerer.struct_types))
            }
            // A tuple pack has the anonymous positional-struct type of its elements.
            ExprKind::TupleExpr(elems) => {
                let mut tys = Vec::with_capacity(elems.len());
                for e in elems {
                    tys.push(self.infer_expr_type(e).unwrap_or_else(|_| Type::i32()));
                }
                Ok(super::types::tuple_type(tys))
            }
            // A tagged-enum variant path is a value of that enum's struct type.
            ExprKind::EnumVariant { enum_name, variant } => {
                // sic namespace member `N::member` → the mangled global's type.
                if self.is_sic() {
                    if let Some(mangled) = self.lowerer.namespace_members.get(&(enum_name.clone(), variant.clone())).cloned() {
                        return self.infer_expr_type(&Expr { kind: ExprKind::Ident(mangled), span: expr.span.clone() });
                    }
                }
                // A plain C-enum variant `E::VARIANT` is an integer discriminant.
                if self.is_sic() && self.resolve_plain_enum_const(enum_name, variant).is_some() {
                    return Ok(Type::i32());
                }
                // A generic constructor (`Option::None`) resolves via the expected
                // target type (sic.md §"Match").
                let resolved = self.resolve_generic_ctor(enum_name, &expr.span).ok().flatten();
                let ename = resolved.as_deref().unwrap_or(enum_name);
                self.lowerer.enum_defs.get(ename).map(|i| i.struct_type.clone())
                    .ok_or_else(|| CompileError::new(format!("'{}' is not a tagged enum", enum_name)))
            }
            ExprKind::Call { func, args } => {
                // sic tagged-enum constructor / unwrap.
                if let ExprKind::EnumVariant { enum_name, variant } = &func.kind {
                    let resolved = self.resolve_generic_ctor(enum_name, &expr.span).ok().flatten();
                    let enum_name = resolved.as_deref().unwrap_or(enum_name.as_str());
                    if let Some(info) = self.lowerer.enum_defs.get(enum_name) {
                        // `Enum::VARIANT(inst)` unwraps → payload type; otherwise
                        // it constructs → the enum struct.
                        if let Some(v) = info.variant(variant) {
                            if v.payload.is_some() && args.len() == 1 {
                                if let Ok(t) = self.infer_expr_type(&args[0]) {
                                    if self.is_enum_struct(&t, enum_name) {
                                        return Ok(v.payload.clone().unwrap());
                                    }
                                }
                            }
                        }
                        return Ok(info.struct_type.clone());
                    }
                }
                // Bare variant constructor `Ok(5)`.
                if let ExprKind::Ident(name) = &func.kind {
                    if self.is_sic() && !matches!(self.lookup(name), Some(LookupResult::Func(_))) {
                        if let Some(en) = self.lowerer.variant_enum.get(name) {
                            if let Some(info) = self.lowerer.enum_defs.get(en) {
                                return Ok(info.struct_type.clone());
                            }
                        }
                    }
                }
                // sic struct method call `obj.method(...)` → the hoisted method's
                // return type (so `auto r = it.next();` infers `Iterator<T>`).
                if self.is_sic() && !self.lowerer.struct_methods.is_empty() {
                    if let ExprKind::Field { base, name } | ExprKind::Arrow { base, name } = &func.kind {
                        let sname = match self.infer_expr_type(base).ok() {
                            Some(Type::Struct(st)) => st.name,
                            Some(Type::Pointer(inner)) => match *inner { Type::Struct(st) => st.name, _ => None },
                            _ => None,
                        };
                        if let Some(mangled) = sname
                            .and_then(|s| self.lowerer.struct_methods.get(&(s, name.clone())).cloned())
                        {
                            if let Some(fref) = self.lowerer.module.func_ref_by_name(&mangled) {
                                return Ok(self.lowerer.module.func_sig(fref).ret.clone());
                            }
                        }
                    }
                }
                // Return type of the callee. A direct call resolves via the
                // module signature; an indirect call takes the pointee function
                // type's return. Without this a call defaults to i32 and a
                // pointer-returning call in a ternary gets truncated to 32 bits.
                if let ExprKind::Ident(name) = &func.kind {
                    if let Some(LookupResult::Func(fref)) = self.lookup(name) {
                        return Ok(self.lowerer.module.func_sig(fref).ret.clone());
                    }
                }
                // Namespaced module call `mod.fn(...)`: the result type is the export's
                // declared return (user-facing, no sret ptr). Without this a
                // string-returning `std.Fmt(...)` defaults to i32 and its initializer
                // mistakes the result for a `char*`.
                // Both spellings of a module call: `mod.fn(...)` (Field) and the
                // canonical `Module::fn(...)` (EnumVariant, sic.md §"Namespace").
                let module_sym = match &func.kind {
                    ExprKind::Field { base, name } => match &base.kind {
                        ExprKind::Ident(m) => Some((m.clone(), name.clone())),
                        _ => None,
                    },
                    // `Module::sym` (flat) or `Module::A::B::sym` (nested): the export
                    // name mangles the intra-module scope path with `__`.
                    ExprKind::EnumVariant { enum_name, variant } => match enum_name.split_once("::") {
                        Some((module, rest)) => Some((module.to_string(), format!("{}__{}", rest.replace("::", "__"), variant))),
                        None => Some((enum_name.clone(), variant.clone())),
                    },
                    _ => None,
                };
                if let Some((m, name)) = module_sym {
                    if let Some(Type::Function(ft)) = self.lowerer.imported_modules
                        .get(&m).and_then(|ex| ex.get(&name)).map(|(_, t)| t)
                    {
                        return Ok(ft.ret.clone());
                    }
                }
                let fty = self.infer_expr_type(func)?;
                Ok(match fty {
                    Type::Pointer(inner) => match *inner {
                        Type::Function(ft) => ft.ret.clone(),
                        _ => Type::i32(),
                    },
                    Type::Function(ft) => ft.ret.clone(),
                    _ => Type::i32(),
                })
            }
            // sic Option/Result unwrap-or-default `opt ?: default` — the result is
            // the payload type (sic.md §"Match").
            ExprKind::Elvis { cond, else_: _ }
                if self.is_sic() && matches!(self.infer_expr_type(cond), Ok(t) if self.is_tagged_enum_struct(&t)) =>
            {
                let t = self.infer_expr_type(cond)?;
                match self.enum_present_variant(&t).and_then(|(_, v)| v.payload) {
                    Some(pty) => Ok(pty),
                    None => Ok(Type::i32()),
                }
            }
            // An expression `match` has the type of its value arms.
            ExprKind::Match { arms, .. } => Ok(self.match_result_type(arms)),
            ExprKind::Ternary { then, else_, .. }
            | ExprKind::Elvis { cond: then, else_ } => {
                // Mirror lower_ternary/lower_elvis's result-type selection.
                let tty = self.infer_expr_type(then).unwrap_or_else(|_| Type::i32());
                let ety = self.infer_expr_type(else_).unwrap_or_else(|_| Type::i32());
                Ok(match (&tty, &ety) {
                    (Type::Pointer(_), _) | (Type::Void, _) => tty,
                    (_, Type::Pointer(_)) => ety,
                    _ if tty.is_float() => tty,
                    _ if ety.is_float() => ety,
                    _ if ety.size_of(self.ptr_size()) > tty.size_of(self.ptr_size()) => ety,
                    _ => tty,
                })
            }
            ExprKind::Assign { lhs, .. } => self.infer_expr_type(lhs),
            // A substring slice is itself a `string` (sic.md §"Built-in string").
            ExprKind::Slice { .. } => Ok(super::types::sic_string_type(self.ptr_size())),
            // `new T` / `new T(n)` yields `T*`.
            ExprKind::New { ty, .. } => {
                let elem = self.lower_type(ty)?;
                // `new dict<…>` yields the dict handle itself (already a pointer).
                if super::types::is_dict(&elem) { Ok(elem) } else { Ok(Type::Pointer(Box::new(elem))) }
            }
            // `@expr` has the referent's (pointer) type.
            ExprKind::Ref { expr, .. } => self.infer_expr_type(expr),
            ExprKind::Comma(_, rhs) => self.infer_expr_type(rhs),
            // GCC statement expression `({ ...; expr; })` has the type of its last
            // statement when that is an expression statement, else void. Needed so
            // `typeof(({...; p;}))` (QEMU's nested qobject_ref) keeps `p`'s type.
            // A trailing bare identifier is usually a temporary declared inside the
            // block (`typeof(x) _o = x; _o;`), invisible to the outer scope, so
            // resolve such declarators here.
            ExprKind::StmtExpr(stmts) => {
                match stmts.last() {
                    Some(ast::Stmt::Expr(e, _)) => {
                        if let ExprKind::Ident(name) = &e.kind {
                            for stmt in stmts {
                                if let ast::Stmt::Decl(ast::Decl::Var { declarators, .. }) = stmt {
                                    if let Some(d) = declarators.iter().find(|d| &d.name == name) {
                                        return self.lower_type(&d.ty);
                                    }
                                }
                            }
                        }
                        self.infer_expr_type(e)
                    }
                    _ => Ok(Type::Void),
                }
            }
            ExprKind::BinOp { op, lhs, rhs } => {
                use BinOpKind::*;
                // Infer each operand's type ONCE and reuse it for every predicate
                // below. Re-inferring per predicate (bigint/fixed/string checks
                // each call `infer_expr_type` again) turned a left-associative
                // chain like `a + b + c + …` into O(4^n) — each BinOp re-walked
                // each child roughly four times.
                let lt = self.infer_expr_type(lhs).unwrap_or_else(|_| Type::i32());
                let rt = self.infer_expr_type(rhs).unwrap_or_else(|_| Type::i32());
                // sic `bigint` arithmetic yields a bigint; comparisons yield int.
                if self.is_sic() && matches!(op, Add | Sub | Mul | Div | Rem | BitAnd | BitOr | BitXor | Shl | Shr)
                    && (super::types::is_bigint(&lt) || super::types::is_bigint(&rt))
                {
                    return Ok(super::types::bigint_type());
                }
                // sic `fixed` arithmetic yields a fixed<I,F> (comparisons yield int,
                // handled below). I/F combine per `fixed_result_dims`.
                if self.is_sic() && matches!(op, Add | Sub | Mul | Div | Rem)
                    && (super::types::is_fixed(&lt) || super::types::is_fixed(&rt))
                {
                    let da = self.fixed_expr_dims(lhs).unwrap_or((20, 0));
                    let db = self.fixed_expr_dims(rhs).unwrap_or((20, 0));
                    let (i, f) = Self::fixed_result_dims(*op, da, db);
                    return Ok(super::types::fixed_type(i, f));
                }
                match op {
                    // Relational/logical operators yield int.
                    Eq | Ne | Lt | Le | Gt | Ge | LogAnd | LogOr => Ok(Type::i32()),
                    // sic string concatenation yields a `string` (either side a
                    // `string` — a literal already infers as `string` in sic).
                    Add if self.is_sic()
                        && (super::types::is_sic_string(&lt) || super::types::is_sic_string(&rt)) =>
                        Ok(super::types::sic_string_type(self.ptr_size())),
                    // sic array concatenation yields an array of the combined
                    // length (sic.md §"Arrays and lists").
                    Add if self.is_sic() => {
                        match (&lt, &rt) {
                            (Type::Array { elem, len: la }, Type::Array { len: lb, .. }) =>
                                Ok(Type::Array { elem: elem.clone(), len: la + lb }),
                            _ => Ok(self.arith_result_type(op, lt, rt)),
                        }
                    }
                    // Arithmetic: pointer/array ± integer keeps the pointer type
                    // (pointer arithmetic; arrays decay to pointer-to-element).
                    // `ptr - ptr` is ptrdiff_t. Otherwise pick the "richer" operand
                    // type so float/wider integer results survive.
                    _ => Ok(self.arith_result_type(op, lt, rt)),
                }
            }
            _ => Ok(Type::i32()),
        }
    }

    /// Result type of an arithmetic binary operator (the C usual-arithmetic /
    /// pointer-arithmetic rules), factored out so the sic array/string special
    /// cases can fall back to it.
    fn arith_result_type(&self, op: &BinOpKind, lt: Type, rt: Type) -> Type {
        let decay = |t: Type| match t {
            Type::Array { elem, .. } => Type::Pointer(elem),
            other => other,
        };
        let lt = decay(lt);
        let rt = decay(rt);
        match (&lt, &rt) {
            (Type::Pointer(_), Type::Pointer(_)) if *op == BinOpKind::Sub => Type::i64(),
            (Type::Pointer(_), _) => lt,
            (_, Type::Pointer(_)) => rt,
            _ if lt.is_float() => lt,
            _ if rt.is_float() => rt,
            _ if rt.size_of(self.ptr_size()) > lt.size_of(self.ptr_size()) => rt,
            _ => lt,
        }
    }

    /// Lower a `va_list` operand to the address of its `__va_list_tag`. A local
    /// `va_list` (the builtin array, or a user-defined struct aliased to
    /// `va_list`) needs its own address; a `va_list` *parameter* has already
    /// decayed to a `__va_list_tag*`, so its value is that address.
    fn lower_va_list_ptr(&mut self, list: &Expr) -> Result<Val> {
        let ty = self.infer_expr_type(list).unwrap_or_else(|_| Type::void_ptr());
        if matches!(ty, Type::Array { .. } | Type::Struct(_) | Type::Union(_)) {
            if let Ok(lv) = self.lower_lvalue(list) {
                return Ok(lv.ptr);
            }
        }
        self.lower_expr(list)
    }

    /// Lower an expression expecting it to produce a pointer (for va_list etc).
    #[allow(dead_code)]
    fn lower_expr_as_ptr(&mut self, expr: &Expr) -> Result<Val> {
        match self.lower_lvalue(expr) {
            Ok(lv) => Ok(lv.ptr),
            Err(_) => self.lower_expr(expr),
        }
    }
}

fn inc_op(ty: &Type, inc: bool) -> BinOp {
    if ty.is_float() {
        if inc { BinOp::FAdd } else { BinOp::FSub }
    } else {
        if inc { BinOp::Add } else { BinOp::Sub }
    }
}

/// A resolved member access: cumulative byte offset from the start of the
/// aggregate, the member's type, and bit-field info if it is one. Drills through
/// anonymous (unnamed) struct/union members, whose fields are accessed as if they
/// were members of the enclosing aggregate (C11 anonymous struct/union).
pub(super) fn resolve_field_access(
    ty: &Type,
    name: &str,
    ptr_size: u32,
    named: &std::collections::HashMap<String, Type>,
) -> Option<(u64, Type, Option<BitField>)> {
    let resolved = super::types::resolve_aggregate(ty, named);
    match &resolved {
        Type::Struct(st) => {
            let (offs, bit_offs, _) = st.layout_full(ptr_size);
            // Direct member.
            for (i, (fname, fty)) in st.fields.iter().enumerate() {
                if fname == name {
                    let bf = st.bitfields.get(i).copied().flatten().map(|w| BitField {
                        bit_offset: *bit_offs.get(i).unwrap_or(&0),
                        width: w,
                        signed: fty.is_signed(),
                    });
                    return Some((*offs.get(i).unwrap_or(&0), fty.clone(), bf));
                }
            }
            // Anonymous member: recurse, adding that member's byte offset.
            for (i, (fname, fty)) in st.fields.iter().enumerate() {
                if fname.is_empty() && matches!(fty, Type::Struct(_) | Type::Union(_)) {
                    if let Some((sub_off, sub_ty, sub_bf)) = resolve_field_access(fty, name, ptr_size, named) {
                        return Some((offs.get(i).copied().unwrap_or(0) + sub_off, sub_ty, sub_bf));
                    }
                }
            }
            None
        }
        Type::Union(u) => {
            // All union members live at offset 0.
            for (fname, fty) in &u.fields {
                if fname == name {
                    return Some((0, fty.clone(), None));
                }
            }
            for (fname, fty) in &u.fields {
                if fname.is_empty() && matches!(fty, Type::Struct(_) | Type::Union(_)) {
                    if let Some(r) = resolve_field_access(fty, name, ptr_size, named) {
                        return Some(r);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Type equality for `_Generic` association matching. Aggregate pointees are
/// stored opaque in some contexts and fully resolved in others, so two
/// otherwise-identical `struct Foo *` can differ by field population; compare
/// named aggregates by name instead.
fn generic_type_eq(a: &Type, b: &Type) -> bool {
    match (a, b) {
        (Type::Pointer(x), Type::Pointer(y)) => generic_type_eq(x, y),
        (Type::Struct(s1), Type::Struct(s2)) => match (&s1.name, &s2.name) {
            (Some(n1), Some(n2)) => n1 == n2,
            _ => a == b,
        },
        (Type::Union(u1), Type::Union(u2)) => match (&u1.name, &u2.name) {
            (Some(n1), Some(n2)) => n1 == n2,
            _ => a == b,
        },
        _ => a == b,
    }
}

#[derive(Clone, Copy)]
enum BitOp { Clz, Ctz, Popcnt, Ffs, Clrsb, Parity }

/// Classify `__builtin_{clz,ctz,popcount,ffs}[l|ll]` into (kind, operand bits).
fn builtin_bit_op(name: &str) -> Option<(BitOp, u32)> {
    let (base, bits) = if let Some(b) = name.strip_suffix("ll") { (b, 64) }
        else if let Some(b) = name.strip_suffix('l') { (b, 64) }
        else { (name, 32) };
    let kind = match base {
        "__builtin_clz"      => BitOp::Clz,
        "__builtin_ctz"      => BitOp::Ctz,
        "__builtin_popcount" => BitOp::Popcnt,
        "__builtin_ffs"      => BitOp::Ffs,
        "__builtin_clrsb"    => BitOp::Clrsb,
        "__builtin_parity"   => BitOp::Parity,
        _ => return None,
    };
    Some((kind, bits))
}

/// Classify an atomic/sync read-modify-write builtin into its arithmetic op and
/// whether it returns the new value (vs the old). Returns `None` for names that
/// aren't of this family (or use an op we don't special-case, e.g. `nand`).
/// Map a `__sync_*`/`__atomic_*` builtin name to its width-generic base by
/// stripping a trailing `_1/_2/_4/_8/_16` size suffix. GCC exposes both the
/// type-generic form and these sized forms (QEMU's 128-bit host atomics use the
/// `_16` variant); both share one handler. Names without such a suffix (or that
/// aren't atomics) are returned unchanged.
fn sync_builtin_base(name: &str) -> &str {
    for w in ["_16", "_8", "_4", "_2", "_1"] {
        if let Some(base) = name.strip_suffix(w) {
            if base.starts_with("__sync_") || base.starts_with("__atomic_") {
                return base;
            }
        }
    }
    name
}

fn atomic_rmw_op(name: &str) -> Option<(BinOp, bool)> {
    let (op_name, ret_new) = if let Some(rest) = name.strip_prefix("__atomic_fetch_") {
        (rest, false)
    } else if let Some(rest) = name.strip_prefix("__atomic_").and_then(|r| r.strip_suffix("_fetch")) {
        (rest, true)
    } else if let Some(rest) = name.strip_prefix("__sync_fetch_and_") {
        (rest, false)
    } else if let Some(rest) = name.strip_prefix("__sync_").and_then(|r| r.strip_suffix("_and_fetch")) {
        (rest, true)
    } else {
        return None;
    };
    let op = match op_name {
        "add" => BinOp::Add,
        "sub" => BinOp::Sub,
        "or"  => BinOp::Or,
        "and" => BinOp::And,
        "xor" => BinOp::Xor,
        _ => return None,
    };
    Some((op, ret_new))
}

