/// The type system used throughout the IR.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Void,
    Bool,
    Int { bits: u32, signed: bool },
    Float32,
    Float64,
    /// x86-64 `long double`: 80-bit extended precision stored in 16 bytes.
    /// Codegen currently treats it as f64 (Cranelift has no x87/f80 support),
    /// so only its size/alignment differ from `Float64`.
    Float80,
    Pointer(Box<Type>),
    Array { elem: Box<Type>, len: usize },
    Struct(StructType),
    Union(UnionType),
    Function(Box<FunctionType>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructType {
    pub name: Option<String>,
    pub fields: Vec<(String, Type)>,
    pub packed: bool,
    /// Parallel to `fields`: `Some(width)` marks a bit-field of the given width
    /// (in bits); its `fields` entry holds the declared storage integer type.
    /// Empty means no bit-fields (default). A zero width forces alignment.
    pub bitfields: Vec<Option<u32>>,
    /// Parallel to `fields`: `Some(n)` is an `__attribute__((aligned(n)))`
    /// override on the member, raising its (and the struct's) alignment. Empty
    /// means no overrides (default).
    pub field_aligns: Vec<Option<u32>>,
    /// Type-level `__attribute__((aligned(n)))` on the struct itself, raising the
    /// whole type's alignment (QEMU's `QEMU_ALIGNED` on `CPUTLBDescFast`).
    pub min_align: Option<u32>,
}

impl StructType {
    /// Construct a plain (bit-field-free) struct.
    pub fn plain(name: Option<String>, fields: Vec<(String, Type)>, packed: bool) -> Self {
        StructType { name, fields, packed, bitfields: Vec::new(), field_aligns: Vec::new(), min_align: None }
    }

    fn bitfield_width(&self, idx: usize) -> Option<u32> {
        self.bitfields.get(idx).copied().flatten()
    }

    /// Effective alignment (bytes) of field `idx`: the max of its type's natural
    /// alignment and any `aligned(n)` override. An override wins even under
    /// `#pragma pack`/`packed` (which otherwise forces alignment 1).
    fn field_align(&self, idx: usize, ty: &Type, ptr_size: u32) -> u64 {
        let natural = if self.packed { 1 } else { ty.align_of(ptr_size) };
        let override_ = self.field_aligns.get(idx).copied().flatten().unwrap_or(0) as u64;
        natural.max(override_).max(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnionType {
    pub name: Option<String>,
    pub fields: Vec<(String, Type)>,
    /// Parallel to `fields`: `aligned(n)` overrides on members (see `StructType`).
    pub field_aligns: Vec<Option<u32>>,
    /// Type-level `__attribute__((aligned(n)))` on the union itself.
    pub min_align: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionType {
    pub ret: Type,
    pub params: Vec<Type>,
    pub variadic: bool,
}

impl Type {
    /// Returns the size of this type in bytes, given a pointer width in bytes.
    pub fn size_of(&self, ptr_size: u32) -> u64 {
        match self {
            Type::Void | Type::Function(_) => 0,
            Type::Bool => 1,
            Type::Int { bits, .. } => (*bits as u64 + 7) / 8,
            Type::Float32 => 4,
            Type::Float64 => 8,
            Type::Float80 => 16,
            Type::Pointer(_) => ptr_size as u64,
            Type::Array { elem, len } => elem.size_of(ptr_size) * (*len as u64),
            Type::Struct(s) => s.size_of(ptr_size),
            Type::Union(u) => u.size_of(ptr_size),
        }
    }

    /// Returns the alignment of this type in bytes.
    pub fn align_of(&self, ptr_size: u32) -> u64 {
        match self {
            Type::Void | Type::Function(_) => 1,
            Type::Bool => 1,
            Type::Int { bits, .. } => ((*bits as u64 + 7) / 8).min(ptr_size as u64),
            Type::Float32 => 4,
            Type::Float64 => 8,
            Type::Float80 => 16,
            Type::Pointer(_) => ptr_size as u64,
            Type::Array { elem, .. } => elem.align_of(ptr_size),
            Type::Struct(s) => s.align_of(ptr_size),
            Type::Union(u) => u.align_of(ptr_size),
        }
    }

    pub fn is_int(&self) -> bool {
        matches!(self, Type::Int { .. } | Type::Bool)
    }

    pub fn is_float(&self) -> bool {
        matches!(self, Type::Float32 | Type::Float64 | Type::Float80)
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self, Type::Pointer(_))
    }

    pub fn is_signed(&self) -> bool {
        match self {
            Type::Int { signed, .. } => *signed,
            Type::Bool => false,
            _ => false,
        }
    }

    pub fn pointee(&self) -> Option<&Type> {
        match self {
            Type::Pointer(inner) => Some(inner),
            _ => None,
        }
    }

    pub fn int_bits(&self) -> Option<u32> {
        match self {
            Type::Int { bits, .. } => Some(*bits),
            Type::Bool => Some(1),
            _ => None,
        }
    }

    /// Promote type for arithmetic (bool → i32, narrow ints → i32 in C semantics).
    pub fn integer_promote(&self) -> Type {
        if self.int_bits().unwrap_or(33) < 32 {
            return Type::Int { bits: 32, signed: true };
        }
        self.clone()
    }

    pub fn i8() -> Type { Type::Int { bits: 8, signed: true } }
    pub fn i16() -> Type { Type::Int { bits: 16, signed: true } }
    pub fn i32() -> Type { Type::Int { bits: 32, signed: true } }
    pub fn i64() -> Type { Type::Int { bits: 64, signed: true } }
    pub fn u8() -> Type { Type::Int { bits: 8, signed: false } }
    pub fn u16() -> Type { Type::Int { bits: 16, signed: false } }
    pub fn u32() -> Type { Type::Int { bits: 32, signed: false } }
    pub fn u64() -> Type { Type::Int { bits: 64, signed: false } }
    pub fn ptr(inner: Type) -> Type { Type::Pointer(Box::new(inner)) }
    pub fn char_ptr() -> Type { Type::ptr(Type::i8()) }
    pub fn void_ptr() -> Type { Type::ptr(Type::Void) }
}

impl StructType {
    /// Compute field byte offsets respecting alignment. Returns (offsets, total_size).
    pub fn layout(&self, ptr_size: u32) -> (Vec<u64>, u64) {
        let (offs, _, size) = self.layout_full(ptr_size);
        (offs, size)
    }

    /// Full layout: byte offsets, bit offsets (within each field's storage unit;
    /// 0 for non-bit-fields), and total size. Implements the System V x86-64
    /// bit-field packing rules (small consecutive bit-fields share a storage
    /// unit; a field that would cross a unit boundary starts a new unit).
    pub fn layout_full(&self, ptr_size: u32) -> (Vec<u64>, Vec<u32>, u64) {
        let mut byte_offsets = Vec::with_capacity(self.fields.len());
        let mut bit_offsets = Vec::with_capacity(self.fields.len());
        let mut bit_pos: u64 = 0; // running position in bits
        let mut max_align = 1u64;

        for (i, (_, ty)) in self.fields.iter().enumerate() {
            let align = self.field_align(i, ty, ptr_size);
            let size = ty.size_of(ptr_size);
            match self.bitfield_width(i) {
                Some(width) => {
                    max_align = max_align.max(align);
                    let width = width as u64;
                    if width == 0 {
                        // Zero-width bit-field: align the next field to `align`.
                        bit_pos = round_up_bits(bit_pos, align * 8);
                        byte_offsets.push(bit_pos / 8);
                        bit_offsets.push(0);
                        continue;
                    }
                    let unit_bits = size * 8;
                    if unit_bits > 0 && (bit_pos % unit_bits) + width > unit_bits {
                        bit_pos = round_up_bits(bit_pos, unit_bits);
                    }
                    let unit_start = if unit_bits > 0 { (bit_pos / unit_bits) * unit_bits } else { bit_pos };
                    byte_offsets.push(unit_start / 8);
                    bit_offsets.push((bit_pos - unit_start) as u32);
                    bit_pos += width;
                }
                None => {
                    max_align = max_align.max(align);
                    bit_pos = round_up_bits(bit_pos, align * 8);
                    byte_offsets.push(bit_pos / 8);
                    bit_offsets.push(0);
                    bit_pos += size * 8;
                }
            }
        }

        let mut total = bit_pos;
        // A type-level `aligned(n)` raises the struct's alignment (and thus its
        // trailing padding) even under `packed`.
        let min_align = self.min_align.unwrap_or(0) as u64;
        let eff_align = max_align.max(min_align);
        if eff_align > 0 && (!self.packed || min_align > 0) {
            total = round_up_bits(total, eff_align * 8);
        }
        (byte_offsets, bit_offsets, (total + 7) / 8)
    }

    pub fn size_of(&self, ptr_size: u32) -> u64 {
        self.layout(ptr_size).1
    }

    pub fn align_of(&self, ptr_size: u32) -> u64 {
        // Even a `packed` struct is aligned to any explicit member `aligned(n)`
        // override, so compute from `field_align` (which folds packed in). A
        // type-level `aligned(n)` raises it further.
        self.fields
            .iter()
            .enumerate()
            .map(|(i, (_, t))| self.field_align(i, t, ptr_size))
            .max()
            .unwrap_or(1)
            .max(self.min_align.unwrap_or(0) as u64)
    }

    pub fn field_offset(&self, idx: usize, ptr_size: u32) -> u64 {
        self.layout(ptr_size).0[idx]
    }

    /// Bit offset of bit-field `idx` within its storage unit (0 for a normal field).
    pub fn field_bit_offset(&self, idx: usize, ptr_size: u32) -> u32 {
        self.layout_full(ptr_size).1[idx]
    }
}

fn round_up_bits(pos: u64, align: u64) -> u64 {
    if align == 0 { return pos; }
    (pos + align - 1) / align * align
}

impl UnionType {
    /// Effective alignment of member `idx`: natural align raised by any
    /// `aligned(n)` override.
    fn field_align(&self, idx: usize, ty: &Type, ptr_size: u32) -> u64 {
        let override_ = self.field_aligns.get(idx).copied().flatten().unwrap_or(0) as u64;
        ty.align_of(ptr_size).max(override_).max(1)
    }

    pub fn size_of(&self, ptr_size: u32) -> u64 {
        let max = self.fields
            .iter()
            .map(|(_, t)| t.size_of(ptr_size))
            .max()
            .unwrap_or(0);
        // A union's size is rounded up to its alignment (which an `aligned(n)`
        // member override or a type-level `aligned(n)` can raise above the
        // largest member's size).
        round_up_bits(max * 8, self.align_of(ptr_size) * 8) / 8
    }

    pub fn align_of(&self, ptr_size: u32) -> u64 {
        self.fields
            .iter()
            .enumerate()
            .map(|(i, (_, t))| self.field_align(i, t, ptr_size))
            .max()
            .unwrap_or(1)
            .max(self.min_align.unwrap_or(0) as u64)
    }
}

/// Usual arithmetic conversion: pick common type for binary ops.
pub fn usual_arith_conv(a: &Type, b: &Type) -> Type {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        // float wins (long double ranks highest)
        (Type::Float80, _) | (_, Type::Float80) => Type::Float80,
        (Type::Float64, _) | (_, Type::Float64) => Type::Float64,
        (Type::Float32, _) | (_, Type::Float32) => Type::Float32,
        // integer promotions
        (Type::Int { bits: ab, signed: as_ }, Type::Int { bits: bb, signed: bs }) => {
            let bits = (*ab).max(*bb);
            let signed = if ab == bb { *as_ && *bs } else if ab > bb { *as_ } else { *bs };
            Type::Int { bits, signed }
        }
        (Type::Bool, other) | (other, Type::Bool) => other.clone(),
        // pointer wins over integer
        (Type::Pointer(_), _) => a.clone(),
        (_, Type::Pointer(_)) => b.clone(),
        _ => a.clone(),
    }
}
