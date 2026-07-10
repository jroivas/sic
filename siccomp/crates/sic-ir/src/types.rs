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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnionType {
    pub name: Option<String>,
    pub fields: Vec<(String, Type)>,
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
        let mut offsets = Vec::with_capacity(self.fields.len());
        let mut offset = 0u64;
        let mut max_align = 1u64;

        for (_, ty) in &self.fields {
            let align = if self.packed { 1 } else { ty.align_of(ptr_size) };
            max_align = max_align.max(align);
            // Pad to alignment
            if align > 0 {
                offset = (offset + align - 1) / align * align;
            }
            offsets.push(offset);
            offset += ty.size_of(ptr_size);
        }

        // Round total size up to struct alignment
        if max_align > 0 && !self.packed {
            offset = (offset + max_align - 1) / max_align * max_align;
        }

        (offsets, offset)
    }

    pub fn size_of(&self, ptr_size: u32) -> u64 {
        self.layout(ptr_size).1
    }

    pub fn align_of(&self, ptr_size: u32) -> u64 {
        if self.packed {
            return 1;
        }
        self.fields
            .iter()
            .map(|(_, t)| t.align_of(ptr_size))
            .max()
            .unwrap_or(1)
    }

    pub fn field_offset(&self, idx: usize, ptr_size: u32) -> u64 {
        self.layout(ptr_size).0[idx]
    }
}

impl UnionType {
    pub fn size_of(&self, ptr_size: u32) -> u64 {
        self.fields
            .iter()
            .map(|(_, t)| t.size_of(ptr_size))
            .max()
            .unwrap_or(0)
    }

    pub fn align_of(&self, ptr_size: u32) -> u64 {
        self.fields
            .iter()
            .map(|(_, t)| t.align_of(ptr_size))
            .max()
            .unwrap_or(1)
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
