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
    /// sic struct reordering (sic.md §"Struct reordering"): when `Some(perm)`,
    /// fields are physically placed in `perm` order (a permutation of field
    /// indices) instead of declaration order, but offsets are still reported per
    /// declaration index — so initializers and by-name access are unaffected while
    /// padding shrinks. `None` = declaration order (the C layout).
    pub layout_order: Option<Vec<usize>>,
}

impl StructType {
    /// Construct a plain (bit-field-free) struct.
    pub fn plain(name: Option<String>, fields: Vec<(String, Type)>, packed: bool) -> Self {
        StructType { name, fields, packed, bitfields: Vec::new(), field_aligns: Vec::new(), min_align: None, layout_order: None }
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
            // Natural alignment is the byte size, capped at 16 (the max scalar
            // alignment on x86-64 SysV). NB: `__int128` is 16-byte aligned — a
            // `.min(ptr_size)` here would wrongly cap it to 8, mis-laying out
            // every struct with an `Int128` (QEMU's MemoryRegion et al.) and
            // breaking 128-bit atomics.
            Type::Int { bits, .. } => ((*bits as u64 + 7) / 8).min(16),
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
        let n = self.fields.len();
        // Offsets are indexed by DECLARATION order even when a `layout_order`
        // permutation places fields physically in a different sequence.
        let mut byte_offsets = vec![0u64; n];
        let mut bit_offsets = vec![0u32; n];
        let mut bit_pos: u64 = 0; // running position in bits
        let mut max_align = 1u64;

        // Physical placement order: the reorder permutation (sic), else declared.
        let order: Vec<usize> = match &self.layout_order {
            Some(p) if p.len() == n => p.clone(),
            _ => (0..n).collect(),
        };

        for &i in &order {
            let ty = &self.fields[i].1;
            let align = self.field_align(i, ty, ptr_size);
            let size = ty.size_of(ptr_size);
            match self.bitfield_width(i) {
                Some(width) => {
                    max_align = max_align.max(align);
                    let width = width as u64;
                    if width == 0 {
                        // Zero-width bit-field: align the next field to `align`.
                        bit_pos = round_up_bits(bit_pos, align * 8);
                        byte_offsets[i] = bit_pos / 8;
                        bit_offsets[i] = 0;
                        continue;
                    }
                    let unit_bits = size * 8;
                    if unit_bits > 0 && (bit_pos % unit_bits) + width > unit_bits {
                        bit_pos = round_up_bits(bit_pos, unit_bits);
                    }
                    let unit_start = if unit_bits > 0 { (bit_pos / unit_bits) * unit_bits } else { bit_pos };
                    byte_offsets[i] = unit_start / 8;
                    bit_offsets[i] = (bit_pos - unit_start) as u32;
                    bit_pos += width;
                }
                None => {
                    max_align = max_align.max(align);
                    bit_pos = round_up_bits(bit_pos, align * 8);
                    byte_offsets[i] = bit_pos / 8;
                    bit_offsets[i] = 0;
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

    /// sic struct reordering (sic.md §"Struct reordering"): compute the physical
    /// field placement that minimizes padding, per a fixed, standardized rule set:
    ///
    ///   1. **Primary key** — the field's storage size (`size_of`), largest first.
    ///   2. **Secondary key** — declaration order: fields of equal size keep their
    ///      written order (a stable sort), so `u32 a; u32 b;` always lays out `a`
    ///      before `b`, no matter what fields sit between them.
    ///   3. A **union** field sorts by its storage size, i.e. its largest member
    ///      (this is just rule 1 applied to `Type::Union::size_of`).
    ///   4. **Only the size is compared** — never signedness, kind, or any other
    ///      property (`i32` and `u32` are interchangeable for ordering).
    ///
    /// Returns `Some(perm)` — a permutation of field indices — only when it actually
    /// changes the order. Returns `None` when the layout must stay exactly as
    /// written: a `packed` struct, any bit-field, any member `aligned(n)`, or a
    /// type-level `aligned(n)` (those forms pin the C layout). The reordering is
    /// also *overridable* per struct (`__order__`) and only applies in sic mode;
    /// that policy gating lives in the caller, and the chosen permutation is carried
    /// in module manifests so a consumer sees the same layout.
    pub fn compute_size_order(&self, ptr_size: u32) -> Option<Vec<usize>> {
        if self.packed
            || !self.bitfields.is_empty()
            || !self.field_aligns.is_empty()
            || self.min_align.is_some()
        {
            return None;
        }
        let mut order: Vec<usize> = (0..self.fields.len()).collect();
        // Stable sort on size only (descending) → rules 1, 2, 4; rule 3 falls out
        // of `Union::size_of` returning the largest member's size.
        order.sort_by(|&a, &b| self.fields[b].1.size_of(ptr_size).cmp(&self.fields[a].1.size_of(ptr_size)));
        if order.iter().enumerate().any(|(i, &o)| i != o) { Some(order) } else { None }
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

#[cfg(test)]
mod reorder_tests {
    use super::*;

    fn i(bits: u32) -> Type { Type::Int { bits, signed: true } }
    fn u(bits: u32) -> Type { Type::Int { bits, signed: false } }

    fn st(fields: Vec<(&str, Type)>) -> StructType {
        StructType::plain(Some("t".into()), fields.into_iter().map(|(n, t)| (n.into(), t)).collect(), false)
    }

    // Rule 1: largest storage size first.
    #[test]
    fn primary_key_is_size_largest_first() {
        let s = st(vec![("a", i(32)), ("b", i(64)), ("c", i(8)), ("d", i(32))]);
        assert_eq!(s.compute_size_order(8), Some(vec![1, 0, 3, 2]));
    }

    // Rule 2: equal-size fields keep declaration order (stable), across gaps.
    #[test]
    fn ties_keep_declaration_order() {
        // a,b,c all size 4; big is size 8 and sits between them.
        let s = st(vec![("a", i(32)), ("big", i(64)), ("b", i(32)), ("c", i(32))]);
        assert_eq!(s.compute_size_order(8), Some(vec![1, 0, 2, 3]));
        // Already sorted equal-size fields → no reorder at all.
        let s2 = st(vec![("a", u(32)), ("b", u(32))]);
        assert_eq!(s2.compute_size_order(8), None);
    }

    // Rule 3: a union field sorts by its largest member.
    #[test]
    fn union_sorts_by_largest_member() {
        let uni = Type::Union(UnionType {
            name: None,
            fields: vec![("x".into(), i(16)), ("y".into(), i(64))],
            field_aligns: Vec::new(),
            min_align: None,
        });
        // union (8) should lead the i32.
        let s = st(vec![("small", i(32)), ("un", uni)]);
        assert_eq!(s.compute_size_order(8), Some(vec![1, 0]));
    }

    // Rule 5: only size is compared — signedness is irrelevant, so an i32/u32
    // pair is already ordered and never swapped.
    #[test]
    fn signedness_is_ignored() {
        let s = st(vec![("a", i(32)), ("b", u(32))]);
        assert_eq!(s.compute_size_order(8), None);
    }

    // Override forms pin the C layout: no reordering.
    #[test]
    fn packed_and_aligned_are_not_reordered() {
        let mut packed = st(vec![("a", i(8)), ("b", i(64))]);
        packed.packed = true;
        assert_eq!(packed.compute_size_order(8), None);

        let mut min_aligned = st(vec![("a", i(8)), ("b", i(64))]);
        min_aligned.min_align = Some(16);
        assert_eq!(min_aligned.compute_size_order(8), None);
    }
}
