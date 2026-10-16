//! `long double` (x86-64 SysV: x87 80-bit extended precision in a 16-byte,
//! 16-aligned slot). sic computes it as a 64-bit `double` but keeps the real
//! 80-bit format in memory and at every C boundary, so structs, pointers,
//! by-value arguments, varargs and `st(0)` returns match gcc bit for bit; only
//! the precision of sic's own arithmetic is that of `double`.
//!
//! The backend converts at those boundaries with four tiny x87 helpers, emitted
//! as module-local machine code (bytes from GNU `as`):
//!
//! ```text
//! __sic_f80_load:  fldt (%rdi); fstpl -8(%rsp); movsd -8(%rsp),%xmm0; ret   double (const void *)
//! __sic_f80_store: movsd %xmm0,-8(%rsp); fldl -8(%rsp); fstpt (%rdi); ret   void (void *, double)
//! __sic_f80_st0:   fstpl -8(%rsp); movsd -8(%rsp),%xmm0; ret                double (): pop st(0)
//! __sic_f80_ret:   movsd %xmm0,-8(%rsp); fldl -8(%rsp); ret                 void (double): push st(0)
//! ```
//!
//! `st0`/`ret` implement the return convention: a call of a function returning
//! `long double` is followed by `__sic_f80_st0` (Cranelift itself never uses
//! the x87 stack, so `st(0)` survives until then), and such a function calls
//! `__sic_f80_ret` right before it returns.

pub const F80_LOAD: &str = "__sic_f80_load";
pub const F80_STORE: &str = "__sic_f80_store";
pub const F80_ST0: &str = "__sic_f80_st0";
pub const F80_RET: &str = "__sic_f80_ret";

/// Machine code of each helper, by symbol name.
pub const F80_HELPERS: &[(&str, &[u8])] = &[
    (F80_LOAD, &[0xdb, 0x2f, 0xdd, 0x5c, 0x24, 0xf8, 0xf2, 0x0f, 0x10, 0x44, 0x24, 0xf8, 0xc3]),
    (F80_STORE, &[0xf2, 0x0f, 0x11, 0x44, 0x24, 0xf8, 0xdd, 0x44, 0x24, 0xf8, 0xdb, 0x3f, 0xc3]),
    (F80_ST0, &[0xdd, 0x5c, 0x24, 0xf8, 0xf2, 0x0f, 0x10, 0x44, 0x24, 0xf8, 0xc3]),
    (F80_RET, &[0xf2, 0x0f, 0x11, 0x44, 0x24, 0xf8, 0xdd, 0x44, 0x24, 0xf8, 0xc3]),
];

/// The 16-byte memory image of `v` as an x87 extended-precision value (10
/// significant bytes, little-endian, then 6 zero padding bytes). Exact: every
/// `double` (including subnormals, infinities and NaNs) is representable.
pub fn f64_to_f80_bytes(v: f64) -> [u8; 16] {
    let bits = v.to_bits();
    let sign = (bits >> 63) as u16;
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    let (e80, mant): (u16, u64) = if exp == 0 {
        if frac == 0 {
            (0, 0)
        } else {
            // Subnormal double = frac * 2^-1074: normalize (explicit integer bit).
            let lz = frac.leading_zeros() as i32;
            ((15372 - lz) as u16, frac << lz)
        }
    } else if exp == 0x7ff {
        (0x7fff, (1u64 << 63) | (frac << 11))
    } else {
        ((exp - 1023 + 16383) as u16, (1u64 << 63) | (frac << 11))
    };
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&mant.to_le_bytes());
    out[8..10].copy_from_slice(&((sign << 15) | e80).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_images() {
        // gcc: `long double x = 1.0L` → 00..80 ff 3f.
        assert_eq!(f64_to_f80_bytes(1.0)[..10], [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]);
        assert_eq!(f64_to_f80_bytes(-2.0)[..10], [0, 0, 0, 0, 0, 0, 0, 0x80, 0x00, 0xc0]);
        assert_eq!(f64_to_f80_bytes(0.0), [0u8; 16]);
        // Smallest subnormal double, 2^-1074: exponent 16383-1074.
        let b = f64_to_f80_bytes(f64::from_bits(1));
        assert_eq!(u16::from_le_bytes([b[8], b[9]]), 16383 - 1074);
        assert_eq!(u64::from_le_bytes(b[..8].try_into().unwrap()), 1u64 << 63);
        assert_eq!(f64_to_f80_bytes(f64::INFINITY)[..10], [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x7f]);
    }
}
