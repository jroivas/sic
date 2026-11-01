//! Hash maps for compiler-internal keys: mostly small integers (`ValId`, block
//! numbers) in maps rebuilt for every function. The standard hasher is SipHash,
//! made to resist attacks no compiler input needs to fear; it was 10% of a run.
//! This one is a rotate, an xor and a multiply per word, and has no random seed,
//! so a map's iteration order is the same on every run.

use std::hash::{BuildHasherDefault, Hasher};

const K: u64 = 0x517c_c1b7_2722_0a95;

#[derive(Default, Clone, Copy)]
pub struct FastHasher { h: u64 }

impl FastHasher {
    #[inline]
    fn add(&mut self, w: u64) { self.h = (self.h.rotate_left(5) ^ w).wrapping_mul(K); }
}

impl Hasher for FastHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks { self.add(u64::from_le_bytes(c.try_into().unwrap())); }
        for &b in chunks.remainder() { self.add(b as u64); }
    }
    #[inline] fn write_u8(&mut self, v: u8) { self.add(v as u64); }
    #[inline] fn write_u16(&mut self, v: u16) { self.add(v as u64); }
    #[inline] fn write_u32(&mut self, v: u32) { self.add(v as u64); }
    #[inline] fn write_u64(&mut self, v: u64) { self.add(v); }
    #[inline] fn write_usize(&mut self, v: usize) { self.add(v as u64); }
    #[inline] fn finish(&self) -> u64 { self.h }
}

pub type HashMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<FastHasher>>;
pub type HashSet<K> = std::collections::HashSet<K, BuildHasherDefault<FastHasher>>;
