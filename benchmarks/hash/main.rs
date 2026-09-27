// FNV-1a hash — a pure arithmetic / memory-read benchmark. Fills 32M bytes with
// LCG values, then runs 4 rounds of FNV-1a hashing. Prints checksum so all
// language versions can be compared.
fn bench_hash() {
    const N: usize = 32000000;
    const R: usize = 4;
    let mut buf = vec![0u8; N];
    let mut x: u32 = 12345;
    for i in 0..N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        buf[i] = (x & 0xFF) as u8;
    }
    let mut h: u32 = 2166136261;
    for _ in 0..R {
        for i in 0..N {
            h ^= buf[i] as u32;
            h = h.wrapping_mul(16777619);
        }
    }
    println!("checksum {}", h);
}

fn main() {
    bench_hash();
}