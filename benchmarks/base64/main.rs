// Base64 encoding — 24M bytes, 4 rounds.
// Uses Vec buffer and static B64 table.

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn main() {
    const N: usize = 24000000;
    const R: usize = 4;
    let mut buf = vec![0u8; N];
    let mut x: u32 = 44444;
    for i in 0..N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        buf[i] = (x & 0xFF) as u8;
    }
    let mut h: u32 = 2166136261;
    for _ in 0..R {
        for i in (0..N - 2).step_by(3) {
            let b0 = buf[i] as u32;
            let b1 = buf[i + 1] as u32;
            let b2 = buf[i + 2] as u32;
            let i0 = b0 / 4;
            let i1 = (b0 & 3) * 16 + b1 / 16;
            let i2 = (b1 & 15) * 4 + b2 / 64;
            let i3 = b2 & 63;
            h ^= B64[i0 as usize] as u32;
            h = h.wrapping_mul(16777619);
            h ^= B64[i1 as usize] as u32;
            h = h.wrapping_mul(16777619);
            h ^= B64[i2 as usize] as u32;
            h = h.wrapping_mul(16777619);
            h ^= B64[i3 as usize] as u32;
            h = h.wrapping_mul(16777619);
        }
    }
    println!("checksum {}", h);
}