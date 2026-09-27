// Run-length encoding — 40M byte buffer, 4 rounds.
// Uses Vec allocation and FNV hash per round.

fn main() {
    const N: usize = 40000000;
    const R: usize = 4;
    let mut buf = vec![0u8; N];
    let mut out = vec![0u8; 2 * N];
    let mut x: u32 = 33333;
    let mut i: usize = 0;
    while i < N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let v = (x & 0xFF) as u8;
        let rl = ((x & 0x7FFFFFFF) % 16) + 1;
        let mut c: u32 = 0;
        while c < rl && i < N {
            buf[i] = v;
            i += 1;
            c += 1;
        }
    }
    let mut h: u32 = 2166136261;
    for _ in 0..R {
        let (mut o, mut p): (usize, usize) = (0, 0);
        while p < N {
            let v = buf[p];
            let mut run: usize = 1;
            while p + run < N && buf[p + run] == v && run < 255 {
                run += 1;
            }
            out[o] = run as u8;
            out[o + 1] = v;
            o += 2;
            p += run;
        }
        for k in 0..o {
            h ^= out[k] as u32;
            h = h.wrapping_mul(16777619);
        }
        h ^= (o % 256) as u32;
        h = h.wrapping_mul(16777619);
        h ^= ((o / 256) % 256) as u32;
        h = h.wrapping_mul(16777619);
        h ^= ((o / 65536) % 256) as u32;
        h = h.wrapping_mul(16777619);
        h ^= ((o / 16777216) % 256) as u32;
        h = h.wrapping_mul(16777619);
    }
    println!("checksum {}", h);
}