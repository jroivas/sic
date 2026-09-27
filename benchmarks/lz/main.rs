fn bench_lz() {
    const N: usize = 4000000;
    const WIN: usize = 512;
    const MAXLEN: usize = 64;
    let mut buf = vec![0u8; N];
    let mut x: u32 = 77771;
    for i in 0..N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        buf[i] = ((x / 65536) % 8) as u8;
    }
    let mut h: u32 = 2166136261;
    let mut p = 0usize;
    while p < N {
        let lo = if p > WIN { p - WIN } else { 0 };
        let mut bestlen = 0usize;
        let mut bestoff = 0usize;
        for sidx in lo..p {
            let mut len = 0usize;
            while p + len < N && len < MAXLEN && buf[sidx + len] == buf[p + len] {
                len += 1;
            }
            if len > bestlen {
                bestlen = len;
                bestoff = p - sidx;
            }
        }
        if bestlen >= 3 {
            h ^= (bestoff & 0xFF) as u32;
            h = h.wrapping_mul(16777619);
            h ^= ((bestoff / 256) & 0xFF) as u32;
            h = h.wrapping_mul(16777619);
            h ^= (bestlen & 0xFF) as u32;
            h = h.wrapping_mul(16777619);
            p += bestlen;
        } else {
            h ^= buf[p] as u32;
            h = h.wrapping_mul(16777619);
            p += 1;
        }
    }
    println!("checksum {}", h);
}

fn main() {
    bench_lz();
}