fn bench_crc32() {
    const N: usize = 16000000;
    const R: usize = 8;
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 == 1 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        table[i as usize] = c;
    }
    let mut buf = vec![0u8; N];
    let mut x: u32 = 88881;
    for i in 0..N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        buf[i] = ((x / 65536) & 0xFF) as u8;
    }
    let mut cs: u32 = 0;
    for _ in 0..R {
        let mut crc: u32 = 0xFFFFFFFF;
        for i in 0..N {
            crc = table[((crc ^ buf[i] as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        crc ^= 0xFFFFFFFF;
        cs = cs.wrapping_mul(1000003).wrapping_add(crc);
    }
    println!("checksum {}", cs);
}

fn main() {
    bench_crc32();
}