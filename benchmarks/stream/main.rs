// STREAM triad — standalone extracted Rust benchmark
fn bench_stream() {
    const N: usize = 16000000;
    const R: usize = 40;
    const K: u32 = 3;
    let mut a = vec![0u32; N];
    let mut b = vec![0u32; N];
    let mut c = vec![0u32; N];
    let mut x: u32 = 11111;
    for i in 0..N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        b[i] = x;
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        c[i] = x;
    }
    for _ in 0..R {
        for i in 0..N {
            a[i] = b[i].wrapping_add(K.wrapping_mul(c[i]));
        }
    }
    let mut cs: u32 = 0;
    for i in 0..N {
        cs = cs.wrapping_mul(1000003).wrapping_add(a[i]);
    }
    println!("checksum {}", cs);
}

fn main() {
    bench_stream();
}