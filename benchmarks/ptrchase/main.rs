// Pointer-chasing (random memory latency) — a random permutation traversal
// benchmark. Creates a 16M-element random permutation via Fisher-Yates shuffle,
// then chases through it for 4M hops. Prints checksum so all language versions
// can be compared.
fn bench_ptrchase() {
    const N: usize = 16000000;
    const HOPS: u64 = 4000000;
    let mut order = vec![0u32; N];
    let mut next = vec![0u32; N];
    for i in 0..N {
        order[i] = i as u32;
    }
    let mut x: u32 = 1;
    for i in (1..N).rev() {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let j = ((x & 0x7FFFFFFF) % (i as u32 + 1)) as usize;
        order.swap(i, j);
    }
    for k in 0..N {
        next[order[k] as usize] = order[(k + 1) % N];
    }
    let (mut sum, mut p): (u32, u32) = (0, 0);
    for _ in 0..HOPS {
        p = next[p as usize];
        sum = sum.wrapping_add(p);
    }
    println!("checksum {}", sum);
}

fn main() {
    bench_ptrchase();
}