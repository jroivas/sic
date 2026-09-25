// 1-D 3-point blur (weighted [1 2 1]/4), many passes. LLVM auto-vectorizes the
// stencil with shifted packed loads; a scalar back end pays per element. Checksum
// sums the truncated values as integers, so it is bit-stable across builds.
const N: usize = 100_000;
const P: usize = 3000;

fn main() {
    let mut a = vec![0.0f64; N];
    let mut b = vec![0.0f64; N];
    for i in 0..N { a[i] = (i % 251) as f64; }
    for _ in 0..P {
        for i in 1..N - 1 { b[i] = (a[i - 1] + 2.0 * a[i] + a[i + 1]) * 0.25; }
        for i in 1..N - 1 { a[i] = b[i]; }
    }
    let mut sum: i64 = 0;
    for i in 0..N { sum += a[i] as i64; }
    println!("{}", sum);
}
