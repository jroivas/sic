// Integer dot product of two large arrays — a pure vectorizable reduction
// (sum += a[i]*b[i]). LLVM auto-vectorizes into SIMD multiply-accumulate. Integer,
// so the sum is exact regardless of reduction order. Prints the dot product.
const N: usize = 50_000_000;

fn main() {
    let mut a = vec![0i32; N];
    let mut b = vec![0i32; N];
    for i in 0..N { a[i] = (i % 1000) as i32; b[i] = ((i * 3 + 1) % 1000) as i32; }
    let mut sum: i64 = 0;
    for i in 0..N { sum += a[i] as i64 * b[i] as i64; }
    println!("{}", sum);
}
