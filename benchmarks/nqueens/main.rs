// N-queens backtracking — standalone extracted Rust benchmark
fn nq_solve(cols: u32, d1: u32, d2: u32, full: u32) -> u64 {
    if cols == full {
        return 1;
    }
    let mut count: u64 = 0;
    let mut avail = !(cols | d1 | d2) & full;
    while avail != 0 {
        let bit = avail & avail.wrapping_neg();
        avail -= bit;
        count += nq_solve(cols | bit, (d1 | bit).wrapping_mul(2) & full, (d2 | bit) / 2, full);
    }
    count
}

fn bench_nqueens() {
    const NQ: u32 = 14;
    let full = (1u32 << NQ) - 1;
    let total = nq_solve(0, 0, 0, full);
    println!("checksum {}", total);
}

fn main() {
    bench_nqueens();
}