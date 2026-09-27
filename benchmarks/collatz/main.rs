// Collatz conjecture step-count sum — a pure arithmetic / branch-prediction
// benchmark. Sums the number of Collatz steps for 1..N and prints the checksum
// so all language versions can be compared.
fn bench_collatz() {
    const N: u64 = 3_000_000;
    let mut total: u64 = 0;
    for i in 1..=N {
        let (mut n, mut steps): (u64, u64) = (i, 0);
        while n != 1 {
            n = if n % 2 == 0 { n / 2 } else { 3 * n + 1 };
            steps += 1;
        }
        total = total.wrapping_add(steps);
    }
    println!("checksum {}", total);
}

fn main() {
    bench_collatz();
}