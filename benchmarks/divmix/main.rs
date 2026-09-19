// A compute-bound loop of integer divisions by constants (independent → throughput-
// bound). LLVM strength-reduces each `/ const` to a magic multiply + shift. Prints
// the sum.
const N: i64 = 200_000_000;

fn main() {
    let mut sum: i64 = 0;
    for i in 1..N {
        sum += i / 7 + i / 13 + i / 143 + i / 1001;
    }
    println!("{}", sum);
}
