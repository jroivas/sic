// Recursive Fibonacci — a pure function-call / recursion benchmark.
// `black_box` keeps the compiler from folding the whole recursion to a constant or
// hoisting it, matching the C/SIC `volatile`. Prints fib(42) as a checksum.
use std::hint::black_box;

fn fib(n: i32) -> i64 {
    if n < 2 { n as i64 } else { fib(n - 1) + fib(n - 2) }
}

fn main() {
    let n = black_box(42);
    println!("{}", fib(n));
}
