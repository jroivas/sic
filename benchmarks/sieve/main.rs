// Sieve of Eratosthenes up to N — an array / tight-loop / memory benchmark.
// Prints the number of primes found so all language versions can be compared.
const N: usize = 100_000_000;

fn main() {
    let mut sieve = vec![1u8; N + 1];
    let mut count: i64 = 0;
    let mut i = 2usize;
    while i <= N {
        if sieve[i] == 1 {
            count += 1;
            let mut j = i * i;
            while j <= N {
                sieve[j] = 0;
                j += i;
            }
        }
        i += 1;
    }
    println!("{}", count);
}
