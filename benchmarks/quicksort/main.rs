// In-place quicksort of N pseudo-random ints — recursion, data-dependent branching
// and swaps, irregular array access. Recurses into the smaller partition and loops
// on the larger, bounding stack depth to O(log N). Prints an order-dependent
// checksum. Slice indexing is bounds-checked (Rust is a safe language too).
const N: usize = 3_000_000;

fn qsort_ints(a: &mut [i32], mut lo: isize, mut hi: isize) {
    while lo < hi {
        let pivot = a[hi as usize];
        let mut i = lo;
        let mut j = lo;
        while j < hi {
            if a[j as usize] < pivot {
                a.swap(i as usize, j as usize);
                i += 1;
            }
            j += 1;
        }
        a.swap(i as usize, hi as usize);
        if i - lo < hi - i { qsort_ints(a, lo, i - 1); lo = i + 1; }
        else               { qsort_ints(a, i + 1, hi); hi = i - 1; }
    }
}

fn main() {
    let mut a = vec![0i32; N];
    let mut s: u64 = 123456789;
    for i in 0..N {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        a[i] = ((s >> 33) % 1000000) as i32;
    }
    qsort_ints(&mut a, 0, N as isize - 1);
    let mut sum: i64 = 0;
    for i in 0..N {
        sum += a[i] as i64 * (i % 251) as i64;
    }
    println!("{}", sum);
}
