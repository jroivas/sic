// Dense integer matrix multiply (N x N), i-k-j order — a nested-loop / array
// indexing / arithmetic benchmark. Prints a checksum (sum of the product matrix)
// so all language versions can be compared.
const N: usize = 1024;

fn main() {
    let mut a = vec![0i32; N * N];
    let mut b = vec![0i32; N * N];
    let mut c = vec![0i32; N * N];
    for i in 0..N * N {
        a[i] = ((i as i64 * 7 + 1) % 100) as i32;
        b[i] = ((i as i64 * 3 + 2) % 100) as i32;
    }
    for i in 0..N {
        for k in 0..N {
            let aik = a[i * N + k];
            for j in 0..N {
                c[i * N + j] += aik * b[k * N + j];
            }
        }
    }
    let mut sum: i64 = 0;
    for i in 0..N * N {
        sum += c[i] as i64;
    }
    println!("{}", sum);
}
