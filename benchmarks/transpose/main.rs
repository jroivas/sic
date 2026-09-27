// Naive out-of-place matrix transpose (4096x4096, 6 rounds).

fn main() {
    const NDIM: usize = 4096;
    const R: usize = 6;
    let mut src = vec![0u32; NDIM * NDIM];
    let mut dst = vec![0u32; NDIM * NDIM];
    let mut x: u32 = 55551;
    for i in 0..NDIM * NDIM {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        src[i] = x;
    }
    for _ in 0..R {
        for i in 0..NDIM {
            for j in 0..NDIM {
                dst[j * NDIM + i] = src[i * NDIM + j];
            }
        }
        std::mem::swap(&mut src, &mut dst);
    }
    let mut cs: u32 = 0;
    for i in 0..NDIM * NDIM {
        cs = cs.wrapping_mul(1000003).wrapping_add(src[i]);
    }
    println!("checksum {}", cs);
}