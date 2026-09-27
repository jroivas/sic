// Conway's Game of Life — standalone extracted Rust benchmark
fn bench_life() {
    const W: usize = 1024;
    const H: usize = 1024;
    const T: usize = 300;
    let mut cur = vec![0u8; W * H];
    let mut nxt = vec![0u8; W * H];
    let mut x: u32 = 22221;
    for i in 0..W * H {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        cur[i] = ((x / 65536) & 1) as u8;
    }
    for _ in 0..T {
        for y in 0..H {
            let ym = if y == 0 { H - 1 } else { y - 1 };
            let yp = if y == H - 1 { 0 } else { y + 1 };
            for xx in 0..W {
                let xm = if xx == 0 { W - 1 } else { xx - 1 };
                let xp = if xx == W - 1 { 0 } else { xx + 1 };
                let n = cur[ym * W + xm] as i32
                    + cur[ym * W + xx] as i32
                    + cur[ym * W + xp] as i32
                    + cur[y * W + xm] as i32
                    + cur[y * W + xp] as i32
                    + cur[yp * W + xm] as i32
                    + cur[yp * W + xx] as i32
                    + cur[yp * W + xp] as i32;
                let alive = cur[y * W + xx];
                nxt[y * W + xx] = if n == 3 || (alive == 1 && n == 2) { 1 } else { 0 };
            }
        }
        std::mem::swap(&mut cur, &mut nxt);
    }
    let mut cs: u32 = 0;
    for i in 0..W * H {
        cs = cs.wrapping_mul(1000003).wrapping_add(cur[i] as u32);
    }
    println!("checksum {}", cs);
}

fn main() {
    bench_life();
}