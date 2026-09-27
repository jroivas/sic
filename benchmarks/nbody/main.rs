// N-body gravity simulation — standalone extracted Rust benchmark
fn bench_nbody() {
    const N: usize = 2048;
    const STEPS: usize = 8;
    const DT: f64 = 0.01;
    const EPS: f64 = 0.05;
    let mut px = vec![0.0f64; N];
    let mut py = vec![0.0f64; N];
    let mut pz = vec![0.0f64; N];
    let mut vx = vec![0.0f64; N];
    let mut vy = vec![0.0f64; N];
    let mut vz = vec![0.0f64; N];
    let mut m = vec![0.0f64; N];
    let mut s: u32 = 7777;
    for i in 0..N {
        s = s.wrapping_mul(1664525).wrapping_add(1013904223);
        px[i] = ((s & 0xFFFF) as f64 / 65536.0) * 2.0 - 1.0;
        s = s.wrapping_mul(1664525).wrapping_add(1013904223);
        py[i] = ((s & 0xFFFF) as f64 / 65536.0) * 2.0 - 1.0;
        s = s.wrapping_mul(1664525).wrapping_add(1013904223);
        pz[i] = ((s & 0xFFFF) as f64 / 65536.0) * 2.0 - 1.0;
        s = s.wrapping_mul(1664525).wrapping_add(1013904223);
        m[i] = (s & 0xFFFF) as f64 / 65536.0 + 0.1;
    }
    for _ in 0..STEPS {
        for i in 0..N {
            let (mut ax, mut ay, mut az) = (0.0f64, 0.0f64, 0.0f64);
            let (xi, yi, zi) = (px[i], py[i], pz[i]);
            for j in 0..N {
                if j == i {
                    continue;
                }
                let dx = px[j] - xi;
                let dy = py[j] - yi;
                let dz = pz[j] - zi;
                let d2 = dx * dx + dy * dy + dz * dz + EPS;
                let mut g = (d2 + 1.0) * 0.5;
                for _ in 0..8 {
                    g = (g + d2 / g) * 0.5;
                }
                let inv3 = 1.0 / (d2 * g);
                let f = m[j] * inv3;
                ax += dx * f;
                ay += dy * f;
                az += dz * f;
            }
            vx[i] += ax * DT;
            vy[i] += ay * DT;
            vz[i] += az * DT;
        }
        for i in 0..N {
            px[i] += vx[i] * DT;
            py[i] += vy[i] * DT;
            pz[i] += vz[i] * DT;
        }
    }
    let mut cs: u32 = 0;
    for i in 0..N {
        cs = cs.wrapping_mul(1000003).wrapping_add((px[i] * 1024.0) as i64 as u32);
        cs = cs.wrapping_mul(1000003).wrapping_add((py[i] * 1024.0) as i64 as u32);
        cs = cs.wrapping_mul(1000003).wrapping_add((pz[i] * 1024.0) as i64 as u32);
    }
    println!("checksum {}", cs);
}

fn main() {
    bench_nbody();
}