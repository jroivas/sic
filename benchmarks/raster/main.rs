// Software 3D rasterizer — renders a spinning, Gouraud-shaded UV sphere into an
// in-memory framebuffer with a z-buffer, for a fixed number of frames. Uses only
// +,-,*,/ and a hand-rolled polynomial sin/cos (libm's differ per language) so
// every language produces a bit-identical checksum.
use std::hint::black_box;

fn r_floor(y: f64) -> f64 {
    let f = (y as i64) as f64;
    if f > y { f - 1.0 } else { f }
}

fn r_sin(mut x: f64) -> f64 {
    const TWO_PI: f64 = 6.283185307179586;
    let k = r_floor(x / TWO_PI + 0.5);
    x = x - k * TWO_PI;
    let x2 = x * x;
    let mut p = -1.0 / 1307674368000.0;
    p = 1.0 / 6227020800.0 + x2 * p;
    p = -1.0 / 39916800.0 + x2 * p;
    p = 1.0 / 362880.0 + x2 * p;
    p = -1.0 / 5040.0 + x2 * p;
    p = 1.0 / 120.0 + x2 * p;
    p = -1.0 / 6.0 + x2 * p;
    p = 1.0 + x2 * p;
    x * p
}

fn r_cos(x: f64) -> f64 {
    const HALF_PI: f64 = 1.5707963267948966;
    r_sin(x + HALF_PI)
}

fn edge(ax: f64, ay: f64, bx: f64, by: f64, cx: f64, cy: f64) -> f64 {
    (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)
}

fn bench_raster() {
    const W: usize = 640;
    const H: usize = 480;
    const RINGS: usize = 24;
    const SECTORS: usize = 24;
    const FRAMES: usize = 240;
    const NV: usize = (RINGS + 1) * (SECTORS + 1);
    const FOCAL: f64 = 500.0;
    const CAM_DIST: f64 = 3.0;

    let (mut bx, mut by, mut bz) = (vec![0f64; NV], vec![0f64; NV], vec![0f64; NV]);
    let mut nv: usize = 0;
    for i in 0..=RINGS {
        let theta = 3.141592653589793 * (i as f64 / RINGS as f64);
        let st = r_sin(theta);
        let ct = r_cos(theta);
        for j in 0..=SECTORS {
            let phi = 6.283185307179586 * (j as f64 / SECTORS as f64);
            let sp = r_sin(phi);
            let cp = r_cos(phi);
            bx[nv] = st * cp;
            by[nv] = ct;
            bz[nv] = st * sp;
            nv += 1;
        }
    }

    let (mut sx, mut sy, mut sz, mut si) = (vec![0f64; NV], vec![0f64; NV], vec![0f64; NV], vec![0f64; NV]);

    let mut color = vec![0u8; W * H];
    let mut zbuf = vec![0f64; W * H];

    let mut checksum: u64 = 0;

    for f in 0..FRAMES {
        let ang = f as f64 * 0.0125;
        let cy = r_cos(ang);
        let syr = r_sin(ang);
        let axx = ang * 0.5;
        let cx = r_cos(axx);
        let sxr = r_sin(axx);

        for v in 0..nv {
            let (px0, py0, pz0) = (bx[v], by[v], bz[v]);
            let rx = px0 * cy + pz0 * syr;
            let rz = -px0 * syr + pz0 * cy;
            let ry = py0;
            let ry2 = ry * cx - rz * sxr;
            let rz2 = ry * sxr + rz * cx;
            let mut inten = -rz2;
            if inten < 0.0 { inten = 0.0; }
            let zc = rz2 + CAM_DIST;
            let invz = 1.0 / zc;
            sx[v] = rx * invz * FOCAL + W as f64 * 0.5;
            sy[v] = ry2 * invz * FOCAL + H as f64 * 0.5;
            sz[v] = zc;
            si[v] = inten;
        }

        for i in 0..W * H { color[i] = 0; zbuf[i] = 1.0e30; }

        for ri in 0..RINGS {
            for sj in 0..SECTORS {
                let a = ri * (SECTORS + 1) + sj;
                let b = a + (SECTORS + 1);
                let tris = [[a, b, a + 1], [a + 1, b, b + 1]];
                for t in 0..2 {
                    let (i0, i1, i2) = (tris[t][0], tris[t][1], tris[t][2]);
                    let area = edge(sx[i0], sy[i0], sx[i1], sy[i1], sx[i2], sy[i2]);
                    if area <= 0.0 { continue; }
                    let mut mnx = sx[i0];
                    if sx[i1] < mnx { mnx = sx[i1]; }
                    if sx[i2] < mnx { mnx = sx[i2]; }
                    let mut mxx = sx[i0];
                    if sx[i1] > mxx { mxx = sx[i1]; }
                    if sx[i2] > mxx { mxx = sx[i2]; }
                    let mut mny = sy[i0];
                    if sy[i1] < mny { mny = sy[i1]; }
                    if sy[i2] < mny { mny = sy[i2]; }
                    let mut mxy = sy[i0];
                    if sy[i1] > mxy { mxy = sy[i1]; }
                    if sy[i2] > mxy { mxy = sy[i2]; }
                    if mnx < 0.0 { mnx = 0.0; }
                    if mxx > (W - 1) as f64 { mxx = (W - 1) as f64; }
                    if mny < 0.0 { mny = 0.0; }
                    if mxy > (H - 1) as f64 { mxy = (H - 1) as f64; }
                    let (x0, x1) = (mnx as usize, mxx as usize);
                    let (y0, y1) = (mny as usize, mxy as usize);
                    for py in y0..=y1 {
                        let pcy = py as f64 + 0.5;
                        for px in x0..=x1 {
                            let pcx = px as f64 + 0.5;
                            let w0 = edge(sx[i1], sy[i1], sx[i2], sy[i2], pcx, pcy);
                            let w1 = edge(sx[i2], sy[i2], sx[i0], sy[i0], pcx, pcy);
                            let w2 = edge(sx[i0], sy[i0], sx[i1], sy[i1], pcx, pcy);
                            if w0 >= 0.0 && w1 >= 0.0 && w2 >= 0.0 {
                                let (l0, l1, l2) = (w0 / area, w1 / area, w2 / area);
                                let depth = l0 * sz[i0] + l1 * sz[i1] + l2 * sz[i2];
                                let idx = py * W + px;
                                if depth < zbuf[idx] {
                                    zbuf[idx] = depth;
                                    let mut inten = l0 * si[i0] + l1 * si[i1] + l2 * si[i2];
                                    if inten < 0.0 { inten = 0.0; }
                                    if inten > 1.0 { inten = 1.0; }
                                    color[idx] = (inten * 255.0) as u8;
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut frame_sum: u64 = 0;
        for i in 0..W * H { frame_sum = frame_sum.wrapping_add(color[i] as u64); }
        checksum = checksum.wrapping_mul(1000003).wrapping_add(frame_sum);
    }

    println!("checksum {}", checksum);
}

fn main() {
    bench_raster();
}