// Mandelbrot set point count over a W x H grid — a floating-point compute benchmark
// (double add/mul/compare in a tight iteration loop), no arrays. Prints the number
// of grid points still bounded after MAXIT iterations (in the set).
const W: i32 = 1000;
const H: i32 = 1000;
const MAXIT: i32 = 256;

fn main() {
    let mut count: i64 = 0;
    for py in 0..H {
        let y0 = py as f64 / H as f64 * 2.0 - 1.0;
        for px in 0..W {
            let x0 = px as f64 / W as f64 * 3.0 - 2.0;
            let mut x = 0.0f64;
            let mut y = 0.0f64;
            let mut it = 0;
            while x * x + y * y <= 4.0 && it < MAXIT {
                let xt = x * x - y * y + x0;
                y = 2.0 * x * y + y0;
                x = xt;
                it += 1;
            }
            if it == MAXIT {
                count += 1;
            }
        }
    }
    println!("{}", count);
}
