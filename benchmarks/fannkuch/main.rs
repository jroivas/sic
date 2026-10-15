// fannkuch-redux (n = 10) — the Computer Language Benchmarks Game.
// Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/fannkuchredux.html
// (algorithm as in the single-threaded programs there; revised BSD licence).
// Adapted: single-threaded, fixed n, prints checksum*1000 + maxflips.
const N: usize = 10;

fn main() {
    let mut perm = [0i32; N];
    let mut perm1 = [0i32; N];
    let mut count = [0i32; N];
    let (mut maxflips, mut checksum, mut permcount) = (0i32, 0i32, 0i32);
    for i in 0..N { perm1[i] = i as i32; }
    let mut r = N;
    loop {
        while r != 1 { count[r - 1] = r as i32; r -= 1; }
        perm.copy_from_slice(&perm1);
        let mut flips = 0;
        let mut k = perm[0] as usize;
        while k != 0 {
            perm[..=k].reverse();
            flips += 1;
            k = perm[0] as usize;
        }
        if flips > maxflips { maxflips = flips; }
        checksum += if permcount % 2 == 0 { flips } else { -flips };
        loop {
            if r == N {
                println!("{}", checksum * 1000 + maxflips);
                return;
            }
            let perm0 = perm1[0];
            for i in 0..r { perm1[i] = perm1[i + 1]; }
            perm1[r] = perm0;
            count[r] -= 1;
            if count[r] > 0 { break; }
            r += 1;
        }
        permcount += 1;
    }
}
