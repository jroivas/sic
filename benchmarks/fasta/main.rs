// fasta (n = 2500000) — the Computer Language Benchmarks Game.
// Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/fasta.html
// (algorithm as in the single-threaded programs there; revised BSD licence).
// Adapted: single-threaded; every output byte (incl. line breaks, no headers) is
// folded into an FNV-1a hash instead of being written; prints the hash.
const IM: u32 = 139968;
const IA: u32 = 3877;
const IC: u32 = 29573;
const LINE: usize = 60;

const ALU: &[u8] = b"GGCCGGGCGCGGTGGCTCACGCCTGTAATCCCAGCACTTTGG\
GAGGCCGAGGCGGGCGGATCACCTGAGGTCAGGAGTTCGAGA\
CCAGCCTGGCCAACATGGTGAAACCCCGTCTCTACTAAAAAT\
ACAAAAATTAGCCGGGCGTGGTGGCGCGCGCCTGTAATCCCA\
GCTACTCGGGAGGCTGAGGCAGGAGAATCGCTTGAACCCGGG\
AGGCGGAGGTTGCAGTGAGCCGAGATCGCGCCACTGCACTCC\
AGCCTGGGCGACAGAGCGAGACTCCGTCTCAAAAA";

struct Out { hash: u32 }
impl Out {
    fn put(&mut self, c: u8) { self.hash ^= c as u32; self.hash = self.hash.wrapping_mul(16777619); }
}

struct Rng { last: u32 }
impl Rng {
    fn gen(&mut self, max: f64) -> f64 {
        self.last = (self.last * IA + IC) % IM;
        max * self.last as f64 / IM as f64
    }
}

fn make_cumulative(t: &mut [(u8, f64)]) {
    let mut p = 0.0;
    for e in t.iter_mut() { p += e.1; e.1 = p; }
}

fn repeat_fasta(out: &mut Out, s: &[u8], n: usize) {
    let mut pos = 0;
    let mut done = 0;
    while done < n {
        let line = if n - done < LINE { n - done } else { LINE };
        for _ in 0..line {
            out.put(s[pos]);
            pos += 1;
            if pos == s.len() { pos = 0; }
        }
        out.put(b'\n');
        done += line;
    }
}

fn random_fasta(out: &mut Out, rng: &mut Rng, t: &[(u8, f64)], n: usize) {
    let mut done = 0;
    while done < n {
        let line = if n - done < LINE { n - done } else { LINE };
        for _ in 0..line {
            let r = rng.gen(1.0);
            let mut k = 0;
            while k < t.len() - 1 && r >= t[k].1 { k += 1; }
            out.put(t[k].0);
        }
        out.put(b'\n');
        done += line;
    }
}

fn main() {
    let n = 2500000;
    let mut iub = [
        (b'a', 0.27), (b'c', 0.12), (b'g', 0.12), (b't', 0.27),
        (b'B', 0.02), (b'D', 0.02), (b'H', 0.02), (b'K', 0.02), (b'M', 0.02),
        (b'N', 0.02), (b'R', 0.02), (b'S', 0.02), (b'V', 0.02), (b'W', 0.02), (b'Y', 0.02),
    ];
    let mut homosapiens = [
        (b'a', 0.3029549426680), (b'c', 0.1979883004921),
        (b'g', 0.1975473066391), (b't', 0.3015094502008),
    ];
    make_cumulative(&mut iub);
    make_cumulative(&mut homosapiens);
    let mut out = Out { hash: 2166136261 };
    let mut rng = Rng { last: 42 };
    repeat_fasta(&mut out, ALU, 2 * n);
    random_fasta(&mut out, &mut rng, &iub, 3 * n);
    random_fasta(&mut out, &mut rng, &homosapiens, 5 * n);
    println!("{}", out.hash);
}
