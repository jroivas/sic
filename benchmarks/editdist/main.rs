// Levenshtein edit distance (two 16K-symbol strings, two-row DP).

fn edit_min3(a: i32, b: i32, c: i32) -> i32 {
    let m = if a < b { a } else { b };
    if m < c { m } else { c }
}

fn main() {
    const LA: usize = 16000;
    const LB: usize = 16000;
    let mut a = vec![0u8; LA];
    let mut b = vec![0u8; LB];
    let mut x: u32 = 66661;
    for i in 0..LA {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        a[i] = ((x / 65536) % 4) as u8;
    }
    for i in 0..LB {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        b[i] = ((x / 65536) % 4) as u8;
    }
    let mut prev = vec![0i32; LB + 1];
    let mut cur = vec![0i32; LB + 1];
    for j in 0..=LB {
        prev[j] = j as i32;
    }
    for i in 1..=LA {
        cur[0] = i as i32;
        for j in 1..=LB {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = edit_min3(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    println!("checksum {}", prev[LB] as u32);
}