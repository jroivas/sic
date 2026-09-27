// Open-addressing hash map (linear probing), 8M insert + 16M lookup, 2^24 table.

fn main() {
    const M: usize = 8000000;
    const Q: usize = 16000000;
    const SIZE: u32 = 1 << 24;
    const MASK: u32 = SIZE - 1;
    let mut keys = vec![0u32; SIZE as usize];
    let mut vals = vec![0u32; SIZE as usize];
    let mut x: u32 = 33331;
    for _ in 0..M {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let key = (x & 0x7FFFFFFF) | 1;
        let mut idx = key & MASK;
        loop {
            if keys[idx as usize] == 0 {
                keys[idx as usize] = key;
                vals[idx as usize] = x;
                break;
            }
            if keys[idx as usize] == key {
                vals[idx as usize] = vals[idx as usize].wrapping_add(x);
                break;
            }
            idx = (idx + 1) & MASK;
        }
    }
    let mut y: u32 = 99989;
    let mut acc: u32 = 0;
    for _ in 0..Q {
        y = y.wrapping_mul(1664525).wrapping_add(1013904223);
        let key = (y & 0x7FFFFFFF) | 1;
        let mut idx = key & MASK;
        let mut steps: u32 = 0;
        loop {
            steps += 1;
            if keys[idx as usize] == 0 {
                break;
            }
            if keys[idx as usize] == key {
                acc = acc.wrapping_add(vals[idx as usize]);
                break;
            }
            idx = (idx + 1) & MASK;
        }
        acc = acc.wrapping_mul(1000003).wrapping_add(steps);
    }
    println!("checksum {}", acc);
}