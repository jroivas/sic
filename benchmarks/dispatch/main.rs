// Indirect dispatch — 4M ops, 32 rounds.
// Uses Vec buffers and function pointer array dispatch.

fn op_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}
fn op_xor(a: u32, b: u32) -> u32 {
    a ^ b
}
fn op_mul(a: u32, b: u32) -> u32 {
    a.wrapping_mul(b | 1)
}
fn op_sub(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b)
}

fn main() {
    const N: usize = 4000000;
    const R: usize = 32;
    let mut code = vec![0u8; N];
    let mut operand = vec![0u32; N];
    let mut x: u32 = 55555;
    for i in 0..N {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        code[i] = ((x & 0x7FFFFFFF) % 4) as u8;
        operand[i] = x;
    }
    let fns: [fn(u32, u32) -> u32; 4] = [op_add, op_xor, op_mul, op_sub];
    let mut acc: u32 = 2166136261;
    for _ in 0..R {
        for i in 0..N {
            acc = fns[code[i] as usize](acc, operand[i]);
        }
    }
    println!("checksum {}", acc);
}