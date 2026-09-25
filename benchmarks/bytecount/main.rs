// Count bytes with the high bit set (>= 128) in a large buffer, several passes — a
// predicate reduction. LLVM auto-vectorizes (packed compare + mask + popcount); a
// scalar back end branches per byte. Integer count, exact regardless of order.
const N: usize = 20_000_000;
const P: usize = 20;

fn main() {
    let mut buf = vec![0u8; N];
    for i in 0..N { buf[i] = ((i * 131 + 7) & 0xff) as u8; }
    let mut cnt: i64 = 0;
    for _ in 0..P {
        for i in 0..N {
            if buf[i] >= 128 { cnt += 1; }
        }
    }
    println!("{}", cnt);
}
