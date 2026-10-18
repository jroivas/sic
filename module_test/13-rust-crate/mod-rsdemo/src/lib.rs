/// A named counter (an opaque handle type in sic).
pub struct Counter {
    n: i64,
    name: String,
}

impl Counter {
    /// The sic constructor too: `rsdemo::Counter c;`.
    pub fn new() -> Counter {
        Counter { n: 0, name: String::from("anon") }
    }
    pub fn named(name: &str) -> Self {
        Counter { n: 0, name: name.to_string() }
    }
    pub fn add(&mut self, k: i64) -> i64 {
        self.n += k;
        self.n
    }
    pub fn get(&self) -> i64 {
        self.n
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    /// `None` for zero parts.
    pub fn split(&self, parts: i64) -> Option<Counter> {
        if parts == 0 { return None; }
        Some(Counter { n: self.n / parts, name: format!("{}/{}", self.name, parts) })
    }
    pub fn merge(&mut self, other: &Counter) {
        self.n += other.n;
    }
    // Skipped: consumes self.
    pub fn into_name(self) -> String {
        self.name
    }
}

pub fn greet(name: &str) -> String {
    format!("hello, {}", name)
}
pub fn shout(s: String) -> String {
    s.to_uppercase()
}
pub fn len_ref(s: &String) -> usize {
    s.len()
}
pub fn checksum(data: &[u8]) -> u32 {
    data.iter().map(|&b| b as u32).sum()
}
pub fn reverse_bytes(mut data: Vec<u8>) -> Vec<u8> {
    data.reverse();
    data
}
pub fn sum(xs: &[i64]) -> i64 {
    xs.iter().sum()
}
pub fn double_all(xs: &mut [i32]) {
    for x in xs.iter_mut() { *x *= 2; }
}
pub fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}
pub fn words_ref(s: &str) -> Vec<&str> {
    s.split(',').collect()
}
pub fn join(xs: &Vec<String>, sep: &str) -> String {
    xs.join(sep)
}
pub fn squares(n: u32) -> Vec<u64> {
    (1..=n as u64).map(|i| i * i).collect()
}
pub fn parse_int(s: &str) -> Result<i64, std::num::ParseIntError> {
    s.trim().parse()
}
pub fn check(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("not ok".to_string()) }
}
pub fn unit_err(x: i32) -> Result<i32, ()> {
    if x >= 0 { Ok(x * 10) } else { Err(()) }
}
pub fn first_char(s: &str) -> Option<char> {
    s.chars().next()
}
pub fn next_char(c: char) -> char {
    char::from_u32(c as u32 + 1).unwrap_or(c)
}
pub fn total(c: &Counter, extra: i64) -> i64 {
    c.n + extra
}
pub fn half(x: f64) -> f64 {
    x / 2.0
}
pub fn is_even(x: u64) -> bool {
    x % 2 == 0
}
// Skipped: generic.
pub fn ident<T>(x: T) -> T {
    x
}
#[allow(dead_code)]
fn private_helper() {}

/// A module: a SIC namespace (`rsdemo::geo::…`).
pub mod geo {
    /// A point (`rsdemo::geo::Point`, re-exported as `rsdemo::Point`).
    pub struct Point {
        x: i64,
        y: i64,
    }

    impl Point {
        pub fn new(x: i64, y: i64) -> Point {
            Point { x, y }
        }
        pub fn dist2(&self) -> i64 {
            self.x * self.x + self.y * self.y
        }
        pub fn add(&self, other: &Point) -> Point {
            Point { x: self.x + other.x, y: self.y + other.y }
        }
    }

    pub fn origin() -> Point {
        Point { x: 0, y: 0 }
    }

    pub const DIM: u32 = 2;
}

pub use geo::origin as zero;
pub use geo::Point;
pub use geo::DIM;

pub const NAME: &str = "rsdemo";
pub const SCALE: f64 = -2.5;
