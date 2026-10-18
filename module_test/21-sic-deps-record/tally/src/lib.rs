/// A counter of words.
pub struct Tally {
    n: u64,
}

impl Tally {
    pub fn new() -> Tally {
        Tally { n: 0 }
    }
    pub fn add(&mut self, text: &str) -> u64 {
        self.n += text.split_whitespace().count() as u64;
        self.n
    }
}
