/// A generic box: `gen::Cell<i32>` and `gen::Cell<u64>` are different types.
pub struct Cell<T> {
    v: T,
}

impl<T: Copy + Default> Cell<T> {
    pub fn new() -> Self {
        Cell { v: T::default() }
    }
    pub fn get(&self) -> T {
        self.v
    }
}
