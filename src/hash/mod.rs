mod erased;
pub use erased::*;

pub trait HashUser {
    fn reset(&mut self);
    fn size(&self) -> usize;
    fn block_size(&self) -> usize;
}

pub trait Hash<const N: usize>: std::io::Write + HashUser {
    fn sum(&mut self) -> [u8; N];
}
