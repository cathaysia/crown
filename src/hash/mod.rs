pub trait Hash: std::io::Write {
    fn sum(&mut self, input: &[u8]) -> Vec<u8>;
    fn reset(&mut self);
    fn size(&self) -> usize;
    fn block_size(&self) -> usize;
}
