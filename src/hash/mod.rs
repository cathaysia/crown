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

pub trait HashVariable: std::io::Write + HashUser {
    fn sum(&mut self, sum: &mut [u8]) -> usize;
    fn sum_vec(&mut self) -> Vec<u8> {
        let mut ret = vec![0u8; self.size()];
        let len = self.sum(&mut ret);
        ret.reserve(len);
        ret
    }
}
