use super::*;
use std::io::Write;

trait ErasedHashInner: Write + HashUser {
    fn sum(&mut self) -> Vec<u8>;
}

pub struct ErasedHash(Box<dyn ErasedHashInner>);

impl ErasedHash {
    pub fn new<T, const N: usize>(h: T) -> Self
    where
        T: Hash<N> + 'static,
    {
        struct Wrapper<T, const N: usize>(T);

        impl<T, const N: usize> Write for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }

        impl<T, const N: usize> HashUser for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn reset(&mut self) {
                self.0.reset()
            }

            fn size(&self) -> usize {
                self.0.size()
            }

            fn block_size(&self) -> usize {
                self.0.block_size()
            }
        }

        impl<T, const N: usize> ErasedHashInner for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn sum(&mut self) -> Vec<u8> {
                self.0.sum().to_vec()
            }
        }

        Self(Box::new(Wrapper(h)))
    }

    pub fn sum(&mut self) -> Vec<u8> {
        self.0.sum()
    }
}

impl Write for ErasedHash {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl HashUser for ErasedHash {
    fn reset(&mut self) {
        self.0.reset()
    }

    fn size(&self) -> usize {
        self.0.size()
    }

    fn block_size(&self) -> usize {
        self.0.block_size()
    }
}
