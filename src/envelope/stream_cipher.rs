use crate::{cipher::StreamCipher, error::CryptoResult};

trait ErasedStreamCipherInner {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
}

pub struct ErasedStreamCipher(Box<dyn ErasedStreamCipherInner>);

impl ErasedStreamCipher {
    pub fn new(stream_cipher: impl StreamCipher + 'static) -> Self {
        struct Wrapper<T>(T);

        impl<T> ErasedStreamCipherInner for Wrapper<T>
        where
            T: StreamCipher + 'static,
        {
            fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
                self.0.xor_key_stream(inout)
            }
        }
        Self(Box::new(Wrapper(stream_cipher)))
    }

    pub fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.0.xor_key_stream(inout)
    }
}
