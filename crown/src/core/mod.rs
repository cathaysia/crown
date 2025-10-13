use crate::error::{CryptoError, CryptoResult};

pub trait CoreWrite {
    fn write(&mut self, buf: &[u8]) -> CryptoResult<usize>;

    fn flush(&mut self) -> CryptoResult<()>;

    fn write_all(&mut self, mut buf: &[u8]) -> CryptoResult<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(CryptoError::IoEof);
                }
                Ok(n) => buf = &buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::io::Write for dyn CoreWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }
}

pub trait CoreRead {
    fn read(&mut self, buf: &mut [u8]) -> CryptoResult<usize>;
}

#[cfg(feature = "std")]
impl std::io::Read for dyn CoreRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }
}
