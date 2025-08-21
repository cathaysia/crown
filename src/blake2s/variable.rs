use super::*;

pub struct Blake2sVariable {
    h: [u32; 8],
    c: [u32; 2],
    size: usize,
    block: [u8; BLOCK_SIZE],
    offset: usize,
    key: [u8; BLOCK_SIZE],
    key_len: usize,
}

const MAGIC: &[u8] = b"b2s";
const MARSHALED_SIZE: usize = MAGIC.len() + 8 * 4 + 2 * 4 + 1 + BLOCK_SIZE + 1;

impl Blake2sVariable {
    pub fn new(key: Option<&[u8]>, hash_size: usize) -> CryptoResult<Self> {
        let key_slice = key.unwrap_or(&[]);
        if key_slice.len() > SIZE {
            return Err(CryptoError::InvalidKeySize(key_slice.len()));
        }
        let mut d = Self {
            h: [0; 8],
            c: [0; 2],
            size: hash_size,
            block: [0; BLOCK_SIZE],
            offset: 0,
            key: [0; BLOCK_SIZE],
            key_len: key_slice.len(),
        };

        d.key[..key_slice.len()].copy_from_slice(key_slice);
        d.reset_impl();

        Ok(d)
    }
    pub fn reset_impl(&mut self) {
        self.h = IV;
        self.h[0] ^= self.size as u32 | ((self.key_len as u32) << 8) | (1 << 16) | (1 << 24);
        self.offset = 0;
        self.c = [0; 2];

        if self.key_len > 0 {
            self.block = self.key;
            self.offset = BLOCK_SIZE;
        }
    }

    fn write_impl(&mut self, p: &[u8]) -> usize {
        let n = p.len();
        let mut p = p;

        if self.offset > 0 {
            let remaining = BLOCK_SIZE - self.offset;
            if n <= remaining {
                let copy_len = n.min(remaining);
                self.block[self.offset..self.offset + copy_len].copy_from_slice(&p[..copy_len]);
                self.offset += copy_len;
                return n;
            }

            self.block[self.offset..].copy_from_slice(&p[..remaining]);
            hash_blocks(&mut self.h, &mut self.c, 0, &self.block);
            self.offset = 0;
            p = &p[remaining..];
        }

        if p.len() > BLOCK_SIZE {
            let mut nn = p.len() & !(BLOCK_SIZE - 1);
            if p.len() == nn {
                nn -= BLOCK_SIZE;
            }
            hash_blocks(&mut self.h, &mut self.c, 0, &p[..nn]);
            p = &p[nn..];
        }

        let copy_len = p.len().min(BLOCK_SIZE);
        self.block[..copy_len].copy_from_slice(&p[..copy_len]);
        self.offset += copy_len;

        n
    }

    fn sum_impl(&self, sum: &mut Vec<u8>) {
        let mut hash = [0u8; SIZE];
        self.finalize(&mut hash);
        sum.extend_from_slice(&hash[..self.size]);
    }

    fn finalize(&self, hash: &mut [u8; SIZE]) {
        let mut block = [0u8; BLOCK_SIZE];
        let mut h = self.h;
        let mut c = self.c;

        block[..self.offset].copy_from_slice(&self.block[..self.offset]);
        let remaining = (BLOCK_SIZE - self.offset) as u32;

        if c[0] < remaining {
            c[1] = c[1].wrapping_sub(1);
        }
        c[0] = c[0].wrapping_sub(remaining);

        hash_blocks(&mut h, &mut c, 0xFFFFFFFF, &block);

        for (i, &v) in h.iter().enumerate() {
            let bytes = v.to_le_bytes();
            hash[4 * i..4 * i + 4].copy_from_slice(&bytes);
        }
    }
}

impl Marshalable for Blake2sVariable {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        if self.key_len != 0 {
            return Err(CryptoError::StringError(
                "crypto/blake2s: cannot marshal MACs".into(),
            ));
        }

        let mut b = Vec::with_capacity(MARSHALED_SIZE);
        b.extend_from_slice(MAGIC);

        for &h in &self.h {
            b.extend_from_slice(&h.to_be_bytes());
        }
        b.extend_from_slice(&self.c[0].to_be_bytes());
        b.extend_from_slice(&self.c[1].to_be_bytes());
        b.push(self.size as u8);
        b.extend_from_slice(&self.block);
        b.push(self.offset as u8);

        Ok(b)
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut pos = MAGIC.len();
        for i in 0..8 {
            self.h[i] = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]);
            pos += 4;
        }

        self.c[0] = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]);
        pos += 4;
        self.c[1] = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]);
        pos += 4;

        self.size = b[pos] as usize;
        pos += 1;

        self.block.copy_from_slice(&b[pos..pos + BLOCK_SIZE]);
        pos += BLOCK_SIZE;

        self.offset = b[pos] as usize;

        Ok(())
    }
}

impl Write for Blake2sVariable {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        Ok(self.write_impl(data))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl HashUser for Blake2sVariable {
    fn reset(&mut self) {
        self.reset_impl();
    }

    fn size(&self) -> usize {
        self.size
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
}

impl HashVariable for Blake2sVariable {
    fn sum(&mut self, sum: &mut [u8]) -> usize {
        let mut result = Vec::new();
        self.sum_impl(&mut result);
        copy(sum, &result)
    }
}
