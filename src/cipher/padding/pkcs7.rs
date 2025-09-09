use super::Padding;
use crate::error::{CryptoError, CryptoResult};

// Copy from block-padding
pub struct Pkcs7;

impl Pkcs7 {
    fn unpad(block: &[u8], strict: bool) -> CryptoResult<&[u8]> {
        if block.len() > 255 {
            panic!("block size is too big for PKCS#7");
        }
        let bs = block.len();
        let n = block[bs - 1];
        if n == 0 || n as usize > bs {
            return Err(CryptoError::UnpadError);
        }
        let s = bs - n as usize;
        if strict && block[s..bs - 1].iter().any(|&v| v != n) {
            return Err(CryptoError::UnpadError);
        }
        Ok(&block[..s])
    }
}

impl Padding for Pkcs7 {
    fn pad(block: &mut [u8], pos: usize) {
        if block.len() > 255 {
            panic!("block size is too big for PKCS#7");
        }
        if pos >= block.len() {
            panic!("`pos` is bigger or equal to block size");
        }
        let n = (block.len() - pos) as u8;
        for b in &mut block[pos..] {
            *b = n;
        }
    }

    fn unpad(block: &[u8]) -> CryptoResult<&[u8]> {
        Pkcs7::unpad(block, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7() {
        // https://node-security.com/posts/cryptography-pkcs-7-padding
        let mut block = [0x58, 0xb3, 0xa9, 0x0, 0x0, 0x0, 0x0, 0x0];
        Pkcs7::pad(&mut block, 3);
        assert_eq!(&block, &[0x58, 0xb3, 0xa9, 0x05, 0x05, 0x05, 0x05, 0x05]);
        let unpad = Pkcs7::unpad(&block, true).unwrap();
        assert_eq!(unpad, &[0x58, 0xb3, 0xa9]);
    }
}
