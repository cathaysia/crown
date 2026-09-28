//! DES-X (DESX) — a DES variant with input/output whitening.
//!
//! `Enc(k1, k2, k)(x) = k1 ⊕ DES_k(x ⊕ k2)`.
//!
//! DESX raises the cost of exhaustive search and differential/linear
//! cryptanalysis while reusing the DES core. It is a historical
//! construction and is **not** recommended for new designs.

use crate::block::des::Des;
use crate::block::BlockCipher;
use crate::error::CryptoResult;

/// DES-X block cipher: 8-byte blocks, three 8-byte keys.
pub struct Desx {
    k1: [u8; 8],
    k2: [u8; 8],
    des: Des,
}

impl Desx {
    /// Build a DES-X cipher from the two whitening keys and the DES key.
    pub fn new(k1: &[u8; 8], k2: &[u8; 8], des_key: &[u8; 8]) -> CryptoResult<Self> {
        let des = Des::new(des_key)?;
        Ok(Self {
            k1: *k1,
            k2: *k2,
            des,
        })
    }
}

impl BlockCipher for Desx {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        assert!(inout.len() >= 8, "DES-X block must be 8 bytes");
        let block = &mut inout[..8];
        for i in 0..8 {
            block[i] ^= self.k2[i];
        }
        self.des.encrypt_block(block);
        for i in 0..8 {
            block[i] ^= self.k1[i];
        }
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        assert!(inout.len() >= 8, "DES-X block must be 8 bytes");
        let block = &mut inout[..8];
        for i in 0..8 {
            block[i] ^= self.k1[i];
        }
        self.des.decrypt_block(block);
        for i in 0..8 {
            block[i] ^= self.k2[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desx() -> Desx {
        Desx::new(
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        )
        .unwrap()
    }

    #[test]
    fn roundtrip() {
        let c = desx();
        let mut buf = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let pt = buf;
        c.encrypt_block(&mut buf);
        assert_ne!(buf, pt);
        c.decrypt_block(&mut buf);
        assert_eq!(buf, pt);
    }

    // Known DESX vector.
    // k1 = 1122334455667788, k2 = aabbccddeeff0011, k = 0123456789abcdef,
    // pt = 0123456789abcdef.
    // pt ⊕ k2 = ab9889ba6754cdfe
    // DES_k(...) = 1dabe92e049e3cc1
    // ⊕ k1       = 0c89da6a51f84b49
    #[test]
    fn known_vector() {
        let c = desx();
        let mut buf = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        c.encrypt_block(&mut buf);
        assert_eq!(
            &buf[..],
            &[0x0c, 0x89, 0xda, 0x6a, 0x51, 0xf8, 0x4b, 0x49][..]
        );
        c.decrypt_block(&mut buf);
        assert_eq!(&buf[..], &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][..]);
    }

    #[test]
    fn zero_whitening_matches_des() {
        // With zero whitening keys, DESX degenerates to plain DES.
        // FIPS vector: key = 0123456789abcdef, pt = 0123456789abcdef
        // ct = 56cc09e7cfdc4cef
        let c = Desx::new(
            &[0u8; 8],
            &[0u8; 8],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        )
        .unwrap();
        let mut buf = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        c.encrypt_block(&mut buf);
        assert_eq!(
            &buf[..],
            &[0x56, 0xcc, 0x09, 0xe7, 0xcf, 0xdc, 0x4c, 0xef][..]
        );
        c.decrypt_block(&mut buf);
        assert_eq!(&buf[..], &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][..]);
    }
}
