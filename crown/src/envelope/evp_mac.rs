//! Unified MAC interface (SipHash, KMAC128/256, CMAC-AES, GMAC-AES).

use crate::block::aes::Aes;
use crate::error::{CryptoError, CryptoResult};
use crate::mac::cmac::Cmac;
use crate::mac::gmac::Gmac;
use crate::mac::kmac::{Kmac128, Kmac256};
use crate::mac::siphash::SipHash;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

trait MacInner {
    fn write(&mut self, data: &[u8]);
    fn sum(&mut self) -> Vec<u8>;
}

/// Type-erased MAC.
pub struct EvpMac(Box<dyn MacInner>);

impl EvpMac {
    /// SipHash-2-4. `key` is 16 bytes; `output_len` is 8 or 16.
    pub fn new_siphash(key: &[u8], output_len: usize) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        struct W(SipHash);
        impl MacInner for W {
            fn write(&mut self, data: &[u8]) {
                self.0.write(data);
            }
            fn sum(&mut self) -> Vec<u8> {
                self.0.sum()[..].to_vec()
            }
        }
        Ok(Self(Box::new(W(SipHash::new(&k, output_len)?))))
    }

    /// KMAC128. `custom` is the customization string (may be empty).
    pub fn new_kmac128(key: &[u8], custom: &[u8], output_len: usize) -> CryptoResult<Self> {
        struct W(Kmac128, usize);
        impl MacInner for W {
            fn write(&mut self, data: &[u8]) {
                self.0.write(data);
            }
            fn sum(&mut self) -> Vec<u8> {
                let mut out = vec![0u8; self.1];
                self.0.sum(&mut out);
                out
            }
        }
        Ok(Self(Box::new(W(Kmac128::new(key, custom)?, output_len))))
    }

    /// KMAC256.
    pub fn new_kmac256(key: &[u8], custom: &[u8], output_len: usize) -> CryptoResult<Self> {
        struct W(Kmac256, usize);
        impl MacInner for W {
            fn write(&mut self, data: &[u8]) {
                self.0.write(data);
            }
            fn sum(&mut self) -> Vec<u8> {
                let mut out = vec![0u8; self.1];
                self.0.sum(&mut out);
                out
            }
        }
        Ok(Self(Box::new(W(Kmac256::new(key, custom)?, output_len))))
    }

    /// AES-CMAC. Key is 16/24/32 bytes. Tag is 16 bytes.
    pub fn new_cmac_aes(key: &[u8]) -> CryptoResult<Self> {
        struct W(Cmac<Aes, 16>);
        impl MacInner for W {
            fn write(&mut self, data: &[u8]) {
                self.0.write(data);
            }
            fn sum(&mut self) -> Vec<u8> {
                self.0.sum().to_vec()
            }
        }
        Ok(Self(Box::new(W(Cmac::<Aes, 16>::new(Aes::new(key)?)?))))
    }

    /// AES-GMAC. Key is 16/24/32 bytes, IV is 12 bytes. Tag is 16 bytes.
    pub fn new_gmac_aes(key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
        if iv.len() != 12 {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(iv);
        struct W(Gmac<Aes>);
        impl MacInner for W {
            fn write(&mut self, data: &[u8]) {
                self.0.write(data);
            }
            fn sum(&mut self) -> Vec<u8> {
                self.0.sum().to_vec()
            }
        }
        Ok(Self(Box::new(W(Gmac::new(Aes::new(key)?, &iv_arr)?))))
    }

    pub fn write(&mut self, data: &[u8]) {
        self.0.write(data);
    }

    pub fn sum(&mut self) -> Vec<u8> {
        self.0.sum()
    }
}
