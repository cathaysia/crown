use cipher::{generic_array::GenericArray, BlockEncrypt};
use rc4::KeyInit;

use super::*;

#[test]
fn test_powx() {
    let mut p = 1u32;
    (0..POWX.len()).for_each(|i| {
        assert_eq!(POWX[i] as u32, p);
        p <<= 1;
        if p & 0x100 != 0 {
            p ^= POLY;
        }
    });
}

struct CryptTest {
    key: &'static [u8],
    input: &'static [u8],
    output: &'static [u8],
}

const ENCRYPT_TESTS: &[CryptTest] = &[
    // Appendix B.
    CryptTest {
        key: &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ],
        input: &[
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ],
        output: &[
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ],
    },
    // Appendix C.1. AES-128
    CryptTest {
        key: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        input: &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        output: &[
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ],
    },
    // Appendix C.2. AES-192
    CryptTest {
        key: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
        input: &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        output: &[
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ],
    },
    // Appendix C.3. AES-256
    CryptTest {
        key: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        input: &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        output: &[
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ],
    },
];

#[test]
fn test_cipher_encrypt() {
    for (i, test) in ENCRYPT_TESTS.iter().enumerate() {
        let cipher = match Aes::new(test.key) {
            Ok(c) => c,
            Err(e) => {
                panic!("Block::new({} bytes) = {}", test.key.len(), e);
            }
        };

        let mut out = test.input.to_vec();
        cipher.encrypt(&mut out);

        for (j, (&actual, &expected)) in out.iter().zip(test.output.iter()).enumerate() {
            if actual != expected {
                panic!(
                    "Block.encrypt {}: out[{}] = {:#x}, want {:#x}",
                    i, j, actual, expected
                );
            }
        }
    }
}

#[test]
fn test_cipher_decrypt() {
    for (i, test) in ENCRYPT_TESTS.iter().enumerate() {
        let cipher = match Aes::new(test.key) {
            Ok(c) => c,
            Err(e) => {
                panic!("Block::new({} bytes) = {}", test.key.len(), e);
            }
        };

        let mut plain = test.output.to_vec();
        cipher.decrypt(&mut plain);

        for (j, (&actual, &expected)) in plain.iter().zip(test.input.iter()).enumerate() {
            if actual != expected {
                panic!(
                    "decrypt_block {}: plain[{}] = {:#x}, want {:#x}",
                    i, j, actual, expected
                );
            }
        }
    }
}

#[test]
fn test_aes_block() {
    for &keylen in &[128, 192, 256] {
        let key_bytes = keylen / 8;
        let key = vec![0u8; key_bytes];

        match Aes::new(&key) {
            Ok(cipher) => {
                assert_eq!(cipher.block_size(), BLOCK_SIZE);

                let plaintext = vec![0u8; BLOCK_SIZE];
                let mut ciphertext = vec![0u8; BLOCK_SIZE];

                cipher.encrypt(&mut ciphertext);
                let mut decrypted = ciphertext.clone();
                cipher.decrypt(&mut decrypted);

                assert_eq!(plaintext, decrypted, "AES-{} round trip failed", keylen);
            }
            Err(e) => {
                panic!("AES-{}: Block::new failed: {}", keylen, e);
            }
        }
    }
}

#[test]
fn test_invalid_key_sizes() {
    for &invalid_size in &[0, 8, 15, 17, 23, 25, 31, 33, 64] {
        let key = vec![0u8; invalid_size];
        match Aes::new(&key) {
            Ok(_) => panic!("Expected error for key size {}", invalid_size),
            Err(CryptoError::InvalidKeySize(size)) => assert_eq!(size, invalid_size),
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_block_size() {
    let key = vec![0u8; 16];
    let cipher = Aes::new(&key).unwrap();
    assert_eq!(cipher.block_size(), 16);
}

#[test]
#[should_panic(expected = "inout not full block")]
fn test_encrypt_short_output() {
    let key = vec![0u8; 16];
    let cipher = Aes::new(&key).unwrap();
    let mut dst = vec![0u8; 15]; // Too short
    cipher.encrypt(&mut dst);
}

#[test]
fn rustcrypto_aes_interop() {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut src = [0u8; 4];

        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src;
            let cipher = super::Aes::new(&key).unwrap();

            for i in (0..src.len()).step_by(BLOCK_SIZE) {
                let end = (i + BLOCK_SIZE).min(src.len());
                if end - i == BLOCK_SIZE {
                    cipher.encrypt(&mut dst[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = aes::Aes256::new(&key.into());

            for chunk in dst.chunks_exact_mut(BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(block);
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
