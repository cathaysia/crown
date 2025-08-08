use xtea::cipher::{BlockCipherEncrypt, KeyInit};

use super::BLOCK_SIZE;
use crate::cipher::BlockCipher;

#[test]
fn rustcrypto_twofish_interop() {
    let mut key = [0u8; 16];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut src = [0u8; 4];

        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src;
            let cipher = super::Xtea::new(&key).unwrap();

            for i in (0..src.len()).step_by(BLOCK_SIZE) {
                let end = (i + BLOCK_SIZE).min(src.len());
                if end - i == BLOCK_SIZE {
                    cipher.encrypt(&mut dst[i..end], &src[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = xtea::Xtea::new(&key.into());

            for chunk in dst.chunks_exact_mut(BLOCK_SIZE) {
                cipher.encrypt_block(chunk.try_into().unwrap());
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
