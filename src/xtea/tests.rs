use xtea::cipher::{BlockCipherEncrypt, KeyInit};

use crate::{cipher::BlockCipher, xtea::Xtea};

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

            for i in (0..src.len()).step_by(Xtea::BLOCK_SIZE) {
                let end = (i + Xtea::BLOCK_SIZE).min(src.len());
                if end - i == Xtea::BLOCK_SIZE {
                    cipher.encrypt(&mut dst[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = xtea::Xtea::new(&key.into());

            for chunk in dst.chunks_exact_mut(Xtea::BLOCK_SIZE) {
                cipher.encrypt_block(chunk.try_into().unwrap());
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
