use crate::block::BlockCipher;
use cipher::KeyInit;

#[test]
fn rustcrypto_cast5_interop() {
    let mut key = [0u8; 16];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut src = [0u8; 4];

        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src;
            let cipher = super::Cast5::new(&key).unwrap();

            for i in (0..src.len()).step_by(super::Cast5::BLOCK_SIZE) {
                let end = (i + super::Cast5::BLOCK_SIZE).min(src.len());
                if end - i == super::Cast5::BLOCK_SIZE {
                    cipher.encrypt_block(&mut dst[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = cast5::Cast5::new(&key.into());

            for chunk in dst.chunks_exact_mut(super::Cast5::BLOCK_SIZE) {
                cipher::BlockEncrypt::encrypt_block(&cipher, chunk.into());
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
