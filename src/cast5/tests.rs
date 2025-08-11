use cipher::generic_array::GenericArray;
use cipher::KeyInit;

use crate::cipher::BlockCipher;

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
                    cipher.encrypt(&mut dst[i..end], &src[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = cast5::Cast5::new(&key.into());

            for chunk in dst.chunks_exact_mut(super::Cast5::BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher::BlockEncrypt::encrypt_block(&cipher, block);
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
