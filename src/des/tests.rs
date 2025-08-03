use cipher::generic_array::GenericArray;
use rc4::KeyInit;

use crate::{
    cipher::BlockCipher,
    des::{DesCipher, BLOCK_SIZE},
};

#[test]
fn rustcrypto_des_interop() {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut src = [0u8; 4];

        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src;
            let cipher = DesCipher::new(&key).unwrap();

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
            let cipher = des::Des::new(&key.into());

            for chunk in dst.chunks_exact_mut(BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher::BlockEncrypt::encrypt_block(&cipher, block);
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
