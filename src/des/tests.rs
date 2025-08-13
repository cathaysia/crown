use cipher::generic_array::GenericArray;
use rc4::KeyInit;

use crate::{
    cipher::BlockCipher,
    des::{Des, TripleDes},
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
            let cipher = Des::new(&key).unwrap();

            for i in (0..src.len()).step_by(Des::BLOCK_SIZE) {
                let end = (i + Des::BLOCK_SIZE).min(src.len());
                if end - i == Des::BLOCK_SIZE {
                    cipher.encrypt(&mut dst[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = des::Des::new(&key.into());

            for chunk in dst.chunks_exact_mut(Des::BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher::BlockEncrypt::encrypt_block(&cipher, block);
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}

#[test]
fn rustcrypto_trides_interop() {
    let mut key = [0u8; 24];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut src = [0u8; 4];

        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src;
            let cipher = TripleDes::new(&key).unwrap();

            for i in (0..src.len()).step_by(Des::BLOCK_SIZE) {
                let end = (i + Des::BLOCK_SIZE).min(src.len());
                if end - i == Des::BLOCK_SIZE {
                    cipher.encrypt(&mut dst[i..end]);
                }
            }
            dst
        };

        let rustcrypto = {
            let mut dst = src;
            let cipher = des::TdesEde3::new(&key.into());

            for chunk in dst.chunks_exact_mut(Des::BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher::BlockEncrypt::encrypt_block(&cipher, block);
            }
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
