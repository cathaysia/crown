mod aes_test;

use super::{CbcDecryptor, CbcEncryptor};
use crate::{block::des::Des, modes::BlockMode};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

#[test]
fn des_cbc() {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut block = [0u8; Des::BLOCK_SIZE];
        rand::fill(&mut block);
        let block = block;

        let mut kt_enc = crate::block::des::Des::new(&key)
            .unwrap()
            .to_cbc_enc(&[0u8; Des::BLOCK_SIZE]);

        let mut kt_dec = crate::block::des::Des::new(&key)
            .unwrap()
            .to_cbc_dec(&[0u8; Des::BLOCK_SIZE]);

        let mut dst = [0u8; Des::BLOCK_SIZE];
        dst.copy_from_slice(&block);

        kt_enc.encrypt(&mut dst);
        kt_dec.encrypt(&mut dst);
        assert_eq!(block, dst);
    }
}

#[test]
#[ignore = "cannot pass"]
fn rustcrypto_des_cbc_interop() {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    type DesCbcEnc = cbc::Encryptor<des::Des>;
    type DesCbcDec = cbc::Decryptor<des::Des>;

    for _ in 0..1000 {
        let mut block = [0u8; Des::BLOCK_SIZE];
        rand::fill(&mut block);
        let block = block;

        {
            let mut kt_enc = crate::block::des::Des::new(&key)
                .unwrap()
                .to_cbc_enc(&[0u8; Des::BLOCK_SIZE]);

            let mut rc_dec = DesCbcDec::new_from_slices(&key, &[0u8; Des::BLOCK_SIZE]).unwrap();

            let mut dst = [0u8; Des::BLOCK_SIZE];
            dst.copy_from_slice(&block);

            kt_enc.encrypt(&mut dst);
            rc_dec.decrypt_block_mut(&mut dst.into());
            assert_eq!(block, dst);
        }

        {
            let mut rc_enc = DesCbcEnc::new_from_slices(&key, &[0u8; Des::BLOCK_SIZE]).unwrap();

            let mut kt_dec = crate::block::des::Des::new(&key)
                .unwrap()
                .to_cbc_dec(&[0u8; Des::BLOCK_SIZE]);

            let mut dst = [0u8; Des::BLOCK_SIZE];
            dst.copy_from_slice(&block);

            rc_enc.encrypt_block_mut(&mut dst.into());
            kt_dec.encrypt(&mut dst);
            assert_eq!(block, dst);
        }
    }
}
