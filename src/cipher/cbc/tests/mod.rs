mod aes_test;

use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::{
    cipher::{
        cbc::{CbcDecAble, CbcEncAble},
        padding::{Pkcs7, ToPaddingCrypt},
        BlockMode,
    },
    des::Des,
};

#[test]
fn des_cbc() {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let mut block = [0u8; Des::BLOCK_SIZE];
        rand::fill(&mut block);
        let block = block;

        let mut kt_enc = crate::des::Des::new(&key)
            .unwrap()
            .to_cbc_enc(&[0u8; Des::BLOCK_SIZE]);

        let mut kt_dec = crate::des::Des::new(&key)
            .unwrap()
            .to_cbc_dec(&[0u8; Des::BLOCK_SIZE]);

        let mut dst = [0u8; Des::BLOCK_SIZE];
        dst.copy_from_slice(&block);

        kt_enc.crypt_blocks(&mut dst);
        kt_dec.crypt_blocks(&mut dst);
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
            let mut kt_enc = crate::des::Des::new(&key)
                .unwrap()
                .to_cbc_enc(&[0u8; Des::BLOCK_SIZE]);

            let mut rc_dec = DesCbcDec::new_from_slices(&key, &[0u8; Des::BLOCK_SIZE]).unwrap();

            let mut dst = [0u8; Des::BLOCK_SIZE];
            dst.copy_from_slice(&block);

            kt_enc.crypt_blocks(&mut dst);
            rc_dec.decrypt_block_mut(&mut dst.into());
            assert_eq!(block, dst);
        }

        {
            let mut rc_enc = DesCbcEnc::new_from_slices(&key, &[0u8; Des::BLOCK_SIZE]).unwrap();

            let mut kt_dec = crate::des::Des::new(&key)
                .unwrap()
                .to_cbc_dec(&[0u8; Des::BLOCK_SIZE]);

            let mut dst = [0u8; Des::BLOCK_SIZE];
            dst.copy_from_slice(&block);

            rc_enc.encrypt_block_mut(&mut dst.into());
            kt_dec.crypt_blocks(&mut dst);
            assert_eq!(block, dst);
        }
    }
}

#[test]
fn boring_des_cbc_interop() {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let len = rand::random_range(2..2000);
        let mut block = vec![0u8; len];
        rand::fill(block.as_mut_slice());
        block[len - 1] = 0x10;

        let mut iv = [0u8; Des::BLOCK_SIZE];
        rand::fill(&mut iv);
        let block = block;

        {
            // Test: kittytls encrypt -> boring decrypt
            let mut kt_enc = crate::des::Des::new(&key)
                .unwrap()
                .to_cbc_enc(&iv)
                .to_padding_crypt::<Pkcs7>();

            let mut dst = block.clone();

            kt_enc.encrypt_alloc(&mut dst).unwrap();

            // BoringSSL decrypt
            let cipher = boring::symm::Cipher::des_cbc();
            let decrypted = boring::symm::decrypt(cipher, &key, Some(&iv), &dst).unwrap();

            assert_eq!(block.to_vec(), decrypted);
        }

        {
            // Test: boring encrypt -> kittytls decrypt
            let cipher = boring::symm::Cipher::des_cbc();

            let encrypted =
                boring::symm::encrypt(cipher, &key, Some(&[0u8; Des::BLOCK_SIZE]), &block).unwrap();

            let mut kt_dec = crate::des::Des::new(&key)
                .unwrap()
                .to_cbc_dec(&[0u8; Des::BLOCK_SIZE])
                .to_padding_crypt::<Pkcs7>();

            let mut dst = encrypted.clone();
            kt_dec.decrypt_alloc(&mut dst).unwrap();

            assert_eq!(block, dst.as_slice());
        }
    }
}
