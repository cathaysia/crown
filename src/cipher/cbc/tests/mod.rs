mod aes_test;

use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::cipher::cbc::{CbcDecAble, CbcEncAble};

#[test]
#[ignore = "cannot pass"]
fn rustcrypto_des_cbc_interop() {
    use crate::des::BLOCK_SIZE;
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    type DesCbcEnc = cbc::Encryptor<des::Des>;
    type DesCbcDec = cbc::Decryptor<des::Des>;

    let mut kt_enc = crate::des::DesCipher::new(&key)
        .unwrap()
        .to_cbc_enc(&[0u8; BLOCK_SIZE]);

    let mut kt_dec = crate::des::DesCipher::new(&key)
        .unwrap()
        .to_cbc_dec(&[0u8; BLOCK_SIZE]);

    let mut rc_dec = DesCbcDec::new_from_slices(&key, &[0u8; BLOCK_SIZE]).unwrap();
    let mut rc_enc = DesCbcEnc::new_from_slices(&key, &[0u8; BLOCK_SIZE]).unwrap();

    for _ in 0..1000 {
        let mut block = [0u8; BLOCK_SIZE];
        rand::fill(&mut block);
        let block = block;

        // self enc and self dec.
        {
            let mut dst = [0u8; BLOCK_SIZE];
            dst.copy_from_slice(&block);

            kt_enc.crypt_blocks(&mut dst, &block);
            let src = dst.to_vec();
            kt_dec.crypt_blocks(&mut dst, &src);
            assert_eq!(block, dst);
        }
        {
            let mut dst = [0u8; BLOCK_SIZE];
            dst.copy_from_slice(&block);

            kt_enc.crypt_blocks(&mut dst, &block);
            rc_dec.decrypt_block_mut(&mut dst.into());
        }

        {
            let mut dst = [0u8; BLOCK_SIZE];
            dst.copy_from_slice(&block);

            rc_enc.encrypt_block_mut(&mut dst.into());
            let src = dst.to_vec();
            kt_dec.crypt_blocks(&mut dst, &src);
            assert_eq!(block, dst);
        }
    }
}
