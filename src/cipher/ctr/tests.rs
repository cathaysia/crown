use cipher::KeyIvInit;

use crate::{
    cipher::{ctr::CtrAble, StreamCipher},
    des::Des,
};

#[test]
fn rustcrypto_des_ctr_interop() {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src.clone();
            let mut ctr = crate::des::Des::new(&key)
                .unwrap()
                .to_ctr(&[0u8; Des::BLOCK_SIZE])
                .unwrap();
            ctr.xor_key_stream(&mut dst, &src).unwrap();
            dst
        };

        let rustcrypto = {
            let mut dst = src.clone();
            type DesCtr64Be = ctr::Ctr64BE<des::Des>;
            let mut cipher = DesCtr64Be::new_from_slices(&key, &[0u8; Des::BLOCK_SIZE]).unwrap();
            cipher::StreamCipher::apply_keystream(&mut cipher, &mut dst);
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
