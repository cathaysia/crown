use cipher::KeyIvInit;

#[test]
fn rustcrypto_aes_ctr_interop() {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = src.clone();
            let block = crate::aes::Block::new(&key).unwrap();
            let mut ctr = crate::cipher::ctr::new_ctr(block, &[0u8; 16]).unwrap();
            ctr.xor_key_stream(&mut dst, &src).unwrap();
            dst
        };

        let rustcrypto = {
            let mut dst = src.clone();
            type Aes256Ctr64Be = ctr::Ctr64BE<aes::Aes256>;
            let mut cipher = Aes256Ctr64Be::new_from_slices(&key, &[0u8; 16]).unwrap();
            rc4::StreamCipher::apply_keystream(&mut cipher, &mut dst);
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
