use chacha20poly1305::aead::AeadMutInPlace;
use rc4::KeyInit;

#[test]
fn rustcrypto_chacha20poly1305_interop() {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce);
    let nonce = nonce;

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());
        let this = {
            let mut dst = vec![];
            let cipher = crate::chacha20ploy1305::ChaCha20Poly1305::new(&key).unwrap();
            cipher.seal(&mut dst, &nonce, &src, &[]).unwrap();
            dst
        };

        let rustcrypto = {
            let mut dst = src.clone();
            let mut cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher
                .encrypt_in_place(&nonce.into(), &[], &mut dst)
                .unwrap();
            dst
        };

        assert_eq!(this, rustcrypto);
    }
}
