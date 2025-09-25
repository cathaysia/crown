use crate::{
    aead::{ocb::Ocb, Aead},
    block::aes::Aes,
};

#[test]
fn test_aes_ocb_enc_and_dec() {
    for _ in 0..1000 {
        let len = rand::random_range(100..4000);
        let mut pt = vec![0u8; len];
        rand::fill(pt.as_mut_slice());

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::fill(&mut nonce);
        rand::fill(&mut key);

        let cipher = Aes::new(&key).unwrap().to_ocb::<16, 12>().unwrap();

        let mut ct = pt.clone();
        cipher
            .seal_in_place_append_tag(&mut ct, &nonce, &[])
            .unwrap();
        cipher.open_in_place(&mut ct, &nonce, &[]).unwrap();

        assert_eq!(pt, ct);
    }
}
