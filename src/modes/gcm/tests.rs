use data::AES_GCMTESTS;

use crate::block::aes::Aes;

use super::{Aead, Gcm};
mod data;

#[test]
fn test_gcm() {
    for test in AES_GCMTESTS {
        let [key, nonce, plaintext, ad, result] = test;
        let key = hex::decode(key).unwrap();
        let nonce = hex::decode(nonce).unwrap();
        let plaintext = hex::decode(plaintext).unwrap();
        let ad = hex::decode(ad).unwrap();
        let result = hex::decode(result).unwrap();
        let tag_size = result.len() - plaintext.len();

        let aes = Aes::new(&key).unwrap();
        if tag_size != 16 || nonce.len() != 12 {
            continue;
        }
        let aesgcm = aes.to_gcm().unwrap();
        let mut inout = plaintext.to_vec();
        aesgcm
            .seal_in_place_append_tag(&mut inout, &nonce, &ad)
            .unwrap();
        assert_eq!(inout, result);
    }
}
