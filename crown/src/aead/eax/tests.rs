use crate::{
    aead::{eax::Eax, Aead},
    block::{aes::Aes, des::Des},
    error::CryptoError,
};

#[test]
fn aes_eax_paper_vectors() {
    let vectors = [
        (
            "233952dee4d5ed5f9b9c6d6ff80ff478",
            "62ec67f9c3a4a407fcb2a8c49031a8b3",
            "6bfb914fd07eae6b",
            "",
            "",
            "e037830e8389f27b025a2d6527e79d01",
        ),
        (
            "91945d3f4dcbee0bf45ef52255f095a4",
            "becaf043b0a23d843194ba972c66debd",
            "fa3bfd4806eb53fa",
            "f7fb",
            "19dd",
            "5c4c9331049d0bdab0277408f67967e5",
        ),
        (
            "01f74ad64077f2e704c0f60ada3dd523",
            "70c3db4f0d26368400a10ed05d2bff5e",
            "234a3463c1264ac6",
            "1a47cb4933",
            "d851d5bae0",
            "3a59f238a23e39199dc9266626c40f80",
        ),
        (
            "8f3f52e3c75c58f5cb261f518f4ad30a",
            "",
            "",
            "",
            "",
            "5adbeefc8fa9cae2b9a6db3f5f6c82e9",
        ),
    ];

    for (key, nonce, aad, plaintext, ciphertext, tag) in vectors {
        let key = hex::decode(key).unwrap();
        let nonce = hex::decode(nonce).unwrap();
        let aad = hex::decode(aad).unwrap();
        let mut inout = hex::decode(plaintext).unwrap();
        let expected_ciphertext = hex::decode(ciphertext).unwrap();
        let expected_tag = hex::decode(tag).unwrap();
        let cipher = Aes::new(&key).unwrap().to_eax::<16>(nonce.len()).unwrap();

        let actual_tag = cipher
            .seal_in_place_separate_tag(&mut inout, &nonce, &aad)
            .unwrap();
        assert_eq!(inout, expected_ciphertext);
        assert_eq!(actual_tag.as_slice(), expected_tag);

        cipher
            .open_in_place_separate_tag(&mut inout, &actual_tag, &nonce, &aad)
            .unwrap();
        assert_eq!(inout, hex::decode(plaintext).unwrap());
    }
}

#[test]
fn authentication_failure_does_not_decrypt() {
    let key = [0x11; 16];
    let nonce = [0x22; 12];
    let aad = [0x33; 7];
    let cipher = Aes::new(&key).unwrap().to_eax::<16>(nonce.len()).unwrap();
    let mut ciphertext = [0x44; 31];
    let mut tag = cipher
        .seal_in_place_separate_tag(&mut ciphertext, &nonce, &aad)
        .unwrap();
    let original_ciphertext = ciphertext;
    tag[0] ^= 1;

    assert_eq!(
        cipher.open_in_place_separate_tag(&mut ciphertext, &tag, &nonce, &aad),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(ciphertext, original_ciphertext);
}

#[test]
fn supports_truncated_tags() {
    let key = [0x11; 16];
    let nonce = [0x22; 12];
    let aad = [0x33; 7];
    let plaintext = [0x44; 31];
    let full_tag_cipher = Aes::new(&key).unwrap().to_eax::<16>(nonce.len()).unwrap();
    let short_tag_cipher = Aes::new(&key).unwrap().to_eax::<8>(nonce.len()).unwrap();
    let mut full_tag_ciphertext = plaintext;
    let mut short_tag_ciphertext = plaintext;

    let full_tag = full_tag_cipher
        .seal_in_place_separate_tag(&mut full_tag_ciphertext, &nonce, &aad)
        .unwrap();
    let short_tag = short_tag_cipher
        .seal_in_place_separate_tag(&mut short_tag_ciphertext, &nonce, &aad)
        .unwrap();

    assert_eq!(full_tag_ciphertext, short_tag_ciphertext);
    assert_eq!(short_tag, full_tag[..short_tag.len()]);
}

#[test]
fn validates_parameters() {
    assert!(matches!(
        Aes::new(&[0; 16]).unwrap().to_eax::<0>(12),
        Err(CryptoError::InvalidTagSize { actual: 0, .. })
    ));
    assert!(matches!(
        Des::new(&[0; 8]).unwrap().to_eax::<8>(12),
        Err(CryptoError::UnsupportedBlockSize(8))
    ));

    let cipher = Aes::new(&[0; 16]).unwrap().to_eax::<16>(12).unwrap();
    assert!(matches!(
        cipher.seal_in_place_separate_tag(&mut [], &[0; 11], &[]),
        Err(CryptoError::InvalidNonceSize { actual: 11, .. })
    ));
}
