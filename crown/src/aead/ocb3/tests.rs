use crate::{
    aead::{ocb3::Ocb3, Aead, AeadUser},
    block::aes::Aes,
    envelope::EvpAeadCipher,
};
use hex;

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

        let cipher = Aes::new(&key).unwrap().to_ocb3::<16, 12>().unwrap();

        let mut ct = pt.clone();
        cipher
            .seal_in_place_append_tag(&mut ct, &nonce, &[])
            .unwrap();
        cipher.open_in_place(&mut ct, &nonce, &[]).unwrap();
        ct.truncate(ct.len() - cipher.tag_size());

        assert_eq!(pt, ct);
    }
}

#[test]
fn test_evpciph_aes_ocb() {
    let test_data = include_str!("evpciph_aes_ocb.txt");

    let mut current_test = TestVector::default();
    let mut test_vectors = Vec::new();

    for line in test_data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if current_test.is_complete() {
                test_vectors.push(current_test.clone());
                current_test = TestVector::default();
            }
            continue;
        }

        if let Some((key, value)) = line.split_once(" = ") {
            match key {
                "Cipher" => {
                    if value == "aes-128-ocb" {
                        current_test.cipher = value.to_string();
                    }
                }
                "Key" => current_test.key = value.to_string(),
                "IV" => current_test.iv = value.to_string(),
                "AAD" => current_test.aad = value.to_string(),
                "Tag" => current_test.tag = value.to_string(),
                "Plaintext" => current_test.pt = value.to_string(),
                "Ciphertext" => current_test.ct = value.to_string(),
                "Operation" => current_test.operation = Some(value.to_string()),
                "Result" => current_test.result = Some(value.to_string()),
                _ => {}
            }
        }
    }

    if current_test.is_complete() {
        test_vectors.push(current_test);
    }

    for test_vector in test_vectors {
        if test_vector.cipher != "aes-128-ocb" {
            continue;
        }

        if test_vector.operation.as_deref() == Some("DECRYPT")
            && test_vector.result.as_deref() == Some("CIPHERFINAL_ERROR")
        {
            continue;
        }

        let key = hex::decode(&test_vector.key).unwrap();
        let iv = hex::decode(&test_vector.iv).unwrap();
        let aad = hex::decode(&test_vector.aad).unwrap();
        let plaintext = hex::decode(&test_vector.pt).unwrap();
        let expected_tag = hex::decode(&test_vector.tag).unwrap();
        let expected_ct = hex::decode(&test_vector.ct).unwrap();

        if iv.len() != 12 {
            continue;
        }

        // The file carries both 12- and 16-byte tags; the tag length is a
        // const generic, so dispatch on it (the nonce is always 12 bytes for
        // these vectors).
        match expected_tag.len() {
            12 => check_aes_ocb::<12>(&key, &iv, &aad, &plaintext, &expected_tag, &expected_ct),
            16 => check_aes_ocb::<16>(&key, &iv, &aad, &plaintext, &expected_tag, &expected_ct),
            _ => continue,
        }
    }
}

/// Seal/open one vector and compare both the ciphertext and the tag.
fn check_aes_ocb<const TAG_SIZE: usize>(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    expected_tag: &[u8],
    expected_ct: &[u8],
) {
    let cipher = EvpAeadCipher::new_aes_ocb3::<TAG_SIZE, 12>(key).unwrap();

    let mut ct = plaintext.to_vec();
    let tag = cipher.seal_in_place_separate_tag(&mut ct, iv, aad).unwrap();

    let tag_hex = hex::encode(&tag);
    let want_hex = hex::encode(expected_tag);
    assert_eq!(
        tag.as_slice(),
        expected_tag,
        "tag mismatch: {want_hex} != {tag_hex}"
    );
    assert_eq!(
        ct,
        expected_ct,
        "ciphertext mismatch: {} != {}",
        hex::encode(expected_ct),
        hex::encode(&ct)
    );

    cipher
        .open_in_place_separate_tag(&mut ct, &tag, iv, aad)
        .unwrap();
    assert_eq!(ct, plaintext, "decryption mismatch");
}

#[derive(Debug, Clone, Default)]
struct TestVector {
    cipher: String,
    key: String,
    iv: String,
    aad: String,
    tag: String,
    pt: String,
    ct: String,
    operation: Option<String>,
    result: Option<String>,
}

impl TestVector {
    fn is_complete(&self) -> bool {
        !self.cipher.is_empty()
            && !self.key.is_empty()
            && !self.iv.is_empty()
            && !self.tag.is_empty()
    }
}
